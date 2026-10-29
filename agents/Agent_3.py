"""Agent_3 agent (CLAUDE.md §5.3): find the commit behind a failure and map active imports.

Run standalone:  python -m agents.Agent_3
Deterministic scoring decides first; ASI:One is only used to break ties, to word the root cause,
and never required for the report to be produced.
"""
import asyncio
from typing import Any, List, Optional   

import httpx 
from uagents import Context

from common.agent_factory import build_agent
from common.asi1_client import ASI1Client, LLMError, truncate
from common.ast_mapper import enclosing_function, merge_symbols
from common.commit_scoring import (
    ScoredCommit, extract_error_location, hunk_covering, is_ambiguous, rank_commits, to_utc_iso,
)
from common.config import get_settings
from common.github_client import GitHubClient
from common.logging import configure_console_utf8, log
from common.models import AgentErrorReport, CommitCorrelationRequest, CommitEvidenceReport
from common.sast_rules import mask_secrets

AGENT_NAME = "Agent_3"
AGENT_LABEL = "Agent_3"  # display name on Agentverse and in uagents logs
PORT = 8003
COMMITS_TO_INSPECT = 5
SNIPPET_LIMIT = 1000
DIFF_LIMIT = 4000
DESCRIPTION = (
    "Agent_3 (Commit-Detective): finds the Git commit that caused a production failure (scores the last 5 commits against the error file/line), explains the root cause from the diff and maps active Python imports. Part of the Sentinel DevSecOps swarm (Fetch-A-Thon 3.0)."
)


class CommitDetective:
    def __init__(self, gh: Optional[GitHubClient] = None, llm: Optional[ASI1Client] = None) -> None:
        self.gh, self.llm = gh, llm
        self._http: Optional[httpx.AsyncClient] = None

    async def startup(self, ctx: Context) -> None:
        if self.gh is None:
            self._http = httpx.AsyncClient(timeout=30)
            self.gh, self.llm = GitHubClient(self._http), ASI1Client(self._http)
        ctx.logger.info(f"Address: {ctx.agent.address}")
        log(ctx.logger, "-", AGENT_NAME, "startup", "✅ ready")

    async def shutdown(self, ctx: Context) -> None:
        if self._http is not None:
            await self._http.aclose()

    async def handle_request(self, ctx: Context, sender: str, msg: CommitCorrelationRequest) -> None:
        inc = msg.incident_id
        try:
            report = await self.investigate(ctx, msg)
            log(ctx.logger, inc, AGENT_NAME, "report",
                f"🧬 Commit {report.suspect_commit_sha[:7]} identified: {report.offending_file}")
            await ctx.send(sender, report)
        except Exception as exc:  # handlers never raise
            log(ctx.logger, inc, AGENT_NAME, "correlate", f"error: {type(exc).__name__}: {exc}", level="error")
            try:
                await ctx.send(sender, AgentErrorReport(
                    incident_id=inc, agent=AGENT_NAME, stage="correlate", error=f"{type(exc).__name__}: {exc}"[:500]))
            except Exception as send_exc:
                log(ctx.logger, inc, AGENT_NAME, "correlate", f"could not deliver error report: {send_exc}", level="error")

    async def investigate(self, ctx: Context, msg: CommitCorrelationRequest) -> CommitEvidenceReport:
        assert self.gh is not None, "GitHub client not initialised"
        inc, repo = msg.incident_id, msg.repo_full_name
        error_file, error_line = extract_error_location(msg.error_snippet)
        log(ctx.logger, inc, AGENT_NAME, "correlate",
            f"🔎 Inspecting last {COMMITS_TO_INSPECT} commits of {repo}@{msg.branch} "
            f"(error at {error_file or '?'}:{error_line or '?'})")

        listing = await self.gh.list_commits(repo, msg.branch, per_page=COMMITS_TO_INSPECT)
        if not listing:
            raise ValueError(f"no commits found on {repo}@{msg.branch}")
        commits = list(await asyncio.gather(*(self.gh.get_commit(repo, c.sha) for c in listing)))

        ranked = rank_commits(commits, error_file, error_line, msg.failing_endpoint, msg.failure_timestamp_utc)
        chosen = ranked[0]
        if is_ambiguous(ranked):
            chosen = await self._llm_tiebreak(ctx, inc, ranked, msg)
        offending_file = chosen.offending_file or (chosen.commit.files[0].filename if chosen.commit.files else "unknown")
        log(ctx.logger, inc, AGENT_NAME, "score",
            f"{chosen.commit.sha[:7]} scored {chosen.score} ({'; '.join(chosen.reasons) or 'no direct signal'})")

        patch = next((f.patch for f in chosen.commit.files if f.filename == offending_file), "")
        snippet = mask_secrets(truncate(hunk_covering(patch, error_line) or patch, SNIPPET_LIMIT))

        function, line_text = await self._locate_in_head(repo, msg.branch, offending_file, error_line)
        explanation = await self._explain(ctx, inc, chosen, offending_file, patch, msg, function, line_text, error_line)
        imports = await self._active_imports(repo, msg.branch)
        log(ctx.logger, inc, AGENT_NAME, "ast", f"🧩 {len(imports)} active import/call symbols mapped")

        return CommitEvidenceReport(
            incident_id=inc, repo_full_name=repo, suspect_commit_sha=chosen.commit.sha,
            suspect_commit_url=chosen.commit.url, author=chosen.commit.author,
            commit_message=chosen.commit.message.strip(), committed_at_utc=to_utc_iso(chosen.commit.committed_at),
            offending_file=offending_file, offending_diff_snippet=snippet,
            root_cause_explanation=explanation, active_ast_imports=imports,
        )

    # -- helpers -----------------------------------------------------------------------

    async def _llm_tiebreak(self, ctx: Context, inc: str, ranked: List[ScoredCommit], msg: CommitCorrelationRequest) -> ScoredCommit:
        top = ranked[0].score
        candidates = [r for r in ranked if r.score == top][:COMMITS_TO_INSPECT] if len(ranked) > 1 and ranked[1].score == top else ranked
        listing = "\n\n".join(
            f"sha: {r.commit.sha}\nmessage: {r.commit.message.strip()[:200]}\n"
            f"diff:\n{truncate(''.join(f.patch for f in r.commit.files), DIFF_LIMIT // len(candidates))}"
            for r in candidates
        )
        try:
            assert self.llm is not None, "LLM client not initialised"
            answer = await self.llm.chat_json(
                "You are a senior SRE. Pick the commit most likely to have caused the reported failure.",
                f"Failing endpoint: {msg.failing_endpoint}\nError: {truncate(msg.error_snippet or 'n/a', SNIPPET_LIMIT)}\n\n"
                f"Candidate commits:\n{listing}",
                '{"sha": "<full sha of one candidate>"}',
            )
            sha = str(answer.get("sha", "")).strip()
            picked = next((r for r in candidates if len(sha) >= 7 and (r.commit.sha.startswith(sha) or sha.startswith(r.commit.sha))), None)
            if picked:
                log(ctx.logger, inc, AGENT_NAME, "score", f"🤖 ASI:One broke the tie: {picked.commit.sha[:7]}")
                return picked
            log(ctx.logger, inc, AGENT_NAME, "score", "ASI:One returned an unknown sha; using most recent", level="warning")
        except (LLMError, AssertionError) as exc:
            log(ctx.logger, inc, AGENT_NAME, "score", f"tie-break unavailable ({exc}); using most recent", level="warning")
        return candidates[0]

    async def _locate_in_head(self, repo: str, branch: str, path: str, line: Optional[int]) -> "tuple[Optional[str], Optional[str]]":
        """(enclosing function name, source text of the error line) from the file as it is on `branch` now."""
        assert self.gh is not None
        try:
            current = await self.gh.get_file(repo, path, branch)
        except Exception:
            return None, None
        if current is None or line is None:
            return None, None
        lines = current.text.splitlines()
        text = lines[line - 1].strip() if 0 < line <= len(lines) else None
        return enclosing_function(current.text, line), text

    async def _explain(
        self, ctx: Context, inc: str, chosen: ScoredCommit, file: str, patch: str, msg: CommitCorrelationRequest,
        function: Optional[str], line_text: Optional[str], error_line: Optional[int],
    ) -> str:
        where = f"{file}:{error_line}" + (f" (in {function}())" if function else "")
        try:
            assert self.llm is not None, "LLM client not initialised"
            text = await self.llm.chat(
                "You are a senior SRE writing a root-cause note. Answer in 2-4 sentences, grounded ONLY in the "
                "diff and error provided. No markdown, no speculation about unseen code.",
                f"Failing endpoint: {msg.failing_endpoint}\nError: {truncate(msg.error_snippet or 'n/a', SNIPPET_LIMIT)}\n"
                f"Error location: {where}\nFailing line: {line_text or 'n/a'}\n"
                f"Commit message: {chosen.commit.message.strip()[:300]}\nDiff of {file}:\n{truncate(patch, DIFF_LIMIT)}",
            )
            return truncate(text.strip(), 800)
        except (LLMError, AssertionError) as exc:
            log(ctx.logger, inc, AGENT_NAME, "explain", f"ASI:One unavailable ({exc}); using deterministic summary", level="warning")
            return (
                f"Commit {chosen.commit.sha[:7]} ('{chosen.commit.message.strip().splitlines()[0][:100]}') changed {file}; "
                f"the failure on {msg.failing_endpoint} originates at {where}"
                + (f": `{line_text}`." if line_text else ".")
            )

    async def _active_imports(self, repo: str, branch: str) -> List[str]:
        assert self.gh is not None
        try:
            sources = await self.gh.fetch_python_sources(repo, branch, cap=30)
        except Exception:
            return []  # a repo without readable Python sources must not fail the investigation
        return merge_symbols(sources.values())


def create_agent(
    seed: Optional[str] = None, mailbox: bool = True, port: int = PORT,
    detective: Optional[CommitDetective] = None, **agent_kwargs: Any,
):
    cfg = get_settings()
    det = detective or CommitDetective()
    agent = build_agent(
        name=AGENT_LABEL, seed=seed or cfg.detective_seed, seed_env="DETECTIVE_SEED", port=port,
        description=DESCRIPTION, mailbox=mailbox, **agent_kwargs,
    )

    @agent.on_event("startup")
    async def _startup(ctx: Context) -> None:
        await det.startup(ctx)

    @agent.on_event("shutdown")
    async def _shutdown(ctx: Context) -> None:
        await det.shutdown(ctx)

    @agent.on_message(CommitCorrelationRequest)
    async def _on_request(ctx: Context, sender: str, msg: CommitCorrelationRequest) -> None:
        await det.handle_request(ctx, sender, msg)

    agent.detective = det  # type: ignore[attr-defined]
    return agent


if __name__ == "__main__":
    configure_console_utf8()
    create_agent(mailbox=True).run()
