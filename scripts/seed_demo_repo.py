"""Seed the demo target repository (DEMO_REPO_FULL_NAME) with a git history Sentinel can work against.

    python -m scripts.seed_demo_repo [--create] [--reset] [--faulty-age-minutes 30] [--yes]

Resulting history on `main` (oldest first):
    README (auto-init or first commit) -> requirements.txt -> Dockerfile -> app.py (WORKING parent version)
    -> README update -> app.py "Require discount_rate in pricing config"  (the faulty commit)

The faulty commit changes exactly one line of app.py, `discount_rate = PRICING.get(...)` ->
`discount_rate = PRICING["discount_rate"]`, at the same line the live demo app reports in `X-Error-Line`, so
Agent_3's scoring (+50 file, +30 hunk covers the line) picks it, and Agent_5's rollback
(the parent commit's version of app.py) is a working file. The repo root holds app.py, requirements.txt and
Dockerfile, which is where the agents look. Only DEMO_REPO_FULL_NAME is written to, only on `main`
(Sentinel itself never pushes to main; this one-off seeding script is the only thing that does).
"""
import argparse
import base64
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

API = "https://api.github.com"
DEMO_DIR = Path(__file__).resolve().parent.parent / "demo_target_app"
FAULT_LINE_TEXT = 'discount_rate = PRICING["discount_rate"]'
SAFE_LINE_TEXT = 'discount_rate = PRICING.get("discount_rate", 0.0)'
FAULTY_MESSAGE = "Require discount_rate in pricing config"


class SeedError(Exception):
    """A readable reason the seeding stopped (never contains the token)."""


def faulty_source() -> str:
    return (DEMO_DIR / "app.py").read_text(encoding="utf-8")


def parent_source() -> str:
    """The same app one commit earlier: identical except the faulty line reads PRICING with a default."""
    faulty = faulty_source()
    if faulty.count(FAULT_LINE_TEXT) != 1:
        raise SeedError(f"demo_target_app/app.py must contain `{FAULT_LINE_TEXT}` exactly once")
    return faulty.replace(FAULT_LINE_TEXT, SAFE_LINE_TEXT, 1)


def readme_text(version: int, stamp: str) -> str:
    return (f"# sentinel-target\n\nDeliberately broken demo service for the Sentinel DevSecOps swarm "
            f"(Fetch-A-Thon 3.0). The intentional bugs are demo content: let Sentinel find them.\n"
            + ("\n" if version == 1 else f"\n_Docs updated {stamp}._\n"))


class Github:
    def __init__(self, client: httpx.Client, token: str) -> None:
        self.client = client
        self.headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                        "X-GitHub-Api-Version": "2022-11-28"}

    def call(self, method: str, path: str, ok: tuple = (200, 201), **kw: Any) -> httpx.Response:
        try:
            resp = self.client.request(method, f"{API}{path}", headers=self.headers, timeout=30, **kw)
        except httpx.HTTPError as exc:
            raise SeedError(f"could not reach GitHub ({type(exc).__name__})") from exc
        if resp.status_code not in ok:
            try:
                detail = str(resp.json().get("message", ""))[:200]
            except ValueError:
                detail = ""
            raise SeedError(f"GitHub {method} {path} -> HTTP {resp.status_code} {detail}".strip())
        return resp

    def file(self, repo: str, path: str) -> Optional[Dict[str, Any]]:
        resp = self.call("GET", f"/repos/{repo}/contents/{path}", ok=(200, 404), params={"ref": "main"})
        return resp.json() if resp.status_code == 200 else None

    def put(self, repo: str, path: str, content: str, message: str, when: datetime, who: Dict[str, str]) -> str:
        existing = self.file(repo, path)
        if existing and base64.b64decode(existing["content"]).decode("utf-8") == content:
            return ""  # identical: nothing to commit
        stamp = when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        who = {**who, "date": stamp}
        body: Dict[str, Any] = {"message": message, "branch": "main", "author": who, "committer": who,
                                "content": base64.b64encode(content.encode("utf-8")).decode("ascii")}
        if existing:
            body["sha"] = existing["sha"]
        return self.call("PUT", f"/repos/{repo}/contents/{path}", json=body).json()["commit"]["sha"]


def ensure_repo(gh: Github, repo: str, create: bool, private: bool) -> None:
    if gh.call("GET", f"/repos/{repo}", ok=(200, 404)).status_code == 200:
        return
    if not create:
        raise SeedError(f"{repo} does not exist. Create it on GitHub (empty is fine) or re-run with --create.")
    owner, name = repo.split("/", 1)
    me = gh.call("GET", "/user").json()["login"]
    path = "/user/repos" if owner.lower() == me.lower() else f"/orgs/{owner}/repos"
    gh.call("POST", path, json={"name": name, "private": private, "auto_init": True,
                                "description": "Deliberately broken demo target for Sentinel (Fetch-A-Thon 3.0)"})


def seed(client: httpx.Client, repo: str, token: str, *, create: bool = False, reset: bool = False, private: bool = False,
         faulty_age_minutes: int = 30, now: Optional[datetime] = None) -> Dict[str, Any]:
    if not token:
        raise SeedError("GITHUB_TOKEN is not set (needs Contents: read/write, and Administration to use --create)")
    if "/" not in repo or repo.count("/") != 1:
        raise SeedError(f"invalid repo {repo!r}; expected owner/name")
    gh = Github(client, token)
    now = now or datetime.now(timezone.utc)
    ensure_repo(gh, repo, create, private)
    current = gh.file(repo, "app.py")
    if current is not None and not reset:
        if base64.b64decode(current["content"]).decode("utf-8") == faulty_source():
            return {"status": "already-seeded", "repo": repo}
        raise SeedError("the repo already has a different app.py; re-run with --reset to rebuild the demo history on top of it")
    user = gh.call("GET", "/user").json()
    who = {"name": user.get("name") or user["login"], "email": f"{user['id']}+{user['login']}@users.noreply.github.com"}
    t_faulty = now - timedelta(minutes=faulty_age_minutes)
    plan: List[tuple] = [
        ("README.md", readme_text(1, ""), "Add README", t_faulty - timedelta(minutes=50)),
        ("requirements.txt", (DEMO_DIR / "requirements.txt").read_text(encoding="utf-8"), "Add pinned requirements", t_faulty - timedelta(minutes=40)),
        ("Dockerfile", (DEMO_DIR / "Dockerfile").read_text(encoding="utf-8"), "Add Dockerfile", t_faulty - timedelta(minutes=30)),
        ("app.py", parent_source(), "Add checkout service", t_faulty - timedelta(minutes=20)),
        ("README.md", readme_text(2, now.strftime("%Y-%m-%d %H:%M UTC")), "Update README", t_faulty - timedelta(minutes=10)),
        ("app.py", faulty_source(), FAULTY_MESSAGE, t_faulty),
    ]
    shas = {}
    for path, content, message, when in plan:
        shas[message] = gh.put(repo, path, content, message, when, who)
    if not shas[FAULTY_MESSAGE]:
        raise SeedError("the faulty commit was not created (app.py already matched); use --reset")
    return {"status": "seeded", "repo": repo, "faulty_commit": shas[FAULTY_MESSAGE], "commits": {k: v for k, v in shas.items() if v}}


def main(argv: Optional[List[str]] = None) -> int:
    from common.config import get_settings
    cfg = get_settings()
    ap = argparse.ArgumentParser(description="Seed the Sentinel demo target repository")
    ap.add_argument("--repo", default=cfg.demo_repo_full_name, help="owner/name (default: DEMO_REPO_FULL_NAME)")
    ap.add_argument("--create", action="store_true", help="create the repo if it does not exist")
    ap.add_argument("--private", action="store_true", help="with --create: make it private")
    ap.add_argument("--reset", action="store_true", help="rebuild the demo history even if app.py already exists")
    ap.add_argument("--faulty-age-minutes", type=int, default=30, help="back-date the faulty commit (0 = now); default 30")
    ap.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    args = ap.parse_args(argv)
    if not args.repo or args.repo.startswith("your-org/"):
        print("Set DEMO_REPO_FULL_NAME in .env (owner/name) or pass --repo.", file=sys.stderr)
        return 2
    print(f"About to write demo files and 6 commits to https://github.com/{args.repo} (branch main).")
    if not args.yes and input("Type the repo name to confirm: ").strip() != args.repo:
        print("Aborted.")
        return 1
    try:
        with httpx.Client() as client:
            result = seed(client, args.repo, cfg.github_token, create=args.create, reset=args.reset, private=args.private,
                          faulty_age_minutes=args.faulty_age_minutes)
    except SeedError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    if result["status"] == "already-seeded":
        print(f"Already seeded: https://github.com/{args.repo} has the faulty app.py. Nothing to do.")
    else:
        print(f"Seeded https://github.com/{args.repo}\nFaulty commit: {result['faulty_commit']}\n"
              f"https://github.com/{args.repo}/commit/{result['faulty_commit']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
