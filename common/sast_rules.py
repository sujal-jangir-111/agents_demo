"""Regex SAST rule set (CLAUDE.md §5.4). Pure functions, no I/O.

Secrets are always masked in returned snippets (first 6 chars + '****').
"""
import os
import re
from dataclasses import dataclass
from typing import Dict, List, Mapping, Optional, Pattern, Tuple

from common.models import SASTFinding

MAX_SNIPPET = 1000
DEBUG_PORTS = {"5678", "9229"}


def mask_secret(value: str) -> str:
    """Keep the first 6 characters, hide the rest."""
    return value[:6] + "****"


@dataclass(frozen=True)
class _Pattern:
    regex: Pattern[str]
    mask_group: int = 0  # which group holds the secret value (secrets only)
    unless: Optional[Pattern[str]] = None  # line is skipped when this also matches


@dataclass(frozen=True)
class Rule:
    rule_id: str
    severity: str
    advice: str
    patterns: Tuple[_Pattern, ...]
    scan_comments: bool = False


def _p(regex: str, mask_group: int = 0, unless: Optional[str] = None, flags: int = 0) -> _Pattern:
    return _Pattern(re.compile(regex, flags), mask_group, re.compile(unless) if unless else None)


_SQL_VERB = r"(?:SELECT|INSERT|UPDATE|DELETE)\b"

SECRET_PATTERNS: Tuple[_Pattern, ...] = (
    _p(r"AKIA[0-9A-Z]{16}"),
    _p(r"sk_(?:live|test)_[0-9a-zA-Z]{10,}"),
    _p(r"ghp_[0-9A-Za-z]{36}"),
    _p(r"github_pat_\w{20,}"),
    _p(r"((?:secret|password|api_key|token)\s*=\s*[\"'])([^\"']{8,})([\"'])", mask_group=2, flags=re.IGNORECASE),
)

PYTHON_RULES: Tuple[Rule, ...] = (
    Rule("HARDCODED_SECRET", "HIGH",
         'Move the secret to an environment variable (os.getenv("NAME")) and rotate the exposed value.',
         SECRET_PATTERNS, scan_comments=True),
    Rule("UNSAFE_EVAL", "HIGH",
         "Avoid eval()/exec() on dynamic input; use ast.literal_eval or explicit dispatch.",
         (_p(r"\beval\("), _p(r"\bexec\("))),
    Rule("UNSAFE_DESERIALIZATION", "HIGH",
         "Use yaml.safe_load (or Loader=yaml.SafeLoader); avoid pickle for untrusted data.",
         (_p(r"\byaml\.load\(", unless=r"SafeLoader|safe_load"), _p(r"\bpickle\.loads\("))),
    Rule("COMMAND_INJECTION", "HIGH",
         "Use subprocess with an argument list and shell=False; never build shell strings from input.",
         (_p(r"shell\s*=\s*True"), _p(r"\bos\.system\("))),
    Rule("SQL_INJECTION", "HIGH",
         "Use parameterized queries (placeholders) instead of string formatting.",
         (
             _p(r"(?<![A-Za-z0-9_])[fF][\"']\s*" + _SQL_VERB, flags=re.IGNORECASE),
             _p(r"[\"']\s*" + _SQL_VERB + r"[^\"']*[\"']\s*%", flags=re.IGNORECASE),
             _p(r"[\"']\s*" + _SQL_VERB + r"[^\"']*[\"']\s*\.format\(", flags=re.IGNORECASE),
         )),
)

_SECRET_RULE = PYTHON_RULES[0]
_ADVICE_NO_USER = "Add a non-root USER instruction so the container does not run as root."
_ADVICE_LATEST = "Pin the base image to a specific version or digest instead of :latest."
_ADVICE_PORT = "Do not EXPOSE debug ports (5678 / 9229) in production images."

_FROM_RE = re.compile(r"^\s*FROM\s+", re.IGNORECASE)
_FROM_LATEST_RE = re.compile(r"^\s*FROM\s+.*:latest\b", re.IGNORECASE)
_USER_RE = re.compile(r"^\s*USER\s+\S+", re.IGNORECASE)
_EXPOSE_RE = re.compile(r"^\s*EXPOSE\s+(.*)$", re.IGNORECASE)


def mask_secrets(text: str) -> str:
    """Mask every secret value found anywhere in `text` (safe to send to an LLM or log)."""
    out = text
    for pat in SECRET_PATTERNS:
        def repl(m: "re.Match[str]", pat: _Pattern = pat) -> str:
            start, end = m.span(pat.mask_group)
            base = m.start()
            return m.group(0)[: start - base] + mask_secret(m.group(pat.mask_group)) + m.group(0)[end - base:]
        out = pat.regex.sub(repl, out)
    return out


def _mask_line(line: str) -> str:
    """Display snippet: stripped, secrets masked, truncated."""
    return mask_secrets(line.strip())[:MAX_SNIPPET]


def _finding(path: str, lineno: int, rule_id: str, severity: str, line: str, advice: str) -> SASTFinding:
    return SASTFinding(
        file_path=path, line_number=lineno, rule_id=rule_id, severity=severity,
        code_snippet=_mask_line(line), remediation_advice=advice,
    )


def _scan_python(path: str, content: str) -> List[SASTFinding]:
    findings: List[SASTFinding] = []
    for lineno, line in enumerate(content.splitlines(), start=1):
        is_comment = line.lstrip().startswith("#")
        for rule in PYTHON_RULES:
            if is_comment and not rule.scan_comments:
                continue
            for pat in rule.patterns:
                if pat.regex.search(line) and not (pat.unless and pat.unless.search(line)):
                    findings.append(_finding(path, lineno, rule.rule_id, rule.severity, line, rule.advice))
                    break  # one finding per rule per line
    return findings


def _scan_dockerfile(path: str, content: str) -> List[SASTFinding]:
    findings: List[SASTFinding] = []
    has_user = False
    last_from = (1, "")
    for lineno, line in enumerate(content.splitlines(), start=1):
        if line.lstrip().startswith("#"):
            continue
        if _USER_RE.match(line):
            has_user = True
        if _FROM_RE.match(line):
            last_from = (lineno, line)
        if _FROM_LATEST_RE.match(line):
            findings.append(_finding(path, lineno, "INSECURE_DOCKER", "MEDIUM", line, _ADVICE_LATEST))
        m = _EXPOSE_RE.match(line)
        if m:
            ports = {tok.split("/")[0] for tok in m.group(1).split()}
            if ports & DEBUG_PORTS:
                findings.append(_finding(path, lineno, "INSECURE_DOCKER", "MEDIUM", line, _ADVICE_PORT))
    if not has_user:
        findings.append(_finding(path, last_from[0], "INSECURE_DOCKER", "MEDIUM", last_from[1], _ADVICE_NO_USER))
    return findings


def _kind(path: str) -> Optional[str]:
    name = os.path.basename(path).lower()
    if name.startswith("dockerfile") or name.endswith(".dockerfile"):
        return "docker"
    if name.endswith(".py"):
        return "python"
    return None


def scan_text(file_path: str, content: str) -> List[SASTFinding]:
    """Run every applicable rule on one file. Unknown file types yield no findings."""
    kind = _kind(file_path)
    if kind == "python":
        findings = _scan_python(file_path, content)
    elif kind == "docker":
        findings = _scan_dockerfile(file_path, content)
    else:
        findings = []
    return sorted(findings, key=lambda f: (f.line_number, f.rule_id))


def scan_files(files: Mapping[str, str]) -> List[SASTFinding]:
    """Scan {path: content}; results ordered by file then line."""
    results: Dict[str, List[SASTFinding]] = {p: scan_text(p, c) for p, c in files.items()}
    return [f for path in sorted(results) for f in results[path]]
