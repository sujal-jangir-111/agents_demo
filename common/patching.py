"""Deterministic patch helpers shared by the Agent_5 and the Scanner's gatekeeper.

The LLM only drafts the runtime-bug fix; everything security-relevant here is plain code:
secret hardening, unsafe-YAML fix, requirements bumps, diff generation, and the
"did the patch actually touch the offending change" check. Pure functions, no I/O.
"""
import ast
import difflib
import re
from typing import Dict, Iterable, List, Optional

from common.models import CVEFinding
from common.osv_client import parse_requirement_line, version_key
from common.sast_rules import SECRET_PATTERNS, mask_secrets

MIN_SIGNIFICANT_LINE = 8  # shorter lines (`)`, `else:`, `pass`) say nothing about whether a bug was fixed

_ASSIGN_RE = re.compile(r'^(\s*)([A-Za-z_]\w*)(\s*(?::[^=]+)?=\s*)(["\']).*?\4(\s*(?:#.*)?)$')


# --------------------------------------------------------------------------- diff

def make_unified_diff(original: str, patched: str, path: str) -> str:
    """The single canonical DISPLAY diff both agents compute (so the attestation can cover it).
    Secrets are masked on both sides first, so a removed hardcoded key never travels in a diff;
    the PR commits file contents, not this text, so it does not need to be applyable."""
    return "\n".join(difflib.unified_diff(
        mask_secrets(original).splitlines(), mask_secrets(patched).splitlines(),
        fromfile=f"a/{path}", tofile=f"b/{path}", lineterm="",
    ))


def added_lines(patch: str) -> List[str]:
    return [ln[1:] for ln in patch.splitlines() if ln.startswith("+") and not ln.startswith("+++")]


def removed_lines(patch: str) -> List[str]:
    return [ln[1:] for ln in patch.splitlines() if ln.startswith("-") and not ln.startswith("---")]


def touches_offending_change(patched: str, offending_added: Iterable[str]) -> bool:
    """True if at least one significant line the offending commit ADDED is gone from the patched file
    (or if the commit added nothing significant, in which case there is nothing to check)."""
    significant = [ln.strip() for ln in offending_added if len(ln.strip()) >= MIN_SIGNIFICANT_LINE]
    if not significant:
        return True
    present = {ln.strip() for ln in patched.splitlines()}
    return any(ln not in present for ln in significant)


# --------------------------------------------------------------------------- source hardening

def ensure_import_os(code: str) -> str:
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return code
    for node in tree.body:
        if isinstance(node, ast.Import) and any(a.name == "os" and not a.asname for a in node.names):
            return code
    lines = code.splitlines(keepends=True)
    first_import = next((n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))), None)
    if first_import is not None:
        at = first_import.lineno - 1
    elif tree.body and isinstance(tree.body[0], ast.Expr) and isinstance(getattr(tree.body[0], "value", None), ast.Constant) \
            and isinstance(tree.body[0].value.value, str):
        at = tree.body[0].end_lineno or 0
    else:
        at = 0
    lines.insert(at, "import os\n")
    return "".join(lines)


def harden_secrets(code: str) -> str:
    """`NAME = "<secret literal>"` -> `NAME = os.getenv("NAME")` (adds `import os` when needed).
    Only simple assignments are rewritten; anything else is left for the gatekeeper to flag."""
    out: List[str] = []
    changed = False
    for line in code.splitlines(keepends=True):
        body = line.rstrip("\r\n")
        newline = line[len(body):]
        m = _ASSIGN_RE.match(body)
        if m and not body.lstrip().startswith("#") and any(p.regex.search(body) for p in SECRET_PATTERNS):
            out.append(f'{m.group(1)}{m.group(2)}{m.group(3)}os.getenv("{m.group(2).upper()}"){m.group(5)}{newline}')
            changed = True
        else:
            out.append(line)
    result = "".join(out)
    return ensure_import_os(result) if changed else result


def fix_unsafe_yaml(code: str) -> str:
    """Single-line `yaml.load(x[, Loader=...])` -> `yaml.safe_load(x)`."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return code
    edits = []
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "load"
                and isinstance(node.func.value, ast.Name) and node.func.value.id == "yaml"
                and node.args and node.lineno == node.end_lineno):
            arg = ast.get_source_segment(code, node.args[0])
            if arg:
                edits.append((node.lineno, node.col_offset, node.end_col_offset, f"yaml.safe_load({arg})"))
    if not edits:
        return code
    lines = code.splitlines(keepends=True)
    for lineno, start, end, replacement in sorted(edits, reverse=True):  # right-to-left keeps offsets valid
        raw = lines[lineno - 1].encode("utf-8")  # ast offsets are UTF-8 byte offsets
        lines[lineno - 1] = (raw[:start] + replacement.encode("utf-8") + raw[end:]).decode("utf-8")
    return "".join(lines)


def revert_hunk(code: str, hunk: str) -> Optional[str]:
    """Undo a commit's change: wherever the hunk's '+' block appears contiguously in `code`, put back
    its '-' block. Deterministic fallback fix when the LLM is unavailable. None if nothing applied."""
    blocks, minus, plus = [], [], []
    for ln in hunk.splitlines()[1:]:  # skip the @@ header
        if ln.startswith("-"):
            minus.append(ln[1:])
        elif ln.startswith("+"):
            plus.append(ln[1:])
        else:
            if minus or plus:
                blocks.append((minus, plus))
            minus, plus = [], []
    if minus or plus:
        blocks.append((minus, plus))

    lines = code.split("\n")
    applied = False
    for minus, plus in blocks:
        if not plus:
            continue
        want = [p.strip() for p in plus]
        for i in range(len(lines) - len(plus) + 1):
            if [ln.strip() for ln in lines[i:i + len(plus)]] == want:
                lines[i:i + len(plus)] = minus
                applied = True
                break
    return "\n".join(lines) if applied else None


# --------------------------------------------------------------------------- dependencies

def compute_bumps(findings: Iterable[CVEFinding]) -> Dict[str, str]:
    """{package: version} to pin: for each REACHABLE PyPI finding, the highest known fixed version."""
    bumps: Dict[str, str] = {}
    for f in findings:
        if not f.is_reachable_in_ast or f.fixed_version == "unknown":
            continue
        if f.package_name not in bumps or version_key(f.fixed_version) > version_key(bumps[f.package_name]):
            bumps[f.package_name] = f.fixed_version
    return bumps


def bump_requirements(text: str, bumps: Dict[str, str]) -> str:
    """Rewrite `name==old` to `name==new` for the given (normalized) names; other lines untouched."""
    out = []
    for line in text.splitlines(keepends=True):
        dep = parse_requirement_line(line)
        if dep and dep.name in bumps:
            line = re.sub(r"(==\s*)[^\s;#\\,]+", lambda m: m.group(1) + bumps[dep.name], line, count=1)
        out.append(line)
    return "".join(out)
