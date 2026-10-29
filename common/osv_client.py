"""OSV.dev client: manifest parsing, batch query, severity/fix resolution, reachability.

Notes:
- querybatch returns only vuln IDs, so details are fetched per unique ID
  (`GET /v1/vulns/{id}`) concurrently and cached in memory.
- Reachability is Python-AST based, so only PyPI packages can be "reachable";
  npm packages are always reported as latent.
- A single querybatch call is made (OSV allows up to 1000 queries per call and
  this MVP does not paginate beyond that).
"""
import asyncio
import json
import math
import re
import tomllib
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

import httpx

from common.http_retry import send_with_retry
from common.models import CVEFinding

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{vuln_id}"

CRITICAL_EXPLOITABLE = "CRITICAL_EXPLOITABLE"
LATENT_DEPENDENCY = "LATENT_DEPENDENCY"

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}

IMPORT_NAME_OVERRIDES = {
    "pyyaml": "yaml",
    "beautifulsoup4": "bs4",
    "pillow": "PIL",
    "scikit-learn": "sklearn",
    "python-jose": "jose",
    "pyjwt": "jwt",
}


class OSVError(Exception):
    """OSV.dev could not be queried (after retries) or returned unusable data."""


@dataclass(frozen=True)
class Dependency:
    name: str  # normalized (PEP 503 for PyPI)
    version: str
    ecosystem: str = "PyPI"

    @property
    def purl(self) -> str:
        return f"pkg:{'pypi' if self.ecosystem == 'PyPI' else 'npm'}/{self.name}@{self.version}"


# --------------------------------------------------------------------------- parsing

def normalize_name(name: str) -> str:
    """PEP 503: lowercase, runs of '-', '_', '.' become '-'."""
    return re.sub(r"[-_.]+", "-", name).lower()


_REQ_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*==\s*([^\s;#\\,]+)")
_NPM_EXACT_RE = re.compile(r"^\d+(?:\.\d+)*(?:[-+][0-9A-Za-z.-]+)?$")


def parse_requirement_line(line: str) -> Optional[Dependency]:
    """Parse one pinned `name==version` line; anything else returns None."""
    line = line.strip()
    if not line or line.startswith(("#", "-")):
        return None
    m = _REQ_RE.match(line)
    if not m or "*" in m.group(2):
        return None
    return Dependency(normalize_name(m.group(1)), m.group(2))


def parse_requirements(text: str) -> List[Dependency]:
    deps = (parse_requirement_line(line) for line in text.splitlines())
    return [d for d in deps if d]


def parse_pyproject(text: str) -> List[Dependency]:
    """Pinned PEP 621 dependencies (`[project]` and optional-dependencies)."""
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    project = data.get("project", {})
    specs: List[str] = list(project.get("dependencies", []))
    for group in project.get("optional-dependencies", {}).values():
        specs.extend(group)
    return [d for d in (parse_requirement_line(s) for s in specs) if d]


def parse_package_json(text: str) -> List[Dependency]:
    """npm dependencies with exact versions (after stripping ^ and ~)."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    deps: List[Dependency] = []
    for section in ("dependencies", "devDependencies"):
        for name, spec in (data.get(section) or {}).items():
            version = str(spec).strip().lstrip("^~").strip()
            if _NPM_EXACT_RE.match(version):
                deps.append(Dependency(name.lower(), version, "npm"))
    return deps


def parse_manifests(files: Dict[str, str]) -> List[Dependency]:
    """Parse {filename: content} for requirements.txt / pyproject.toml / package.json, de-duplicated."""
    deps: List[Dependency] = []
    for path, content in files.items():
        base = path.rsplit("/", 1)[-1]
        if base == "requirements.txt":
            deps.extend(parse_requirements(content))
        elif base == "pyproject.toml":
            deps.extend(parse_pyproject(content))
        elif base == "package.json":
            deps.extend(parse_package_json(content))
    return list(dict.fromkeys(deps))


# --------------------------------------------------------------------------- versions / severity

def version_key(version: str) -> Tuple[int, ...]:
    return tuple(int(n) for n in re.findall(r"\d+", version))


def _cvss3_roundup(x: float) -> float:
    n = round(x * 100000)
    return n / 100000.0 if n % 10000 == 0 else (math.floor(n / 10000) + 1) / 10.0


_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def cvss3_base_score(vector: str) -> Optional[float]:
    """CVSS v3.0/3.1 base score from a vector string, or None if unparseable."""
    if not vector.startswith(("CVSS:3.0/", "CVSS:3.1/")):
        return None
    try:
        m = dict(part.split(":", 1) for part in vector.split("/")[1:])
        changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[m["PR"]]
        iss = 1 - (1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
        expl = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr * _UI[m["UI"]]
    except (KeyError, ValueError):
        return None
    if impact <= 0:
        return 0.0
    total = impact + expl
    return _cvss3_roundup(min(1.08 * total if changed else total, 10))


def _bucket(score: float) -> str:
    if score >= 9:
        return "CRITICAL"
    if score >= 7:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    return "LOW"


def severity_from_vuln(vuln: Dict[str, Any]) -> str:
    """database_specific.severity first, else CVSS-derived bucket, else UNKNOWN."""
    declared = str((vuln.get("database_specific") or {}).get("severity", "")).upper()
    declared = {"MODERATE": "MEDIUM"}.get(declared, declared)
    if declared in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        return declared
    for entry in vuln.get("severity") or []:
        raw = str(entry.get("score", ""))
        try:
            score: Optional[float] = float(raw)
        except ValueError:
            score = cvss3_base_score(raw)
        if score is not None:
            return _bucket(score)
    return "UNKNOWN"


def fixed_version_for(vuln: Dict[str, Any], dep: Dependency) -> str:
    """Smallest `fixed` event above the installed version for this package, else 'unknown'."""
    installed = version_key(dep.version)
    candidates: List[str] = []
    for affected in vuln.get("affected") or []:
        pkg = affected.get("package") or {}
        if pkg.get("ecosystem") != dep.ecosystem:
            continue
        name = normalize_name(pkg.get("name", "")) if dep.ecosystem == "PyPI" else str(pkg.get("name", "")).lower()
        if name != dep.name:
            continue
        for rng in affected.get("ranges") or []:
            for event in rng.get("events") or []:
                fixed = event.get("fixed")
                if fixed and version_key(fixed) > installed:
                    candidates.append(fixed)
    return min(candidates, key=version_key) if candidates else "unknown"


# --------------------------------------------------------------------------- reachability

def import_name_for(package: str) -> str:
    norm = normalize_name(package)
    return IMPORT_NAME_OVERRIDES.get(norm, norm.replace("-", "_"))


def is_reachable(dep: Dependency, active_imports: Iterable[str]) -> bool:
    if dep.ecosystem != "PyPI":
        return False
    return import_name_for(dep.name) in set(active_imports)


def classify(finding: CVEFinding) -> str:
    return CRITICAL_EXPLOITABLE if finding.is_reachable_in_ast else LATENT_DEPENDENCY


def count_reachable(findings: Iterable[CVEFinding], severity: str) -> int:
    """Number of reachable findings of the given severity (used for total_reachable_critical)."""
    return sum(1 for f in findings if f.is_reachable_in_ast and f.severity == severity)


# --------------------------------------------------------------------------- HTTP

async def _request(client: httpx.AsyncClient, method: str, url: str, **kwargs: Any) -> Any:
    """JSON request using the shared retry policy (common/http_retry.py)."""
    resp = await send_with_retry(client, method, url, error_cls=OSVError, label=f"OSV request to {url}", **kwargs)
    if resp.status_code >= 400:
        raise OSVError(f"OSV request to {url} failed: HTTP {resp.status_code}")
    try:
        return resp.json()
    except ValueError as exc:
        raise OSVError(f"OSV returned invalid JSON from {url}") from exc


async def query_batch(client: httpx.AsyncClient, deps: List[Dependency]) -> Dict[Dependency, List[str]]:
    """One querybatch call -> vuln IDs per dependency."""
    if not deps:
        return {}
    payload = {"queries": [
        {"package": {"name": d.name, "ecosystem": d.ecosystem}, "version": d.version} for d in deps
    ]}
    data = await _request(client, "POST", OSV_BATCH_URL, json=payload)
    results = data.get("results") if isinstance(data, dict) else None
    if not isinstance(results, list) or len(results) != len(deps):
        raise OSVError("OSV querybatch returned an unexpected response shape")
    return {d: [v["id"] for v in (r.get("vulns") or []) if "id" in v] for d, r in zip(deps, results)}


async def fetch_vulns(
    client: httpx.AsyncClient, vuln_ids: Iterable[str], cache: Optional[Dict[str, Dict[str, Any]]] = None
) -> Dict[str, Optional[Dict[str, Any]]]:
    """Fetch full records concurrently; a failed fetch maps to None instead of raising."""
    cache = cache if cache is not None else {}
    unique = list(dict.fromkeys(vuln_ids))

    async def one(vuln_id: str) -> Optional[Dict[str, Any]]:
        if vuln_id in cache:
            return cache[vuln_id]
        try:
            record = await _request(client, "GET", OSV_VULN_URL.format(vuln_id=vuln_id))
        except OSVError:
            return None
        cache[vuln_id] = record
        return record

    records = await asyncio.gather(*(one(v) for v in unique))
    return dict(zip(unique, records))


def _summary(vuln: Optional[Dict[str, Any]]) -> str:
    if not vuln:
        return "Details unavailable from OSV.dev"
    text = vuln.get("summary") or (vuln.get("details") or "").strip().split("\n")[0]
    return text[:300] or "No summary provided"


async def build_cve_findings(
    client: httpx.AsyncClient,
    deps: List[Dependency],
    active_imports: Iterable[str],
    cache: Optional[Dict[str, Dict[str, Any]]] = None,
) -> List[CVEFinding]:
    """Full SCA pass: batch query, detail fetch, severity, fixed version, reachability."""
    imports = set(active_imports)
    hits = await query_batch(client, deps)
    details = await fetch_vulns(client, (vid for ids in hits.values() for vid in ids), cache)
    findings: List[CVEFinding] = []
    for dep, ids in hits.items():
        for vid in dict.fromkeys(ids):
            vuln = details.get(vid)
            findings.append(CVEFinding(
                package_name=dep.name,
                installed_version=dep.version,
                fixed_version=fixed_version_for(vuln, dep) if vuln else "unknown",
                vuln_id=vid,
                severity=severity_from_vuln(vuln) if vuln else "UNKNOWN",
                is_reachable_in_ast=is_reachable(dep, imports),
                summary=_summary(vuln),
            ))
    findings.sort(key=lambda f: (-SEVERITY_RANK.get(f.severity, 0), f.package_name, f.vuln_id))
    return findings
