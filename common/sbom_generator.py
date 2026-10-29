"""CycloneDX v1.5 SBOM builder (hand-built dict, no extra dependency)."""
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from common.models import CVEFinding
from common.osv_client import Dependency

SPEC_VERSION = "1.5"
_SEVERITY_MAP = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "UNKNOWN": "unknown"}


def _component(dep: Dependency) -> Dict[str, Any]:
    return {
        "type": "library",
        "bom-ref": dep.purl,
        "name": dep.name,
        "version": dep.version,
        "purl": dep.purl,
    }


def _vulnerability(finding: CVEFinding, refs: Dict[str, str]) -> Dict[str, Any]:
    vuln: Dict[str, Any] = {
        "id": finding.vuln_id,
        "source": {"name": "OSV", "url": f"https://osv.dev/vulnerability/{finding.vuln_id}"},
        "ratings": [{"severity": _SEVERITY_MAP.get(finding.severity, "unknown")}],
        "description": finding.summary,
        "affects": [{"ref": refs[finding.package_name]}] if finding.package_name in refs else [],
    }
    if finding.fixed_version != "unknown":
        vuln["recommendation"] = f"Upgrade {finding.package_name} to {finding.fixed_version} or later"
    return vuln


def build_sbom(
    deps: Iterable[Dependency],
    repo_full_name: str,
    incident_id: str,
    findings: Optional[Iterable[CVEFinding]] = None,
    timestamp: Optional[str] = None,
    serial_number: Optional[str] = None,
) -> Dict[str, Any]:
    """CycloneDX 1.5 BOM. `timestamp` / `serial_number` can be fixed for reproducible output."""
    dep_list: List[Dependency] = list(dict.fromkeys(deps))
    refs = {d.name: d.purl for d in dep_list}
    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": serial_number or f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp or datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "tools": {"components": [{"type": "application", "name": "Sentinel", "version": "1.0.0"}]},
            "component": {"type": "application", "name": repo_full_name, "bom-ref": f"incident:{incident_id}"},
        },
        "components": [_component(d) for d in dep_list],
        "vulnerabilities": [_vulnerability(f, refs) for f in (findings or [])],
    }


def sbom_to_json(sbom: Dict[str, Any]) -> str:
    return json.dumps(sbom, indent=2, sort_keys=False)
