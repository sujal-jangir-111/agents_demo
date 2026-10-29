import json

from common.models import CVEFinding
from common.osv_client import Dependency
from common.sbom_generator import build_sbom, sbom_to_json

DEPS = [Dependency("pyyaml", "5.3"), Dependency("urllib3", "1.24.1"), Dependency("lodash", "4.17.4", "npm")]
FINDING = CVEFinding(
    package_name="pyyaml", installed_version="5.3", fixed_version="5.4", vuln_id="GHSA-8q59-q68h-6hv4",
    severity="CRITICAL", is_reachable_in_ast=True, summary="Improper Input Validation",
)


def make(**kw):
    return build_sbom(DEPS, "org/sentinel-target", "inc-abc12345", timestamp="2026-01-01T00:00:00+00:00",
                      serial_number="urn:uuid:00000000-0000-0000-0000-000000000000", **kw)


def test_envelope_is_cyclonedx_1_5():
    bom = make()
    assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.5" and bom["version"] == 1
    assert bom["serialNumber"].startswith("urn:uuid:")
    assert bom["metadata"]["component"]["name"] == "org/sentinel-target"
    assert bom["vulnerabilities"] == []


def test_components_have_purls():
    comps = {c["name"]: c for c in make()["components"]}
    assert comps["pyyaml"]["purl"] == "pkg:pypi/pyyaml@5.3" and comps["pyyaml"]["bom-ref"] == "pkg:pypi/pyyaml@5.3"
    assert comps["lodash"]["purl"] == "pkg:npm/lodash@4.17.4"
    assert all(c["type"] == "library" for c in comps.values())


def test_vulnerabilities_link_to_components():
    vuln = make(findings=[FINDING])["vulnerabilities"][0]
    assert vuln["id"] == "GHSA-8q59-q68h-6hv4"
    assert vuln["ratings"] == [{"severity": "critical"}]
    assert vuln["affects"] == [{"ref": "pkg:pypi/pyyaml@5.3"}]
    assert "5.4" in vuln["recommendation"]


def test_unknown_fix_has_no_recommendation_and_dedupes_components():
    f = FINDING.copy(update={"fixed_version": "unknown"})
    bom = build_sbom(DEPS + DEPS, "o/r", "inc-1", findings=[f])
    assert "recommendation" not in bom["vulnerabilities"][0] and len(bom["components"]) == 3


def test_defaults_generate_unique_serial_and_json_roundtrip():
    a, b = build_sbom(DEPS, "o/r", "i"), build_sbom(DEPS, "o/r", "i")
    assert a["serialNumber"] != b["serialNumber"]
    assert json.loads(sbom_to_json(make(findings=[FINDING])))["specVersion"] == "1.5"
