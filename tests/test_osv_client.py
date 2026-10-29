from pathlib import Path

import httpx
import pytest
import respx

from common import osv_client as osv
from common.ast_mapper import extract_symbols
from common.osv_client import Dependency, OSVError

DEMO = Path(__file__).resolve().parent.parent / "demo_target_app"
DEMO_REQS = (DEMO / "requirements.txt").read_text(encoding="utf-8")
DEMO_APP = (DEMO / "app.py").read_text(encoding="utf-8")

PYYAML = Dependency("pyyaml", "5.3")
URLLIB3 = Dependency("urllib3", "1.24.1")

# Offline fixture records shaped like OSV responses (IDs are sample data for the mocks).
VULN_PYYAML = {
    "id": "GHSA-8q59-q68h-6hv4",
    "summary": "Improper Input Validation in PyYAML",
    "database_specific": {"severity": "CRITICAL"},
    "affected": [{
        "package": {"name": "PyYAML", "ecosystem": "PyPI"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.4"}]}],
    }],
}
VULN_URLLIB3 = {
    "id": "GHSA-urllib3-sample",
    "details": "CRLF injection\nmore text",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    "affected": [{
        "package": {"name": "urllib3", "ecosystem": "PyPI"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.24.2"}, {"fixed": "1.25.9"}]}],
    }],
}


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    async def instant(_):
        return None
    monkeypatch.setattr("common.http_retry._sleep", instant)


# ------------------------------------------------------------------ parsing

def test_demo_requirements_parse_only_pinned():
    assert osv.parse_requirements(DEMO_REQS) == [PYYAML, URLLIB3]


def test_requirements_edge_cases():
    text = "\n".join([
        "# comment", "-r other.txt", "Flask_Login==0.6.3  # inline", "requests[security]==2.0.0 ; python_version>'3'",
        "django>=4", "numpy==1.*", "", "PyYAML == 5.3",
    ])
    assert osv.parse_requirements(text) == [
        Dependency("flask-login", "0.6.3"), Dependency("requests", "2.0.0"), Dependency("pyyaml", "5.3"),
    ]


def test_package_json_strips_carets_and_skips_ranges():
    text = '{"dependencies": {"lodash": "^4.17.4", "left-pad": "~1.0.0", "x": ">=1", "y": "latest", "z": "1.2.3"}}'
    assert osv.parse_package_json(text) == [
        Dependency("lodash", "4.17.4", "npm"), Dependency("left-pad", "1.0.0", "npm"), Dependency("z", "1.2.3", "npm"),
    ]
    assert osv.parse_package_json("not json") == []


def test_pyproject_parse():
    text = '[project]\nname="x"\ndependencies=["pyyaml==5.3", "fastapi>=0.1"]\n[project.optional-dependencies]\ndev=["pytest==8.0.0"]\n'
    assert osv.parse_pyproject(text) == [Dependency("pyyaml", "5.3"), Dependency("pytest", "8.0.0")]
    assert osv.parse_pyproject("= broken") == []


def test_parse_manifests_dedupes():
    deps = osv.parse_manifests({"requirements.txt": "pyyaml==5.3\n", "sub/requirements.txt": "pyyaml==5.3\n", "README.md": "x"})
    assert deps == [PYYAML]


def test_normalize_name():
    assert osv.normalize_name("Foo_Bar.baz") == "foo-bar-baz"


# ------------------------------------------------------------------ severity / fixed version

def test_cvss3_known_scores():
    assert osv.cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert osv.cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N") == 7.5
    assert osv.cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N") == 6.1
    assert osv.cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") == 0.0
    assert osv.cvss3_base_score("CVSS:4.0/AV:N") is None
    assert osv.cvss3_base_score("garbage") is None


def test_severity_sources():
    assert osv.severity_from_vuln({"database_specific": {"severity": "MODERATE"}}) == "MEDIUM"
    assert osv.severity_from_vuln(VULN_URLLIB3) == "CRITICAL"
    assert osv.severity_from_vuln({"severity": [{"type": "CVSS_V3", "score": "7.2"}]}) == "HIGH"
    assert osv.severity_from_vuln({"severity": [{"type": "CVSS_V3", "score": "3.1"}]}) == "LOW"
    assert osv.severity_from_vuln({"severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N"}]}) == "UNKNOWN"
    assert osv.severity_from_vuln({}) == "UNKNOWN"


def test_fixed_version_picks_smallest_greater_than_installed():
    assert osv.fixed_version_for(VULN_PYYAML, PYYAML) == "5.4"
    assert osv.fixed_version_for(VULN_URLLIB3, URLLIB3) == "1.24.2"
    assert osv.fixed_version_for(VULN_URLLIB3, Dependency("urllib3", "1.26.0")) == "unknown"
    assert osv.fixed_version_for(VULN_PYYAML, Dependency("other", "1.0")) == "unknown"


# ------------------------------------------------------------------ reachability

def test_import_name_mapping():
    assert osv.import_name_for("PyYAML") == "yaml"
    assert osv.import_name_for("pillow") == "PIL"
    assert osv.import_name_for("python_jose") == "jose"
    assert osv.import_name_for("my-cool.pkg") == "my_cool_pkg"


def test_demo_reachability_from_real_ast():
    imports = extract_symbols(DEMO_APP)
    assert osv.is_reachable(PYYAML, imports) is True
    assert osv.is_reachable(URLLIB3, imports) is False
    assert osv.is_reachable(Dependency("yaml", "1", "npm"), imports) is False


# ------------------------------------------------------------------ HTTP (respx mocks)

def batch_ok(*vuln_lists):
    return httpx.Response(200, json={"results": [{"vulns": [{"id": i} for i in ids]} if ids else {} for ids in vuln_lists]})


@respx.mock
async def test_build_cve_findings_for_demo_dependencies():
    batch = respx.post(osv.OSV_BATCH_URL).mock(return_value=batch_ok([VULN_PYYAML["id"]], [VULN_URLLIB3["id"]]))
    respx.get(osv.OSV_VULN_URL.format(vuln_id=VULN_PYYAML["id"])).mock(return_value=httpx.Response(200, json=VULN_PYYAML))
    respx.get(osv.OSV_VULN_URL.format(vuln_id=VULN_URLLIB3["id"])).mock(return_value=httpx.Response(200, json=VULN_URLLIB3))
    async with httpx.AsyncClient() as client:
        findings = await osv.build_cve_findings(client, [PYYAML, URLLIB3], extract_symbols(DEMO_APP))
    assert batch.call_count == 1
    by_pkg = {f.package_name: f for f in findings}
    assert by_pkg["pyyaml"].fixed_version == "5.4" and by_pkg["pyyaml"].is_reachable_in_ast
    assert by_pkg["pyyaml"].severity == "CRITICAL" and osv.classify(by_pkg["pyyaml"]) == osv.CRITICAL_EXPLOITABLE
    assert by_pkg["urllib3"].fixed_version == "1.24.2" and not by_pkg["urllib3"].is_reachable_in_ast
    assert osv.classify(by_pkg["urllib3"]) == osv.LATENT_DEPENDENCY
    assert by_pkg["urllib3"].summary == "CRLF injection"
    assert osv.count_reachable(findings, "CRITICAL") == 1


@respx.mock
async def test_shared_vuln_id_fetched_once_and_cached():
    respx.post(osv.OSV_BATCH_URL).mock(return_value=batch_ok(["V-1"], ["V-1"]))
    route = respx.get(osv.OSV_VULN_URL.format(vuln_id="V-1")).mock(return_value=httpx.Response(200, json={"id": "V-1"}))
    cache: dict = {}
    async with httpx.AsyncClient() as client:
        findings = await osv.build_cve_findings(client, [PYYAML, URLLIB3], [], cache)
    assert route.call_count == 1 and len(findings) == 2 and "V-1" in cache
    assert all(f.severity == "UNKNOWN" and f.fixed_version == "unknown" for f in findings)


@respx.mock
async def test_clean_dependency_yields_no_findings_and_empty_input_skips_network():
    respx.post(osv.OSV_BATCH_URL).mock(return_value=batch_ok([]))
    async with httpx.AsyncClient() as client:
        assert await osv.build_cve_findings(client, [Dependency("fastapi", "9.9.9")], []) == []
        assert await osv.build_cve_findings(client, [], []) == []


@respx.mock
async def test_retries_5xx_then_succeeds():
    route = respx.post(osv.OSV_BATCH_URL).mock(side_effect=[httpx.Response(503), httpx.Response(502), batch_ok([])])
    async with httpx.AsyncClient() as client:
        assert await osv.query_batch(client, [PYYAML]) == {PYYAML: []}
    assert route.call_count == 3


@respx.mock
async def test_gives_up_after_three_attempts_with_clean_error():
    route = respx.post(osv.OSV_BATCH_URL).mock(side_effect=httpx.ConnectTimeout("slow"))
    async with httpx.AsyncClient() as client:
        with pytest.raises(OSVError, match="3 attempts.*ConnectTimeout"):
            await osv.query_batch(client, [PYYAML])
    assert route.call_count == 3


@respx.mock
async def test_4xx_not_retried():
    route = respx.post(osv.OSV_BATCH_URL).mock(return_value=httpx.Response(400))
    async with httpx.AsyncClient() as client:
        with pytest.raises(OSVError, match="HTTP 400"):
            await osv.query_batch(client, [PYYAML])
    assert route.call_count == 1


@respx.mock
async def test_malformed_responses_raise_osv_error():
    respx.post(osv.OSV_BATCH_URL).mock(return_value=httpx.Response(200, json={"results": []}))
    async with httpx.AsyncClient() as client:
        with pytest.raises(OSVError, match="unexpected response"):
            await osv.query_batch(client, [PYYAML])
    respx.post(osv.OSV_BATCH_URL).mock(return_value=httpx.Response(200, text="<html>"))
    async with httpx.AsyncClient() as client:
        with pytest.raises(OSVError, match="invalid JSON"):
            await osv.query_batch(client, [PYYAML])


@respx.mock
async def test_failed_detail_fetch_degrades_to_unknown_finding():
    respx.post(osv.OSV_BATCH_URL).mock(return_value=batch_ok(["V-9"]))
    respx.get(osv.OSV_VULN_URL.format(vuln_id="V-9")).mock(return_value=httpx.Response(500))
    async with httpx.AsyncClient() as client:
        findings = await osv.build_cve_findings(client, [PYYAML], ["yaml"])
    assert len(findings) == 1 and findings[0].severity == "UNKNOWN"
    assert findings[0].summary == "Details unavailable from OSV.dev" and findings[0].is_reachable_in_ast


# ------------------------------------------------------------------ live (opt-in)

@pytest.mark.integration
async def test_live_osv_flags_demo_dependencies():
    async with httpx.AsyncClient(timeout=30) as client:
        findings = await osv.build_cve_findings(client, [PYYAML, URLLIB3], extract_symbols(DEMO_APP))
    names = {f.package_name for f in findings}
    assert {"pyyaml", "urllib3"} <= names
    assert any(f.package_name == "pyyaml" and f.is_reachable_in_ast for f in findings)
