import importlib.util
import uuid

import httpx

from common import gatekeeper
from common.models import CVEFinding
from common.osv_client import Dependency
from common.patching import (
    added_lines, bump_requirements, compute_bumps, ensure_import_os, fix_unsafe_yaml, harden_secrets,
    make_unified_diff, removed_lines, revert_hunk, touches_offending_change,
)
from common.sast_rules import scan_text
from tests.fakes import (
    DEMO_FILES, FAULT_LINE, checkout_patch, fully_fixed_app_source, runtime_fixed_app_source,
)


def cve(pkg="pyyaml", fixed="5.4", reachable=True, vuln="GHSA-1", sev="CRITICAL", installed="5.3") -> CVEFinding:
    return CVEFinding(package_name=pkg, installed_version=installed, fixed_version=fixed, vuln_id=vuln,
                      severity=sev, is_reachable_in_ast=reachable, summary="s")


# ------------------------------------------------------------------ secrets / yaml

def test_harden_secrets_moves_demo_key_to_env_and_keeps_comment():
    out = harden_secrets(DEMO_FILES["app.py"])
    assert 'STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY")  # obviously fake demo key' in out
    assert "sk_test_51SENTINELDEMOxxxxxxxx" not in out
    assert not [f for f in scan_text("app.py", out) if f.rule_id == "HARDCODED_SECRET"]
    assert out.count("import os") == 1  # already imported -> not duplicated


def test_harden_secrets_adds_import_and_handles_other_names():
    out = harden_secrets('"""doc"""\nimport json\napi_key = "abcdefghijklmnop"\n')
    assert 'api_key = os.getenv("API_KEY")' in out and out.index("import os") < out.index("import json")
    assert harden_secrets("x = 'short'\n") == "x = 'short'\n"
    # non-assignment secrets are left for the gatekeeper to flag
    expr = 'call("AKIAIOSFODNN7EXAMPLE")\n'
    assert harden_secrets(expr) == expr


def test_ensure_import_os_positions():
    assert ensure_import_os("x = 1\n").startswith("import os\n")
    assert ensure_import_os('"""d"""\nx = 1\n').splitlines()[:2] == ['"""d"""', "import os"]
    assert ensure_import_os("import os\n") == "import os\n"
    assert ensure_import_os("def broken(:\n") == "def broken(:\n"


def test_fix_unsafe_yaml_variants():
    assert fix_unsafe_yaml("d = yaml.load(txt, Loader=yaml.Loader)\n") == "d = yaml.safe_load(txt)\n"
    assert fix_unsafe_yaml("d = yaml.load(open('f'))\n") == "d = yaml.safe_load(open('f'))\n"
    two = fix_unsafe_yaml("a = yaml.load(x, Loader=L); b = yaml.load(y, Loader=L)\n")
    assert two == "a = yaml.safe_load(x); b = yaml.safe_load(y)\n"
    assert fix_unsafe_yaml("é = 'ü'; d = yaml.load(t, Loader=L)\n") == "é = 'ü'; d = yaml.safe_load(t)\n"
    assert fix_unsafe_yaml("yaml.safe_load(x)\n") == "yaml.safe_load(x)\n"
    assert fix_unsafe_yaml("broken(:\n") == "broken(:\n"


# ------------------------------------------------------------------ dependencies

def test_compute_bumps_uses_reachable_highest_known_fix():
    findings = [cve(fixed="5.3.1", vuln="A"), cve(fixed="5.4", vuln="B"), cve("urllib3", "1.24.2", reachable=False),
                cve("flask", "unknown")]
    assert compute_bumps(findings) == {"pyyaml": "5.4"}
    assert compute_bumps([cve("x", "1.10"), cve("x", "1.9")]) == {"x": "1.10"}  # numeric, not lexical


def test_bump_requirements_touches_only_target_lines():
    out = bump_requirements(DEMO_FILES["requirements.txt"], {"pyyaml": "5.4"})
    assert "pyyaml==5.4\n" in out and "urllib3==1.24.1" in out and "fastapi" in out
    assert bump_requirements("PyYAML[extra] == 5.3 ; python_version>'3'\n", {"pyyaml": "5.4"}) == \
        "PyYAML[extra] == 5.4 ; python_version>'3'\n"


# ------------------------------------------------------------------ diff / offending change / revert

def test_unified_diff_and_line_helpers():
    diff = make_unified_diff("a\nb\n", "a\nc\n", "app.py")
    assert diff.startswith("--- a/app.py\n+++ b/app.py") and removed_lines(diff) == ["b"] and added_lines(diff) == ["c"]
    assert make_unified_diff("same\n", "same\n", "f") == ""


def test_touches_offending_change():
    added = ['        discount_rate = PRICING["discount_rate"]', "    )", ""]
    assert touches_offending_change("x\n", added) is True
    assert touches_offending_change(DEMO_FILES["app.py"], added) is False  # faulty line still there
    assert touches_offending_change(runtime_fixed_app_source(), added) is True
    assert touches_offending_change("anything", ["    )", "x"]) is True  # nothing significant to check


def test_revert_hunk_restores_previous_line():
    reverted = revert_hunk(DEMO_FILES["app.py"], checkout_patch())
    assert reverted is not None and 'discount_rate = PRICING.get("discount_rate", 0.0)' in reverted
    assert reverted.splitlines()[FAULT_LINE - 1].strip() == 'discount_rate = PRICING.get("discount_rate", 0.0)'
    assert revert_hunk("unrelated\n", checkout_patch()) is None


async def test_patched_demo_app_really_serves_checkout(tmp_path, monkeypatch):
    """Execute the reverted code: the KeyError is gone and /api/checkout returns 200."""
    monkeypatch.setenv("DEMO_ADMIN_TOKEN", "t")
    path = tmp_path / "patched_app.py"
    path.write_text(fully_fixed_app_source(), encoding="utf-8")
    spec = importlib.util.spec_from_file_location(f"patched_{uuid.uuid4().hex}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    transport = httpx.ASGITransport(app=module.app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://x") as c:
        r = await c.get("/api/checkout", params={"sku": "SKU-1", "quantity": 2})
        assert r.status_code == 200 and r.json()["total"] == 43.2
        assert (await c.get("/api/checkout", params={"sku": "x' OR '1'='1"})).status_code == 404  # no SQL injection


# ------------------------------------------------------------------ gatekeeper pure checks

def test_attestation_hash_formula_is_stable():
    import hashlib
    h = gatekeeper.attestation_hash("inc-1", "app.py", "DIFF", "REQS", "agent1q")
    assert h == hashlib.sha256(b"inc-1app.pyDIFFREQSagent1q").hexdigest() and len(h) == 64
    assert h != gatekeeper.attestation_hash("inc-1", "app.py", "DIFF2", "REQS", "agent1q")


def test_check_sast_and_syntax():
    assert gatekeeper.check_sast("app.py", fully_fixed_app_source()) == []
    reasons = gatekeeper.check_sast("app.py", runtime_fixed_app_source())
    assert len(reasons) == 3 and any(r.startswith("HARDCODED_SECRET") and "sk_tes****" in r for r in reasons)
    assert not any("sk_test_51SENTINELDEMOxxxxxxxx" in r for r in reasons)
    assert gatekeeper.check_syntax("app.py", "def f(:\n")[0].startswith("patched file does not parse")
    assert gatekeeper.check_syntax("README.md", "def f(:\n") == []


def test_check_diff_cases():
    good = make_unified_diff("a\n", "b\n", "f.py")
    assert gatekeeper.check_diff("a\n", "b\n", "f.py", good, "main") == []
    assert "not found" in gatekeeper.check_diff(None, "b\n", "f.py", good, "main")[0]
    assert "no changes" in gatekeeper.check_diff("a\n", "a\n", "f.py", "", "main")[0]
    assert "does not match" in gatekeeper.check_diff("a\n", "b\n", "f.py", "forged diff", "main")[0]


def test_check_cves_fixed_cases():
    prev = [{"package_name": "pyyaml", "vuln_id": "GHSA-1", "fixed_version": "5.4"}]
    new_ok = [Dependency("pyyaml", "5.4")]
    assert gatekeeper.check_cves_fixed(prev, new_ok, []) == []
    assert "not pinned" in gatekeeper.check_cves_fixed(prev, [Dependency("other", "1")], [])[0]
    assert "still affects" in gatekeeper.check_cves_fixed(prev, new_ok, [cve("pyyaml", "5.4", installed="5.4", vuln="GHSA-1")])[0]
    assert "below the fixed version" in gatekeeper.check_cves_fixed(prev, [Dependency("pyyaml", "5.3.1")], [])[0]
    unknown = [{"package_name": "x", "vuln_id": "V", "fixed_version": "unknown"}]
    assert gatekeeper.check_cves_fixed(unknown, [Dependency("x", "9")], []) == []
    assert gatekeeper.check_no_critical([cve(sev="CRITICAL"), cve(sev="HIGH", vuln="2")])[0].startswith("GHSA-1 [CRITICAL]")


def test_check_fault_fixed():
    added = ['        discount_rate = PRICING["discount_rate"]']
    assert gatekeeper.check_fault_fixed(runtime_fixed_app_source(), added) == []
    assert "still present" in gatekeeper.check_fault_fixed(DEMO_FILES["app.py"], added)[0]


def test_display_diff_never_carries_a_full_secret():
    original = 'KEY = "sk_test_51SENTINELDEMOxxxxxxxx"\n'
    diff = make_unified_diff(original, 'KEY = os.getenv("KEY")\n', "app.py")
    assert "sk_test_51SENTINELDEMOxxxxxxxx" not in diff and "sk_tes****" in diff
    # both sides mask identically, so independent recomputation (the gatekeeper) matches exactly
    assert diff == make_unified_diff(original, 'KEY = os.getenv("KEY")\n', "app.py")
