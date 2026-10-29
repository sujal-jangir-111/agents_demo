from dataclasses import replace

import pytest

from common import incident_card as card
from common.blast_radius import compute_blast_radius, minutes_between
from common.config import Settings
from common.intent import extract_repo, extract_url, parse_action, parse_intent
from tests.fakes import make_evidence, make_patch_result, make_vuln_report

BASE = replace(Settings(), traffic_rpm=120, avg_order_value_usd=40, conversion_rate=0.03, sla_target=0.999)


# ------------------------------------------------------------------ intent

@pytest.mark.parametrize("text,mode,repo,url", [
    ("Diagnose and heal the outage on https://sentinel-target.onrender.com for repo org/sentinel-target",
     "diagnose_and_heal", "org/sentinel-target", "https://sentinel-target.onrender.com"),
    ("my checkout is returning 500s at https://shop.io/ (repo acme/shop)", "diagnose_and_heal", "acme/shop", "https://shop.io/"),
    ("Run a security audit of acme/api", "security_audit", "acme/api", None),
    ("scan acme/api for CVEs", "security_audit", "acme/api", None),
    ("chaos test https://x.io for repo a/b", "chaos_test", "a/b", "https://x.io"),
    ("please inject a fault into https://x.io, repo a/b", "chaos_test", "a/b", "https://x.io"),
    ("status", "status", None, None),
    ("what is the status of inc-1a2b3c4d?", "status", None, None),
])
def test_requests_are_parsed(text, mode, repo, url):
    i = parse_intent(text)
    assert (i.mode, i.repo, i.url) == (mode, repo, url) and i.action is None


@pytest.mark.parametrize("text,action", [
    ("approve", "approve"), ("Yes, go ahead", "approve"), ("LGTM", "approve"), ("authorize it", "approve"),
    ("reject", "reject"), ("No", "reject"), ("cancel this", "reject"), ("don't do it", "reject"),
    ("rollback", "rollback"), ("please roll back the commit", "rollback"),
])
def test_decisions_are_parsed(text, action):
    assert parse_intent(text).action == action and parse_action(text) == action


def test_incident_id_is_extracted_and_plain_chat_is_not_a_request():
    assert parse_intent("approve INC-1A2B3C4D").incident_id == "inc-1a2b3c4d"
    for text in ("hello", "thanks!", "what can you do?"):
        i = parse_intent(text)
        assert not i.is_request and i.action is None
    assert parse_action("I would like you to diagnose https://x.io and then maybe approve something later on please") is None


def test_url_and_repo_helpers():
    assert extract_url("see https://a.io/x?y=1, then") == "https://a.io/x?y=1"
    assert extract_repo("use and/or whatever") is None
    assert extract_repo("https://github.com/o/r is a url but acme/shop is the repo") == "acme/shop"
    assert extract_repo("repo: org/sentinel-target.") == "org/sentinel-target"
    assert not parse_intent("heal https://x.io").is_complete and parse_intent("heal https://x.io for acme/x").is_complete


# ------------------------------------------------------------------ blast radius (§8)

def blast(**kw):
    args = dict(failing_probes=3, total_probes=6, p95_ms=100.0, commit_time_iso="2026-01-02T10:00:00+00:00",
                failure_time_iso="2026-01-02T12:00:00+00:00", reachable_critical=0, reachable_high=0,
                secrets_found=0, secret_introduced_by_suspect=False, settings=BASE)
    args.update(kw)
    return compute_blast_radius(**args)


def test_blast_radius_formulas():
    b = blast()
    assert b.failure_ratio == 0.5
    assert b.dropped_requests_hr == 120 * 60 * 0.5 == 3600
    assert b.revenue_at_risk_hr == pytest.approx(3600 * 0.03 * 40) == pytest.approx(4320)
    assert b.minutes_since_commit == 120
    assert b.sla_budget_burn_pct == pytest.approx(120 / (30 * 24 * 60 * 0.001) * 100)   # 277.8 %
    assert b.credential_exposure_minutes is None and b.score == 20


def test_blast_score_components_and_cap():
    assert blast(reachable_critical=1, reachable_high=2, secrets_found=1, p95_ms=1500).score == 20 + 10 + 10 + 20 + 10
    assert blast(failing_probes=6, reachable_critical=10).score == 100          # capped
    assert blast(p95_ms=1000).score == 20                                          # strictly greater than 1000 ms


def test_credential_exposure_only_when_suspect_commit_introduced_the_secret():
    assert blast(secrets_found=1, secret_introduced_by_suspect=True).credential_exposure_minutes == 120
    assert blast(secrets_found=1, secret_introduced_by_suspect=False).credential_exposure_minutes is None
    assert blast(secrets_found=0, secret_introduced_by_suspect=True).credential_exposure_minutes is None


def test_blast_radius_edge_cases_and_assumptions_text():
    assert blast(failing_probes=0, total_probes=0).failure_ratio == 0
    assert minutes_between("2026-01-02T12:00:00+00:00", "2026-01-02T10:00:00+00:00") == 0   # clock skew never negative
    assert minutes_between("garbage", "2026-01-02T10:00:00+00:00") == 0
    custom = blast(settings=replace(BASE, traffic_rpm=60, sla_target=0.99))
    assert custom.dropped_requests_hr == 1800 and "TRAFFIC_RPM=60" in custom.assumptions() and "SLA_TARGET=0.99" in custom.assumptions()


# ------------------------------------------------------------------ card rendering

PROBE = {"endpoint": "/api/checkout", "status": 500, "latency_ms": 12.4, "failure_ts": "t", "failing": 3, "total": 6, "p95_ms": 12.0}


def test_incident_card_for_an_approved_patch():
    text = card.build_incident_card("inc-1", "http://demo", "acme/r", PROBE, make_evidence("inc-1"), make_vuln_report("inc-1"),
                                    make_patch_result("inc-1", attempts=2), blast(), 3)
    for needle in ("## 🛡️ Sentinel Incident `inc-1`", "HTTP 500 @ 12 ms", "[`c0ffee1`]", "@alice", "CRITICAL_EXPLOITABLE (reachable)",
                   "LATENT_DEPENDENCY", "HARDCODED_SECRET", "**Blast score**", "$4,320", "_Assumptions:", "attempt 2/3",
                   "ab12cd34ef567890…", "```diff", "`pyyaml` 5.3 → **5.4**", "Reply **approve**"):
        assert needle in text, needle
    assert "sk_test_51SENTINELDEMOxxxxxxxx" not in text                      # masked in the diff and findings


def test_incident_card_when_the_gatekeeper_rejected_everything():
    text = card.build_incident_card("inc-1", "http://demo", "acme/r", PROBE, make_evidence("inc-1"), make_vuln_report("inc-1"),
                                    make_patch_result("inc-1", approved=False, attempts=3), blast(), 3)
    assert "No safe patch after 3 attempt(s)" in text and "SQL_INJECTION at line 83" in text and "Reply **rollback**" in text
    no_rb = card.build_incident_card("inc-1", "http://demo", "acme/r", PROBE, make_evidence("inc-1"), make_vuln_report("inc-1"),
                                     make_patch_result("inc-1", approved=False, rollback=False), blast(), 3)
    assert "No rollback is available" in no_rb and "Reply **rollback**" not in no_rb


def test_tables_escape_pipes_and_cap_rows():
    v = make_vuln_report("i")
    v.cve_findings = v.cve_findings * 5
    table = card.findings_table(v)
    assert "…and" in table and table.count("\n|") <= card.MAX_ROWS * 2 + 3
    assert card._cell("a|b\nc") == "a\\|b c" and card.findings_table(make_vuln_report("i").__class__(
        incident_id="i", repo_full_name="r", cve_findings=[], sast_findings=[], total_reachable_critical=0)) == "_No dependency or code findings._"


def test_audit_report():
    text = card.build_audit_report("inc-9", "acme/r", make_evidence("inc-9"), make_vuln_report("inc-9"))
    assert "Security Audit `inc-9`" in text and "3 mapped" not in text and "(2 reachable, 1 reachable CRITICAL)" in text
    assert "read-only" in text
