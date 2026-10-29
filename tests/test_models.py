from common import models as m
from common.config import Settings


def test_probe_request_defaults():
    r = m.HealthProbeRequest(incident_id="inc-1", service_url="https://x.test")
    assert r.endpoints == ["/health", "/api/checkout"]
    assert r.inject_chaos is False and r.is_canary_check is False


def test_attestation_defaults_and_nesting():
    att = m.SecurityApprovalAttestation(
        incident_id="inc-1", approved=False, attestation_hash="",
        target_file="app.py", patched_code_content="", updated_requirements_txt="", unified_diff="",
    )
    assert att.rejection_reasons == []
    cmd = m.ExecuteRemediationCommand(
        incident_id="inc-1", repo_full_name="o/r", action_type="OPEN_PR_AND_HOTFIX",
        dorado_tx_hash="AB", payer_wallet="fetch1x", attestation=att,
    )
    assert cmd.service_reload_webhook is None
    assert m.ExecuteRemediationCommand.parse_raw(cmd.json()).attestation.target_file == "app.py"


def test_report_roundtrip():
    rep = m.HealthProbeReport(
        incident_id="inc-1", service_url="u", is_healthy=False, is_canary_check=False,
        metrics=[m.EndpointMetric(endpoint="/api/checkout", status_code=500, latency_ms=12.5, timestamp_utc="t")],
    )
    back = m.HealthProbeReport.parse_raw(rep.json())
    assert back.metrics[0].error_snippet is None and back.metrics[0].status_code == 500


def test_extra_models():
    assert m.AgentErrorReport(incident_id="i", agent="a", stage="s", error="e").error == "e"


def test_settings_defaults(monkeypatch):
    for k in ("TRAFFIC_RPM", "SLA_TARGET", "REMEDIATION_PRICE_ATESTFET", "ASI1_MODEL"):
        monkeypatch.delenv(k, raising=False)
    s = Settings()
    assert s.traffic_rpm == 120 and s.sla_target == 0.999
    assert s.remediation_price_atestfet == 10**17 and s.asi1_model == "asi1-mini"
