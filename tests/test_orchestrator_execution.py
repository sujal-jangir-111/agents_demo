"""Step 10, Orchestrator side: APPROVED -> ExecuteRemediationCommand -> RemediationCompletionReport -> canary -> RESOLVED."""
from uagents_core.contrib.protocols.payment import CompletePayment

from common.models import (
    AgentErrorReport, ExecuteRemediationCommand, HealthProbeReport, HealthProbeRequest, RemediationCompletionReport,
)
from tests.fakes import PAYER, TX_GOOD, make_probe_report
from tests.test_orchestrator import ADDR, REPO, URL, USER, chat, make_orch, sent, stored, texts, to_awaiting_approval
from tests.test_payment import commit, pay_orch, to_ctx

PR = f"https://github.com/{REPO}/pull/1"
SBOM = f"https://github.com/{REPO}/blob/sentinel/fix-x/sbom.cdx.json"


def remediation(inc: str, success: bool = True, hook: bool = True, tx: str = "") -> RemediationCompletionReport:
    return RemediationCompletionReport(
        incident_id=inc, success=success, pr_url=PR if success else "", sbom_file_url=SBOM if success else "", dorado_tx_hash=tx,
        dorado_explorer_url=f"https://explore-dorado.fetch.ai/transactions/{tx}" if tx else "", redeploy_triggered=hook,
        summary_message="Fix PR opened" if success else "GitHub write refused")


def canary(inc: str, healthy: bool = True) -> HealthProbeReport:
    rep = make_probe_report(inc, healthy=healthy)
    return HealthProbeReport(incident_id=inc, service_url=URL, is_healthy=healthy, is_canary_check=True, metrics=rep.metrics)


async def approved(orch, ctx, **kw) -> str:
    inc = await to_awaiting_approval(orch, ctx, **kw)
    await orch.handle_chat(ctx, USER, chat("rollback" if kw.get("approved") is False else "approve"))
    return inc


async def paid(orch, ctx) -> str:
    inc = await to_awaiting_approval(orch, ctx)
    await orch.handle_commit_payment(ctx, USER, commit(TX_GOOD, inc))
    return inc


# ------------------------------------------------------------------ approval -> execution

async def test_approval_sends_the_execute_command_to_the_executor(ctx):
    orch = make_orch()
    inc = await approved(orch, ctx)
    (cmd,) = sent(ctx, ADDR["executor"], ExecuteRemediationCommand)
    assert cmd.incident_id == inc and cmd.action_type == "OPEN_PR_AND_HOTFIX" and cmd.repo_full_name == REPO
    assert cmd.attestation.approved and cmd.attestation.attestation_hash and cmd.attestation.target_file == "app.py"
    assert cmd.service_reload_webhook == f"{URL}/admin/apply-hotfix" and cmd.dorado_tx_hash == "" and cmd.payer_wallet == ""
    assert stored(ctx, inc)["state"] == "EXECUTING"
    assert "Change authorized" in texts(ctx)[-1] and "Agent_5 will now open the pull request" in texts(ctx)[-1]


async def test_verified_payment_flows_into_the_execute_command_with_the_tx_and_payer(ctx):
    orch = pay_orch()
    inc = await paid(orch, ctx)
    (cmd,) = sent(ctx, ADDR["executor"], ExecuteRemediationCommand)
    assert cmd.dorado_tx_hash == TX_GOOD and cmd.payer_wallet == PAYER and stored(ctx, inc)["state"] == "EXECUTING"
    assert len(to_ctx(ctx, CompletePayment)) == 1


async def test_nothing_is_executed_before_authorization(ctx):
    orch = pay_orch()
    await to_awaiting_approval(orch, ctx)
    await orch.handle_chat(ctx, USER, chat("approve"))                         # approve is NOT payment
    assert sent(ctx, ADDR["executor"], ExecuteRemediationCommand) == []
    skip = make_orch()
    await to_awaiting_approval(skip, ctx)
    assert sent(ctx, ADDR["executor"], ExecuteRemediationCommand) == []        # waiting for the user's decision


async def test_rollback_authorization_sends_a_rollback_command(ctx):
    orch = make_orch()
    inc = await approved(orch, ctx, approved=False)
    (cmd,) = sent(ctx, ADDR["executor"], ExecuteRemediationCommand)
    assert cmd.incident_id == inc and cmd.action_type == "ROLLBACK_COMMIT" and not cmd.attestation.approved
    assert "roll back the suspect commit" in texts(ctx)[-1]


async def test_reject_never_reaches_the_executor(ctx):
    orch = make_orch()
    await to_awaiting_approval(orch, ctx)
    await orch.handle_chat(ctx, USER, chat("reject"))
    assert sent(ctx, ADDR["executor"], ExecuteRemediationCommand) == []


# ------------------------------------------------------------------ remediation report -> canary

async def test_successful_report_triggers_a_canary_probe_and_tells_the_user(ctx):
    orch = make_orch()
    inc = await approved(orch, ctx)
    await orch.handle_remediation_report(ctx, ADDR["executor"], remediation(inc))
    canaries = [r for r in sent(ctx, ADDR["watchdog"], HealthProbeRequest) if r.is_canary_check]
    assert len(canaries) == 1 and canaries[0].service_url == URL and canaries[0].incident_id == inc and not canaries[0].inject_chaos
    assert stored(ctx, inc)["state"] == "VERIFYING"
    msg = texts(ctx)[-1]
    assert PR in msg and SBOM in msg and "hotfix triggered" in msg and "canary" in msg


async def test_failed_report_fails_the_incident_with_a_clear_message(ctx):
    orch = make_orch()
    inc = await approved(orch, ctx)
    await orch.handle_remediation_report(ctx, ADDR["executor"], remediation(inc, success=False))
    assert stored(ctx, inc)["state"] == "FAILED" and "GitHub write refused" in texts(ctx)[-1]
    assert [r for r in sent(ctx, ADDR["watchdog"], HealthProbeRequest) if r.is_canary_check] == []


async def test_report_from_the_wrong_sender_or_stage_is_ignored(ctx):
    orch = make_orch()
    inc = await approved(orch, ctx)
    await orch.handle_remediation_report(ctx, ADDR["scanner"], remediation(inc))
    assert stored(ctx, inc)["state"] == "EXECUTING"
    await orch.handle_remediation_report(ctx, ADDR["executor"], remediation("inc-unknown"))
    other = make_orch()
    inc2 = await to_awaiting_approval(other, ctx)                                # still awaiting approval: report is out of order
    await other.handle_remediation_report(ctx, ADDR["executor"], remediation(inc2))
    assert stored(ctx, inc2)["state"] == "AWAITING_APPROVAL"


async def test_executor_error_while_executing_fails_with_recovery_and_mentions_a_recorded_payment(ctx):
    orch = pay_orch()
    inc = await paid(orch, ctx)
    await orch.handle_agent_error(ctx, ADDR["executor"], AgentErrorReport(incident_id=inc, agent="Agent_5", stage="execute",
                                                                          error="ExecutionRefused: the attestation does not verify"))
    msg = texts(ctx)[-1]
    assert stored(ctx, inc)["state"] == "FAILED" and "does not verify" in msg and "Nothing was merged" in msg and "payment" in msg and TX_GOOD[:12] in msg


# ------------------------------------------------------------------ canary verdict

async def test_healthy_canary_resolves_the_incident_with_a_before_after_report(ctx):
    orch = pay_orch()
    inc = await paid(orch, ctx)
    await orch.handle_remediation_report(ctx, ADDR["executor"], remediation(inc, tx=TX_GOOD))
    await orch.handle_probe_report(ctx, ADDR["watchdog"], canary(inc))
    assert stored(ctx, inc)["state"] == "RESOLVED"
    final = texts(ctx)[-1]
    for needle in ("RESOLVED", "`/api/checkout` HTTP 500 → HTTP 200", "Before → after", "3/6", "0/6", PR, SBOM,
                   f"explore-dorado.fetch.ai/transactions/{TX_GOOD}", "0.1 FET", "✅ triggered", "not merged"):
        assert needle in final, needle
    assert any(c.__class__.__name__ == "EndSessionContent" for c in ctx.sent[-1][1].content)      # session ends


async def test_skipped_payment_final_report_says_so(ctx):
    orch = make_orch()
    inc = await approved(orch, ctx)
    await orch.handle_remediation_report(ctx, ADDR["executor"], remediation(inc))
    await orch.handle_probe_report(ctx, ADDR["watchdog"], canary(inc))
    assert "none (payment skipped, dev mode)" in texts(ctx)[-1] and stored(ctx, inc)["state"] == "RESOLVED"


async def test_rollback_final_report_has_no_attestation(ctx):
    orch = make_orch()
    inc = await approved(orch, ctx, approved=False)
    await orch.handle_remediation_report(ctx, ADDR["executor"], remediation(inc))
    await orch.handle_probe_report(ctx, ADDR["watchdog"], canary(inc))
    final = texts(ctx)[-1]
    assert "Rollback pull request" in final and "n/a (rollback)" in final


async def test_unhealthy_canary_is_reported_honestly_and_not_resolved(ctx):
    orch = make_orch()
    inc = await approved(orch, ctx)
    await orch.handle_remediation_report(ctx, ADDR["executor"], remediation(inc, hook=False))
    await orch.handle_probe_report(ctx, ADDR["watchdog"], canary(inc, healthy=False))
    final = texts(ctx)[-1]
    assert stored(ctx, inc)["state"] == "FAILED" and "still failing" in final and "HTTP 500" in final and PR in final
    assert "not triggered" in final and "RESOLVED" not in final


async def test_canary_from_the_wrong_sender_or_a_replay_is_ignored(ctx):
    orch = make_orch()
    inc = await approved(orch, ctx)
    await orch.handle_remediation_report(ctx, ADDR["executor"], remediation(inc))
    await orch.handle_probe_report(ctx, ADDR["scanner"], canary(inc))
    assert stored(ctx, inc)["state"] == "VERIFYING"
    await orch.handle_probe_report(ctx, ADDR["watchdog"], canary(inc))
    count = len(texts(ctx))
    await orch.handle_probe_report(ctx, ADDR["watchdog"], canary(inc, healthy=False))      # late duplicate must not undo RESOLVED
    assert stored(ctx, inc)["state"] == "RESOLVED" and len(texts(ctx)) == count


async def test_canary_report_for_an_incident_that_is_not_verifying_is_ignored(ctx):
    orch = make_orch()
    inc = await to_awaiting_approval(orch, ctx)
    await orch.handle_probe_report(ctx, ADDR["watchdog"], canary(inc))
    assert stored(ctx, inc)["state"] == "AWAITING_APPROVAL"


# ------------------------------------------------------------------ timeouts and status

async def test_stuck_execution_and_stuck_canary_time_out(ctx):
    from tests.test_orchestrator import Clock
    clock = Clock()
    orch = make_orch(clock=clock)
    first = await approved(orch, ctx)
    clock.t += 121
    await orch.sweep(ctx)
    assert stored(ctx, first)["state"] == "FAILED" and "Agent_5" in texts(ctx)[-1]
    second = await approved(orch, ctx)
    await orch.handle_remediation_report(ctx, ADDR["executor"], remediation(second))
    clock.t += 61
    await orch.sweep(ctx)
    assert stored(ctx, second)["state"] == "FAILED" and "Agent_2" in texts(ctx)[-1]


async def test_status_shows_the_executing_state(ctx):
    orch = make_orch()
    await approved(orch, ctx)
    await orch.handle_chat(ctx, USER, chat("status"))
    assert "EXECUTING" in texts(ctx)[-1]
