"""Step 9: the Orchestrator's payment protocol (seller role) and Dorado verification, with a fake chain."""
import asyncio
from dataclasses import replace

from uagents import Model
from uagents_core.contrib.protocols.chat import ChatMessage
from uagents_core.contrib.protocols.payment import (
    CancelPayment, CommitPayment, CompletePayment, Funds, RejectPayment, RequestPayment, payment_protocol_spec,
)

from agents.Agent_1 import MAX_PAYMENT_FAILURES, create_agent
from tests.conftest import FakeContext
from tests.fakes import (
    PAYER, PRICE, TX_FAILED, TX_GOOD, TX_OTHER, TX_SECOND, TX_UNDER, WALLET, FakeChain, fake_verifier, make_tx, standard_chain,
)
from tests.test_orchestrator import EMPTY, USER, USER2, Clock, chat, make_orch, stored, texts, to_awaiting_approval

PAY = replace(EMPTY, orchestrator_wallet_address=WALLET, remediation_price_atestfet=PRICE)


def pay_orch(chain=None, **kw):
    return make_orch(settings=PAY, skip_payment=False, verifier=fake_verifier(chain or standard_chain()), **kw)


def commit(tx, ref=None, amount=PRICE):
    return CommitPayment(funds=Funds(amount=str(amount), currency="atestfet"), recipient=WALLET, transaction_id=tx, reference=ref)


def to_ctx(ctx, kind, dest=USER):
    return [m for d, m in ctx.sent if d == dest and isinstance(m, kind)]


async def waiting(orch, ctx, **kw):
    return await to_awaiting_approval(orch, ctx, **kw)


# ------------------------------------------------------------------ requesting payment

async def test_request_payment_is_sent_before_the_incident_card(ctx):
    orch = pay_orch()
    inc = await waiting(orch, ctx)
    to_user = [m for d, m in ctx.sent if d == USER]
    pay_idx = next(i for i, m in enumerate(to_user) if isinstance(m, RequestPayment))
    card_idx = next(i for i, m in enumerate(to_user) if isinstance(m, ChatMessage) and "Sentinel Incident" in m.text())
    assert pay_idx < card_idx                                                     # CLAUDE.md 9.2 timing rule: payment card first
    req = to_ctx(ctx, RequestPayment)[0]
    assert req.reference == inc and req.recipient == WALLET and req.deadline_seconds == 1800
    assert req.accepted_funds == [Funds(amount=str(PRICE), currency="atestfet", payment_method="fet_direct")]
    assert req.metadata["incident_id"] == inc and "0.1 FET" in req.description
    assert stored(ctx, inc)["state"] == "AWAITING_PAYMENT"
    card = texts(ctx)[-1]
    assert "paying **0.1 FET**" in card and "Reply **approve**" not in card


async def test_skip_payment_dev_bypass_still_works_and_sends_no_payment_request(ctx):
    orch = make_orch(skip_payment=True)
    inc = await waiting(orch, ctx)
    assert to_ctx(ctx, RequestPayment) == [] and stored(ctx, inc)["state"] == "AWAITING_APPROVAL"
    await orch.handle_chat(ctx, USER, chat("approve"))
    assert stored(ctx, inc)["state"] == "EXECUTING" and "skipped" in stored(ctx, inc)["authorization"]


async def test_rollback_only_incident_is_also_paid_for(ctx):
    orch = pay_orch()
    inc = await waiting(orch, ctx, approved=False)
    assert to_ctx(ctx, RequestPayment)[0].metadata["action"] == "ROLLBACK_COMMIT"
    await orch.handle_commit_payment(ctx, USER, commit(TX_GOOD, inc))
    assert stored(ctx, inc)["state"] == "EXECUTING" and stored(ctx, inc)["action_type"] == "ROLLBACK_COMMIT"


async def test_missing_wallet_fails_the_incident_instead_of_asking_for_payment(ctx):
    orch = make_orch(settings=replace(EMPTY, orchestrator_wallet_address=""), skip_payment=False)
    inc = await waiting(orch, ctx)
    assert to_ctx(ctx, RequestPayment) == [] and stored(ctx, inc)["state"] == "FAILED"
    assert "ORCHESTRATOR_WALLET_ADDRESS" in texts(ctx)[-1]


async def test_approve_while_waiting_for_payment_resends_the_request_and_changes_nothing(ctx):
    orch = pay_orch()
    inc = await waiting(orch, ctx)
    await orch.handle_chat(ctx, USER, chat("approve"))
    assert stored(ctx, inc)["state"] == "AWAITING_PAYMENT" and len(to_ctx(ctx, RequestPayment)) == 2
    assert "waiting for your **0.1 FET** payment" in texts(ctx)[-1]
    await orch.handle_chat(ctx, USER, chat("status"))
    assert "AWAITING_PAYMENT" in texts(ctx)[-1] and "paying **0.1 FET**" in texts(ctx)[-1]


# ------------------------------------------------------------------ valid payment

async def test_valid_payment_is_verified_completed_and_approves_the_incident(ctx):
    orch = pay_orch()
    inc = await waiting(orch, ctx)
    await orch.handle_commit_payment(ctx, USER, commit(TX_GOOD, inc))
    state = stored(ctx, inc)
    assert state["state"] == "EXECUTING" and state["dorado_tx_hash"] == TX_GOOD and state["payer_wallet"] == PAYER
    assert state["authorized_by"] == USER and "0.1 FET" in state["authorization"]
    (done,) = to_ctx(ctx, CompletePayment)
    assert done.transaction_id == TX_GOOD
    msg = texts(ctx)[-1]
    assert "Payment verified" in msg and "Change authorized" in msg and f"/{TX_GOOD}" in msg
    assert to_ctx(ctx, CancelPayment) == []


async def test_commit_without_reference_matches_the_pending_incident_of_that_user(ctx):
    orch = pay_orch()
    inc = await waiting(orch, ctx)
    await orch.handle_commit_payment(ctx, USER, commit(TX_GOOD))
    assert stored(ctx, inc)["state"] == "EXECUTING"


async def test_duplicate_commit_after_success_is_idempotent(ctx):
    orch = pay_orch()
    inc = await waiting(orch, ctx)
    await orch.handle_commit_payment(ctx, USER, commit(TX_GOOD, inc))
    await orch.handle_commit_payment(ctx, USER, commit(TX_GOOD, inc))
    assert len(to_ctx(ctx, CompletePayment)) == 2 and to_ctx(ctx, CancelPayment) == [] and stored(ctx, inc)["state"] == "EXECUTING"


# ------------------------------------------------------------------ invalid payments are refused safely

async def test_underpaid_wrong_recipient_failed_and_unknown_transactions_never_approve():
    for tx, why in [(TX_UNDER, "Underpaid"), (TX_OTHER, "different wallet"), (TX_FAILED, "failed on-chain"), ("F" * 64, "not found"), ("junk", "64 hex")]:
        c = FakeContext()
        orch = pay_orch()
        inc = await waiting(orch, c)
        await orch.handle_commit_payment(c, USER, commit(tx, inc))
        assert stored(c, inc)["state"] == "AWAITING_PAYMENT", tx                 # still not authorized
        (cancel,) = to_ctx(c, CancelPayment)
        assert why in cancel.reason and to_ctx(c, CompletePayment) == []
        assert why in texts(c)[-1] and "Nothing was authorized" in texts(c)[-1]
        assert len(to_ctx(c, RequestPayment)) == 2                               # retry option: a fresh payment request
        assert "dorado_tx_hash" not in stored(c, inc)


async def test_a_refused_transaction_does_not_burn_the_hash_and_a_correct_retry_succeeds(ctx):
    orch = pay_orch(FakeChain(make_tx(TX_UNDER, amount=PRICE - 1), make_tx(TX_GOOD)))
    inc = await waiting(orch, ctx)
    await orch.handle_commit_payment(ctx, USER, commit(TX_UNDER, inc))
    await orch.handle_commit_payment(ctx, USER, commit(TX_UNDER, inc))          # same bad hash: still "underpaid", not "replay"
    assert "already used" not in texts(ctx)[-1] and "Underpaid" in texts(ctx)[-1]
    await orch.handle_commit_payment(ctx, USER, commit(TX_GOOD, inc))
    assert stored(ctx, inc)["state"] == "EXECUTING"


async def test_replayed_transaction_cannot_authorize_a_second_incident(ctx):
    orch = pay_orch()
    first = await waiting(orch, ctx)
    await orch.handle_commit_payment(ctx, USER, commit(TX_GOOD, first))
    second = await waiting(orch, ctx)
    await orch.handle_commit_payment(ctx, USER, commit(TX_GOOD, second))
    assert stored(ctx, first)["state"] == "EXECUTING" and stored(ctx, second)["state"] == "AWAITING_PAYMENT"
    assert "already used" in texts(ctx)[-1] and "dorado_tx_hash" not in stored(ctx, second)
    assert to_ctx(ctx, CancelPayment)[-1].reason.startswith("That transaction hash was already used")
    await orch.handle_commit_payment(ctx, USER, commit(TX_SECOND, second))       # a genuinely new payment works
    assert stored(ctx, second)["state"] == "EXECUTING"


async def test_replay_is_remembered_across_orchestrator_instances_via_storage(ctx):
    inc = await waiting(pay_orch(), ctx)
    await pay_orch().handle_commit_payment(ctx, USER, commit(TX_GOOD, inc))
    other = await waiting(pay_orch(), ctx)
    await pay_orch().handle_commit_payment(ctx, USER, commit(TX_GOOD.lower(), other))   # fresh instance, same storage, other case
    assert stored(ctx, other)["state"] == "AWAITING_PAYMENT" and "already used" in texts(ctx)[-1]


async def test_two_concurrent_commits_of_the_same_hash_authorize_only_one_incident(ctx):
    chain = standard_chain()
    chain.gate = asyncio.Event()
    orch = pay_orch(chain)
    first = await waiting(orch, ctx)
    second = await waiting(orch, ctx)
    racing = asyncio.create_task(orch.handle_commit_payment(ctx, USER, commit(TX_GOOD, first)))
    await asyncio.sleep(0.01)                                                    # the first is now on the chain lookup, hash reserved
    await orch.handle_commit_payment(ctx, USER, commit(TX_GOOD, second))
    chain.gate.set()
    await racing
    assert stored(ctx, first)["state"] == "EXECUTING" and stored(ctx, second)["state"] == "AWAITING_PAYMENT"


async def test_commit_with_no_pending_request_is_refused(ctx):
    orch = pay_orch()
    await orch.handle_commit_payment(ctx, USER, commit(TX_GOOD, "inc-unknown"))
    assert to_ctx(ctx, CancelPayment) and to_ctx(ctx, CompletePayment) == [] and "nothing was authorized" in texts(ctx)[-1]
    assert not ctx.storage.get(f"used_tx:{TX_GOOD}")


async def test_another_user_cannot_pay_for_or_cancel_my_incident(ctx):
    orch = pay_orch()
    inc = await waiting(orch, ctx)
    await orch.handle_commit_payment(ctx, USER2, commit(TX_GOOD, inc))
    assert stored(ctx, inc)["state"] == "AWAITING_PAYMENT" and to_ctx(ctx, CancelPayment, USER2)
    await orch.handle_payment_declined(ctx, USER2, RejectPayment(reason="not mine"))
    assert stored(ctx, inc)["state"] == "AWAITING_PAYMENT"


async def test_repeated_definitive_failures_cancel_the_incident(ctx):
    orch = pay_orch()
    inc = await waiting(orch, ctx)
    for _ in range(MAX_PAYMENT_FAILURES):
        await orch.handle_commit_payment(ctx, USER, commit(TX_UNDER, inc))
    assert stored(ctx, inc)["state"] == "CANCELLED" and "Too many failed payments" in texts(ctx)[-1]
    assert len(to_ctx(ctx, RequestPayment)) == MAX_PAYMENT_FAILURES              # the original plus one per retry, none after the last


async def test_a_transaction_that_is_not_indexed_yet_does_not_use_up_attempts(ctx):
    orch = pay_orch()
    inc = await waiting(orch, ctx)
    for _ in range(MAX_PAYMENT_FAILURES + 2):
        await orch.handle_commit_payment(ctx, USER, commit("F" * 64, inc))
    assert stored(ctx, inc)["state"] == "AWAITING_PAYMENT"


async def test_verifier_crash_is_contained_and_releases_the_hash(ctx):
    class Boom:
        async def verify(self, *a, **k):
            raise RuntimeError("boom")

    orch = make_orch(settings=PAY, skip_payment=False, verifier=Boom())
    inc = await waiting(orch, ctx)
    await orch.handle_commit_payment(ctx, USER, commit(TX_GOOD, inc))
    assert stored(ctx, inc)["state"] == "AWAITING_PAYMENT" and "Nothing was authorized" in texts(ctx)[-1]
    assert not ctx.storage.get(f"used_tx:{TX_GOOD}")


# ------------------------------------------------------------------ user cancellation and timeouts

async def test_user_rejecting_or_cancelling_the_payment_cancels_cleanly():
    for message in (RejectPayment(reason="too expensive"), CancelPayment(transaction_id=None, reason="changed my mind"), RejectPayment()):
        c = FakeContext()
        orch = pay_orch()
        inc = await waiting(orch, c)
        await orch.handle_payment_declined(c, USER, message)
        assert stored(c, inc)["state"] == "CANCELLED" and "Payment declined" in texts(c)[-1] and "No changes were made" in texts(c)[-1]
        await orch.handle_commit_payment(c, USER, commit(TX_GOOD, inc))          # a late payment cannot revive it
        assert stored(c, inc)["state"] == "CANCELLED"


async def test_declining_with_nothing_pending_is_ignored(ctx):
    await pay_orch().handle_payment_declined(ctx, USER, RejectPayment())
    assert ctx.sent == []


async def test_typing_reject_while_awaiting_payment_cancels(ctx):
    orch = pay_orch()
    inc = await waiting(orch, ctx)
    await orch.handle_chat(ctx, USER, chat("reject"))
    assert stored(ctx, inc)["state"] == "CANCELLED"


async def test_unpaid_incident_expires_and_a_late_payment_is_not_consumed(ctx):
    clock = Clock()
    orch = pay_orch(clock=clock, approval_timeout=100.0)
    inc = await waiting(orch, ctx)
    clock.t += 99
    await orch.sweep(ctx)
    assert stored(ctx, inc)["state"] == "AWAITING_PAYMENT"
    clock.t += 5
    await orch.sweep(ctx)
    assert stored(ctx, inc)["state"] == "CANCELLED" and "expired without payment" in texts(ctx)[-1]
    assert to_ctx(ctx, RequestPayment)[0].deadline_seconds == 100
    await orch.handle_commit_payment(ctx, USER, commit(TX_GOOD, inc))
    assert stored(ctx, inc)["state"] == "CANCELLED" and "has **not** been consumed" in texts(ctx)[-1]
    assert not ctx.storage.get(f"used_tx:{TX_GOOD}")


# ------------------------------------------------------------------ wiring

async def test_agent_includes_the_payment_protocol_and_a_cancel_handler():
    agent = create_agent(seed="payment wiring seed", enable_agent_inspector=False)
    assert {p.name for p in agent.protocols.values()} >= {payment_protocol_spec.name, "AgentChatProtocol"}
    assert Model.build_schema_digest(CancelPayment) in agent._protocol._signed_message_handlers   # agent-level handler
