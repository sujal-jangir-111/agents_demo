from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from common.dorado import (
    DoradoVerifier, explorer_url, format_fet, parse_coins, tx_info_from_response,
)
from tests.fakes import PAYER, PRICE, TX_GOOD, WALLET, FakeChain, fake_verifier, make_tx


def verify(chain, tx=TX_GOOD, **kw):
    return fake_verifier(chain).verify(tx, kw.pop("recipient", WALLET), kw.pop("min_amount", PRICE), **kw)


def test_format_and_parse_helpers():
    assert format_fet(PRICE) == "0.1 FET" and format_fet(10 ** 18) == "1 FET" and format_fet(0) == "0 FET"
    assert parse_coins("100atestfet, 5ibc/ABC,junk") == [(100, "atestfet"), (5, "ibc/ABC")] and parse_coins("") == []
    assert explorer_url("https://explore-dorado.fetch.ai/transactions/", "AB") == "https://explore-dorado.fetch.ai/transactions/AB"


def response(logs=None, events=None, code=0):
    log = lambda ev: SimpleNamespace(events=ev)  # noqa: E731
    return SimpleNamespace(hash="ab" * 32, code=code, raw_log="", timestamp=None, events=events or {}, logs=[log(e) for e in (logs or [])])


def test_cosmpy_response_is_parsed_from_message_logs_not_the_fee_transfer():
    resp = response(logs=[{"transfer": {"sender": PAYER, "recipient": WALLET, "amount": f"{PRICE}atestfet"}}],
                    events={"transfer": {"sender": PAYER, "recipient": "fetch1feecollector", "amount": "5atestfet"}})
    info = tx_info_from_response(resp)
    assert [(t.recipient, t.amount, t.denom) for t in info.transfers] == [(WALLET, PRICE, "atestfet")] and info.code == 0


def test_flattened_events_are_the_fallback_when_there_are_no_logs():
    info = tx_info_from_response(response(events={"transfer": {"sender": PAYER, "recipient": WALLET, "amount": f"{PRICE}atestfet,3foo"}}))
    assert {(t.amount, t.denom) for t in info.transfers} == {(PRICE, "atestfet"), (3, "foo")}
    assert tx_info_from_response(response()).transfers == ()


async def test_valid_payment_is_accepted_and_the_payer_is_reported():
    res = await verify(FakeChain(make_tx(TX_GOOD)))
    assert res.ok and res.payer == PAYER and res.amount == PRICE and res.tx_hash == TX_GOOD and "0.1 FET" in res.reason


async def test_overpayment_is_accepted_and_hash_case_is_normalized():
    res = await verify(FakeChain(make_tx(TX_GOOD, amount=PRICE * 3)), tx=TX_GOOD.lower())
    assert res.ok and res.amount == PRICE * 3 and res.tx_hash == TX_GOOD


@pytest.mark.parametrize("bad", ["", "not-a-hash", "A" * 63, "G" * 64, "A" * 64 + "; DROP"])
async def test_malformed_hashes_are_refused_without_touching_the_chain(bad):
    chain = FakeChain()
    res = await verify(chain, tx=bad)
    assert not res.ok and res.definitive and chain.lookups == []


async def test_underpaid_wrong_recipient_wrong_denom_and_failed_tx_are_refused():
    under = await verify(FakeChain(make_tx(TX_GOOD, amount=PRICE - 1)))
    assert not under.ok and under.definitive and "Underpaid" in under.reason
    other = await verify(FakeChain(make_tx(TX_GOOD, recipient="fetch1someoneelse")))
    assert not other.ok and "different wallet" in other.reason
    denom = await verify(FakeChain(make_tx(TX_GOOD, denom="uatom")))
    assert not denom.ok and "no atestfet transfer" in denom.reason
    failed = await verify(FakeChain(make_tx(TX_GOOD, code=11)))
    assert not failed.ok and failed.definitive and "failed on-chain" in failed.reason


async def test_a_transaction_older_than_the_request_cannot_authorize_it():
    now = datetime.now(timezone.utc)
    old = make_tx(TX_GOOD, timestamp=now - timedelta(hours=1))
    assert not (await verify(FakeChain(old), not_before=now)).ok
    assert (await verify(FakeChain(make_tx(TX_GOOD, timestamp=now + timedelta(seconds=5))), not_before=now)).ok
    naive = make_tx(TX_GOOD, timestamp=(now - timedelta(hours=1)).replace(tzinfo=None))
    assert not (await verify(FakeChain(naive), not_before=now)).ok


async def test_unknown_transaction_is_retried_then_reported_as_undecided():
    chain, sleeps = FakeChain(), []

    async def sleep(s):
        sleeps.append(s)

    res = await DoradoVerifier(fetch=chain.fetch, attempts=5, delay=3.0, sleep=sleep).verify(TX_GOOD, WALLET, PRICE)
    assert not res.ok and not res.definitive and "not found" in res.reason
    assert len(chain.lookups) == 5 and sleeps == [3.0] * 4          # 5 attempts with 3 s backoff, no sleep after the last


async def test_a_late_indexed_transaction_is_found_on_a_retry():
    chain = FakeChain()
    calls = []

    async def fetch(h):
        calls.append(h)
        return make_tx(TX_GOOD) if len(calls) == 3 else None

    assert (await DoradoVerifier(fetch=fetch, attempts=5, delay=0, sleep=fake_verifier(chain)._sleep).verify(TX_GOOD, WALLET, PRICE)).ok
    assert len(calls) == 3


async def test_rpc_errors_are_retried_and_never_raised():
    attempts = []

    async def broken(h):
        attempts.append(h)
        raise ConnectionError("dorado rpc down")

    res = await DoradoVerifier(fetch=broken, attempts=3, delay=0, sleep=fake_verifier(FakeChain())._sleep).verify(TX_GOOD, WALLET, PRICE)
    assert not res.ok and not res.definitive and "ConnectionError" in res.reason and len(attempts) == 3


async def test_missing_wallet_configuration_is_reported_not_trusted():
    res = await fake_verifier(FakeChain(make_tx(TX_GOOD))).verify(TX_GOOD, "", PRICE)
    assert not res.ok and not res.definitive


def test_default_fetcher_is_lazy_and_makes_no_network_call_on_construction():
    verifier = DoradoVerifier()
    assert verifier.fetch._client is None and verifier.attempts == 5 and verifier.delay == 3.0
