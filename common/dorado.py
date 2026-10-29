"""Dorado testnet payment verification (CLAUDE.md §9.3).

`DoradoVerifier.verify` answers one question: did transaction `tx_hash` succeed on Dorado and move at least the
required amount of `atestfet` to the expected wallet? Fetching the transaction is injectable (`fetch`), so tests
run with no network; the default fetcher uses cosmpy's synchronous `LedgerClient` in a worker thread.
Replay protection (a hash may authorize only one incident) is done by the caller, which owns the storage.
"""
import asyncio
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, List, Optional, Tuple

DENOM = "atestfet"
ATESTFET_PER_FET = 10 ** 18
TX_HASH_RE = re.compile(r"^[0-9A-Fa-f]{64}$")
_COIN_RE = re.compile(r"^(\d+)([a-zA-Z][a-zA-Z0-9/:._-]*)$")


@dataclass(frozen=True)
class Transfer:
    sender: str
    recipient: str
    amount: int
    denom: str


@dataclass(frozen=True)
class TxInfo:
    tx_hash: str
    code: int
    transfers: Tuple[Transfer, ...]
    timestamp: Optional[datetime] = None
    raw_log: str = ""


@dataclass(frozen=True)
class PaymentVerification:
    ok: bool
    reason: str                 # user-safe explanation (also set when ok)
    definitive: bool = True     # False = could not decide (not indexed yet / RPC trouble): the user may simply retry
    tx_hash: str = ""
    payer: str = ""
    amount: int = 0


FetchTx = Callable[[str], Awaitable[Optional[TxInfo]]]


def format_fet(atestfet: int) -> str:
    whole, frac = divmod(int(atestfet), ATESTFET_PER_FET)
    return f"{whole}.{frac:018d}".rstrip("0").rstrip(".") + " FET"


def explorer_url(base: str, tx_hash: str) -> str:
    return f"{base.rstrip('/')}/{tx_hash}"


def parse_coins(text: str) -> List[Tuple[int, str]]:
    """'100atestfet,5foo' -> [(100, 'atestfet'), (5, 'foo')]; malformed parts are skipped."""
    coins = []
    for part in (text or "").split(","):
        m = _COIN_RE.match(part.strip())
        if m:
            coins.append((int(m.group(1)), m.group(2)))
    return coins


def _transfers_from_event(event: dict) -> List[Transfer]:
    sender, recipient = str(event.get("sender", "")), str(event.get("recipient", ""))
    return [Transfer(sender, recipient, amount, denom) for amount, denom in parse_coins(str(event.get("amount", "")))]


def tx_info_from_response(resp: Any) -> TxInfo:
    """Convert a cosmpy TxResponse. Per-message logs are preferred: they exclude the fee transfer, which shares the
    `transfer` event type in the flattened `events` (used only when a chain version returns no logs)."""
    transfers: List[Transfer] = []
    for log in getattr(resp, "logs", None) or []:
        event = (getattr(log, "events", None) or {}).get("transfer")
        if event:
            transfers += _transfers_from_event(event)
    if not transfers:
        event = (getattr(resp, "events", None) or {}).get("transfer")
        if event:
            transfers = _transfers_from_event(event)
    return TxInfo(tx_hash=str(resp.hash), code=int(resp.code), transfers=tuple(transfers),
                  timestamp=getattr(resp, "timestamp", None), raw_log=str(getattr(resp, "raw_log", ""))[:300])


class CosmpyFetcher:
    """Live lookup against Dorado. The ledger client is created on first use (no network at import time)."""

    def __init__(self) -> None:
        self._client: Any = None

    def _query(self, tx_hash: str) -> Optional[TxInfo]:
        from cosmpy.aerial.client import LedgerClient, NetworkConfig
        from cosmpy.aerial.exceptions import NotFoundError

        if self._client is None:
            self._client = LedgerClient(NetworkConfig.fetchai_stable_testnet())  # Dorado
        try:
            return tx_info_from_response(self._client.query_tx(tx_hash))
        except NotFoundError:
            return None

    async def __call__(self, tx_hash: str) -> Optional[TxInfo]:
        return await asyncio.to_thread(self._query, tx_hash)  # cosmpy is synchronous


class DoradoVerifier:
    def __init__(self, fetch: Optional[FetchTx] = None, attempts: int = 5, delay: float = 3.0,
                 sleep: Callable[[float], Awaitable[Any]] = asyncio.sleep) -> None:
        self.fetch = fetch or CosmpyFetcher()
        self.attempts, self.delay, self._sleep = max(1, attempts), delay, sleep

    async def _lookup(self, tx_hash: str) -> Tuple[Optional[TxInfo], str]:
        problem = ""
        for attempt in range(self.attempts):
            try:
                info = await self.fetch(tx_hash)
                if info is not None:
                    return info, ""
                problem = f"transaction not found on Dorado after {attempt + 1} attempt(s) (it may not be indexed yet)"
            except Exception as exc:  # RPC/DNS/gRPC trouble: retry, then report as undecided
                problem = f"Dorado lookup failed ({type(exc).__name__})"
            if attempt + 1 < self.attempts:
                await self._sleep(self.delay)
        return None, problem

    async def verify(self, tx_hash: str, recipient: str, min_amount: int, denom: str = DENOM,
                     not_before: Optional[datetime] = None) -> PaymentVerification:
        tx_hash = (tx_hash or "").strip()
        if not TX_HASH_RE.match(tx_hash):
            return PaymentVerification(False, "That does not look like a Dorado transaction hash (64 hex characters).")
        tx_hash = tx_hash.upper()
        if not recipient:
            return PaymentVerification(False, "The payment wallet is not configured on my side.", definitive=False, tx_hash=tx_hash)
        info, problem = await self._lookup(tx_hash)
        if info is None:
            return PaymentVerification(False, problem, definitive=False, tx_hash=tx_hash)
        if info.code != 0:
            return PaymentVerification(False, f"Transaction failed on-chain (code {info.code}), so nothing was paid.", tx_hash=tx_hash)
        if not_before is not None and info.timestamp is not None:
            stamp = info.timestamp if info.timestamp.tzinfo else info.timestamp.replace(tzinfo=timezone.utc)
            if stamp < not_before:
                return PaymentVerification(False, "That transaction was made before this payment was requested, so it cannot authorize this change.", tx_hash=tx_hash)
        ours = [t for t in info.transfers if t.recipient == recipient and t.denom == denom]
        if not ours:
            others = [t for t in info.transfers if t.denom == denom]
            why = ("it pays a different wallet" if others else f"it contains no {denom} transfer")
            return PaymentVerification(False, f"Transaction succeeded but {why}; expected a payment to `{recipient}`.", tx_hash=tx_hash)
        payer = ours[0].sender
        paid = sum(t.amount for t in ours if t.sender == payer)
        if paid < min_amount:
            return PaymentVerification(False, f"Underpaid: received {format_fet(paid)}, required {format_fet(min_amount)}.",
                                       tx_hash=tx_hash, payer=payer, amount=paid)
        return PaymentVerification(True, f"{format_fet(paid)} received from `{payer}`.", tx_hash=tx_hash, payer=payer, amount=paid)
