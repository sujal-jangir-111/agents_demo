"""Counterfactual Blast Radius (CLAUDE.md §8). Deterministic Python; the LLM never computes these numbers.

failure_ratio        = failing_probes / total_probes
dropped_requests_hr  = TRAFFIC_RPM * 60 * failure_ratio
revenue_at_risk_hr   = dropped_requests_hr * CONVERSION_RATE * AVG_ORDER_VALUE_USD
minutes_since_commit = failure_time - suspect_commit_time
sla_budget_burn_pct  = minutes_since_commit / (30*24*60 * (1 - SLA_TARGET)) * 100
credential_exposure  = minutes since the commit that introduced a HARDCODED_SECRET (if any)
score (0-100)        = min(100, 40*failure_ratio + 10*reachable_critical + 5*reachable_high
                              + 20*(secrets>0) + 10*(p95>1000ms))
"""
from dataclasses import dataclass
from typing import Optional

from common.commit_scoring import parse_iso
from common.config import Settings

SLA_WINDOW_MINUTES = 30 * 24 * 60


@dataclass(frozen=True)
class BlastRadius:
    failure_ratio: float
    dropped_requests_hr: float
    revenue_at_risk_hr: float
    minutes_since_commit: float
    sla_budget_burn_pct: float
    credential_exposure_minutes: Optional[float]
    score: float
    # assumptions, echoed in the card so the numbers are explainable
    traffic_rpm: float
    avg_order_value_usd: float
    conversion_rate: float
    sla_target: float

    def assumptions(self) -> str:
        return (f"TRAFFIC_RPM={self.traffic_rpm:g}, AVG_ORDER_VALUE_USD={self.avg_order_value_usd:g}, "
                f"CONVERSION_RATE={self.conversion_rate:g}, SLA_TARGET={self.sla_target:g}")


def minutes_between(earlier_iso: str, later_iso: str) -> float:
    """Non-negative minutes from `earlier_iso` to `later_iso` (0 if either is unparseable)."""
    a, b = parse_iso(earlier_iso), parse_iso(later_iso)
    if a is None or b is None:
        return 0.0
    return max(0.0, (b - a).total_seconds() / 60)


def compute_blast_radius(
    *,
    failing_probes: int,
    total_probes: int,
    p95_ms: float,
    commit_time_iso: str,
    failure_time_iso: str,
    reachable_critical: int,
    reachable_high: int,
    secrets_found: int,
    secret_introduced_by_suspect: bool,
    settings: Settings,
) -> BlastRadius:
    ratio = failing_probes / total_probes if total_probes else 0.0
    dropped = settings.traffic_rpm * 60 * ratio
    revenue = dropped * settings.conversion_rate * settings.avg_order_value_usd
    minutes = minutes_between(commit_time_iso, failure_time_iso)
    budget_minutes = SLA_WINDOW_MINUTES * (1 - settings.sla_target)
    burn = minutes / budget_minutes * 100 if budget_minutes > 0 else 0.0
    exposure = minutes if secrets_found > 0 and secret_introduced_by_suspect else None
    score = min(
        100.0,
        40 * ratio + 10 * reachable_critical + 5 * reachable_high
        + (20 if secrets_found > 0 else 0) + (10 if p95_ms > 1000 else 0),
    )
    return BlastRadius(
        failure_ratio=ratio, dropped_requests_hr=dropped, revenue_at_risk_hr=revenue,
        minutes_since_commit=minutes, sla_budget_burn_pct=burn, credential_exposure_minutes=exposure,
        score=score, traffic_rpm=settings.traffic_rpm, avg_order_value_usd=settings.avg_order_value_usd,
        conversion_rate=settings.conversion_rate, sla_target=settings.sla_target,
    )
