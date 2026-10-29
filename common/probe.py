"""HTTP burst-probe logic for the Agent_2. Pure async functions, no uagents.

Design notes:
- Every individual request becomes one EndpointMetric (3 per endpoint by default), so
  `failing_probes / total_probes` for the blast radius is just a count over `metrics`,
  and p50/p95 can be recomputed from them without any schema change.
- Endpoints are probed concurrently; the requests within one endpoint run sequentially
  so each latency measurement is not distorted by its siblings.
- Nothing here raises: network errors become `status_code=0` with the exception class
  name in `error_snippet`.
"""
import asyncio
import math
import re
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Sequence, Tuple

import httpx

from common.models import EndpointMetric, HealthProbeRequest, HealthProbeReport
from common.sast_rules import mask_secrets

BURST_SIZE = 3
TIMEOUT_SECONDS = 10.0
MAX_SNIPPET = 1000
CHAOS_PATH = "/admin/simulate-fault"

_FILE_RE = re.compile(r"X-Error-File:\s*(\S+)")
_LINE_RE = re.compile(r"X-Error-Line:\s*(\d+)")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def build_url(service_url: str, endpoint: str) -> str:
    return service_url.rstrip("/") + "/" + endpoint.lstrip("/")


def build_error_snippet(response: httpx.Response) -> str:
    """`HTTP <code> <json body>` plus the X-Error-File / X-Error-Line headers, <= 1,000 chars."""
    tail = ""
    for header in ("X-Error-File", "X-Error-Line"):
        if header in response.headers:
            tail += f"\n{header}: {response.headers[header]}"
    head = f"HTTP {response.status_code} "
    body = response.text.strip()
    room = max(0, MAX_SNIPPET - len(head) - len(tail))
    return mask_secrets(head + body[:room] + tail)[:MAX_SNIPPET]


def parse_error_snippet(snippet: Optional[str]) -> Tuple[Optional[str], Optional[int]]:
    """(X-Error-File, X-Error-Line) recovered from an error_snippet; used by Agent_3."""
    if not snippet:
        return None, None
    file_m, line_m = _FILE_RE.search(snippet), _LINE_RE.search(snippet)
    return (file_m.group(1) if file_m else None), (int(line_m.group(1)) if line_m else None)


async def probe_once(client: httpx.AsyncClient, service_url: str, endpoint: str) -> EndpointMetric:
    timestamp = _now_iso()
    started = time.perf_counter()
    try:
        response = await client.get(build_url(service_url, endpoint), timeout=TIMEOUT_SECONDS, follow_redirects=True)
    except Exception as exc:  # DNS, TLS, timeout, bad URL ... never raise out of a probe
        latency = (time.perf_counter() - started) * 1000
        return EndpointMetric(
            endpoint=endpoint, status_code=0, latency_ms=round(latency, 2),
            error_snippet=f"{type(exc).__name__}: {str(exc)}"[:MAX_SNIPPET], timestamp_utc=timestamp,
        )
    latency = (time.perf_counter() - started) * 1000
    snippet = None if response.is_success else build_error_snippet(response)
    return EndpointMetric(
        endpoint=endpoint, status_code=response.status_code, latency_ms=round(latency, 2),
        error_snippet=snippet, timestamp_utc=timestamp,
    )


async def _probe_endpoint(client: httpx.AsyncClient, service_url: str, endpoint: str, count: int) -> List[EndpointMetric]:
    return [await probe_once(client, service_url, endpoint) for _ in range(count)]


async def run_burst(
    client: httpx.AsyncClient, service_url: str, endpoints: Sequence[str], count: int = BURST_SIZE
) -> List[EndpointMetric]:
    """Probe all endpoints concurrently, `count` requests each; metrics keep endpoint order."""
    groups = await asyncio.gather(*(_probe_endpoint(client, service_url, e, count) for e in endpoints))
    return [metric for group in groups for metric in group]


async def inject_chaos(client: httpx.AsyncClient, service_url: str, admin_token: str) -> bool:
    """POST /admin/simulate-fault with the demo token. Returns success; never raises."""
    if not admin_token:
        return False
    try:
        response = await client.post(
            build_url(service_url, CHAOS_PATH), headers={"X-Sentinel-Token": admin_token}, timeout=TIMEOUT_SECONDS,
        )
        return response.is_success
    except Exception:
        return False


def percentile(values: Sequence[float], pct: float) -> float:
    """Nearest-rank percentile (0 for an empty sequence)."""
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = max(1, math.ceil(pct / 100 * len(ordered)))
    return ordered[rank - 1]


def summarize(metrics: Sequence[EndpointMetric]) -> Dict[str, float]:
    """Burst-wide p50/p95 latency plus failing/total probe counts."""
    latencies = [m.latency_ms for m in metrics]
    return {
        "p50_ms": percentile(latencies, 50),
        "p95_ms": percentile(latencies, 95),
        "failing": float(sum(1 for m in metrics if not 200 <= m.status_code < 300)),
        "total": float(len(metrics)),
    }


def is_healthy(metrics: Sequence[EndpointMetric]) -> bool:
    return bool(metrics) and all(200 <= m.status_code < 300 for m in metrics)


async def probe_service(
    client: httpx.AsyncClient, request: HealthProbeRequest, admin_token: str = ""
) -> Tuple[HealthProbeReport, bool]:
    """Run a full probe for a request. Returns (report, chaos_injected)."""
    chaos_ok = False
    if request.inject_chaos:
        chaos_ok = await inject_chaos(client, request.service_url, admin_token)
    metrics = await run_burst(client, request.service_url, request.endpoints)
    report = HealthProbeReport(
        incident_id=request.incident_id, service_url=request.service_url,
        is_healthy=is_healthy(metrics), is_canary_check=request.is_canary_check, metrics=metrics,
    )
    return report, chaos_ok
