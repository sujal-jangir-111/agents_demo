"""Single source of configuration. Loads .env and exposes typed settings."""
import os
from dataclasses import dataclass, field
from typing import List

from dotenv import load_dotenv

load_dotenv()


def _get(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _get_float(name: str, default: float) -> float:
    try:
        return float(_get(name, str(default)))
    except ValueError:
        return default


def _get_int(name: str, default: int) -> int:
    try:
        return int(_get(name, str(default)))
    except ValueError:
        return default


def _get_list(name: str) -> List[str]:
    return [p.strip() for p in _get(name).split(",") if p.strip()]


@dataclass(frozen=True)
class Settings:
    # ASI:One
    asi1_api_key: str = field(default_factory=lambda: _get("ASI1_API_KEY"))
    asi1_model: str = field(default_factory=lambda: _get("ASI1_MODEL", "asi1-mini"))
    asi1_base_url: str = "https://api.asi1.ai/v1/chat/completions"

    # GitHub / demo target
    github_token: str = field(default_factory=lambda: _get("GITHUB_TOKEN"))
    demo_repo_full_name: str = field(default_factory=lambda: _get("DEMO_REPO_FULL_NAME"))
    demo_service_url: str = field(default_factory=lambda: _get("DEMO_SERVICE_URL"))
    demo_admin_token: str = field(default_factory=lambda: _get("DEMO_ADMIN_TOKEN"))
    # Extra repos the executor may write to (in addition to DEMO_REPO_FULL_NAME)
    github_write_allowlist: List[str] = field(default_factory=lambda: _get_list("GITHUB_WRITE_ALLOWLIST"))

    # Agent seeds
    orchestrator_seed: str = field(default_factory=lambda: _get("ORCHESTRATOR_SEED"))
    watchdog_seed: str = field(default_factory=lambda: _get("WATCHDOG_SEED"))
    detective_seed: str = field(default_factory=lambda: _get("DETECTIVE_SEED"))
    scanner_seed: str = field(default_factory=lambda: _get("SCANNER_SEED"))
    executor_seed: str = field(default_factory=lambda: _get("EXECUTOR_SEED"))

    # Payment / chain
    orchestrator_wallet_address: str = field(default_factory=lambda: _get("ORCHESTRATOR_WALLET_ADDRESS"))
    remediation_price_atestfet: int = field(
        default_factory=lambda: _get_int("REMEDIATION_PRICE_ATESTFET", 100_000_000_000_000_000)
    )
    dorado_explorer_base: str = field(
        default_factory=lambda: _get("DORADO_EXPLORER_BASE", "https://explore-dorado.fetch.ai/transactions")
    )
    skip_payment: bool = field(default_factory=lambda: _get("SKIP_PAYMENT", "false").lower() == "true")

    # Remediation
    patch_max_attempts: int = field(default_factory=lambda: _get_int("PATCH_MAX_ATTEMPTS", 3))

    # Watchdog
    watchdog_targets: List[str] = field(default_factory=lambda: _get_list("WATCHDOG_TARGETS"))
    watchdog_interval_seconds: int = field(default_factory=lambda: _get_int("WATCHDOG_INTERVAL_SECONDS", 60))

    # Blast radius assumptions
    traffic_rpm: float = field(default_factory=lambda: _get_float("TRAFFIC_RPM", 120))
    avg_order_value_usd: float = field(default_factory=lambda: _get_float("AVG_ORDER_VALUE_USD", 40))
    conversion_rate: float = field(default_factory=lambda: _get_float("CONVERSION_RATE", 0.03))
    sla_target: float = field(default_factory=lambda: _get_float("SLA_TARGET", 0.999))


def get_settings() -> Settings:
    """Build settings from the current environment (re-read on each call)."""
    return Settings()


settings = get_settings()
