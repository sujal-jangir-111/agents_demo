"""One place that builds every Sentinel uagents Agent (CLAUDE.md §5 / §9.5)."""
import os
from typing import Any, Dict

from uagents import Agent
from uagents.resolver import RulesBasedResolver

from common.addresses import all_addresses

LOCAL_PORTS = {"orchestrator": 8001, "watchdog": 8002, "detective": 8003, "scanner": 8004, "executor": 8005}


def local_mode() -> bool:
    """True when AGENT_MAILBOX=false (local testing without Agentverse mailboxes)."""
    return os.getenv("AGENT_MAILBOX", "true").strip().lower() in ("false", "0", "no", "off")


def local_rules() -> Dict[str, str]:
    """agent address -> http://127.0.0.1:<port>/submit for every agent whose seed/address is configured."""
    return {addr: f"http://127.0.0.1:{LOCAL_PORTS[key]}/submit" for key, addr in all_addresses().items() if addr}


def build_agent(
    *, name: str, seed: str, seed_env: str, port: int, description: str, mailbox: bool = True, **agent_kwargs: Any
) -> Agent:
    """Agent(name, seed, port, mailbox, publish_agent_details=True). Live runs keep mailbox=True;
    tests pass mailbox=False plus a no-op registration policy. A missing seed is a hard error so an
    agent never silently starts with a random (non-reproducible) address.

    Mailbox note (checked against uagents 0.26 source): with mailbox=True and NO `endpoint`, the only endpoint the
    agent registers is the Agentverse mailbox. Every message it receives, including agent-to-agent traffic between
    local processes, is therefore delivered through its Agentverse mailbox, so ALL agents must have their mailbox
    connected once via the Inspector link (Connect -> Mailbox). Never pass `endpoint=` here: it overrides the mailbox."""
    if not seed:
        raise RuntimeError(f"{seed_env} is not set; copy .env.example to .env and fill in the seeds")
    readme = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "agents", "readmes",
                          name.replace("-", "_") + ".md")
    if "readme_path" not in agent_kwargs and os.path.isfile(readme):
        agent_kwargs["readme_path"] = readme      # shown on the Agentverse profile, with the Innovation Lab badges
    if local_mode() and "endpoint" not in agent_kwargs and "resolve" not in agent_kwargs:
        # AGENT_MAILBOX=false: no Agentverse at all. Agents POST to each other's local /submit endpoint,
        # resolved from the fixed port table instead of the Almanac.
        mailbox = False
        agent_kwargs["endpoint"] = [f"http://127.0.0.1:{port}/submit"]
        agent_kwargs["resolve"] = RulesBasedResolver(local_rules())
    return Agent(
        name=name, seed=seed, port=port, mailbox=mailbox, publish_agent_details=True,
        description=description, **agent_kwargs,
    )
