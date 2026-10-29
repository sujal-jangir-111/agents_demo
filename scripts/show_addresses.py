"""Print the five agent addresses derived from the seeds in .env (seeds themselves are never printed).

    python -m scripts.show_addresses            # table
    python -m scripts.show_addresses --markdown # README registry rows
"""
import sys

from common.addresses import all_addresses

AGENTS = [("orchestrator", "Agent_1", 8001), ("watchdog", "Agent_2", 8002),
          ("detective", "Agent_3", 8003), ("scanner", "Agent_4", 8004),
          ("executor", "Agent_5", 8005)]


def main(argv=None) -> int:
    markdown = "--markdown" in (argv if argv is not None else sys.argv[1:])
    addresses = all_addresses()
    missing = [key.upper() + "_SEED" for key, _, _ in AGENTS if not addresses[key]]
    if missing:
        print("Missing in .env: " + ", ".join(missing), file=sys.stderr)
        return 1
    for key, name, port in AGENTS:
        addr = addresses[key]
        if markdown:
            print(f"| {name} | `{addr}` | https://agentverse.ai/agents/details/{addr}/profile | {port} |")
        else:
            print(f"{name:<8} {port}  {addr}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
