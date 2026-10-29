![tag:innovationlab](https://img.shields.io/badge/innovationlab-3D8BD3)
![tag:hackathon](https://img.shields.io/badge/hackathon-5F43F1)

# Agent_1 (Sentinel-Orchestrator)

ASI:One entry point of the Sentinel swarm. Send it an outage and it probes the service, finds the guilty commit, scans for CVEs, drafts a security-vetted fix and, after your approval or a 0.1 FET Dorado payment, opens a GitHub PR with an SBOM, triggers the hotfix and verifies recovery.

Part of **Sentinel**, a 5-agent autonomous DevSecOps and self-healing swarm built with Fetch.ai uAgents for Fetch-A-Thon 3.0. The entry point is **Agent_1 (Sentinel-Orchestrator)**; ask it in chat and it coordinates the other four agents.

## Example prompts
- `Diagnose and heal the outage on http://127.0.0.1:9000 for repo owner/repo`
- `Run a security audit on owner/repo`
- `Chaos test http://127.0.0.1:9000`
- `status`, then `approve` or `rollback` when the incident card appears

## Protocols
Agent Chat Protocol (Markdown cards and progress updates) and Agent Payment Protocol (seller, 0.1 FET change-control payment verified on Dorado).
