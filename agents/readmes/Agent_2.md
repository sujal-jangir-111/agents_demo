![tag:innovationlab](https://img.shields.io/badge/innovationlab-3D8BD3)
![tag:hackathon](https://img.shields.io/badge/hackathon-5F43F1)

# Agent_2 (Telemetry-Watchdog)

Probes a live service with a concurrent burst (3 requests per endpoint), records status, latency, p50/p95 and the error snippet with the failing file and line, runs canary checks after a fix, and can inject chaos in the demo app.

Part of **Sentinel**, a 5-agent autonomous DevSecOps and self-healing swarm built with Fetch.ai uAgents for Fetch-A-Thon 3.0. The entry point is **Agent_1 (Sentinel-Orchestrator)**; ask it in chat and it coordinates the other four agents.

## Used by
Agent_1 (Sentinel-Orchestrator) sends it `HealthProbeRequest` messages and receives `HealthProbeReport` replies. It is not chatted with directly.
