![tag:innovationlab](https://img.shields.io/badge/innovationlab-3D8BD3)
![tag:hackathon](https://img.shields.io/badge/hackathon-5F43F1)

# Agent_3 (Commit-Detective)

Correlates a production failure with the Git commit that caused it by scoring the last 5 commits against the failing file, line and endpoint, explains the root cause from the diff, and maps the active Python imports and call symbols for reachability analysis.

Part of **Sentinel**, a 5-agent autonomous DevSecOps and self-healing swarm built with Fetch.ai uAgents for Fetch-A-Thon 3.0. The entry point is **Agent_1 (Sentinel-Orchestrator)**; ask it in chat and it coordinates the other four agents.

## Used by
Agent_1 (Sentinel-Orchestrator) sends `CommitCorrelationRequest` and receives `CommitEvidenceReport`. It is not chatted with directly.
