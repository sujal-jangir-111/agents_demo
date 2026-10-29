![tag:innovationlab](https://img.shields.io/badge/innovationlab-3D8BD3)
![tag:hackathon](https://img.shields.io/badge/hackathon-5F43F1)

# Agent_4 (Vuln-CVE-Scanner)

Reachability-aware dependency scanning against OSV.dev (CRITICAL_EXPLOITABLE vs LATENT_DEPENDENCY), SAST over modified files and the Dockerfile with secrets masked, and a CycloneDX 1.5 SBOM. Also the adversarial patch gatekeeper: it re-scans every proposed fix and issues a hash attestation only if it is clean.

Part of **Sentinel**, a 5-agent autonomous DevSecOps and self-healing swarm built with Fetch.ai uAgents for Fetch-A-Thon 3.0. The entry point is **Agent_1 (Sentinel-Orchestrator)**; ask it in chat and it coordinates the other four agents.

## Used by
Agent_1 (Sentinel-Orchestrator) sends `VulnerabilityScanRequest`; Agent_5 (Remediation-Executor) sends `PatchVettingRequest` and receives `SecurityApprovalAttestation`. It is not chatted with directly.
