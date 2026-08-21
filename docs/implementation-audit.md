# CyberKimi v0.1 implementation audit

This audit is scoped to the authorization-bound, evidence-first v0.1 product. Kimi may reason about evidence, but deterministic control-plane code must own engagement scope, capability attenuation, policy, approvals, execution, evidence custody, finding verification, and release gates.

## Verified baseline

The default branch contains a deterministic repository-review path, immutable engagement and asset records, signed scope tokens and execution grants, typed tool manifests, local evidence storage and redaction, finding-state transitions, a Moonshot/Kimi client prototype, SQLite persistence, a CLI, packaging metadata, and an initial test workflow.

## Ordered completion backlog

1. **Release foundation.** Make CLI version/help behavior deterministic, run CI on the audit branch, and keep wheel-install smoke tests green.
2. **v0.1 security ceiling.** Remove R4/extended/comprehensive execution from the v0.1 contracts and require exact human approval for every R3 action. Retain R0–R3 only.
3. **Engagement lifecycle.** Add amend, revoke, approval, and inspection commands with immutable revision semantics and durable audit records.
4. **Scratch validation.** Add isolated scratch worktrees for patch/test hypotheses; never modify the registered source tree.
5. **Hunt mode.** Complete bounded local ingestion, schema inspection, filtering, timeline construction, Sigma evaluation, and packet-capture metadata handling without public network access.
6. **Lab mode.** Enforce registered local endpoints, DNS/IP pinning, rootless hardened execution, bounded property checks, reset semantics, and exact R3 approvals.
7. **Evaluation and release gates.** Add deterministic benchmarks, precision/recall and Wilson intervals, authorization and redaction gates, and machine-readable evaluation output.
8. **Audit, replay, and exports.** Verify the audit hash chain, support tool-only replay, and export redacted Markdown, JSON, SARIF, and CycloneDX artifacts.
9. **Hardening and documentation.** Add adversarial/property/provider tests, threat-model and architecture docs, contributor/security guidance, and a final full CI matrix.
10. **Integration.** Remove stale transport workflows and divergent prototype branches from the release path, merge only a green audited branch into `main`, and verify the final `main` commit.

## Explicitly deferred beyond v0.1

Public-internet scanning, cloud administration, production writes, arbitrary shell or binary execution, credential extraction, persistence, stealth, lateral movement, external propagation, unrestricted exploitation, and recursive agent spawning are not part of v0.1.
