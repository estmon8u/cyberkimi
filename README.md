# CyberKimi

CyberKimi v0.1 is an authorization-bound, evidence-first security-analysis harness for explicitly registered local repositories, local evidence bundles, and isolated local lab environments.

> Kimi reasons about security; deterministic control-plane code establishes authorization, attenuates capabilities, validates policy, executes approved typed operations, stores evidence, and verifies findings.

## Supported modes

- **`review`** — deterministic review of registered local source assets, with optional Kimi-assisted reasoning.
- **`hunt`** — bounded investigation of local JSON, NDJSON, CSV, Parquet, text-log, SARIF, Sigma, and packet-capture metadata inputs.
- **`lab run`** — predefined security-property checks against registered local Docker Compose or CI-ephemeral environments only.

CyberKimi does not authorize public-internet scanning, production mutation, arbitrary command execution, credential extraction, persistence, stealth, lateral movement, or open-ended exploitation.

## Install

```bash
python -m pip install -e '.[dev]'
cyberkimi --version
cyberkimi init --state-directory .cyberkimi
cyberkimi doctor --state-directory .cyberkimi
```

## Development checks

```bash
python -m ruff check src tests
python -m ruff format --check src tests
python -m mypy src
python -m pytest
python -m build
```

See `docs/architecture.md`, `docs/security-model.md`, and `docs/deferred.md` for the implementation contract and explicit non-v0.1 capabilities.
