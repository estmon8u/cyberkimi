# CyberKimi

CyberKimi v0.1 is an authorization-bound, evidence-first security-analysis harness for explicitly registered local repositories, local evidence bundles, and isolated local lab environments.

> Kimi reasons about security; deterministic control-plane code establishes authorization, attenuates capabilities, validates policy, executes approved typed operations, stores evidence, and verifies findings.

## Security boundary

CyberKimi v0.1 supports local defensive analysis only. It does not authorize public-internet scanning, production mutation, arbitrary command execution, credential extraction, persistence, stealth, lateral movement, or open-ended exploitation.

## Install

```bash
python -m pip install -e '.[dev]'
cyberkimi --version
cyberkimi init --state-directory .cyberkimi
cyberkimi doctor --state-directory .cyberkimi
```

## Development

```bash
python -m ruff check src tests
python -m ruff format --check src tests
python -m mypy src
python -m pytest
python -m build
```

The implementation is developed in phase commits. `CHANGELOG.md` records the release-level changes and `docs/` describes the final architecture and threat model.
