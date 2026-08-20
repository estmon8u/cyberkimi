from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Any

import yaml

from cyberkimi.core import AccessMode, DataClassification, RiskTier, TrustProfile, utc_now
from cyberkimi.engagement.models import EngagementManifest


def load_manifest(path: Path) -> EngagementManifest:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("engagement manifest must contain a YAML object")
    data = _normalize_legacy_manifest(data)
    return EngagementManifest.model_validate(data)


def dump_manifest(manifest: EngagementManifest, path: Path) -> None:
    payload = manifest.model_dump(mode="json", exclude_none=True)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")


def provision_repository_manifest(
    *,
    target: Path,
    owner: str,
    engagement_id: str,
    name: str | None = None,
    duration_days: int = 7,
    classification: DataClassification = DataClassification.INTERNAL,
    read_write: bool = False,
) -> EngagementManifest:
    target = target.expanduser().resolve(strict=True)
    if not target.is_dir():
        raise ValueError("repository target must be a directory")
    now = utc_now()
    repo_name = target.name.lower().replace("_", "-")
    payload: dict[str, Any] = {
        "engagement": {
            "id": engagement_id,
            "name": name or f"{repo_name}-review",
            "owner": owner,
            "purpose": "defensive_security_assessment",
            "created_at": now.isoformat(),
            "expires_at": (now + timedelta(days=duration_days)).isoformat(),
            "flags": [],
            "revision": 1,
        },
        "authorization": {
            "basis": "local_owner_attestation",
            "status": "self_attested",
            "approver": owner,
            "auto_approve_within_scope": True,
            "allow_harness_asset_progression": False,
        },
        "scope": {
            "repositories": [
                {
                    "id": f"repo:{repo_name}",
                    "path": str(target),
                    "access": AccessMode.READ_WRITE.value
                    if read_write
                    else AccessMode.READ_ONLY.value,
                    "data_classification": classification.value,
                }
            ],
            "public_internet_permitted": False,
        },
        "allowed_capabilities": {
            "source_read": True,
            "source_modify": "approval_required" if read_write else False,
            "static_analysis": True,
            "dependency_analysis": True,
            "runtime_observation": False,
            "bounded_validation": False,
        },
        "prohibited_capabilities": {
            "persistence": True,
            "destructive_operations": True,
            "credential_extraction": True,
            "stealth_or_evasion": True,
            "external_propagation": True,
            "third_party_targeting": True,
        },
        "budgets": {"selected": "default"},
        "data_handling": {
            "redact_secrets_before_model": True,
            "retain_raw_evidence_locally": True,
            "send_raw_secrets_to_model": False,
        },
        "maximum_risk_tier": RiskTier.R3_ACTIVE_VALIDATION.value,
        "allowed_trust_profiles": [TrustProfile.RESTRICTED.value],
    }
    return EngagementManifest.model_validate(payload)


def _normalize_legacy_manifest(data: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(data)
    scope = dict(normalized.get("scope") or {})
    public_internet = scope.pop("public_internet", None)
    if isinstance(public_internet, dict):
        scope["public_internet_permitted"] = bool(public_internet.get("permitted", False))
    for collection_name, prefix in (
        ("runtime_environments", "lab"),
        ("repositories", "repo"),
        ("log_sources", "logs"),
    ):
        entries = scope.get(collection_name) or []
        for entry in entries:
            identifier = entry.get("id")
            if isinstance(identifier, str) and ":" not in identifier:
                entry["id"] = f"{prefix}:{identifier}"
    normalized["scope"] = scope

    budgets = normalized.get("budgets")
    if isinstance(budgets, dict) and "max_parallel_tasks" in budgets:
        normalized["budgets"] = {"selected": "extended", "extended": budgets}
        engagement = dict(normalized.get("engagement") or {})
        flags = set(engagement.get("flags") or [])
        flags.add("extended_operations")
        engagement["flags"] = sorted(flags)
        normalized["engagement"] = engagement
    return normalized
