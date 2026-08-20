from __future__ import annotations

import re
from typing import Any

from jsonschema import Draft202012Validator
from pydantic import Field, field_validator, model_validator

from cyberkimi.core import AssetType, RiskTier, StrictModel, TrustProfile
from cyberkimi.errors import ValidationFailure


_SAFE_ALIAS = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


class RuntimeLimits(StrictModel):
    timeout_seconds: int = Field(default=60, ge=1, le=7200)
    cpu_limit: float = Field(default=1.0, gt=0, le=32)
    memory_mb: int = Field(default=512, ge=64, le=65536)
    process_limit: int = Field(default=64, ge=1, le=4096)
    output_bytes: int = Field(default=1_000_000, ge=1024, le=100_000_000)


class CapabilityProfile(StrictModel):
    name: str
    risk_tier: RiskTier
    effects: frozenset[str]
    network: bool = False
    filesystem: str = Field(default="read_only", pattern=r"^(read_only|read_write)$")
    trust_profile: TrustProfile = TrustProfile.RESTRICTED
    runtime: RuntimeLimits = RuntimeLimits()
    requires_engagement_flag: str | None = None
    requires_approval: bool = False
    kill_switch_required: bool = False


class ToolManifest(StrictModel):
    internal_id: str
    name: str
    version: str
    kimi_alias: str
    category: str
    description: str
    accepted_assets: frozenset[AssetType]
    arguments_schema: dict[str, Any]
    base_profile: CapabilityProfile
    authorized_profiles: tuple[CapabilityProfile, ...] = ()

    @field_validator("kimi_alias")
    @classmethod
    def validate_alias(cls, value: str) -> str:
        if not _SAFE_ALIAS.fullmatch(value):
            raise ValueError("Kimi function alias must contain only letters, numbers, '_' or '-'")
        return value

    @model_validator(mode="after")
    def validate_manifest(self) -> "ToolManifest":
        Draft202012Validator.check_schema(self.arguments_schema)
        names = [self.base_profile.name, *(item.name for item in self.authorized_profiles)]
        if len(names) != len(set(names)):
            raise ValueError("tool profile names must be unique")
        if self.base_profile.requires_engagement_flag:
            raise ValueError("base profile cannot require an engagement flag")
        return self

    def validate_arguments(self, arguments: dict[str, Any]) -> None:
        errors = sorted(Draft202012Validator(self.arguments_schema).iter_errors(arguments), key=str)
        if errors:
            raise ValidationFailure(f"tool arguments failed schema validation: {errors[0].message}")

    def profile(self, name: str | None, *, engagement_flags: frozenset[str]) -> CapabilityProfile:
        if name is None or name == self.base_profile.name:
            return self.base_profile
        for profile in self.authorized_profiles:
            if profile.name != name:
                continue
            required = profile.requires_engagement_flag
            if required and required not in engagement_flags:
                raise ValidationFailure(
                    f"profile {name!r} requires engagement flag {required!r}"
                )
            return profile
        raise ValidationFailure(f"unknown deployment profile {name!r} for {self.name}")

    def kimi_definition(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.kimi_alias,
                "description": self.description,
                "parameters": self.arguments_schema,
                "strict": True,
            },
        }
