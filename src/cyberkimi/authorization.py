"""Ed25519 scope tokens, exact approvals, and single-use execution grants."""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, TypeVar

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel
from sqlalchemy import insert, select, update
from sqlalchemy.engine import Connection

from cyberkimi.audit import AuditStore
from cyberkimi.canonical import b64url_decode, b64url_encode, canonical_bytes, sha256_digest
from cyberkimi.errors import ApprovalRequired, AuthorizationError, GrantError
from cyberkimi.ids import new_id
from cyberkimi.models import (
    ApprovalRecord,
    Engagement,
    ExecutionGrant,
    ProposedAction,
    ScopeClaims,
    TaskSpec,
    ToolManifest,
)
from cyberkimi.persistence import Database, approvals, execution_grants, scope_tokens, tasks

T = TypeVar("T", bound=BaseModel)


class SigningKeyStore:
    def __init__(self, private_path: Path, public_path: Path):
        self.private_path = private_path
        self.public_path = public_path

    def ensure(self) -> None:
        self.private_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.private_path.exists() and self.public_path.exists():
            return
        private = Ed25519PrivateKey.generate()
        private_bytes = private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        public_bytes = private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self._atomic_secret_write(self.private_path, private_bytes, 0o600)
        self._atomic_secret_write(self.public_path, public_bytes, 0o644)

    @staticmethod
    def _atomic_secret_write(path: Path, content: bytes, mode: int) -> None:
        temporary = path.with_suffix(path.suffix + ".tmp")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        try:
            os.write(descriptor, content)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, path)
        os.chmod(path, mode)

    def private_key(self) -> Ed25519PrivateKey:
        self.ensure()
        key = serialization.load_pem_private_key(self.private_path.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise AuthorizationError("scope private key is not Ed25519")
        return key

    def public_key(self) -> Ed25519PublicKey:
        self.ensure()
        key = serialization.load_pem_public_key(self.public_path.read_bytes())
        if not isinstance(key, Ed25519PublicKey):
            raise AuthorizationError("scope public key is not Ed25519")
        return key


class SignedEnvelope:
    def __init__(self, keys: SigningKeyStore):
        self.keys = keys

    def sign(self, model: BaseModel) -> str:
        payload = canonical_bytes(model)
        signature = self.keys.private_key().sign(payload)
        return f"{b64url_encode(payload)}.{b64url_encode(signature)}"

    def verify(self, token: str, model_type: type[T]) -> T:
        try:
            payload_part, signature_part = token.split(".", maxsplit=1)
            payload = b64url_decode(payload_part)
            signature = b64url_decode(signature_part)
            self.keys.public_key().verify(signature, payload)
            return model_type.model_validate_json(payload)
        except Exception as exc:
            raise AuthorizationError("invalid signed envelope") from exc


class ScopeTokenService:
    def __init__(self, database: Database, audit: AuditStore, signer: SignedEnvelope):
        self.database = database
        self.audit = audit
        self.signer = signer

    def issue(
        self,
        engagement: Engagement,
        task: TaskSpec,
        asset_digests: dict[str, str],
        *,
        lifetime: timedelta = timedelta(hours=1),
    ) -> tuple[str, str]:
        if not engagement.active_at():
            raise AuthorizationError("engagement revision is not active")
        if task.engagement_id != engagement.engagement_id or task.engagement_revision != engagement.revision:
            raise AuthorizationError("task is not pinned to the engagement revision")
        now = datetime.now(timezone.utc)
        claims = ScopeClaims(
            engagement_id=engagement.engagement_id,
            engagement_revision=engagement.revision,
            task_id=task.task_id,
            asset_digests=asset_digests,
            allowed_effects=task.allowed_effects,
            risk_ceiling=task.risk_ceiling,
            iat=int(now.timestamp()),
            exp=int((now + lifetime).timestamp()),
            nonce=new_id("SCOPE"),
        )
        token = self.signer.sign(claims)
        digest = sha256_digest(token)
        with self.database.transaction() as connection:
            connection.execute(
                insert(scope_tokens).values(
                    token_digest=digest,
                    task_id=task.task_id,
                    token=token,
                    expires_at=now + lifetime,
                    revoked=False,
                )
            )
            connection.execute(
                insert(tasks).values(
                    task_id=task.task_id,
                    engagement_id=task.engagement_id,
                    engagement_revision=task.engagement_revision,
                    asset_id=task.asset_id,
                    mode=task.mode.value,
                    status=task.status,
                    task_json=task.model_dump_json(),
                    scope_token_digest=digest,
                    created_at=task.created_at,
                )
            )
            self.audit.append(
                engagement.engagement_id,
                "scope_token.issued",
                {"task_id": task.task_id, "token_digest": digest, "exp": claims.exp},
                connection=connection,
            )
        return token, digest

    def verify(
        self,
        token: str,
        expected_task: TaskSpec,
        expected_digest: str,
        *,
        now: datetime | None = None,
    ) -> ScopeClaims:
        claims = self.signer.verify(token, ScopeClaims)
        moment = now or datetime.now(timezone.utc)
        if claims.iss != "cyberkimi-scope-service" or claims.aud != "cyberkimi-control-plane":
            raise AuthorizationError("unexpected scope token issuer or audience")
        if claims.exp <= int(moment.timestamp()) or claims.iat > int(moment.timestamp()) + 30:
            raise AuthorizationError("scope token expired or not yet valid")
        digest = sha256_digest(token)
        if digest != expected_digest:
            raise AuthorizationError("scope token digest mismatch")
        if claims.task_id != expected_task.task_id:
            raise AuthorizationError("scope token task mismatch")
        if (
            claims.engagement_id != expected_task.engagement_id
            or claims.engagement_revision != expected_task.engagement_revision
        ):
            raise AuthorizationError("scope token engagement mismatch")
        if not expected_task.allowed_effects.issubset(claims.allowed_effects):
            raise AuthorizationError("scope token does not contain task effects")
        if expected_task.risk_ceiling > claims.risk_ceiling:
            raise AuthorizationError("scope token risk ceiling is insufficient")
        row = self.database.fetch_one(
            select(scope_tokens).where(scope_tokens.c.token_digest == expected_digest)
        )
        if row is None or bool(row["revoked"]):
            raise AuthorizationError("scope token is unknown or revoked")
        if str(row["task_id"]) != expected_task.task_id:
            raise AuthorizationError("stored scope token task mismatch")
        return claims


class ApprovalService:
    def __init__(self, database: Database, audit: AuditStore):
        self.database = database
        self.audit = audit

    def record(
        self,
        engagement_id: str,
        action_digest: str,
        actor_id: str,
        decision: str,
        *,
        expires_in: timedelta = timedelta(minutes=10),
        comment: str = "",
    ) -> ApprovalRecord:
        now = datetime.now(timezone.utc)
        record = ApprovalRecord(
            approval_id=new_id("APR"),
            action_digest=action_digest,
            actor_id=actor_id,
            decision="approved" if decision == "approved" else "denied",
            issued_at=now,
            expires_at=now + expires_in,
            comment=comment,
        )
        with self.database.transaction() as connection:
            connection.execute(
                insert(approvals).values(
                    approval_id=record.approval_id,
                    action_digest=record.action_digest,
                    decision=record.decision,
                    approval_json=record.model_dump_json(),
                    expires_at=record.expires_at,
                    consumed_at=None,
                )
            )
            self.audit.append(
                engagement_id,
                "approval.recorded",
                {
                    "approval_id": record.approval_id,
                    "action_digest": action_digest,
                    "decision": record.decision,
                    "actor_id": actor_id,
                },
                connection=connection,
            )
        return record

    def require_valid(
        self,
        action_digest: str,
        *,
        connection: Connection | None = None,
        consume: bool = False,
    ) -> ApprovalRecord:
        def load(tx: Connection) -> ApprovalRecord:
            row = tx.execute(
                select(approvals).where(approvals.c.action_digest == action_digest)
            ).mappings().first()
            if row is None:
                raise ApprovalRequired("exact action approval is missing")
            record = ApprovalRecord.model_validate_json(str(row["approval_json"]))
            now = datetime.now(timezone.utc)
            if record.decision != "approved" or record.expires_at <= now:
                raise ApprovalRequired("exact action approval is denied or expired")
            if row["consumed_at"] is not None:
                raise ApprovalRequired("exact action approval was already consumed")
            if consume:
                tx.execute(
                    update(approvals)
                    .where(
                        approvals.c.approval_id == record.approval_id,
                        approvals.c.consumed_at.is_(None),
                    )
                    .values(consumed_at=now)
                )
            return record

        if connection is not None:
            return load(connection)
        with self.database.transaction() as tx:
            return load(tx)


class GrantService:
    def __init__(self, database: Database, audit: AuditStore, signer: SignedEnvelope):
        self.database = database
        self.audit = audit
        self.signer = signer

    def mint(
        self,
        engagement_id: str,
        action: ProposedAction,
        action_digest: str,
        *,
        approval_id: str | None,
        lifetime: timedelta = timedelta(minutes=2),
        connection: Connection,
    ) -> tuple[str, ExecutionGrant]:
        now = datetime.now(timezone.utc)
        grant = ExecutionGrant(
            grant_id=new_id("GRANT"),
            action_digest=action_digest,
            tool_manifest_digest=action.tool_manifest_digest,
            asset_binding_digest=action.asset_binding_digest,
            operator_profile=action.operator_profile,
            budget_reservation_id=action.budget.reservation_id,
            approval_id=approval_id,
            iat=int(now.timestamp()),
            exp=int((now + lifetime).timestamp()),
            nonce=new_id("NONCE"),
        )
        token = self.signer.sign(grant)
        connection.execute(
            insert(execution_grants).values(
                grant_id=grant.grant_id,
                action_digest=grant.action_digest,
                nonce=grant.nonce,
                grant_token=token,
                expires_at=now + lifetime,
                consumed_at=None,
            )
        )
        self.audit.append(
            engagement_id,
            "execution_grant.minted",
            {
                "grant_id": grant.grant_id,
                "action_digest": action_digest,
                "approval_id": approval_id,
            },
            connection=connection,
        )
        return token, grant

    def verify_and_consume(
        self,
        token: str,
        expected_action: ProposedAction,
        expected_action_digest: str,
        *,
        engagement_id: str,
    ) -> ExecutionGrant:
        try:
            grant = self.signer.verify(token, ExecutionGrant)
        except AuthorizationError as exc:
            raise GrantError(str(exc)) from exc
        now = datetime.now(timezone.utc)
        if grant.exp <= int(now.timestamp()) or grant.iat > int(now.timestamp()) + 30:
            raise GrantError("execution grant expired or not yet valid")
        if grant.action_digest != expected_action_digest:
            raise GrantError("execution grant action mismatch")
        if grant.tool_manifest_digest != expected_action.tool_manifest_digest:
            raise GrantError("execution grant tool mismatch")
        if grant.asset_binding_digest != expected_action.asset_binding_digest:
            raise GrantError("execution grant asset mismatch")
        if grant.operator_profile != expected_action.operator_profile:
            raise GrantError("execution grant profile mismatch")
        with self.database.transaction() as connection:
            row = connection.execute(
                select(execution_grants).where(execution_grants.c.grant_id == grant.grant_id)
            ).mappings().first()
            if row is None or row["consumed_at"] is not None:
                raise GrantError("execution grant is unknown or already consumed")
            result = connection.execute(
                update(execution_grants)
                .where(
                    execution_grants.c.grant_id == grant.grant_id,
                    execution_grants.c.consumed_at.is_(None),
                )
                .values(consumed_at=now)
            )
            if result.rowcount != 1:
                raise GrantError("execution grant replay detected")
            self.audit.append(
                engagement_id,
                "execution_grant.consumed",
                {"grant_id": grant.grant_id, "action_digest": grant.action_digest},
                connection=connection,
            )
        return grant


def action_digest(
    engagement: Engagement,
    task: TaskSpec,
    action: ProposedAction,
    tool: ToolManifest,
) -> str:
    return sha256_digest(
        {
            "engagement_id": engagement.engagement_id,
            "engagement_revision": engagement.revision,
            "scope_token_digest": action.scope_token_digest,
            "task_id": task.task_id,
            "subtask_id": action.subtask_id,
            "tool_name": tool.name,
            "tool_version": tool.version,
            "tool_manifest_digest": action.tool_manifest_digest,
            "asset_id": action.asset_id,
            "asset_binding_digest": action.asset_binding_digest,
            "arguments": action.arguments,
            "requested_effects": sorted(action.requested_effects),
            "risk_tier": action.risk_tier.name,
            "budget_reservation": action.budget,
            "operator_profile": action.operator_profile,
        }
    )
