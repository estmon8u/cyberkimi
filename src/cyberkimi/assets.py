"""Immutable asset registration, path safety, and endpoint pinning."""

from __future__ import annotations

import hashlib
import ipaddress
import os
import socket
import stat
import subprocess
from pathlib import Path
from typing import Any

from sqlalchemy import insert, select

from cyberkimi.audit import AuditStore
from cyberkimi.canonical import sha256_bytes, sha256_digest
from cyberkimi.errors import AuthorizationError, ValidationFailure
from cyberkimi.models import Asset, AssetBinding, AssetKind, EndpointBinding, Engagement
from cyberkimi.persistence import Database, assets

MAX_BINDING_FILES = 100_000
MAX_BINDING_BYTES = 1_000_000_000


def _git_output(root: Path, *args: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), *args],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
            env={"PATH": os.environ.get("PATH", "")},
        )
    except (FileNotFoundError, subprocess.SubprocessError):
        return None
    return result.stdout.strip()


def directory_digest(root: Path) -> str:
    """Hash a bounded local tree without following escaping symlinks."""

    root = root.resolve(strict=True)
    digest = hashlib.sha256()
    file_count = 0
    byte_count = 0
    for path in sorted(root.rglob("*"), key=lambda p: p.as_posix()):
        try:
            relative = path.relative_to(root)
            info = path.lstat()
        except (OSError, ValueError) as exc:
            raise ValidationFailure(f"cannot inspect {path}: {exc}") from exc
        if relative.parts and relative.parts[0] in {".git", ".cyberkimi"}:
            continue
        if stat.S_ISLNK(info.st_mode):
            target = path.resolve(strict=False)
            try:
                target.relative_to(root)
            except ValueError as exc:
                raise ValidationFailure(f"symlink escapes registered root: {relative}") from exc
            digest.update(f"L\0{relative.as_posix()}\0{os.readlink(path)}\0".encode())
            continue
        if path.is_dir():
            digest.update(f"D\0{relative.as_posix()}\0".encode())
            continue
        if not path.is_file():
            raise ValidationFailure(f"unsupported filesystem entry: {relative}")
        file_count += 1
        byte_count += info.st_size
        if file_count > MAX_BINDING_FILES or byte_count > MAX_BINDING_BYTES:
            raise ValidationFailure("asset exceeds binding limits")
        digest.update(f"F\0{relative.as_posix()}\0{info.st_size}\0".encode())
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def build_binding(root: Path, kind: AssetKind) -> AssetBinding:
    root = root.resolve(strict=True)
    if kind is AssetKind.REPOSITORY:
        commit = _git_output(root, "rev-parse", "HEAD")
        status = _git_output(root, "status", "--porcelain=v1", "-z")
        dirty_digest = sha256_bytes(status.encode()) if status else None
        return AssetBinding(
            git_commit=commit,
            dirty_tree_digest=dirty_digest,
            content_digest=directory_digest(root),
        )
    if kind is AssetKind.DOCKER_COMPOSE_LAB:
        data = root.read_bytes() if root.is_file() else b""
        return AssetBinding(compose_digest=sha256_bytes(data), content_digest=sha256_bytes(data))
    if root.is_file():
        return AssetBinding(content_digest=sha256_bytes(root.read_bytes()))
    return AssetBinding(content_digest=directory_digest(root))


def asset_binding_digest(asset: Asset) -> str:
    return sha256_digest(
        {
            "asset_id": asset.asset_id,
            "kind": asset.kind,
            "locator_type": asset.locator_type,
            "canonical_locator": asset.canonical_locator,
            "binding": asset.binding,
            "allowed_effects": sorted(asset.allowed_effects),
            "data_classification": asset.data_classification,
            "endpoint_allowlist": asset.endpoint_allowlist,
        }
    )


def safe_resolve(root: Path, relative_path: str, *, require_file: bool = True) -> Path:
    if "\x00" in relative_path:
        raise ValidationFailure("NUL byte in path")
    requested = Path(relative_path)
    if requested.is_absolute() or ".." in requested.parts:
        raise ValidationFailure("path must be a relative path beneath the registered root")
    resolved_root = root.resolve(strict=True)
    resolved = (resolved_root / requested).resolve(strict=True)
    try:
        resolved.relative_to(resolved_root)
    except ValueError as exc:
        raise ValidationFailure("path escapes registered root") from exc
    info = resolved.stat()
    if stat.S_ISSOCK(info.st_mode) or stat.S_ISCHR(info.st_mode) or stat.S_ISBLK(info.st_mode):
        raise ValidationFailure("device and socket files are forbidden")
    if require_file and not resolved.is_file():
        raise ValidationFailure("requested path is not a regular file")
    return resolved


def endpoint_url(endpoint: EndpointBinding, path: str = "/") -> str:
    if not path.startswith("/") or ".." in Path(path).parts:
        raise ValidationFailure("endpoint path must be absolute and traversal-free")
    host = endpoint.host or endpoint.service
    assert host is not None
    prefix = endpoint.path_prefix.rstrip("/")
    suffix = path if path.startswith("/") else f"/{path}"
    return f"{endpoint.scheme}://{host}:{endpoint.port}{prefix}{suffix}"


def validate_endpoint_resolution(endpoint: EndpointBinding) -> tuple[str, ...]:
    host = endpoint.host
    if host is None:
        # Compose service DNS is isolated to the registered lab network and is resolved by the lab operator.
        return endpoint.pinned_ips
    try:
        infos = socket.getaddrinfo(host, endpoint.port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValidationFailure(f"cannot resolve registered endpoint {host}: {exc}") from exc
    addresses = sorted({info[4][0] for info in infos})
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not (ip.is_loopback or ip.is_private or ip.is_link_local):
            raise ValidationFailure(f"public endpoint forbidden in v0.1: {address}")
    if endpoint.pinned_ips and set(addresses) != set(endpoint.pinned_ips):
        raise AuthorizationError("endpoint DNS result differs from immutable pin set")
    return tuple(addresses)


class AssetRegistry:
    def __init__(self, database: Database, audit: AuditStore):
        self.database = database
        self.audit = audit

    def register_engagement_assets(self, engagement: Engagement) -> None:
        with self.database.transaction() as connection:
            for asset in engagement.assets:
                existing = connection.execute(
                    select(assets.c.asset_json).where(assets.c.asset_id == asset.asset_id)
                ).first()
                if existing is not None:
                    raise ValidationFailure(f"asset ID is immutable and already exists: {asset.asset_id}")
                canonical = Path(asset.canonical_locator).resolve(strict=True)
                if str(canonical) != asset.canonical_locator:
                    raise ValidationFailure(
                        f"asset locator must already be canonical: {asset.canonical_locator}"
                    )
                actual = build_binding(canonical, asset.kind)
                if actual != asset.binding:
                    raise ValidationFailure(f"asset binding mismatch: {asset.asset_id}")
                connection.execute(
                    insert(assets).values(
                        asset_id=asset.asset_id,
                        engagement_id=engagement.engagement_id,
                        engagement_revision=engagement.revision,
                        kind=asset.kind.value,
                        binding_digest=asset_binding_digest(asset),
                        asset_json=asset.model_dump_json(),
                        status=asset.status,
                    )
                )
                self.audit.append(
                    engagement.engagement_id,
                    "asset.registered",
                    {
                        "asset_id": asset.asset_id,
                        "engagement_revision": engagement.revision,
                        "binding_digest": asset_binding_digest(asset),
                    },
                    connection=connection,
                )

    def get(self, asset_id: str) -> Asset:
        row = self.database.fetch_one(select(assets).where(assets.c.asset_id == asset_id))
        if row is None:
            raise KeyError(asset_id)
        return Asset.model_validate_json(str(row["asset_json"]))

    def verify_binding(self, asset: Asset) -> str:
        canonical = Path(asset.canonical_locator).resolve(strict=True)
        actual = build_binding(canonical, asset.kind)
        if actual != asset.binding:
            raise AuthorizationError(f"asset content binding changed: {asset.asset_id}")
        return asset_binding_digest(asset)
