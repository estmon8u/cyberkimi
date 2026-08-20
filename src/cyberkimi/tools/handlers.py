from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Callable

import yaml

from cyberkimi.evidence.models import HandlerOutput
from cyberkimi.evidence.redaction import extract_secrets, redact_text
from cyberkimi.errors import ToolExecutionError, ValidationFailure


Handler = Callable[[Path, dict[str, Any]], HandlerOutput]


class HandlerRegistry:
    def __init__(self) -> None:
        self._handlers: dict[str, Handler] = {
            "repository.read": repository_read,
            "repository.search": repository_search,
            "source.secret_scan": secret_scan,
            "dependency.extract": dependency_extract,
            "logs.parse": logs_parse,
            "lab.inventory": lab_inventory,
            "lab.evaluate_security_property": lab_property,
        }

    def require(self, name: str) -> Handler:
        handler = self._handlers.get(name)
        if handler is None:
            raise ToolExecutionError(f"no deterministic handler registered for {name}")
        return handler


def repository_read(root: Path, arguments: dict[str, Any]) -> HandlerOutput:
    path = _contained(root, str(arguments["path"]))
    if not path.is_file():
        raise ToolExecutionError(f"repository file does not exist: {arguments['path']}")
    start = int(arguments.get("start_line", 1))
    end = int(arguments.get("end_line", start + 199))
    if end < start or end - start > 500:
        raise ValidationFailure("repository.read is limited to 501 lines")
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    selected = [
        {"line": number, "text": lines[number - 1]}
        for number in range(start, min(end, len(lines)) + 1)
    ]
    payload = {"path": str(path.relative_to(root)), "start_line": start, "end_line": end, "lines": selected}
    return _output(payload, "source_excerpt", "source_location", f"Read {len(selected)} bounded source lines")


def repository_search(root: Path, arguments: dict[str, Any]) -> HandlerOutput:
    query = str(arguments["query"])
    maximum = int(arguments.get("max_results", 50))
    results: list[dict[str, Any]] = []
    lowered = query.lower()
    for path in _iter_text_files(root):
        for line_number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if lowered in line.lower():
                cleaned, _ = redact_text(line[:1000], redact_pii=False)
                results.append(
                    {
                        "path": str(path.relative_to(root)),
                        "line": line_number,
                        "excerpt": cleaned,
                    }
                )
                if len(results) >= maximum:
                    break
        if len(results) >= maximum:
            break
    payload = {"query": query, "result_count": len(results), "results": results}
    return _output(payload, "source_search", "source_location", f"Found {len(results)} bounded matches")


def secret_scan(root: Path, arguments: dict[str, Any]) -> HandlerOutput:
    maximum = int(arguments.get("max_results", 200))
    findings: list[dict[str, Any]] = []
    raw_matches: list[dict[str, Any]] = []
    for path in _iter_text_files(root):
        for line_number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            for secret_type, value in extract_secrets(line):
                fingerprint = _sha256(value)
                cleaned, _ = redact_text(line[:1000], redact_pii=False)
                findings.append(
                    {
                        "path": str(path.relative_to(root)),
                        "line": line_number,
                        "secret_type": secret_type,
                        "secret_fingerprint": fingerprint,
                        "excerpt": cleaned,
                    }
                )
                raw_matches.append(
                    {
                        "path": str(path.relative_to(root)),
                        "line": line_number,
                        "secret_type": secret_type,
                        **{secret_type: value},
                    }
                )
                if len(findings) >= maximum:
                    break
            if len(findings) >= maximum:
                break
        if len(findings) >= maximum:
            break
    raw = json.dumps({"matches": raw_matches}, sort_keys=True).encode()
    normalized = {"result_count": len(findings), "results": findings}
    return HandlerOutput(
        raw=raw,
        normalized=normalized,
        evidence_type="secret_scan",
        evidence_class="secret_pattern_match",
        summary=f"Detected {len(findings)} candidate assigned secrets",
    )


def dependency_extract(root: Path, arguments: dict[str, Any]) -> HandlerOutput:
    dependencies: list[dict[str, str]] = []
    requirements = root / str(arguments.get("path", "requirements.txt"))
    if requirements.is_file():
        for line in requirements.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            match = re.match(r"^([A-Za-z0-9_.-]+)\s*(?:==|~=|>=|<=|>|<)?\s*([^;\s]+)?", line)
            if match:
                dependencies.append({"name": match.group(1), "version": match.group(2) or "unbounded", "ecosystem": "PyPI"})
    payload = {"record_count": len(dependencies), "dependencies": dependencies}
    return _output(payload, "dependency_inventory", "dependency_record", f"Extracted {len(dependencies)} dependency records")


def logs_parse(root: Path, arguments: dict[str, Any]) -> HandlerOutput:
    source = root if root.is_file() else _contained(root, str(arguments.get("path", "events.jsonl")))
    if not source.is_file():
        raise ToolExecutionError("declared log source does not exist")
    events: list[dict[str, Any]] = []
    maximum = int(arguments.get("max_events", 1000))
    for index, line in enumerate(source.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
            event = value if isinstance(value, dict) else {"value": value}
        except json.JSONDecodeError:
            event = {"message": line}
        event["source_line"] = index
        events.append(event)
        if len(events) >= maximum:
            break
    events.sort(key=lambda item: str(item.get("timestamp", "")))
    payload = {"event_count": len(events), "events": events}
    return _output(payload, "normalized_log_events", "timeline_event", f"Normalized {len(events)} log events")


def lab_inventory(root: Path, arguments: dict[str, Any]) -> HandlerOutput:
    compose = root if root.is_file() else _contained(root, str(arguments.get("compose_file", "compose.yaml")))
    if not compose.is_file():
        raise ToolExecutionError("declared compose file does not exist")
    payload_yaml = yaml.safe_load(compose.read_text(encoding="utf-8")) or {}
    services = payload_yaml.get("services", {}) if isinstance(payload_yaml, dict) else {}
    inventory = [
        {"service": str(name), "image": str(value.get("image", "")) if isinstance(value, dict) else ""}
        for name, value in sorted(services.items())
    ]
    payload = {"service_count": len(inventory), "services": inventory}
    return _output(payload, "lab_inventory", "runtime_inventory", f"Inventoried {len(inventory)} declared services")


def lab_property(root: Path, arguments: dict[str, Any]) -> HandlerOutput:
    template = str(arguments["template"])
    if template != "service_running":
        raise ToolExecutionError(
            "compact v0.1 supports only the predefined service_running property; no arbitrary network request is accepted"
        )
    inventory = lab_inventory(root, {"compose_file": arguments.get("compose_file", "compose.yaml")})
    service = str(arguments["service"])
    names = {item["service"] for item in inventory.normalized["services"]}
    payload = {
        "template": template,
        "service": service,
        "property_satisfied": service in names,
        "basis": "declared_compose_inventory",
    }
    return _output(payload, "security_property_result", "deterministic_property", f"Evaluated predefined property {template}")


def _contained(root: Path, relative: str) -> Path:
    base = root.resolve()
    candidate = Path(relative)
    if candidate.is_absolute():
        raise ToolExecutionError("absolute paths are not accepted by typed repository tools")
    resolved = (base / candidate).resolve()
    if not resolved.is_relative_to(base):
        raise ToolExecutionError("path escaped the declared asset")
    return resolved


def _iter_text_files(root: Path):
    for path in sorted(root.rglob("*")):
        if not path.is_file() or ".git" in path.parts:
            continue
        try:
            if path.stat().st_size > 1_000_000:
                continue
            sample = path.read_bytes()[:4096]
        except OSError:
            continue
        if b"\x00" in sample:
            continue
        yield path


def _output(payload: dict[str, Any], evidence_type: str, evidence_class: str, summary: str) -> HandlerOutput:
    return HandlerOutput(
        raw=json.dumps(payload, sort_keys=True, default=str).encode(),
        normalized=payload,
        evidence_type=evidence_type,
        evidence_class=evidence_class,
        summary=summary,
    )


def _sha256(value: str) -> str:
    import hashlib
    return hashlib.sha256(value.encode()).hexdigest()
