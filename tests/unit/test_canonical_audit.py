from __future__ import annotations

from cyberkimi.canonical import canonical_text, sha256_digest


def test_canonical_json_is_order_independent() -> None:
    left = {"b": [2, 1], "a": {"z": True}}
    right = {"a": {"z": True}, "b": [2, 1]}
    assert canonical_text(left) == canonical_text(right)
    assert sha256_digest(left) == sha256_digest(right)
    assert sha256_digest({"effects": frozenset({"b", "a"})}) == sha256_digest(
        {"effects": frozenset({"a", "b"})}
    )


def test_audit_chain_verifies(runtime: dict[str, object]) -> None:
    audit = runtime["audit"]
    ok, detail = audit.verify("ENG-TEST")  # type: ignore[attr-defined]
    assert ok, detail
    assert audit.count("ENG-TEST") >= 2  # type: ignore[attr-defined]
