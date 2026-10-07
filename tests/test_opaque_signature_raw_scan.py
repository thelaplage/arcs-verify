from __future__ import annotations

from arcs_verify.verifier import (
    _contains_prohibited_value,
    _raw_content_scan_view,
    _walk,
)


def _prohibited_paths(receipt: dict) -> list[str]:
    projected = _raw_content_scan_view(receipt)
    paths: list[str] = []

    def walk(value, path="$"):
        if isinstance(value, dict):
            for key, item in value.items():
                if isinstance(item, str) and _contains_prohibited_value(item):
                    paths.append(f"{path}.{key}")
                walk(item, f"{path}.{key}")
        elif isinstance(value, list):
            for index, item in enumerate(value):
                walk(item, f"{path}[{index}]")

    walk(projected)
    return paths


def test_opaque_signature_bytes_are_not_raw_content() -> None:
    receipt = {
        "receipt_kind": "outcome",
        "extensions": {"note": "safe"},
        "receipt_signature": {
            "algorithm": "Ed25519",
            "canonicalization": "RFC8785-JCS",
            "key_id": "urn:key:test",
            "signature": "abcsk-ABCDEFGHIJKLMNxyz",
        },
    }

    assert _prohibited_paths(receipt) == []


def test_semantic_secret_like_value_still_fails() -> None:
    receipt = {
        "receipt_kind": "outcome",
        "extensions": {"note": "sk-ABCDEFGHIJKLMN"},
        "receipt_signature": {
            "algorithm": "Ed25519",
            "canonicalization": "RFC8785-JCS",
            "key_id": "urn:key:test",
            "signature": "opaque",
        },
    }

    assert _prohibited_paths(receipt) == ["$.extensions.note"]


def test_projection_does_not_mutate_signed_receipt() -> None:
    receipt = {
        "receipt_signature": {
            "algorithm": "Ed25519",
            "canonicalization": "RFC8785-JCS",
            "key_id": "urn:key:test",
            "signature": "abcsk-ABCDEFGHIJKLMNxyz",
        }
    }

    projected = _raw_content_scan_view(receipt)

    assert receipt["receipt_signature"]["signature"] == "abcsk-ABCDEFGHIJKLMNxyz"
    assert projected["receipt_signature"]["signature"] == "<opaque-ed25519-signature-bytes>"
