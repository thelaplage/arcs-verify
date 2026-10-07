from __future__ import annotations

from arcs_verify.verifier import _raw_content_errors


def _receipt(signature: str, **extra):
    value = {
        "receipt_signature": {
            "algorithm": "Ed25519",
            "canonicalization": "RFC8785-JCS",
            "key_id": "urn:test:key:1",
            "signature": signature,
        }
    }
    value.update(extra)
    return value


def test_raw_content_scan_ignores_token_shaped_opaque_signature_bytes() -> None:
    receipt = _receipt("AAAsk-ABCDEFGHIJKLMNopaqueSignatureBytes")
    assert _raw_content_errors(receipt) == []


def test_raw_content_scan_still_rejects_same_token_in_semantic_field() -> None:
    receipt = _receipt(
        "opaque-signature",
        extensions={"note": "sk-ABCDEFGHIJKLMN"},
    )
    assert "raw_content.prohibited_value" in _raw_content_errors(receipt)


def test_raw_content_scan_still_rejects_private_path_outside_signature() -> None:
    receipt = _receipt(
        "opaque-signature",
        extensions={"note": "/Users/example/private-source"},
    )
    assert "raw_content.prohibited_value" in _raw_content_errors(receipt)
