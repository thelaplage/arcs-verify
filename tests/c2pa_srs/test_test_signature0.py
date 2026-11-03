"""SIGVERIFY0: constructed crypto vectors; NOT a real producer replay.

The real producer-to-verifier test will supply a SIGN0 artifact and public key
as separately retained bytes. This file imports no producer implementation.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json

import pytest
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from arcs_verify.c2pa_test_signature0 import (
    APPROVED_UNSIGNED_SHA256,
    TEST_ISSUER,
    TEST_KEY_ID_PREFIX,
    TestReceiverKey,
    verify_test_signed_observation,
)


def constructed_signed_test():
    """SYNTHETIC crypto fixture, not a C2PA observed-side or issuer proof."""
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    key_id = TEST_KEY_ID_PREFIX + hashlib.sha256(public).hexdigest()
    doc = {
        "receipt_version": "srs.core.v5.1",
        "profile_id": "srs.c2pa.validation_observation",
        "profile_version": "v0.1",
        "issuer_id": TEST_ISSUER,
        "receipt_id": "test-provisional-only",
        "native_validation_state": "Invalid",
        "extensions": {
            "dagr_ingest_test_signature0": {
                "original_observation_sha256": "sha256:" + sorted(APPROVED_UNSIGNED_SHA256)[0],
                "issuer_status": "test_non_operational",
                "key_scope": "ephemeral_memory_only",
            },
            "unrecognized_signed_extension": {"proof": "synthetic"},
        },
        "receipt_signature": {
            "algorithm": "Ed25519", "canonicalization": "RFC8785-JCS",
            "key_id": key_id,
        },
    }
    signature = key.sign(rfc8785.dumps(doc))
    doc["receipt_signature"]["signature"] = base64.urlsafe_b64encode(signature).decode().rstrip("=")
    return doc, public


def wire(doc) -> bytes:
    return rfc8785.dumps(doc)


def trust(key: bytes, *, trusted: bool, issuer: str = TEST_ISSUER):
    return {TEST_KEY_ID_PREFIX + hashlib.sha256(key).hexdigest(): TestReceiverKey(issuer_id=issuer, public_key_raw=key, trusted_for_test=trusted)}


def test_valid_signature_only_under_an_explicitly_selected_test_key():
    doc, public = constructed_signed_test()
    result = verify_test_signed_observation(wire(doc), selected_test_keys=trust(public, trusted=True)).as_dict()
    assert (result["signature_valid"], result["issuer_key_resolved"], result["issuer_key_trusted"]) == ("pass", "pass", "pass")
    assert result["failure_codes"] == []
    assert result["scope"] == "offline_non_operational_test_only"
    assert result["issuer_standing"] == "not_evaluated"
    assert result["content_truth"] == "not_evaluated"
    assert result["native_c2pa_signer_trust"] == "not_evaluated"
    assert result["independent_tsa_trust"] == "not_evaluated"
    assert result["operational_issuance"] == "not_authorized"


def test_crypto_validity_key_resolution_and_key_trust_are_separate():
    doc, public = constructed_signed_test()
    unknown = verify_test_signed_observation(wire(doc), selected_test_keys={})
    assert (unknown.signature_valid, unknown.issuer_key_resolved, unknown.issuer_key_trusted) == ("not_evaluated", "fail", "not_evaluated")
    assert unknown.failure_codes == ("key_id_unresolved",)
    untrusted = verify_test_signed_observation(wire(doc), selected_test_keys=trust(public, trusted=False))
    assert (untrusted.signature_valid, untrusted.issuer_key_resolved, untrusted.issuer_key_trusted) == ("pass", "pass", "fail")
    wrong_issuer = verify_test_signed_observation(wire(doc), selected_test_keys=trust(public, trusted=True, issuer="other"))
    assert (wrong_issuer.signature_valid, wrong_issuer.issuer_key_resolved, wrong_issuer.issuer_key_trusted) == ("pass", "pass", "fail")


def test_wrong_key_is_not_signature_validity_or_issuer_trust():
    doc, _ = constructed_signed_test()
    other = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    declared_id = doc["receipt_signature"]["key_id"]
    selected = {declared_id: TestReceiverKey(issuer_id=TEST_ISSUER, public_key_raw=other, trusted_for_test=True)}
    result = verify_test_signed_observation(wire(doc), selected_test_keys=selected)
    assert result.signature_valid == "not_evaluated"
    assert result.issuer_key_resolved == "fail"
    assert "key_id_public_key_mismatch" in result.failure_codes


@pytest.mark.parametrize("mutation", [
    lambda d: d.update(receipt_id="substituted"),
    lambda d: d["extensions"].update(unrecognized_signed_extension={"proof": "tampered"}),
    lambda d: d["extensions"].pop("unrecognized_signed_extension"),
    lambda d: d["receipt_signature"].update(signature="A" * 86),
])
def test_semantic_change_or_invalid_signature_never_passes(mutation):
    doc, public = constructed_signed_test()
    mutation(doc)
    result = verify_test_signed_observation(wire(doc), selected_test_keys=trust(public, trusted=True))
    assert result.signature_valid != "pass"
    assert result.failure_codes


def test_key_id_mutation_fails_before_cryptographic_verification():
    doc, public = constructed_signed_test()
    doc["receipt_signature"]["key_id"] = "issuer.production/some-key"
    result = verify_test_signed_observation(wire(doc), selected_test_keys=trust(public, trusted=True))
    assert result.signature_valid == "not_evaluated"
    assert result.failure_codes == ("signature_object_invalid",)


def test_reformatted_json_has_the_same_jcs_signed_preimage():
    doc, public = constructed_signed_test()
    pretty = json.dumps(doc, indent=4, sort_keys=False).encode("utf-8")
    result = verify_test_signed_observation(pretty, selected_test_keys=trust(public, trusted=True))
    assert result.signature_valid == "pass"


def test_unknown_test_provenance_does_not_pass_even_with_valid_crypto():
    doc, public = constructed_signed_test()
    doc["extensions"]["dagr_ingest_test_signature0"]["original_observation_sha256"] = "sha256:" + "0" * 64
    result = verify_test_signed_observation(wire(doc), selected_test_keys=trust(public, trusted=True))
    assert result.signature_valid == "not_evaluated"
    assert result.failure_codes == ("test_provenance_not_admitted",)


def test_missing_or_unauthorized_key_cannot_trigger_network_resolution(monkeypatch):
    import socket
    def no_network(*args, **kwargs):
        raise AssertionError("unexpected network access")
    monkeypatch.setattr(socket, "socket", no_network)
    doc, _ = constructed_signed_test()
    result = verify_test_signed_observation(wire(doc), selected_test_keys={})
    assert result.issuer_key_resolved == "fail"
