"""HARDEN0-P1: receiver-side source binding and receipt identity.

Constructed receipts only. The source bytes are the genuine frozen unsigned
observations already retained in this repository, so the source finding is
exercised against real bytes without importing any producer implementation.
"""
from __future__ import annotations

import base64
import copy
import hashlib
from pathlib import Path

import pytest
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from arcs_verify.c2pa_test_signature0 import (
    TEST_ISSUER,
    TEST_KEY_ID_PREFIX,
    TEST_RECEIPT_ID_PREFIX,
    TestReceiverKey,
    verify_test_signed_observation,
)

PRODUCED = Path(__file__).resolve().parent / "produced"
SPECIMENS = ("positive", "negative_native_invalid_exit0", "negative_remote_manifest_missing")


def source_bytes(name: str) -> bytes:
    return (PRODUCED / name / "observation.json").read_bytes()


def digest_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def new_key() -> tuple[Ed25519PrivateKey, bytes, str]:
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return key, public, hashlib.sha256(public).hexdigest()


def receipt_id_for(declared_digest: str, key_fingerprint: str) -> str:
    return TEST_RECEIPT_ID_PREFIX + declared_digest[-16:] + "-" + key_fingerprint[:16]


def build_receipt(declared: str, key_fingerprint: str, receipt_id: str | None = None) -> dict:
    doc = {
        "receipt_version": "srs.core.v5.1",
        "profile_id": "srs.c2pa.validation_observation",
        "profile_version": "v0.1",
        "issuer_id": TEST_ISSUER,
        "receipt_id": receipt_id if receipt_id is not None else receipt_id_for(declared[7:], key_fingerprint),
        "native_validation_state": "Invalid",
        "extensions": {
            "dagr_ingest_test_signature0": {
                "original_observation_sha256": declared,
                "issuer_status": "test_non_operational",
                "key_scope": "ephemeral_memory_only",
            },
        },
        "receipt_signature": {
            "algorithm": "Ed25519",
            "canonicalization": "RFC8785-JCS",
            "key_id": TEST_KEY_ID_PREFIX + key_fingerprint,
        },
    }
    return doc


def sign(doc: dict, key: Ed25519PrivateKey) -> bytes:
    signed = copy.deepcopy(doc)
    signed["receipt_signature"]["signature"] = base64.urlsafe_b64encode(
        key.sign(rfc8785.dumps(signed))
    ).decode("ascii").rstrip("=")
    return rfc8785.dumps(signed)


def selected(public: bytes, *, trusted: bool = True) -> dict:
    key_id = TEST_KEY_ID_PREFIX + hashlib.sha256(public).hexdigest()
    return {key_id: TestReceiverKey(issuer_id=TEST_ISSUER, public_key_raw=public, trusted_for_test=trusted)}


def fixture(name: str = "positive"):
    data = source_bytes(name)
    declared = "sha256:" + digest_of(data)
    key, public, fingerprint = new_key()
    doc = build_receipt(declared, fingerprint)
    return sign(doc, key), public, data


def test_genuine_source_bytes_and_identity_both_pass():
    wire, public, data = fixture()
    result = verify_test_signed_observation(wire, selected_test_keys=selected(public), source_bytes=data)
    assert result.signature_valid == "pass"
    assert result.source_integrity == "pass"
    assert result.receipt_identity == "pass"
    assert result.source_failure_codes == ()
    assert result.identity_failure_codes == ()
    assert result.supplied_source_sha256 == "sha256:" + digest_of(data)
    assert result.as_dict()["scope"] == "offline_non_operational_test_only"


def test_declared_hash_alone_never_establishes_source_or_identity():
    wire, public, _ = fixture()
    result = verify_test_signed_observation(wire, selected_test_keys=selected(public))
    assert result.signature_valid == "pass"
    assert result.source_integrity == "not_evaluated"
    assert result.source_failure_codes == ("source_bytes_missing",)
    assert result.receipt_identity == "not_evaluated"
    assert result.identity_failure_codes == ("receipt_identity_unverified",)
    assert result.supplied_source_sha256 is None


def test_substituted_source_bytes_are_refused_without_affecting_signature():
    wire, public, _ = fixture("positive")
    other = source_bytes("negative_remote_manifest_missing")
    result = verify_test_signed_observation(wire, selected_test_keys=selected(public), source_bytes=other)
    assert result.signature_valid == "pass"
    assert result.source_integrity == "fail"
    assert result.source_failure_codes == ("source_digest_mismatch",)
    assert result.receipt_identity == "not_evaluated"
    assert result.identity_failure_codes == ("receipt_identity_unverified",)


def test_single_modified_source_byte_is_refused():
    wire, public, data = fixture()
    modified = bytearray(data)
    modified[len(modified) // 2] ^= 0x01
    result = verify_test_signed_observation(
        wire, selected_test_keys=selected(public), source_bytes=bytes(modified),
    )
    assert result.signature_valid == "pass"
    assert result.source_integrity == "fail"
    assert result.source_failure_codes == ("source_digest_mismatch",)


@pytest.mark.parametrize("receipt_id", [
    "test-provisional-only",
    TEST_RECEIPT_ID_PREFIX + "ZZZZ",
    TEST_RECEIPT_ID_PREFIX + "0" * 16,
    "",
])
def test_malformed_identity_is_refused_even_when_the_signature_is_valid(receipt_id):
    data = source_bytes("positive")
    declared = "sha256:" + digest_of(data)
    key, public, fingerprint = new_key()
    wire = sign(build_receipt(declared, fingerprint, receipt_id=receipt_id), key)
    result = verify_test_signed_observation(wire, selected_test_keys=selected(public), source_bytes=data)
    assert result.signature_valid == "pass"
    assert result.source_integrity == "pass"
    assert result.receipt_identity == "fail"
    assert "receipt_id_malformed" in result.identity_failure_codes


def test_missing_identity_is_refused():
    data = source_bytes("positive")
    declared = "sha256:" + digest_of(data)
    key, public, fingerprint = new_key()
    doc = build_receipt(declared, fingerprint)
    del doc["receipt_id"]
    wire = sign(doc, key)
    result = verify_test_signed_observation(wire, selected_test_keys=selected(public), source_bytes=data)
    assert result.signature_valid == "pass"
    assert result.receipt_identity == "fail"
    assert result.identity_failure_codes == ("receipt_id_malformed",)


def test_validly_resigned_receipt_with_substituted_identity_is_refused():
    data = source_bytes("negative_native_invalid_exit0")
    declared = "sha256:" + digest_of(data)
    key, public, fingerprint = new_key()
    _, _, other_fingerprint = new_key()
    substituted = receipt_id_for(declared[7:], other_fingerprint)
    wire = sign(build_receipt(declared, fingerprint, receipt_id=substituted), key)
    result = verify_test_signed_observation(wire, selected_test_keys=selected(public), source_bytes=data)
    assert result.signature_valid == "pass"
    assert result.source_integrity == "pass"
    assert result.receipt_identity == "fail"
    assert result.identity_failure_codes == ("receipt_id_mismatch",)


def test_identity_requires_the_selected_key_fingerprint():
    """The id must carry the receiver-selected fingerprint, not just any fingerprint."""
    data = source_bytes("positive")
    declared = "sha256:" + digest_of(data)
    key, public, fingerprint = new_key()
    unrelated = new_key()[2]
    wire = sign(
        build_receipt(declared, fingerprint, receipt_id=receipt_id_for(declared[7:], unrelated)), key,
    )
    result = verify_test_signed_observation(wire, selected_test_keys=selected(public), source_bytes=data)
    assert result.signature_valid == "pass"
    assert result.source_integrity == "pass"
    assert result.receipt_identity == "fail"
    assert result.identity_failure_codes == ("receipt_id_mismatch",)

    # A mapping that resolves the declared key id to different bytes never reaches
    # the identity check at all: the key binding is refused first.
    other_public = new_key()[1]
    mismatched = verify_test_signed_observation(
        wire,
        selected_test_keys={
            TEST_KEY_ID_PREFIX + hashlib.sha256(public).hexdigest(): TestReceiverKey(
                issuer_id=TEST_ISSUER, public_key_raw=other_public, trusted_for_test=True,
            )
        },
        source_bytes=data,
    )
    assert mismatched.signature_valid == "not_evaluated"
    assert "key_id_public_key_mismatch" in mismatched.failure_codes
    assert mismatched.receipt_identity == "not_evaluated"
    assert mismatched.identity_failure_codes == ("receipt_identity_unverified",)


def test_validly_resigned_receipt_bound_to_the_wrong_source_is_refused():
    genuine = source_bytes("positive")
    other = source_bytes("negative_native_invalid_exit0")
    declared = "sha256:" + digest_of(genuine)
    key, public, fingerprint = new_key()
    wire = sign(
        build_receipt(declared, fingerprint, receipt_id=receipt_id_for(digest_of(other), fingerprint)), key,
    )
    result = verify_test_signed_observation(wire, selected_test_keys=selected(public), source_bytes=genuine)
    assert result.signature_valid == "pass"
    assert result.source_integrity == "pass"
    assert result.receipt_identity == "fail"
    assert result.identity_failure_codes == ("receipt_id_mismatch",)


def test_bytes_matching_an_unapproved_reference_are_refused():
    """Byte consistency is not admission: the reference must be a frozen digest."""
    data = b'{"not": "an approved frozen specimen"}'
    declared = "sha256:" + digest_of(data)
    key, public, fingerprint = new_key()
    wire = sign(
        build_receipt(declared, fingerprint, receipt_id=receipt_id_for(declared[7:], fingerprint)), key,
    )
    result = verify_test_signed_observation(wire, selected_test_keys=selected(public), source_bytes=data)
    assert result.signature_valid == "not_evaluated"
    assert result.failure_codes == ("test_provenance_not_admitted",)
    assert result.source_integrity == "fail"
    assert result.source_failure_codes == ("source_not_admitted",)


def test_source_pass_is_independent_of_admission_and_signature():
    """Matching bytes and an admitted reference do not depend on profile admission."""
    data = source_bytes("positive")
    declared = "sha256:" + digest_of(data)
    key, public, fingerprint = new_key()
    doc = build_receipt(declared, fingerprint)
    doc["profile_version"] = "v9"
    wire = sign(doc, key)
    result = verify_test_signed_observation(wire, selected_test_keys=selected(public), source_bytes=data)
    assert result.signature_valid == "not_evaluated"
    assert result.source_integrity == "pass"
    assert result.source_failure_codes == ()
    assert result.receipt_identity == "not_evaluated"


def test_unknown_provenance_still_reports_source_and_identity_states():
    data = source_bytes("positive")
    key, public, fingerprint = new_key()
    wire = sign(build_receipt("sha256:" + "0" * 64, fingerprint, receipt_id=receipt_id_for("0" * 64, fingerprint)), key)
    result = verify_test_signed_observation(wire, selected_test_keys=selected(public), source_bytes=data)
    assert result.signature_valid == "not_evaluated"
    assert result.failure_codes == ("test_provenance_not_admitted",)
    assert result.source_integrity == "fail"
    assert result.source_failure_codes == ("source_digest_mismatch",)
    assert result.receipt_identity == "not_evaluated"
    assert result.identity_failure_codes == ("receipt_identity_unverified",)
