from __future__ import annotations

import base64
import copy
import hashlib
import json

import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from arcs_verify.dagr_authority_context_producer import (
    PRODUCER_IMPLEMENTATION_REF,
    verify_dagr_authority_context_producer_receipt,
)

ARTIFACT_BYTES = (
    '{"authority_context_digest":"sha256:3c09cff6da82d296a07d2e748468ec33e552f1e75178ceebe1af6b563bfadc3e",'
    '"authority_profile_ref":"approver","authority_provenance":{"authority_source_ref":"github:thelaplage/dagr-runtime#78:review-comment:5463723050:owner-ratification:2026-08-29",'
    '"effective_from":"2026-08-29T17:05:43Z","genesis_digest":"sha256:46b453d61d15946163b7b58336bbeceed4092e867910b6ff56fe1129338b9dc8",'
    '"genesis_id":"dagr-merit-operator-authority-v0.1","status":"active","supporting_review_ref":"github:thelaplage/dagr-runtime#77"},'
    '"authority_source":"operator_authority_profile","domain":"action","operator_identity_ref":"operator:thelaplage",'
    '"review_roles":["approver","auditor"],"schema":"dagr.resolved-authority-context/v0.1",'
    '"transaction_digest":"sha256:2c307edb0f07dc837d9b845392d3247167ecf82a09ff611aeaea2d9ba55d6877",'
    '"transaction_id":"transaction:external-harness:fixture:001"}'
).encode("utf-8")
KEY_ID = "did:key:test-dagr-authority-context-producer-surface"


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _receipt() -> dict:
    artifact = json.loads(ARTIFACT_BYTES)
    provenance = artifact["authority_provenance"]
    return {
        "receipt_version": "srs.core.v5.1",
        "profile_id": "dagr.authority_context_producer.v1",
        "profile_version": "v1.0",
        "receipt_id": "srs:receipt:authority-context-producer:surface:001",
        "receipt_type": "provenance",
        "receipt_kind": "authority_context_producer",
        "boundary_type": "artifact_emission",
        "protocol_binding": "dagr-runtime",
        "subject_ref": "artifact:authority-context:surface:001",
        "subject_ref_origin": "binding_minted",
        "issuer_id": "dagr-runtime",
        "runtime_instance_id": "runtime:surface:001",
        "issued_at": "2026-08-31T20:00:00Z",
        "artifact_classes_covered": ["dagr.resolved-authority-context/v0.1"],
        "artifact_classes_excluded": [
            "governed_genesis_raw_bytes",
            "countervail_authorization",
            "execution_result",
            "receiver_custody",
        ],
        "attestation_limits": [
            "attests producer claim over exact artifact bytes and declared DAGR identities only",
            "does not independently establish same-genesis binding",
            "does not establish action permission or Countervail authorization",
            "does not establish execution or receiver custody",
            "signature validity alone does not establish signer trust",
        ],
        "extensions": {
            "dagr.authority_context_producer.context_schema": artifact["schema"],
            "dagr.authority_context_producer.context_digest": artifact["authority_context_digest"],
            "dagr.authority_context_producer.artifact_sha256": (
                "sha256:" + hashlib.sha256(ARTIFACT_BYTES).hexdigest()
            ),
            "dagr.authority_context_producer.artifact_media_type": "application/json",
            "dagr.authority_context_producer.transaction_id": artifact["transaction_id"],
            "dagr.authority_context_producer.transaction_digest": artifact["transaction_digest"],
            "dagr.authority_context_producer.genesis_id": provenance["genesis_id"],
            "dagr.authority_context_producer.genesis_digest": provenance["genesis_digest"],
            "dagr.authority_context_producer.producer_implementation_ref": PRODUCER_IMPLEMENTATION_REF,
        },
    }


def _signed_verify(receipt: dict):
    private = Ed25519PrivateKey.generate()
    value = copy.deepcopy(receipt)
    value["receipt_signature"] = {
        "algorithm": "Ed25519",
        "canonicalization": "RFC8785-JCS",
        "key_id": KEY_ID,
    }
    value["receipt_signature"]["signature"] = _b64url(
        private.sign(rfc8785.dumps(value))
    )
    receipt_bytes = json.dumps(
        value, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    keyring = {
        "issuers": [
            {
                "key_id": KEY_ID,
                "issuer_id": "dagr-runtime",
                "public_key": _b64url(public),
                "trusted": True,
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2027-01-01T00:00:00Z",
            }
        ]
    }
    return verify_dagr_authority_context_producer_receipt(
        receipt_bytes=receipt_bytes,
        context_artifact_bytes=ARTIFACT_BYTES,
        keyring=keyring,
    )


def test_resigned_extra_top_level_decision_is_rejected() -> None:
    receipt = _receipt()
    receipt["decision"] = "ALLOW"
    report = _signed_verify(receipt)
    assert report.signature_valid is True
    assert report.profile_binding is False
    assert report.producer_authorship_established is False
    assert "profile.top_level_surface_mismatch" in report.failure_codes
    assert "profile.prohibited_claim_key:decision" in report.failure_codes


def test_resigned_extra_covered_authorization_class_is_rejected() -> None:
    receipt = _receipt()
    receipt["artifact_classes_covered"].append("countervail_authorization")
    report = _signed_verify(receipt)
    assert report.signature_valid is True
    assert report.attestation_limits is False
    assert report.producer_authorship_established is False
    assert "attestation.exact_surface_mismatch" in report.failure_codes


def test_resigned_stronger_attestation_limit_is_rejected() -> None:
    receipt = _receipt()
    receipt["attestation_limits"].append("this receipt authorizes execution")
    report = _signed_verify(receipt)
    assert report.signature_valid is True
    assert report.attestation_limits is False
    assert report.producer_authorship_established is False
    assert "attestation.exact_surface_mismatch" in report.failure_codes


def test_representative_exact_surface_still_passes() -> None:
    report = _signed_verify(_receipt())
    assert report.profile_binding is True
    assert report.attestation_limits is True
    assert report.signature_valid is True
    assert report.issuer_key_trusted is True
    assert report.producer_authorship_established is True
    assert report.failure_codes == []
