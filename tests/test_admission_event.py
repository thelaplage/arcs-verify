from __future__ import annotations

import ast
import base64
import copy
import inspect

import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import arcs_verify.admission_event as admission_event
from arcs_verify.admission_event import verify_admission_event_receipt


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _receipt_body() -> dict:
    return {
        "receipt_version": "srs.core.v5.1",
        "profile_id": "srs.activity.admission_event",
        "profile_version": "v0.1",
        "receipt_id": "activity-admission-event-test-0001",
        "receipt_type": "provenance",
        "receipt_kind": "admission_event",
        "boundary_type": "admission_event_boundary",
        "protocol_binding": "counterpedia-admission-chain",
        "subject_ref": "urn:counterpedia:record:CP-EXAMPLE-0001:edition:ED-0001",
        "issuer_id": "issuer.test/admission-event/2026-08",
        "runtime_instance_id": "runtime-admission-event-test-0001",
        "boundary_id": "boundary-admission-event-0001",
        "issued_at": "2026-08-27T04:30:00Z",
        "visibility": "PRIVATE_ORG",
        "namespace_authority_ref": "urn:counterpedia:authority:operator:test",
        "subject_record_ref": "urn:counterpedia:record:CP-EXAMPLE-0001",
        "subject_edition_ref": "urn:counterpedia:record:CP-EXAMPLE-0001:edition:ED-0001",
        "standing_act": "ADMITTED",
        "governed_result_ref": "urn:dagr:final-admission-decision:example-0001",
        "governed_result_digest": "sha256:" + "1" * 64,
        "policy_profile_ref": "urn:dagr:policy:institutional-admission:v0.1",
        "policy_digest": "sha256:" + "2" * 64,
        "disposition_id": "disposition:institutional-admission:example-0001",
        "disposition_digest": "sha256:" + "3" * 64,
        "basis_refs": [
            "sha256:" + "4" * 64,
            "0123456789abcdef0123456789abcdef01234567",
        ],
        "artifact_classes_covered": [
            "admission_event_record",
            "subject_edition_identity",
            "governed_result_identity",
            "policy_identity",
        ],
        "artifact_classes_excluded": [
            "subject_content_bytes",
            "evidence_content_bytes",
            "universal_truth",
            "downstream_reliance",
        ],
        "attestation_limits": [admission_event.ATTESTATION_LIMIT],
        "machine_limitations": [{"code": "CONTENT_NOT_VERIFIED"}],
        "extensions": {},
    }


def _sign(body: dict, *, private_key: Ed25519PrivateKey | None = None):
    private_key = private_key or Ed25519PrivateKey.generate()
    receipt = copy.deepcopy(body)
    receipt["receipt_signature"] = {
        "algorithm": "Ed25519",
        "canonicalization": "RFC8785-JCS",
        "key_id": "key.test/admission-event/1",
        "signature": "",
    }
    preimage = copy.deepcopy(receipt)
    del preimage["receipt_signature"]["signature"]
    receipt["receipt_signature"]["signature"] = _b64url(
        private_key.sign(rfc8785.dumps(preimage))
    )
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    keyring = {
        "trust_bundle_version": "srs.trust_bundle.v0.1",
        "issuers": [
            {
                "issuer_id": body["issuer_id"],
                "key_id": "key.test/admission-event/1",
                "algorithm": "Ed25519",
                "public_key": _b64url(public_key),
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2027-01-01T00:00:00Z",
                "trusted": True,
            }
        ],
    }
    return receipt, keyring, private_key


def test_valid_signed_admission_event_passes_all_axes() -> None:
    receipt, keyring, _ = _sign(_receipt_body())
    report = verify_admission_event_receipt(receipt, keyring)
    assert report.passed is True
    assert report.failure_codes == []
    assert report.envelope is True
    assert report.profile is True
    assert report.signature_valid is True
    assert report.issuer_key_resolved is True
    assert report.issuer_key_trusted is True


def test_governed_result_digest_mutation_after_signing_fails() -> None:
    receipt, keyring, _ = _sign(_receipt_body())
    receipt["governed_result_digest"] = "sha256:" + "9" * 64
    report = verify_admission_event_receipt(receipt, keyring)
    assert report.passed is False
    assert report.signature_valid is False
    assert "signature_invalid" in report.failure_codes


def test_standing_act_mutation_after_signing_fails_even_if_new_value_is_valid() -> None:
    receipt, keyring, _ = _sign(_receipt_body())
    receipt["standing_act"] = "REFUSED"
    report = verify_admission_event_receipt(receipt, keyring)
    assert report.passed is False
    assert report.profile is True
    assert report.signature_valid is False
    assert "signature_invalid" in report.failure_codes


def test_resigned_invalid_standing_act_is_profile_failure() -> None:
    body = _receipt_body()
    body["standing_act"] = "admitted"
    receipt, keyring, _ = _sign(body)
    report = verify_admission_event_receipt(receipt, keyring)
    assert report.passed is False
    assert report.signature_valid is True
    assert report.profile is False
    assert "admission_event.invalid_standing_act" in report.failure_codes


def test_resigned_subject_edition_mismatch_is_profile_failure() -> None:
    body = _receipt_body()
    body["subject_ref"] = "urn:counterpedia:record:CP-EXAMPLE-0001:edition:ED-OTHER"
    receipt, keyring, _ = _sign(body)
    report = verify_admission_event_receipt(receipt, keyring)
    assert report.passed is False
    assert report.signature_valid is True
    assert report.profile is False
    assert "admission_event.subject_binding_mismatch" in report.failure_codes


def test_resigned_aggregate_field_is_rejected() -> None:
    body = _receipt_body()
    body["standing_score"] = 1.0
    receipt, keyring, _ = _sign(body)
    report = verify_admission_event_receipt(receipt, keyring)
    assert report.passed is False
    assert report.signature_valid is True
    assert report.profile is False
    assert "admission_event.aggregate_field_present" in report.failure_codes


def test_wrong_issuer_for_resolved_key_is_not_trusted() -> None:
    receipt, keyring, _ = _sign(_receipt_body())
    keyring["issuers"][0]["issuer_id"] = "issuer.test/not-the-emitter"
    report = verify_admission_event_receipt(receipt, keyring)
    assert report.passed is False
    assert report.issuer_key_resolved is True
    assert report.signature_valid is True
    assert report.issuer_key_trusted is False
    assert "key_untrusted" in report.failure_codes


def test_verifier_imports_no_dagr_producer_or_runtime_code() -> None:
    tree = ast.parse(inspect.getsource(admission_event))
    imported: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module)
    assert not [name for name in imported if name == "dagr" or name.startswith("dagr_")]
    assert not [name for name in imported if name.startswith("dagr_runtime")]
    assert not [name for name in imported if name.startswith("dagr_mcp")]


def test_profile_source_head_is_exact_arcs_srs_pr52_head() -> None:
    assert admission_event.PROFILE_SOURCE_HEAD == "ac7b04feb390c99055bd265157ef616ecb7ff9dc"
