from __future__ import annotations

import ast
import base64
import copy
import inspect

import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import arcs_verify.admission_event_v0_2 as admission_event_v02
from arcs_verify.admission_event_v0_2 import verify_admission_event_v0_2_receipt


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _base_body() -> dict:
    return {
        "receipt_version": "srs.core.v5.1",
        "profile_id": "srs.activity.admission_event",
        "profile_version": "v0.2",
        "receipt_id": "activity-admission-event-v02-test-0001",
        "receipt_type": "provenance",
        "receipt_kind": "admission_event",
        "boundary_type": "admission_event_boundary",
        "protocol_binding": "counterpedia-admission-chain",
        "subject_ref": "urn:counterpedia:record:CP-EXAMPLE-0001:edition:ED-0001",
        "issuer_id": "issuer.test/admission-event/2026-08",
        "runtime_instance_id": "runtime-admission-event-v02-test-0001",
        "boundary_id": "boundary-admission-event-v02-test-0001",
        "issued_at": "2026-08-27T05:30:00Z",
        "visibility": "PRIVATE_ORG",
        "namespace_authority_ref": "urn:counterpedia:authority:operator:test",
        "subject_record_ref": "urn:counterpedia:record:CP-EXAMPLE-0001",
        "subject_edition_ref": "urn:counterpedia:record:CP-EXAMPLE-0001:edition:ED-0001",
        "standing_act": "ADMITTED",
        "governed_result_ref": "urn:dagr:final-admission-decision:example-v02-0001",
        "governed_result_digest": "sha256:" + "1" * 64,
        "policy_profile_ref": "urn:dagr:policy:institutional-admission:v0.1",
        "policy_digest": "sha256:" + "2" * 64,
        "disposition_id": "disposition:institutional-admission:example-v02-0001",
        "disposition_digest": "sha256:" + "3" * 64,
        "basis_refs": ["sha256:" + "4" * 64],
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
        "attestation_limits": [admission_event_v02.v01.ATTESTATION_LIMIT],
        "machine_limitations": [{"code": "CONTENT_NOT_VERIFIED"}],
        "extensions": {},
    }


def _superseded_body() -> dict:
    body = _base_body()
    predecessor = "event:counterpedia:admission:CP-EXAMPLE-0001:0001"
    successor = "event:counterpedia:admission:CP-EXAMPLE-0001:0002"
    body.update(
        {
            "receipt_id": "activity-admission-event-v02-test-superseded-0001",
            "standing_act": "SUPERSEDED",
            "governed_result_ref": "urn:dagr:final-admission-decision:example-v02-successor-0002",
            "basis_refs": [predecessor, successor, "sha256:" + "4" * 64],
            "attestation_limits": [
                admission_event_v02.v01.ATTESTATION_LIMIT,
                admission_event_v02.SUPERSESSION_LIMIT,
            ],
            "extensions": {
                "supersession": {
                    "kind": "replacement_admission",
                    "predecessor_event_ref": predecessor,
                    "predecessor_event_digest": "sha256:" + "5" * 64,
                    "successor_event_ref": successor,
                    "successor_event_digest": "sha256:" + "6" * 64,
                    "successor_subject_edition_ref": "urn:counterpedia:record:CP-EXAMPLE-0001:edition:ED-0002",
                }
            },
        }
    )
    return body


def _sign(body: dict, *, private_key: Ed25519PrivateKey | None = None):
    private_key = private_key or Ed25519PrivateKey.generate()
    receipt = copy.deepcopy(body)
    receipt["receipt_signature"] = {
        "algorithm": "Ed25519",
        "canonicalization": "RFC8785-JCS",
        "key_id": "key.test/admission-event-v02/1",
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
                "key_id": "key.test/admission-event-v02/1",
                "algorithm": "Ed25519",
                "public_key": _b64url(public_key),
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2027-01-01T00:00:00Z",
                "trusted": True,
            }
        ],
    }
    return receipt, keyring, private_key


def test_valid_signed_admitted_v02_passes_without_supersession_extension() -> None:
    receipt, keyring, _ = _sign(_base_body())
    report = verify_admission_event_v0_2_receipt(receipt, keyring)
    assert report.passed is True
    assert report.profile is True
    assert report.supersession_binding is True
    assert report.signature_valid is True


def test_valid_signed_superseded_v02_passes_all_axes() -> None:
    receipt, keyring, _ = _sign(_superseded_body())
    report = verify_admission_event_v0_2_receipt(receipt, keyring)
    assert report.passed is True
    assert report.failure_codes == []
    assert report.profile is True
    assert report.supersession_binding is True
    assert report.attestation_limits_present is True
    assert report.signature_valid is True


def test_post_signature_successor_event_mutation_fails_signature() -> None:
    receipt, keyring, _ = _sign(_superseded_body())
    receipt["extensions"]["supersession"]["successor_event_ref"] = (
        "event:counterpedia:admission:CP-EXAMPLE-0001:9999"
    )
    report = verify_admission_event_v0_2_receipt(receipt, keyring)
    assert report.passed is False
    assert report.signature_valid is False
    assert "signature_invalid" in report.failure_codes


def test_resigned_same_event_on_both_sides_fails_supersession_binding() -> None:
    body = _superseded_body()
    ext = body["extensions"]["supersession"]
    ext["successor_event_ref"] = ext["predecessor_event_ref"]
    body["basis_refs"] = [ext["predecessor_event_ref"], "sha256:" + "4" * 64]
    receipt, keyring, _ = _sign(body)
    report = verify_admission_event_v0_2_receipt(receipt, keyring)
    assert report.signature_valid is True
    assert report.profile is True
    assert report.supersession_binding is False
    assert "admission_event_v02.supersession_same_event" in report.failure_codes


def test_resigned_same_edition_as_replacement_fails_supersession_binding() -> None:
    body = _superseded_body()
    body["extensions"]["supersession"]["successor_subject_edition_ref"] = body[
        "subject_edition_ref"
    ]
    receipt, keyring, _ = _sign(body)
    report = verify_admission_event_v0_2_receipt(receipt, keyring)
    assert report.signature_valid is True
    assert report.profile is True
    assert report.supersession_binding is False
    assert "admission_event_v02.supersession_same_edition" in report.failure_codes


def test_resigned_missing_successor_ref_from_basis_fails_binding() -> None:
    body = _superseded_body()
    successor = body["extensions"]["supersession"]["successor_event_ref"]
    body["basis_refs"].remove(successor)
    receipt, keyring, _ = _sign(body)
    report = verify_admission_event_v0_2_receipt(receipt, keyring)
    assert report.signature_valid is True
    assert report.profile is True
    assert report.supersession_binding is False
    assert "admission_event_v02.successor_ref_not_in_basis" in report.failure_codes


def test_resigned_admitted_with_supersession_extension_is_profile_failure() -> None:
    body = _base_body()
    body["extensions"] = copy.deepcopy(_superseded_body()["extensions"])
    receipt, keyring, _ = _sign(body)
    report = verify_admission_event_v0_2_receipt(receipt, keyring)
    assert report.signature_valid is True
    assert report.profile is False
    assert report.supersession_binding is False
    assert "admission_event_v02.supersession_extension_wrong_act" in report.failure_codes


def test_resigned_retired_token_is_not_reinterpreted_as_superseded() -> None:
    body = _base_body()
    body["standing_act"] = "RETIRED"
    receipt, keyring, _ = _sign(body)
    report = verify_admission_event_v0_2_receipt(receipt, keyring)
    assert report.signature_valid is True
    assert report.profile is False
    assert "admission_event_v02.invalid_standing_act" in report.failure_codes


def test_resigned_supersession_without_retirement_boundary_limit_fails() -> None:
    body = _superseded_body()
    body["attestation_limits"] = [admission_event_v02.v01.ATTESTATION_LIMIT]
    receipt, keyring, _ = _sign(body)
    report = verify_admission_event_v0_2_receipt(receipt, keyring)
    assert report.signature_valid is True
    assert report.attestation_limits_present is False
    assert "attestation.missing_required_limit" in report.failure_codes


def test_raw_secret_smuggling_inside_supersession_extension_is_refused() -> None:
    body = _superseded_body()
    body["extensions"]["note"] = {"access_token": "opaque-secret-material"}
    receipt, keyring, _ = _sign(body)
    report = verify_admission_event_v0_2_receipt(receipt, keyring)
    assert report.signature_valid is True
    assert report.raw_content_exclusion is False
    assert "raw_content.forbidden_key:access_token" in report.failure_codes


def test_v02_verifier_imports_no_producer_runtime() -> None:
    tree = ast.parse(inspect.getsource(admission_event_v02))
    imported: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module)
    assert not [name for name in imported if name.startswith("dagr_runtime")]
    assert not [name for name in imported if name.startswith("dagr_mcp")]
    assert not [name for name in imported if name.startswith("counterpedia")]


def test_v02_profile_source_is_exact_arcs_srs_pr53_schema_blob() -> None:
    assert admission_event_v02.PROFILE_SOURCE_HEAD == "b276945eed5fb83a6eb08df09d122da62a59cc60"
    assert admission_event_v02.PROFILE_SOURCE_BLOB_SHA1 == "7338dbbe161ac4454b0454d27713efbc52079dc0"
