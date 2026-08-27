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
    owner_binding = "counterpedia:admission-supersession-binding:CP-EXAMPLE-0001:0001:0002"
    body.update(
        {
            "receipt_id": "activity-admission-event-v02-test-superseded-0001",
            "standing_act": "SUPERSEDED",
            "governed_result_ref": "urn:dagr:final-admission-decision:example-v02-successor-0002",
            "basis_refs": [predecessor, successor, owner_binding, "sha256:" + "4" * 64],
            "attestation_limits": [
                admission_event_v02.v01.ATTESTATION_LIMIT,
                admission_event_v02.SUPERSESSION_LIMIT,
            ],
            "extensions": {
                "supersession": {
                    "kind": "replacement_admission",
                    "predecessor_event_ref": predecessor,
                    "predecessor_event_core_digest": "sha256:" + "5" * 64,
                    "successor_event_ref": successor,
                    "successor_event_core_digest": "sha256:" + "6" * 64,
                    "successor_subject_record_ref": body["subject_record_ref"],
                    "successor_subject_edition_ref": "urn:counterpedia:record:CP-EXAMPLE-0001:edition:ED-0002",
                    "semantic_owner_binding_ref": owner_binding,
                    "semantic_owner_binding_digest": "sha256:" + "7" * 64,
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
    receipt["receipt_signature"]["signature"] = _b64url(private_key.sign(rfc8785.dumps(preimage)))
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
    assert report.profile_schema_digest is True
    assert report.profile is True
    assert report.supersession_binding is True
    assert report.authority_field_exclusion is True
    assert report.signature_valid is True


def test_valid_signed_superseded_v02_passes_all_axes() -> None:
    receipt, keyring, _ = _sign(_superseded_body())
    report = verify_admission_event_v0_2_receipt(receipt, keyring)
    assert report.passed is True
    assert report.failure_codes == []
    assert report.profile_schema_digest is True
    assert report.profile_schema_sha256.startswith("sha256:")
    assert report.supersession_binding is True


def test_vendored_profile_bytes_are_exact_source_blob() -> None:
    data = admission_event_v02.PROFILE_SCHEMA_PATH.read_bytes()
    assert admission_event_v02._git_blob_sha1(data) == admission_event_v02.PROFILE_SOURCE_BLOB_SHA1
    assert admission_event_v02.PROFILE_SOURCE_HEAD == "d2e0652b9e2f7b224dbaad042b53acede418b194"
    assert admission_event_v02.PROFILE_SOURCE_BLOB_SHA1 == "a91eb860688d4a449d0042174a55706e344a304a"


def test_post_signature_successor_event_mutation_fails_signature() -> None:
    receipt, keyring, _ = _sign(_superseded_body())
    receipt["extensions"]["supersession"]["successor_event_ref"] = "event:counterpedia:admission:CP-EXAMPLE-0001:9999"
    report = verify_admission_event_v0_2_receipt(receipt, keyring)
    assert report.passed is False
    assert report.signature_valid is False
    assert "signature_invalid" in report.failure_codes


def test_resigned_same_event_on_both_sides_fails_supersession_binding() -> None:
    body = _superseded_body()
    ext = body["extensions"]["supersession"]
    ext["successor_event_ref"] = ext["predecessor_event_ref"]
    body["basis_refs"] = [ext["predecessor_event_ref"], ext["semantic_owner_binding_ref"], "sha256:" + "4" * 64]
    receipt, keyring, _ = _sign(body)
    report = verify_admission_event_v0_2_receipt(receipt, keyring)
    assert report.signature_valid is True
    assert report.supersession_binding is False
    assert "admission_event_v02.supersession_same_event" in report.failure_codes


def test_resigned_same_edition_as_replacement_fails_supersession_binding() -> None:
    body = _superseded_body()
    body["extensions"]["supersession"]["successor_subject_edition_ref"] = body["subject_edition_ref"]
    receipt, keyring, _ = _sign(body)
    report = verify_admission_event_v0_2_receipt(receipt, keyring)
    assert report.signature_valid is True
    assert report.supersession_binding is False
    assert "admission_event_v02.supersession_same_edition" in report.failure_codes


def test_resigned_cross_record_successor_fails_independent_binding() -> None:
    body = _superseded_body()
    body["extensions"]["supersession"]["successor_subject_record_ref"] = "urn:counterpedia:record:OTHER"
    receipt, keyring, _ = _sign(body)
    report = verify_admission_event_v0_2_receipt(receipt, keyring)
    assert report.signature_valid is True
    assert report.profile is True
    assert report.supersession_binding is False
    assert "admission_event_v02.supersession_cross_record" in report.failure_codes


def test_resigned_missing_owner_binding_ref_from_basis_fails_binding() -> None:
    body = _superseded_body()
    owner_ref = body["extensions"]["supersession"]["semantic_owner_binding_ref"]
    body["basis_refs"].remove(owner_ref)
    receipt, keyring, _ = _sign(body)
    report = verify_admission_event_v0_2_receipt(receipt, keyring)
    assert report.signature_valid is True
    assert report.supersession_binding is False
    assert "admission_event_v02.semantic_owner_binding_ref_not_in_basis" in report.failure_codes


def test_nested_authority_field_smuggling_is_refused_even_when_resigned() -> None:
    body = _superseded_body()
    body["machine_limitations"].append({"code": "OTHER", "standing_score": 0.98})
    receipt, keyring, _ = _sign(body)
    report = verify_admission_event_v0_2_receipt(receipt, keyring)
    assert report.signature_valid is True
    assert report.authority_field_exclusion is False
    assert "authority_field.forbidden:standing_score" in report.failure_codes


def test_top_level_truth_or_authority_effect_is_refused_by_profile_and_verifier() -> None:
    for key in ("truth", "verified", "authority_effect"):
        body = _superseded_body()
        body[key] = True if key != "authority_effect" else "admitted"
        receipt, keyring, _ = _sign(body)
        report = verify_admission_event_v0_2_receipt(receipt, keyring)
        assert report.signature_valid is True
        assert report.profile is False, key
        assert report.authority_field_exclusion is False, key


def test_unregistered_extension_is_schema_failure() -> None:
    body = _superseded_body()
    body["extensions"]["note"] = {"harmless": "still-unregistered"}
    receipt, keyring, _ = _sign(body)
    report = verify_admission_event_v0_2_receipt(receipt, keyring)
    assert report.signature_valid is True
    assert report.profile is False


def test_resigned_retired_token_is_not_reinterpreted_as_superseded() -> None:
    body = _base_body()
    body["standing_act"] = "RETIRED"
    receipt, keyring, _ = _sign(body)
    report = verify_admission_event_v0_2_receipt(receipt, keyring)
    assert report.signature_valid is True
    assert report.profile is False


def test_raw_secret_smuggling_remains_refused() -> None:
    body = _superseded_body()
    body["machine_limitations"].append({"code": "OTHER", "access_token": "opaque-secret-material"})
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
