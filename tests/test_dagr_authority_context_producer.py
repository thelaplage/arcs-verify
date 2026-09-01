from __future__ import annotations

import ast
import base64
import copy
import hashlib
import inspect
import json
from importlib.resources import files

import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import arcs_verify.dagr_authority_context_producer as verifier
from arcs_verify.dagr_authority_context_producer import (
    DAGR_EXTENSION_SCHEMA_SHA256,
    DAGR_PROFILE_DECLARATION_SHA256,
    EXTERNAL_PROFILE_SCHEMA_SHA256,
    PRODUCER_IMPLEMENTATION_REF,
    SRS_ENVELOPE_SHA256,
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
ARTIFACT_SHA = "sha256:462a5aa10ed54ce53b71dc6b35155e11e3b02c2c0662fcfaf5d6857548b3c93c"
CONTEXT_DIGEST = "sha256:3c09cff6da82d296a07d2e748468ec33e552f1e75178ceebe1af6b563bfadc3e"
GENESIS_DIGEST = "sha256:46b453d61d15946163b7b58336bbeceed4092e867910b6ff56fe1129338b9dc8"
KEY_ID = "did:key:test-dagr-authority-context-producer"


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _context_digest(value: dict) -> str:
    provenance = value["authority_provenance"]
    preimage = (
        "DAGR-RESOLVED-AUTHORITY-CONTEXT-V0.1\n"
        f"schema={value['schema']}\n"
        f"domain={value['domain']}\n"
        f"transaction_id={value['transaction_id']}\n"
        f"transaction_digest={value['transaction_digest']}\n"
        f"operator_identity_ref={value['operator_identity_ref']}\n"
        f"authority_profile_ref={value['authority_profile_ref']}\n"
        f"review_role_count={len(value['review_roles'])}\n"
    )
    for index, role in enumerate(value["review_roles"]):
        preimage += f"review_role_{index}={role}\n"
    preimage += (
        f"authority_source={value['authority_source']}\n"
        f"authority_genesis_id={provenance['genesis_id']}\n"
        f"authority_genesis_digest={provenance['genesis_digest']}\n"
        f"authority_genesis_status={provenance['status']}\n"
        f"authority_effective_from={provenance['effective_from']}\n"
        f"authority_source_ref={provenance['authority_source_ref']}\n"
        f"supporting_review_ref={provenance['supporting_review_ref']}\n"
    )
    return "sha256:" + hashlib.sha256(preimage.encode()).hexdigest()


def _receipt_for_artifact(artifact_bytes: bytes = ARTIFACT_BYTES) -> dict:
    artifact = json.loads(artifact_bytes)
    provenance = artifact["authority_provenance"]
    return {
        "receipt_version": "srs.core.v5.1",
        "profile_id": "dagr.authority_context_producer.v1",
        "profile_version": "v1.0",
        "receipt_id": "srs:receipt:authority-context-producer:test:001",
        "receipt_type": "provenance",
        "receipt_kind": "authority_context_producer",
        "boundary_type": "artifact_emission",
        "protocol_binding": "dagr-runtime",
        "subject_ref": "artifact:authority-context:test:001",
        "subject_ref_origin": "binding_minted",
        "issuer_id": "dagr-runtime",
        "runtime_instance_id": "runtime:test:001",
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
            "dagr.authority_context_producer.artifact_sha256": "sha256:" + hashlib.sha256(artifact_bytes).hexdigest(),
            "dagr.authority_context_producer.artifact_media_type": "application/json",
            "dagr.authority_context_producer.transaction_id": artifact["transaction_id"],
            "dagr.authority_context_producer.transaction_digest": artifact["transaction_digest"],
            "dagr.authority_context_producer.genesis_id": provenance["genesis_id"],
            "dagr.authority_context_producer.genesis_digest": provenance["genesis_digest"],
            "dagr.authority_context_producer.producer_implementation_ref": PRODUCER_IMPLEMENTATION_REF,
        },
    }


def _sign(receipt: dict, private_key: Ed25519PrivateKey) -> bytes:
    value = copy.deepcopy(receipt)
    value["receipt_signature"] = {
        "algorithm": "Ed25519",
        "canonicalization": "RFC8785-JCS",
        "key_id": KEY_ID,
    }
    signature = private_key.sign(rfc8785.dumps(value))
    value["receipt_signature"]["signature"] = _b64url(signature)
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _keyring(private_key: Ed25519PrivateKey, *, trusted: bool = True) -> dict:
    public = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return {
        "issuers": [
            {
                "key_id": KEY_ID,
                "issuer_id": "dagr-runtime",
                "public_key": _b64url(public),
                "trusted": trusted,
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2027-01-01T00:00:00Z",
            }
        ]
    }


def _verify(
    *,
    artifact_bytes: bytes = ARTIFACT_BYTES,
    receipt: dict | None = None,
    trusted: bool = True,
):
    private = Ed25519PrivateKey.generate()
    receipt_bytes = _sign(receipt or _receipt_for_artifact(artifact_bytes), private)
    return verify_dagr_authority_context_producer_receipt(
        receipt_bytes=receipt_bytes,
        context_artifact_bytes=artifact_bytes,
        keyring=_keyring(private, trusted=trusted),
    )


def test_pinned_contract_bytes_are_exact() -> None:
    data = files("arcs_verify").joinpath("data")
    assert hashlib.sha256(data.joinpath("srs-envelope-v0.2.1-e487.schema.json").read_bytes()).hexdigest() == SRS_ENVELOPE_SHA256
    assert hashlib.sha256(data.joinpath("srs-external-profile-declaration-e487.schema.json").read_bytes()).hexdigest() == EXTERNAL_PROFILE_SCHEMA_SHA256
    assert hashlib.sha256(data.joinpath("dagr-authority-context-producer-cb2760.profile.json").read_bytes()).hexdigest() == DAGR_PROFILE_DECLARATION_SHA256
    assert hashlib.sha256(data.joinpath("dagr-authority-context-producer-cb2760.extensions.schema.json").read_bytes()).hexdigest() == DAGR_EXTENSION_SCHEMA_SHA256


def test_representative_trusted_signed_receipt_establishes_narrow_authorship_only() -> None:
    assert "sha256:" + hashlib.sha256(ARTIFACT_BYTES).hexdigest() == ARTIFACT_SHA
    assert _context_digest(json.loads(ARTIFACT_BYTES)) == CONTEXT_DIGEST
    report = _verify()
    assert report.passed is True
    assert report.producer_authorship_established is True
    assert report.signature_valid is True
    assert report.issuer_key_trusted is True
    assert report.artifact_digest is True
    assert report.projection_binding is True
    assert report.failure_codes == []
    projection = report.to_dict()
    assert projection["same_genesis_binding"] == "not_evaluated"
    assert projection["action_permission"] == "not_evaluated"
    assert projection["countervail_authorization"] == "not_evaluated"
    assert projection["execution"] == "not_evaluated"
    assert projection["receiver_custody"] == "not_evaluated"
    assert projection["truth"] == "not_evaluated"


def test_valid_signature_with_untrusted_key_keeps_axes_separate() -> None:
    report = _verify(trusted=False)
    assert report.signature_valid is True
    assert report.issuer_key_resolved is True
    assert report.issuer_key_trusted is False
    assert report.producer_authorship_established is False
    assert "key_untrusted" in report.failure_codes


def test_exact_artifact_serialization_change_fails_even_when_semantic_digest_is_same() -> None:
    private = Ed25519PrivateKey.generate()
    receipt_bytes = _sign(_receipt_for_artifact(ARTIFACT_BYTES), private)
    changed = ARTIFACT_BYTES + b"\n"
    assert json.loads(changed)["authority_context_digest"] == CONTEXT_DIGEST
    report = verify_dagr_authority_context_producer_receipt(
        receipt_bytes=receipt_bytes,
        context_artifact_bytes=changed,
        keyring=_keyring(private),
    )
    assert report.context_digest is True
    assert report.artifact_digest is False
    assert report.producer_authorship_established is False
    assert "artifact.digest_mismatch" in report.failure_codes


def test_transaction_projection_mismatch_fails_with_fresh_valid_signature() -> None:
    receipt = _receipt_for_artifact()
    receipt["extensions"]["dagr.authority_context_producer.transaction_id"] = "transaction:other:001"
    report = _verify(receipt=receipt)
    assert report.signature_valid is True
    assert report.extension_schema is True
    assert report.artifact_digest is True
    assert report.projection_binding is False
    assert report.producer_authorship_established is False
    assert "artifact.projection_mismatch" in report.failure_codes


def test_genesis_projection_mismatch_fails_with_fresh_valid_signature() -> None:
    receipt = _receipt_for_artifact()
    receipt["extensions"]["dagr.authority_context_producer.genesis_digest"] = "sha256:" + "a" * 64
    report = _verify(receipt=receipt)
    assert report.signature_valid is True
    assert report.extension_schema is True
    assert report.projection_binding is False
    assert report.producer_authorship_established is False


def test_wrong_producer_implementation_ref_fails_profile_extension() -> None:
    receipt = _receipt_for_artifact()
    receipt["extensions"]["dagr.authority_context_producer.producer_implementation_ref"] = "github:thelaplage/dagr-runtime@" + "0" * 40
    report = _verify(receipt=receipt)
    assert report.signature_valid is True
    assert report.extension_schema is False
    assert report.producer_authorship_established is False
    assert "extensions.schema_invalid" in report.failure_codes


def test_authorship_can_pass_for_context_that_independent_same_genesis_would_reject() -> None:
    context = json.loads(ARTIFACT_BYTES)
    context["operator_identity_ref"] = "operator:attacker"
    context["authority_context_digest"] = _context_digest(context)
    altered = json.dumps(context, sort_keys=True, separators=(",", ":")).encode()
    report = _verify(artifact_bytes=altered)
    assert report.context_schema is True
    assert report.context_digest is True
    assert report.projection_binding is True
    assert report.producer_authorship_established is True
    assert report.to_dict()["same_genesis_binding"] == "not_evaluated"


def test_missing_or_invalid_receipt_never_infers_authorship_from_context() -> None:
    report = verify_dagr_authority_context_producer_receipt(
        receipt_bytes=b"{}",
        context_artifact_bytes=ARTIFACT_BYTES,
        keyring={"issuers": []},
    )
    assert report.context_schema is True
    assert report.context_digest is True
    assert report.producer_authorship_established is False
    assert report.to_dict()["same_genesis_binding"] == "not_evaluated"


def test_countervail_permission_claim_field_is_rejected_even_when_resigned() -> None:
    receipt = _receipt_for_artifact()
    receipt["countervail_authorization"] = "ALLOW"
    report = _verify(receipt=receipt)
    assert report.signature_valid is True
    assert report.prohibited_claims_absent is False
    assert report.producer_authorship_established is False
    assert "profile.prohibited_claim_key:countervail_authorization" in report.failure_codes


def test_receiver_custody_claim_is_rejected_even_when_resigned() -> None:
    receipt = _receipt_for_artifact()
    receipt["receiver_custody"] = True
    report = _verify(receipt=receipt)
    assert report.signature_valid is True
    assert report.prohibited_claims_absent is False
    assert report.producer_authorship_established is False


def test_candidate_context_identity_is_rejected() -> None:
    context = json.loads(ARTIFACT_BYTES)
    context["schema"] = "dagr.resolved-authority-context-candidate/v0.1"
    context["authority_context_digest"] = _context_digest(context)
    altered = json.dumps(context, sort_keys=True, separators=(",", ":")).encode()
    report = _verify(artifact_bytes=altered)
    assert report.context_schema is False
    assert report.producer_authorship_established is False


def test_duplicate_receipt_keys_fail_before_crypto() -> None:
    private = Ed25519PrivateKey.generate()
    signed = _sign(_receipt_for_artifact(), private)
    duplicated = signed[:-1] + b',"receipt_type":"provenance"}'
    report = verify_dagr_authority_context_producer_receipt(
        receipt_bytes=duplicated,
        context_artifact_bytes=ARTIFACT_BYTES,
        keyring=_keyring(private),
    )
    assert report.signature_valid is False
    assert report.producer_authorship_established is False
    assert "receipt.duplicate_key:receipt_type" in report.failure_codes


def test_substituted_permissive_contract_bytes_never_participate_in_pass() -> None:
    report = verify_dagr_authority_context_producer_receipt(
        receipt_bytes=b"{}",
        context_artifact_bytes=ARTIFACT_BYTES,
        keyring={"issuers": []},
        envelope_schema_bytes=b"{}\n",
        profile_schema_bytes=b"{}\n",
        profile_declaration_bytes=b"{}\n",
        extension_schema_bytes=b"{}\n",
        context_schema_bytes=b"{}\n",
    )
    assert report.envelope_schema_digest is False
    assert report.profile_schema_digest is False
    assert report.profile_declaration_digest is False
    assert report.extension_schema_digest is False
    assert report.context_schema_digest is False
    assert report.passed is False


def test_verifier_imports_no_producer_or_same_genesis_implementation() -> None:
    tree = ast.parse(inspect.getsource(verifier))
    imported: set[str] = set()
    imported_modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported.add(alias.name.split(".")[0])
                imported_modules.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
            imported_modules.add(node.module)
    assert "dagr_runtime" not in imported
    assert "dagr_sdk" not in imported
    assert "arcs_srs" not in imported
    assert "arcs_verify.dagr_authority_context" not in imported_modules
