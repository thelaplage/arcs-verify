"""Independent verifier for DAGR authority-context producer SRS receipts.

This verifier consumes serialized bytes and independently supplied trust material.
It imports no DAGR runtime/SDK and no SRS producer implementation.

A PASS establishes only a trust-relative producer-authorship attestation under the
ratified ``dagr.authority_context_producer.v1`` profile: the trusted signer signed
an SRS receipt that binds one exact serialized canonical ResolvedAuthorityContext
artifact and an exact DAGR context/transaction/genesis projection.

It does *not* establish that the context actually derives from the governed
operator-authority genesis. That is the separate ``dagr_authority_context``
same-genesis verifier. It also does not establish action permission, Countervail
InvocationAuthority, execution, truth, or receiver custody.
"""
from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import asdict, dataclass, field
from importlib.resources import files
from typing import Any, Mapping

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator, FormatChecker

from arcs_verify.verifier import (
    SIGNATURE_MEMBERS,
    _b64url_decode,
    _contains_prohibited_value,
    _parse_time,
    _raw_content_failure,
    _walk,
)

SRS_SOURCE_HEAD = "e4878869226cbcfcc1f37bae54f52cb0ba0b72b2"
SRS_ENVELOPE_PUBLICATION = "0.2.1"
SRS_RECEIPT_VERSION = "srs.core.v5.1"
SRS_ENVELOPE_SHA256 = "2afa1ec9f093fd7c06c4f5db7bfd37cc63e64e3dcbe47c963f4df586a1c18ca1"
EXTERNAL_PROFILE_SCHEMA_SHA256 = "342642f4b2f120541f2094a8aadc5d6de9b0ea4548a12363b05333c92f524eaf"

DAGR_PROFILE_SOURCE_HEAD = "cb2760c26ea4e68f63c23afd465e6d65bbe9be54"
DAGR_PROFILE_DECLARATION_SHA256 = "4b7a6245d9c281e91c7e8114533db9de887ba57f460f79ed898a886cecb48f25"
DAGR_EXTENSION_SCHEMA_SHA256 = "d4878d9fe92a0435d85f37866734816489f605101eebdc2f44a5c6fb0781bdc2"
DAGR_CONTEXT_SCHEMA_SHA256 = "d80ed87823fb32c9d1cd9bded11c4c76f8532700203662cef691cd2dbf6f2935"

PROFILE_ID = "dagr.authority_context_producer.v1"
PROFILE_VERSION = "v1.0"
RECEIPT_TYPE = "provenance"
RECEIPT_KIND = "authority_context_producer"
RECEIPT_CLASS = "provenance"
CONTEXT_SCHEMA_ID = "dagr.resolved-authority-context/v0.1"
PRODUCER_IMPLEMENTATION_REF = (
    "github:thelaplage/dagr-runtime@14ed91604506b015f34c39e6dffb25ccdfc0b10c"
)

_EXACT_TOP_LEVEL_FIELDS = frozenset(
    {
        "receipt_version",
        "profile_id",
        "profile_version",
        "receipt_id",
        "receipt_type",
        "receipt_kind",
        "boundary_type",
        "protocol_binding",
        "subject_ref",
        "subject_ref_origin",
        "issuer_id",
        "runtime_instance_id",
        "issued_at",
        "artifact_classes_covered",
        "artifact_classes_excluded",
        "attestation_limits",
        "extensions",
        "receipt_signature",
    }
)
_EXACT_COVERED = [CONTEXT_SCHEMA_ID]
_EXACT_EXCLUDED = [
    "governed_genesis_raw_bytes",
    "countervail_authorization",
    "execution_result",
    "receiver_custody",
]
_EXACT_LIMITS = [
    "attests producer claim over exact artifact bytes and declared DAGR identities only",
    "does not independently establish same-genesis binding",
    "does not establish action permission or Countervail authorization",
    "does not establish execution or receiver custody",
    "signature validity alone does not establish signer trust",
]
_PROHIBITED_CLAIM_KEYS = {
    "allow",
    "allowed",
    "authorized",
    "authorization",
    "action_permission",
    "permission",
    "countervail_authorization",
    "countervail_decision",
    "decision",
    "invocation_authority",
    "execution_authorization",
    "execution_result",
    "receiver_custody",
    "custody_ack",
    "truth",
    "factually_true",
}


@dataclass(slots=True)
class DagrAuthorityContextProducerVerificationReport:
    envelope_schema_digest: bool = False
    profile_schema_digest: bool = False
    profile_declaration_digest: bool = False
    extension_schema_digest: bool = False
    context_schema_digest: bool = False
    envelope: bool = False
    profile_declaration: bool = False
    profile_cross_field: bool = False
    profile_binding: bool = False
    extension_schema: bool = False
    context_schema: bool = False
    context_digest: bool = False
    artifact_digest: bool = False
    projection_binding: bool = False
    attestation_limits: bool = False
    raw_content_exclusion: bool = False
    prohibited_claims_absent: bool = False
    signature_valid: bool = False
    issuer_key_resolved: bool = False
    issuer_key_trusted: bool = False
    producer_authorship_established: bool = False
    failure_codes: list[str] = field(default_factory=list)
    details: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.producer_authorship_established

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data.update(
            {
                "passed": self.passed,
                "profile_id": PROFILE_ID,
                "profile_version": PROFILE_VERSION,
                "profile_source_head": DAGR_PROFILE_SOURCE_HEAD,
                "srs_source_head": SRS_SOURCE_HEAD,
                "same_genesis_binding": "not_evaluated",
                "action_permission": "not_evaluated",
                "countervail_authorization": "not_evaluated",
                "execution": "not_evaluated",
                "receiver_custody": "not_evaluated",
                "truth": "not_evaluated",
            }
        )
        return data


def _dedupe(
    report: DagrAuthorityContextProducerVerificationReport,
) -> DagrAuthorityContextProducerVerificationReport:
    report.failure_codes = list(dict.fromkeys(report.failure_codes))
    report.details = list(dict.fromkeys(report.details))
    return report


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_tagged(data: bytes) -> str:
    return "sha256:" + _sha256(data)


def _strict_json_loads(value: bytes, *, label: str) -> Any:
    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError(f"{label}.duplicate_key:{key}")
            result[key] = item
        return result

    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label}.invalid_utf8") from exc
    try:
        return json.loads(text, object_pairs_hook=no_duplicates)
    except (json.JSONDecodeError, ValueError) as exc:
        if isinstance(exc, ValueError) and str(exc).startswith(f"{label}.duplicate_key:"):
            raise
        raise ValueError(f"{label}.invalid_json") from exc


def _schema_errors(instance: Any, schema: Any) -> list[str]:
    if not isinstance(schema, dict):
        return ["schema.not_object"]
    try:
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        errors = sorted(
            validator.iter_errors(instance),
            key=lambda error: list(error.absolute_path),
        )
    except Exception as exc:
        return [f"schema.validator_error:{type(exc).__name__}"]
    return [error.message for error in errors]


def _profile_cross_field_findings(profile: Any) -> list[str]:
    if not isinstance(profile, dict):
        return ["profile.not_object"]
    if profile.get("profile_id") != PROFILE_ID:
        return ["profile.id_mismatch"]
    if profile.get("profile_version") != PROFILE_VERSION:
        return ["profile.version_mismatch"]
    expected_compat = {
        "published_version": SRS_ENVELOPE_PUBLICATION,
        "sha256": SRS_ENVELOPE_SHA256,
    }
    if profile.get("compatible_envelopes") != [expected_compat]:
        return ["profile.envelope_pin_mismatch"]
    if profile.get("permitted_receipt_types") != [RECEIPT_TYPE]:
        return ["profile.receipt_type_set_mismatch"]
    if profile.get("receipt_type_classifications") != [
        {
            "receipt_type": RECEIPT_TYPE,
            "receipt_class": RECEIPT_CLASS,
            "receipt_kind": RECEIPT_KIND,
        }
    ]:
        return ["profile.classification_mismatch"]
    if profile.get("extension_namespace") != "dagr.authority_context_producer":
        return ["profile.extension_namespace_mismatch"]
    if profile.get("raw_content_posture") != "hash_only":
        return ["profile.raw_content_posture_mismatch"]
    if profile.get("signing_required") is not True:
        return ["profile.signing_not_required"]
    if profile.get("attestation_limits_required") is not True:
        return ["profile.attestation_limits_not_required"]
    return []


def _compute_context_digest(context: Mapping[str, Any]) -> str:
    provenance = context["authority_provenance"]
    preimage = (
        "DAGR-RESOLVED-AUTHORITY-CONTEXT-V0.1\n"
        f"schema={context['schema']}\n"
        f"domain={context['domain']}\n"
        f"transaction_id={context['transaction_id']}\n"
        f"transaction_digest={context['transaction_digest']}\n"
        f"operator_identity_ref={context['operator_identity_ref']}\n"
        f"authority_profile_ref={context['authority_profile_ref']}\n"
        f"review_role_count={len(context['review_roles'])}\n"
    )
    for index, role in enumerate(context["review_roles"]):
        preimage += f"review_role_{index}={role}\n"
    preimage += (
        f"authority_source={context['authority_source']}\n"
        f"authority_genesis_id={provenance['genesis_id']}\n"
        f"authority_genesis_digest={provenance['genesis_digest']}\n"
        f"authority_genesis_status={provenance['status']}\n"
        f"authority_effective_from={provenance['effective_from']}\n"
        f"authority_source_ref={provenance['authority_source_ref']}\n"
        f"supporting_review_ref={provenance['supporting_review_ref']}\n"
    )
    return _sha256_tagged(preimage.encode("utf-8"))


def _claim_key_findings(receipt: Mapping[str, Any]) -> list[str]:
    findings: list[str] = []
    for key, _value in _walk(receipt):
        if isinstance(key, str) and key.lower() in _PROHIBITED_CLAIM_KEYS:
            findings.append(f"profile.prohibited_claim_key:{key}")
    return findings


def verify_dagr_authority_context_producer_receipt(
    *,
    receipt_bytes: bytes,
    context_artifact_bytes: bytes,
    keyring: dict[str, Any],
    envelope_schema_bytes: bytes | None = None,
    profile_schema_bytes: bytes | None = None,
    profile_declaration_bytes: bytes | None = None,
    extension_schema_bytes: bytes | None = None,
    context_schema_bytes: bytes | None = None,
) -> DagrAuthorityContextProducerVerificationReport:
    """Verify the independent producer-authorship axis from serialized bytes."""

    report = DagrAuthorityContextProducerVerificationReport()
    package = files("arcs_verify").joinpath("data")
    if envelope_schema_bytes is None:
        envelope_schema_bytes = package.joinpath(
            "srs-envelope-v0.2.1-e487.schema.json"
        ).read_bytes()
    if profile_schema_bytes is None:
        profile_schema_bytes = package.joinpath(
            "srs-external-profile-declaration-e487.schema.json"
        ).read_bytes()
    if profile_declaration_bytes is None:
        profile_declaration_bytes = package.joinpath(
            "dagr-authority-context-producer-cb2760.profile.json"
        ).read_bytes()
    if extension_schema_bytes is None:
        extension_schema_bytes = package.joinpath(
            "dagr-authority-context-producer-cb2760.extensions.schema.json"
        ).read_bytes()
    if context_schema_bytes is None:
        context_schema_bytes = package.joinpath(
            "dagr-resolved-authority-context-1a12726f.schema.json"
        ).read_bytes()

    report.envelope_schema_digest = _sha256(envelope_schema_bytes) == SRS_ENVELOPE_SHA256
    report.profile_schema_digest = (
        _sha256(profile_schema_bytes) == EXTERNAL_PROFILE_SCHEMA_SHA256
    )
    report.profile_declaration_digest = (
        _sha256(profile_declaration_bytes) == DAGR_PROFILE_DECLARATION_SHA256
    )
    report.extension_schema_digest = (
        _sha256(extension_schema_bytes) == DAGR_EXTENSION_SCHEMA_SHA256
    )
    report.context_schema_digest = (
        _sha256(context_schema_bytes) == DAGR_CONTEXT_SCHEMA_SHA256
    )
    for ok, code in (
        (report.envelope_schema_digest, "envelope_schema.digest_mismatch"),
        (report.profile_schema_digest, "profile_schema.digest_mismatch"),
        (report.profile_declaration_digest, "profile_declaration.digest_mismatch"),
        (report.extension_schema_digest, "extension_schema.digest_mismatch"),
        (report.context_schema_digest, "context_schema.digest_mismatch"),
    ):
        if not ok:
            report.failure_codes.append(code)

    try:
        receipt = _strict_json_loads(receipt_bytes, label="receipt")
        context = _strict_json_loads(context_artifact_bytes, label="context")
        envelope_schema = _strict_json_loads(
            envelope_schema_bytes, label="envelope_schema"
        )
        profile_schema = _strict_json_loads(
            profile_schema_bytes, label="profile_schema"
        )
        profile = _strict_json_loads(profile_declaration_bytes, label="profile")
        extension_schema = _strict_json_loads(
            extension_schema_bytes, label="extension_schema"
        )
        context_schema = _strict_json_loads(
            context_schema_bytes, label="context_schema"
        )
    except ValueError as exc:
        report.failure_codes.append(str(exc))
        return _dedupe(report)
    if not isinstance(receipt, dict) or not isinstance(context, dict):
        report.failure_codes.append("input.not_object")
        return _dedupe(report)

    envelope_errors = _schema_errors(receipt, envelope_schema)
    report.envelope = not envelope_errors and report.envelope_schema_digest
    if envelope_errors:
        report.failure_codes.append("envelope.schema_invalid")
        report.details.extend(envelope_errors)

    profile_errors = _schema_errors(profile, profile_schema)
    report.profile_declaration = bool(
        not profile_errors
        and report.profile_schema_digest
        and report.profile_declaration_digest
    )
    if profile_errors:
        report.failure_codes.append("profile.schema_invalid")
        report.details.extend(profile_errors)

    cross_findings = _profile_cross_field_findings(profile)
    report.profile_cross_field = not cross_findings and report.profile_declaration
    report.failure_codes.extend(cross_findings)

    binding_findings: list[str] = []
    if set(receipt) != _EXACT_TOP_LEVEL_FIELDS:
        binding_findings.append("profile.top_level_surface_mismatch")
    expected_receipt_fields = {
        "receipt_version": SRS_RECEIPT_VERSION,
        "profile_id": PROFILE_ID,
        "profile_version": PROFILE_VERSION,
        "receipt_type": RECEIPT_TYPE,
        "receipt_kind": RECEIPT_KIND,
        "boundary_type": "artifact_emission",
        "protocol_binding": "dagr-runtime",
        "subject_ref_origin": "binding_minted",
    }
    for key, expected in expected_receipt_fields.items():
        if receipt.get(key) != expected:
            binding_findings.append(f"receipt.{key}_mismatch")
    if not isinstance(receipt.get("subject_ref"), str) or not receipt.get("subject_ref"):
        binding_findings.append("receipt.subject_ref_invalid")
    report.profile_binding = not binding_findings and report.profile_cross_field
    report.failure_codes.extend(binding_findings)

    extensions = receipt.get("extensions")
    extension_errors = _schema_errors(extensions, extension_schema)
    report.extension_schema = not extension_errors and report.extension_schema_digest
    if extension_errors:
        report.failure_codes.append("extensions.schema_invalid")
        report.details.extend(extension_errors)

    context_errors = _schema_errors(context, context_schema)
    report.context_schema = not context_errors and report.context_schema_digest
    if context_errors:
        report.failure_codes.append("context.schema_invalid")
        report.details.extend(context_errors)

    if report.context_schema:
        try:
            recomputed = _compute_context_digest(context)
            report.context_digest = recomputed == context.get("authority_context_digest")
        except Exception as exc:
            report.details.append(f"context_digest_recompute:{type(exc).__name__}")
            report.context_digest = False
        if not report.context_digest:
            report.failure_codes.append("context.digest_mismatch")

    if isinstance(extensions, dict):
        report.artifact_digest = (
            extensions.get("dagr.authority_context_producer.artifact_sha256")
            == _sha256_tagged(context_artifact_bytes)
        )
    if not report.artifact_digest:
        report.failure_codes.append("artifact.digest_mismatch")

    if report.context_schema and isinstance(extensions, dict):
        provenance = context.get("authority_provenance")
        expected_projection = {
            "dagr.authority_context_producer.context_schema": context.get("schema"),
            "dagr.authority_context_producer.context_digest": context.get(
                "authority_context_digest"
            ),
            "dagr.authority_context_producer.transaction_id": context.get(
                "transaction_id"
            ),
            "dagr.authority_context_producer.transaction_digest": context.get(
                "transaction_digest"
            ),
            "dagr.authority_context_producer.genesis_id": (
                provenance.get("genesis_id") if isinstance(provenance, dict) else None
            ),
            "dagr.authority_context_producer.genesis_digest": (
                provenance.get("genesis_digest")
                if isinstance(provenance, dict)
                else None
            ),
            "dagr.authority_context_producer.producer_implementation_ref": (
                PRODUCER_IMPLEMENTATION_REF
            ),
            "dagr.authority_context_producer.artifact_media_type": "application/json",
        }
        report.projection_binding = all(
            extensions.get(key) == value for key, value in expected_projection.items()
        )
    if not report.projection_binding:
        report.failure_codes.append("artifact.projection_mismatch")

    covered = receipt.get("artifact_classes_covered")
    excluded = receipt.get("artifact_classes_excluded")
    limits = receipt.get("attestation_limits")
    report.attestation_limits = bool(
        covered == _EXACT_COVERED
        and excluded == _EXACT_EXCLUDED
        and limits == _EXACT_LIMITS
    )
    if not report.attestation_limits:
        report.failure_codes.append("attestation.exact_surface_mismatch")

    raw_findings: list[str] = []
    for key, value in _walk(receipt):
        if key is not None:
            failure = _raw_content_failure(key, value)
            if failure is not None:
                raw_findings.append(failure)
        if isinstance(value, str) and _contains_prohibited_value(value):
            raw_findings.append("raw_content.prohibited_value")
    report.raw_content_exclusion = not raw_findings
    report.failure_codes.extend(raw_findings)

    claim_findings = _claim_key_findings(receipt)
    report.prohibited_claims_absent = not claim_findings
    report.failure_codes.extend(claim_findings)

    signature = receipt.get("receipt_signature")
    if (
        not isinstance(signature, dict)
        or set(signature) != SIGNATURE_MEMBERS
        or signature.get("algorithm") != "Ed25519"
        or signature.get("canonicalization") != "RFC8785-JCS"
    ):
        report.failure_codes.append("signature_object_invalid")
        return _dedupe(report)

    key_id = signature.get("key_id")
    entries = keyring.get("issuers", []) if isinstance(keyring, dict) else []
    entry = next(
        (
            item
            for item in entries
            if isinstance(item, dict) and item.get("key_id") == key_id
        ),
        None,
    )
    report.issuer_key_resolved = entry is not None
    if entry is None:
        report.failure_codes.append("key_id_unresolved")
        return _dedupe(report)

    try:
        public_key_bytes = _b64url_decode(
            entry.get("public_key"), code="public_key_encoding_invalid"
        )
        signature_bytes = _b64url_decode(
            signature.get("signature"), code="signature_encoding_invalid"
        )
        if len(public_key_bytes) != 32:
            raise ValueError("public_key_encoding_invalid")
        if len(signature_bytes) != 64:
            raise ValueError("signature_encoding_invalid")
        preimage = copy.deepcopy(receipt)
        del preimage["receipt_signature"]["signature"]
        canonical = rfc8785.dumps(preimage)
        Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(
            signature_bytes, canonical
        )
        report.signature_valid = True
    except InvalidSignature:
        report.failure_codes.append("signature_invalid")
    except ValueError as exc:
        report.failure_codes.append(str(exc))
    except Exception:
        report.failure_codes.append("preimage_canonicalization_failed")

    try:
        issued_at = _parse_time(receipt["issued_at"])
        trusted = (
            entry.get("trusted") is True
            and entry.get("issuer_id") == receipt.get("issuer_id")
            and _parse_time(entry["not_before"])
            <= issued_at
            <= _parse_time(entry["not_after"])
        )
    except Exception:
        trusted = False
    report.issuer_key_trusted = bool(trusted)
    if not report.issuer_key_trusted:
        report.failure_codes.append("key_untrusted")

    report.producer_authorship_established = all(
        (
            report.envelope_schema_digest,
            report.profile_schema_digest,
            report.profile_declaration_digest,
            report.extension_schema_digest,
            report.context_schema_digest,
            report.envelope,
            report.profile_declaration,
            report.profile_cross_field,
            report.profile_binding,
            report.extension_schema,
            report.context_schema,
            report.context_digest,
            report.artifact_digest,
            report.projection_binding,
            report.attestation_limits,
            report.raw_content_exclusion,
            report.prohibited_claims_absent,
            report.signature_valid,
            report.issuer_key_resolved,
            report.issuer_key_trusted,
        )
    )
    return _dedupe(report)


__all__ = [
    "DagrAuthorityContextProducerVerificationReport",
    "verify_dagr_authority_context_producer_receipt",
]
