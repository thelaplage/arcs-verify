"""Independent verification for SRS vNext external-profile receipts.

The verifier consumes serialized receipt/profile/schema bytes plus an
independently supplied keyring.  It imports no producer/runtime package and
never asks an emitter how a receipt should verify.

This first lane pins the reviewed candidate SRS vNext and external-profile
schema byte identities from arcs-srs #57 (head e22fd692...).  The schema bytes
are caller-supplied and must hash to these independent pins before they can
participate in a PASS.  A caller cannot substitute a permissive schema merely
by pointing the verifier at it.

A PASS is structural/profile/cryptographic conformance to the pinned candidate
contracts and supplied trust context.  It is not truth, authorization, DAGR
standing, evidence standing, publication, or certification.
"""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any

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

SRS_VNEXT_SOURCE_REPO = "thelaplage/arcs-srs"
SRS_VNEXT_SOURCE_PR = 57
SRS_VNEXT_SOURCE_HEAD = "e22fd69218451a86cf639bcce4691f7e1d6975c9"
SRS_VNEXT_ENVELOPE_SOURCE_BLOB = "39beaeaa65ab97e6e81d32057b52ac20c3f8a1ea"
SRS_VNEXT_ENVELOPE_SHA256 = "71a9b365eb7c3d320d173772f6b823bb2bc3c15174eef30f6038ea7b84bde967"
EXTERNAL_PROFILE_SCHEMA_SOURCE_BLOB = "4832c73870820575362ccd98868de990c51b74c1"
EXTERNAL_PROFILE_SCHEMA_SHA256 = "342642f4b2f120541f2094a8aadc5d6de9b0ea4548a12363b05333c92f524eaf"

FROZEN_V0_2_1_RECEIPT_TYPES = frozenset(
    {"sdk_enforcement", "grace_session", "connection", "provenance"}
)
KIND_QUALIFIED_TYPES: dict[str, tuple[str, ...]] = {
    "sdk_enforcement": ("admission", "outcome"),
}


@dataclass(slots=True)
class ExternalProfileVerificationReport:
    envelope_schema_digest: bool = False
    profile_schema_digest: bool = False
    envelope: bool = False
    profile_declaration: bool = False
    profile_cross_field: bool = False
    receipt_profile_binding: bool = False
    contract_refs: bool = False
    raw_content_exclusion: bool = False
    signature_valid: bool = False
    issuer_key_resolved: bool = False
    issuer_key_trusted: bool = False
    attestation_limits_present: bool = False
    selected_receipt_class: str | None = None
    failure_codes: list[str] = field(default_factory=list)
    details: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(
            (
                self.envelope_schema_digest,
                self.profile_schema_digest,
                self.envelope,
                self.profile_declaration,
                self.profile_cross_field,
                self.receipt_profile_binding,
                self.contract_refs,
                self.raw_content_exclusion,
                self.signature_valid,
                self.issuer_key_resolved,
                self.issuer_key_trusted,
                self.attestation_limits_present,
            )
        )

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["passed"] = self.passed
        return data


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _schema_validate(instance: Any, schema_bytes: bytes) -> list[str]:
    try:
        schema = json.loads(schema_bytes)
    except Exception:
        return ["schema_bytes_not_json"]
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    return [error.message for error in sorted(validator.iter_errors(instance), key=lambda e: list(e.path))]


def external_profile_cross_field_findings(declaration: Any) -> list[str]:
    """Independently enforce #57's cross-array profile-conformance rules.

    Per-field grammar is enforced by the pinned JSON Schema first.  This helper
    owns only the set relationships JSON Schema does not express.
    """

    if not isinstance(declaration, dict):
        return ["profile.not_object"]
    permitted = declaration.get("permitted_receipt_types")
    classifications = declaration.get("receipt_type_classifications")
    envelopes = declaration.get("compatible_envelopes")
    if not isinstance(permitted, list) or not isinstance(classifications, list) or not isinstance(envelopes, list):
        return ["profile.cross_field_inputs_invalid"]

    findings: list[str] = []
    permitted_set = {item for item in permitted if isinstance(item, str)}
    covered: set[str] = set()
    covered_kinds: dict[str, set[str | None]] = {}
    mappings: dict[tuple[str, str | None], str] = {}

    for entry in classifications:
        if not isinstance(entry, dict):
            findings.append("profile.classification_not_object")
            continue
        receipt_type = entry.get("receipt_type")
        receipt_class = entry.get("receipt_class")
        receipt_kind = entry.get("receipt_kind")
        if not isinstance(receipt_type, str) or not isinstance(receipt_class, str):
            findings.append("profile.classification_incomplete")
            continue
        covered.add(receipt_type)
        kind_key = receipt_kind if isinstance(receipt_kind, str) else None
        covered_kinds.setdefault(receipt_type, set()).add(kind_key)
        if receipt_type not in permitted_set:
            findings.append("profile.classification_for_undeclared_type")
        key = (receipt_type, kind_key)
        prior = mappings.get(key)
        if prior is not None and prior != receipt_class:
            findings.append("profile.conflicting_duplicate_classification")
        else:
            mappings[key] = receipt_class

    if permitted_set - covered:
        findings.append("profile.permitted_type_unclassified")

    declares_v021 = any(
        isinstance(env, dict) and env.get("published_version") == "0.2.1"
        for env in envelopes
    )
    if declares_v021 and not permitted_set.issubset(FROZEN_V0_2_1_RECEIPT_TYPES):
        findings.append("profile.v0_2_1_permits_non_frozen_type")

    for receipt_type, required_kinds in KIND_QUALIFIED_TYPES.items():
        if receipt_type not in permitted_set:
            continue
        kinds = covered_kinds.get(receipt_type, set())
        if None in kinds:
            findings.append("profile.kind_required_but_unqualified_classification")
        if any(kind not in kinds for kind in required_kinds):
            findings.append("profile.missing_kind_qualified_classification")

    return list(dict.fromkeys(findings))


def _selected_class(receipt: dict[str, Any], profile: dict[str, Any]) -> tuple[str | None, list[str]]:
    receipt_type = receipt.get("receipt_type")
    receipt_kind = receipt.get("receipt_kind")
    candidates: set[str] = set()
    for entry in profile.get("receipt_type_classifications", []):
        if not isinstance(entry, dict) or entry.get("receipt_type") != receipt_type:
            continue
        declared_kind = entry.get("receipt_kind")
        if declared_kind is None or declared_kind == receipt_kind:
            receipt_class = entry.get("receipt_class")
            if isinstance(receipt_class, str):
                candidates.add(receipt_class)
    if len(candidates) != 1:
        return None, ["receipt.profile_classification_missing_or_ambiguous"]
    return next(iter(candidates)), []


def verify_external_profile_receipt(
    receipt_bytes: bytes,
    profile_declaration_bytes: bytes,
    keyring: dict[str, Any],
    *,
    envelope_schema_bytes: bytes,
    profile_schema_bytes: bytes,
) -> ExternalProfileVerificationReport:
    report = ExternalProfileVerificationReport()

    report.envelope_schema_digest = _sha256(envelope_schema_bytes) == SRS_VNEXT_ENVELOPE_SHA256
    if not report.envelope_schema_digest:
        report.failure_codes.append("envelope_schema.digest_mismatch")
    report.profile_schema_digest = _sha256(profile_schema_bytes) == EXTERNAL_PROFILE_SCHEMA_SHA256
    if not report.profile_schema_digest:
        report.failure_codes.append("profile_schema.digest_mismatch")

    try:
        receipt = json.loads(receipt_bytes)
    except Exception:
        report.failure_codes.append("receipt.not_json")
        return report
    try:
        profile = json.loads(profile_declaration_bytes)
    except Exception:
        report.failure_codes.append("profile.not_json")
        return report
    if not isinstance(receipt, dict) or not isinstance(profile, dict):
        report.failure_codes.append("input.not_object")
        return report

    envelope_errors = _schema_validate(receipt, envelope_schema_bytes)
    report.envelope = not envelope_errors and report.envelope_schema_digest
    if envelope_errors:
        report.failure_codes.append("envelope.schema_invalid")
        report.details.extend(envelope_errors)

    profile_schema_errors = _schema_validate(profile, profile_schema_bytes)
    report.profile_declaration = not profile_schema_errors and report.profile_schema_digest
    if profile_schema_errors:
        report.failure_codes.append("profile.schema_invalid")
        report.details.extend(profile_schema_errors)

    cross_findings = external_profile_cross_field_findings(profile)
    report.profile_cross_field = not cross_findings
    report.failure_codes.extend(cross_findings)

    binding_errors: list[str] = []
    if receipt.get("profile_id") != profile.get("profile_id"):
        binding_errors.append("receipt.profile_id_mismatch")
    if receipt.get("profile_version") != profile.get("profile_version"):
        binding_errors.append("receipt.profile_version_mismatch")
    if receipt.get("receipt_type") not in profile.get("permitted_receipt_types", []):
        binding_errors.append("receipt.type_not_permitted")
    selected_class, classification_errors = _selected_class(receipt, profile)
    binding_errors.extend(classification_errors)
    report.selected_receipt_class = selected_class
    report.receipt_profile_binding = not binding_errors
    report.failure_codes.extend(binding_errors)

    refs = receipt.get("contract_refs")
    expected_envelope_digest = "sha256:" + _sha256(envelope_schema_bytes)
    expected_profile_digest = "sha256:" + _sha256(profile_declaration_bytes)
    refs_ok = isinstance(refs, dict)
    envelope_ref = refs.get("envelope_contract") if isinstance(refs, dict) else None
    profile_ref = refs.get("profile_contract") if isinstance(refs, dict) else None
    refs_ok = bool(
        refs_ok
        and isinstance(envelope_ref, dict)
        and envelope_ref.get("digest") == expected_envelope_digest
        and isinstance(profile_ref, dict)
        and profile_ref.get("id") == profile.get("profile_id")
        and profile_ref.get("version") == profile.get("profile_version")
        and profile_ref.get("digest") == expected_profile_digest
    )
    report.contract_refs = refs_ok
    if not refs_ok:
        report.failure_codes.append("receipt.contract_refs_mismatch")

    raw_errors: list[str] = []
    for key, value in _walk(receipt):
        if key is not None:
            failure = _raw_content_failure(key, value)
            if failure is not None:
                raw_errors.append(failure)
        if isinstance(value, str) and _contains_prohibited_value(value):
            raw_errors.append("raw_content.prohibited_value")
    report.raw_content_exclusion = not raw_errors
    report.failure_codes.extend(raw_errors)

    limits = receipt.get("attestation_limits")
    report.attestation_limits_present = bool(
        isinstance(limits, list)
        and limits
        and all(isinstance(item, str) and item.strip() for item in limits)
    )
    if not report.attestation_limits_present:
        report.failure_codes.append("attestation.missing_or_empty")

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
        Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(signature_bytes, canonical)
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
            and _parse_time(entry["not_before"]) <= issued_at <= _parse_time(entry["not_after"])
        )
    except Exception:
        trusted = False
    report.issuer_key_trusted = bool(trusted)
    if not report.issuer_key_trusted:
        report.failure_codes.append("key_untrusted")

    if profile.get("signing_required") is True and not report.signature_valid:
        report.failure_codes.append("profile.required_signature_invalid")

    return _dedupe(report)


def _dedupe(report: ExternalProfileVerificationReport) -> ExternalProfileVerificationReport:
    report.failure_codes = list(dict.fromkeys(report.failure_codes))
    report.details = list(dict.fromkeys(report.details))
    return report
