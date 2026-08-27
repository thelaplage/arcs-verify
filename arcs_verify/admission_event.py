"""Independent verifier for srs.activity.admission_event.v0.1.

This module imports no DAGR producer/runtime implementation. It consumes only
serialized receipt content, a serialized trust bundle, and verifier-owned
contract constants. The profile is provisional while arcs-srs PR #52 is
unmerged; PROFILE_SOURCE_HEAD pins the exact proposed contract reviewed here.
"""
from __future__ import annotations

import argparse
import base64
import copy
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Iterable, Mapping

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator

PROFILE = "srs.activity.admission_event.v0.1"
PROFILE_ID = "srs.activity.admission_event"
PROFILE_VERSION = "v0.1"
PROFILE_SOURCE_HEAD = "ac7b04feb390c99055bd265157ef616ecb7ff9dc"
PROFILE_SOURCE_PATH = "schemas/activity-profiles/v0.1/srs.activity.admission_event.v0.1.schema.json"
RECEIPT_VERSION = "srs.core.v5.1"
ENVELOPE_SCHEMA_PATH = (
    Path(__file__).resolve().parent / "data" / "srs-envelope-v0.2.1.schema.json"
)
ENVELOPE_SCHEMA_SHA256 = (
    "2afa1ec9f093fd7c06c4f5db7bfd37cc63e64e3dcbe47c963f4df586a1c18ca1"
)
SHA256_REF = re.compile(r"^sha256:[0-9a-f]{64}$")
HEX_COMMIT = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
OPAQUE_REF = re.compile(r"^[A-Za-z][A-Za-z0-9._+/-]*:[^\s]+$")
VISIBILITY = frozenset({"LOCAL", "PRIVATE_ORG", "SHARED", "PUBLIC_CANDIDATE", "PUBLIC"})
STANDING_ACTS = frozenset({"ADMITTED", "REFUSED", "DEFERRED", "SUPERSEDED"})
REQUIRED = frozenset({
    "receipt_version", "profile_id", "profile_version", "receipt_id",
    "receipt_type", "receipt_kind", "boundary_type", "protocol_binding",
    "subject_ref", "issuer_id", "runtime_instance_id", "boundary_id",
    "issued_at", "visibility", "namespace_authority_ref", "subject_record_ref",
    "subject_edition_ref", "standing_act", "governed_result_ref",
    "governed_result_digest", "policy_profile_ref", "policy_digest",
    "disposition_id", "disposition_digest", "basis_refs",
    "artifact_classes_covered", "artifact_classes_excluded",
    "attestation_limits", "machine_limitations", "extensions",
})
COVERED = frozenset({
    "admission_event_record", "subject_edition_identity",
    "governed_result_identity", "policy_identity",
})
EXCLUDED = frozenset({
    "subject_content_bytes", "evidence_content_bytes",
    "universal_truth", "downstream_reliance",
})
AGGREGATE_KEYS = frozenset({
    "aggregate_verdict", "aggregate_activity_verdict", "trust_score",
    "reputation", "reputation_score", "activity_score", "reliance_score",
    "standing_score",
})
ATTESTATION_LIMIT = (
    "This receipt records that the named authority performed the declared standing "
    "act for the exact subject edition and binds that event to the referenced "
    "governed result and policy basis. It does not establish factual truth, "
    "publication, universal standing, current validity, downstream reliance, or "
    "that the governed result itself was correctly decided."
)
SIGNATURE_MEMBERS = frozenset({"algorithm", "canonicalization", "key_id", "signature"})
RAW_CONTENT_KEYS = frozenset({
    "prompt_text", "transcript", "raw_payload", "tool_arguments", "arguments",
    "result_body", "headers",
})


@dataclass
class AdmissionEventVerificationReport:
    envelope_schema_digest: bool = False
    envelope: bool = False
    profile: bool = False
    raw_content_exclusion: bool = False
    attestation_limits_present: bool = False
    signature_valid: bool = False
    issuer_key_resolved: bool = False
    issuer_key_trusted: bool = False
    failure_codes: list[str] = field(default_factory=list)
    details: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all((
            self.envelope_schema_digest,
            self.envelope,
            self.profile,
            self.raw_content_exclusion,
            self.attestation_limits_present,
            self.signature_valid,
            self.issuer_key_resolved,
            self.issuer_key_trusted,
        ))

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["passed"] = self.passed
        data["profile_identity"] = PROFILE
        data["profile_source_head"] = PROFILE_SOURCE_HEAD
        return data


def _dedupe(report: AdmissionEventVerificationReport) -> AdmissionEventVerificationReport:
    report.failure_codes = list(dict.fromkeys(report.failure_codes))
    report.details = list(dict.fromkeys(report.details))
    return report


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _b64url_decode(value: object, *, code: str) -> bytes:
    if not isinstance(value, str) or not value or "=" in value:
        raise ValueError(code)
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:
        raise ValueError(code) from exc
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value:
        raise ValueError(code)
    return decoded


def _walk(value: Any) -> Iterable[tuple[str | None, Any]]:
    if isinstance(value, dict):
        for key, item in value.items():
            yield str(key), item
            yield from _walk(item)
    elif isinstance(value, list):
        for item in value:
            yield None, item
            yield from _walk(item)


def _basis_ref(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and (
            SHA256_REF.fullmatch(value) is not None
            or HEX_COMMIT.fullmatch(value) is not None
            or OPAQUE_REF.fullmatch(value) is not None
        )
    )


def _profile_errors(receipt: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    missing = sorted(REQUIRED - receipt.keys())
    if missing:
        errors.append("admission_event.missing_required:" + ",".join(missing))

    expected = {
        "receipt_version": RECEIPT_VERSION,
        "profile_id": PROFILE_ID,
        "profile_version": PROFILE_VERSION,
        "receipt_type": "provenance",
        "receipt_kind": "admission_event",
        "boundary_type": "admission_event_boundary",
    }
    for key, expected_value in expected.items():
        if receipt.get(key) != expected_value:
            errors.append(f"admission_event.invalid_{key}")

    for key in (
        "receipt_id", "protocol_binding", "subject_ref", "issuer_id",
        "runtime_instance_id", "boundary_id", "issued_at", "namespace_authority_ref",
        "subject_record_ref", "subject_edition_ref", "governed_result_ref",
        "policy_profile_ref", "disposition_id",
    ):
        value = receipt.get(key)
        if not isinstance(value, str) or not value or value.strip() != value:
            errors.append(f"admission_event.invalid_text:{key}")

    if receipt.get("visibility") not in VISIBILITY:
        errors.append("admission_event.invalid_visibility")
    if receipt.get("standing_act") not in STANDING_ACTS:
        errors.append("admission_event.invalid_standing_act")
    if receipt.get("subject_ref") != receipt.get("subject_edition_ref"):
        errors.append("admission_event.subject_binding_mismatch")

    for key in ("governed_result_digest", "policy_digest", "disposition_digest"):
        value = receipt.get(key)
        if not isinstance(value, str) or SHA256_REF.fullmatch(value) is None:
            errors.append(f"admission_event.invalid_digest:{key}")

    basis = receipt.get("basis_refs")
    basis_strings = [item for item in basis if isinstance(item, str)] if isinstance(basis, list) else []
    if (
        not isinstance(basis, list)
        or not basis
        or len(set(basis_strings)) != len(basis)
        or not all(_basis_ref(item) for item in basis)
    ):
        errors.append("admission_event.invalid_basis_refs")

    covered = receipt.get("artifact_classes_covered")
    covered_set = set(covered) if isinstance(covered, list) and all(isinstance(x, str) for x in covered) else set()
    if not COVERED.issubset(covered_set):
        errors.append("admission_event.missing_required_covered_classes")
    excluded = receipt.get("artifact_classes_excluded")
    excluded_set = set(excluded) if isinstance(excluded, list) and all(isinstance(x, str) for x in excluded) else set()
    if not EXCLUDED.issubset(excluded_set):
        errors.append("admission_event.missing_required_excluded_classes")

    limitations = receipt.get("machine_limitations")
    codes = {
        item.get("code")
        for item in limitations
        if isinstance(item, dict) and isinstance(item.get("code"), str)
    } if isinstance(limitations, list) else set()
    if "CONTENT_NOT_VERIFIED" not in codes:
        errors.append("admission_event.missing_content_not_verified")

    if any(key in receipt for key in AGGREGATE_KEYS):
        errors.append("admission_event.aggregate_field_present")
    if not isinstance(receipt.get("extensions"), dict):
        errors.append("admission_event.extensions_not_object")
    return errors


def _raw_content_errors(receipt: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    for key, value in _walk(receipt):
        if key in RAW_CONTENT_KEYS:
            errors.append(f"raw_content.forbidden_key:{key}")
        if isinstance(value, str) and (
            "/Users/" in value or "/home/" in value or "/private/var" in value
        ):
            errors.append("raw_content.private_path")
    return errors


def verify_admission_event_receipt(
    receipt: Mapping[str, Any],
    keyring: Mapping[str, Any],
) -> AdmissionEventVerificationReport:
    report = AdmissionEventVerificationReport()

    schema_bytes = ENVELOPE_SCHEMA_PATH.read_bytes()
    schema_sha = hashlib.sha256(schema_bytes).hexdigest()
    report.envelope_schema_digest = schema_sha == ENVELOPE_SCHEMA_SHA256
    if not report.envelope_schema_digest:
        report.failure_codes.append("schema.digest_mismatch")

    try:
        schema = json.loads(schema_bytes)
        schema_errors = sorted(
            Draft202012Validator(schema).iter_errors(dict(receipt)),
            key=lambda error: list(error.path),
        )
    except Exception as exc:
        report.failure_codes.append("envelope.schema_unreadable")
        report.details.append(str(exc))
        return _dedupe(report)

    report.envelope = not schema_errors
    for error in schema_errors:
        report.failure_codes.append("envelope.schema_invalid")
        report.details.append(error.message)

    profile_errors = _profile_errors(receipt)
    report.profile = not profile_errors
    report.failure_codes.extend(profile_errors)

    raw_errors = _raw_content_errors(receipt)
    report.raw_content_exclusion = not raw_errors
    report.failure_codes.extend(raw_errors)

    limits = receipt.get("attestation_limits")
    report.attestation_limits_present = (
        isinstance(limits, list)
        and ATTESTATION_LIMIT in limits
        and all(isinstance(item, str) and item.strip() for item in limits)
    )
    if not report.attestation_limits_present:
        report.failure_codes.append("attestation.missing_required_limit")

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
    entries = keyring.get("issuers", []) if isinstance(keyring, Mapping) else []
    entry = next(
        (
            item for item in entries
            if isinstance(item, dict) and item.get("key_id") == key_id
        ),
        None,
    )
    report.issuer_key_resolved = entry is not None
    if entry is None:
        report.failure_codes.append("key_id_unresolved")
        return _dedupe(report)

    try:
        public_key = _b64url_decode(
            entry.get("public_key"), code="public_key_encoding_invalid"
        )
        signature_bytes = _b64url_decode(
            signature.get("signature"), code="signature_encoding_invalid"
        )
        if len(public_key) != 32:
            raise ValueError("public_key_encoding_invalid")
        if len(signature_bytes) != 64:
            raise ValueError("signature_encoding_invalid")
    except ValueError as exc:
        report.failure_codes.append(str(exc))
        return _dedupe(report)

    preimage = copy.deepcopy(dict(receipt))
    del preimage["receipt_signature"]["signature"]
    try:
        canonical = rfc8785.dumps(preimage)
    except Exception:
        report.failure_codes.append("preimage_canonicalization_failed")
        return _dedupe(report)

    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature_bytes, canonical
        )
        report.signature_valid = True
    except InvalidSignature:
        report.failure_codes.append("signature_invalid")

    try:
        issued_at = _parse_time(receipt["issued_at"])
        report.issuer_key_trusted = bool(
            entry.get("trusted") is True
            and entry.get("issuer_id") == receipt.get("issuer_id")
            and _parse_time(entry["not_before"]) <= issued_at <= _parse_time(entry["not_after"])
        )
    except Exception:
        report.issuer_key_trusted = False
    if not report.issuer_key_trusted:
        report.failure_codes.append("key_untrusted")
    return _dedupe(report)


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("receipt", type=Path)
    parser.add_argument("--keyring", required=True, type=Path)
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args(argv)
    try:
        receipt = _load_json(args.receipt)
        keyring = _load_json(args.keyring)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"source error: {exc}")
        return 2
    report = verify_admission_event_receipt(receipt, keyring)
    if args.as_json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        for key in (
            "envelope_schema_digest", "envelope", "profile",
            "raw_content_exclusion", "attestation_limits_present",
            "signature_valid", "issuer_key_resolved", "issuer_key_trusted",
        ):
            print(f"{key}: {'PASS' if getattr(report, key) else 'FAIL'}")
        for code in report.failure_codes:
            print(f"failure: {code}")
    return 0 if report.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
