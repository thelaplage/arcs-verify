"""Independent verifier for ``srs.activity.admission_event.v0.2``.

v0.2 is additive over the landed v0.1 verifier. This module reuses only
verifier-owned low-level helpers/constants; it does not rewrite the receipt to
v0.1 and imports no DAGR/Counterpedia producer implementation.

The new independent finding is ``supersession_binding``. A PASS for a
SUPERSEDED receipt requires exact predecessor/successor references, distinct
editions, both event refs in ``basis_refs``, and the required
supersession-not-retirement attestation.
"""
from __future__ import annotations

import argparse
import copy
from dataclasses import asdict, dataclass, field
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator

from arcs_verify import admission_event as v01

PROFILE = "srs.activity.admission_event.v0.2"
PROFILE_ID = "srs.activity.admission_event"
PROFILE_VERSION = "v0.2"
PROFILE_SOURCE_HEAD = "b276945eed5fb83a6eb08df09d122da62a59cc60"
PROFILE_SOURCE_PATH = (
    "schemas/activity-profiles/v0.2/"
    "srs.activity.admission_event.v0.2.schema.json"
)
PROFILE_SOURCE_BLOB_SHA1 = "7338dbbe161ac4454b0454d27713efbc52079dc0"

SUPERSESSION_LIMIT = (
    "A SUPERSEDED admission-event receipt records replacement by the named "
    "successor admission event. It does not establish that the predecessor was "
    "false, invalid, deleted, or retired; terminal withdrawal without a "
    "replacement is outside this profile."
)
SUPERSESSION_KEYS = frozenset(
    {
        "kind",
        "predecessor_event_ref",
        "predecessor_event_digest",
        "successor_event_ref",
        "successor_event_digest",
        "successor_subject_edition_ref",
    }
)


@dataclass
class AdmissionEventV02VerificationReport:
    envelope_schema_digest: bool = False
    envelope: bool = False
    profile: bool = False
    supersession_binding: bool = False
    raw_content_exclusion: bool = False
    attestation_limits_present: bool = False
    signature_valid: bool = False
    issuer_key_resolved: bool = False
    issuer_key_trusted: bool = False
    failure_codes: list[str] = field(default_factory=list)
    details: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(
            (
                self.envelope_schema_digest,
                self.envelope,
                self.profile,
                self.supersession_binding,
                self.raw_content_exclusion,
                self.attestation_limits_present,
                self.signature_valid,
                self.issuer_key_resolved,
                self.issuer_key_trusted,
            )
        )

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["passed"] = self.passed
        data["profile_identity"] = PROFILE
        data["profile_source_head"] = PROFILE_SOURCE_HEAD
        data["profile_source_blob_sha1"] = PROFILE_SOURCE_BLOB_SHA1
        return data


def _dedupe(
    report: AdmissionEventV02VerificationReport,
) -> AdmissionEventV02VerificationReport:
    report.failure_codes = list(dict.fromkeys(report.failure_codes))
    report.details = list(dict.fromkeys(report.details))
    return report


def _profile_errors(receipt: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    missing = sorted(v01.REQUIRED - receipt.keys())
    if missing:
        errors.append("admission_event_v02.missing_required:" + ",".join(missing))

    expected = {
        "receipt_version": v01.RECEIPT_VERSION,
        "profile_id": PROFILE_ID,
        "profile_version": PROFILE_VERSION,
        "receipt_type": "provenance",
        "receipt_kind": "admission_event",
        "boundary_type": "admission_event_boundary",
    }
    for key, expected_value in expected.items():
        if receipt.get(key) != expected_value:
            errors.append(f"admission_event_v02.invalid_{key}")

    for key in (
        "receipt_id",
        "protocol_binding",
        "subject_ref",
        "issuer_id",
        "runtime_instance_id",
        "boundary_id",
        "issued_at",
        "namespace_authority_ref",
        "subject_record_ref",
        "subject_edition_ref",
        "governed_result_ref",
        "policy_profile_ref",
        "disposition_id",
    ):
        value = receipt.get(key)
        if not isinstance(value, str) or not value or value.strip() != value:
            errors.append(f"admission_event_v02.invalid_text:{key}")

    if receipt.get("visibility") not in v01.VISIBILITY:
        errors.append("admission_event_v02.invalid_visibility")
    if receipt.get("standing_act") not in v01.STANDING_ACTS:
        errors.append("admission_event_v02.invalid_standing_act")
    if receipt.get("subject_ref") != receipt.get("subject_edition_ref"):
        errors.append("admission_event_v02.subject_binding_mismatch")

    for key in ("governed_result_digest", "policy_digest", "disposition_digest"):
        value = receipt.get(key)
        if not isinstance(value, str) or v01.SHA256_REF.fullmatch(value) is None:
            errors.append(f"admission_event_v02.invalid_digest:{key}")

    basis = receipt.get("basis_refs")
    basis_strings = (
        [item for item in basis if isinstance(item, str)]
        if isinstance(basis, list)
        else []
    )
    if (
        not isinstance(basis, list)
        or not basis
        or len(set(basis_strings)) != len(basis)
        or not all(v01._basis_ref(item) for item in basis)
    ):
        errors.append("admission_event_v02.invalid_basis_refs")

    covered = receipt.get("artifact_classes_covered")
    covered_set = (
        set(covered)
        if isinstance(covered, list) and all(isinstance(x, str) for x in covered)
        else set()
    )
    if not v01.COVERED.issubset(covered_set):
        errors.append("admission_event_v02.missing_required_covered_classes")

    excluded = receipt.get("artifact_classes_excluded")
    excluded_set = (
        set(excluded)
        if isinstance(excluded, list) and all(isinstance(x, str) for x in excluded)
        else set()
    )
    if not v01.EXCLUDED.issubset(excluded_set):
        errors.append("admission_event_v02.missing_required_excluded_classes")

    limitations = receipt.get("machine_limitations")
    codes = (
        {
            item.get("code")
            for item in limitations
            if isinstance(item, Mapping) and isinstance(item.get("code"), str)
        }
        if isinstance(limitations, list)
        else set()
    )
    if "CONTENT_NOT_VERIFIED" not in codes:
        errors.append("admission_event_v02.missing_content_not_verified")

    if any(key in receipt for key in v01.AGGREGATE_KEYS):
        errors.append("admission_event_v02.aggregate_field_present")

    extensions = receipt.get("extensions")
    if not isinstance(extensions, Mapping):
        errors.append("admission_event_v02.extensions_not_object")
        return errors

    supersession = extensions.get("supersession")
    if receipt.get("standing_act") == "SUPERSEDED":
        if not isinstance(supersession, Mapping):
            errors.append("admission_event_v02.supersession_extension_missing")
        else:
            if set(supersession) != SUPERSESSION_KEYS:
                errors.append("admission_event_v02.supersession_extension_shape")
            if supersession.get("kind") != "replacement_admission":
                errors.append("admission_event_v02.supersession_kind_invalid")
            for key in ("predecessor_event_ref", "successor_event_ref"):
                if not v01._basis_ref(supersession.get(key)):
                    errors.append(f"admission_event_v02.invalid_supersession_ref:{key}")
            for key in ("predecessor_event_digest", "successor_event_digest"):
                value = supersession.get(key)
                if not isinstance(value, str) or v01.SHA256_REF.fullmatch(value) is None:
                    errors.append(f"admission_event_v02.invalid_supersession_digest:{key}")
            successor_edition = supersession.get("successor_subject_edition_ref")
            if (
                not isinstance(successor_edition, str)
                or not successor_edition
                or successor_edition.strip() != successor_edition
            ):
                errors.append(
                    "admission_event_v02.invalid_text:successor_subject_edition_ref"
                )
    elif supersession is not None:
        errors.append("admission_event_v02.supersession_extension_wrong_act")
    return errors


def _supersession_errors(receipt: Mapping[str, Any]) -> list[str]:
    extensions = receipt.get("extensions")
    supersession = (
        extensions.get("supersession")
        if isinstance(extensions, Mapping)
        else None
    )
    if receipt.get("standing_act") != "SUPERSEDED":
        return (
            ["admission_event_v02.supersession_extension_wrong_act"]
            if supersession is not None
            else []
        )
    if not isinstance(supersession, Mapping):
        return ["admission_event_v02.supersession_extension_missing"]

    errors: list[str] = []
    predecessor = supersession.get("predecessor_event_ref")
    successor = supersession.get("successor_event_ref")
    if predecessor == successor:
        errors.append("admission_event_v02.supersession_same_event")
    if receipt.get("subject_edition_ref") == supersession.get(
        "successor_subject_edition_ref"
    ):
        errors.append("admission_event_v02.supersession_same_edition")
    basis = receipt.get("basis_refs")
    if not isinstance(basis, list) or predecessor not in basis:
        errors.append("admission_event_v02.predecessor_ref_not_in_basis")
    if not isinstance(basis, list) or successor not in basis:
        errors.append("admission_event_v02.successor_ref_not_in_basis")
    return errors


def verify_admission_event_v0_2_receipt(
    receipt: Mapping[str, Any],
    keyring: Mapping[str, Any],
) -> AdmissionEventV02VerificationReport:
    report = AdmissionEventV02VerificationReport()

    schema_bytes = v01.ENVELOPE_SCHEMA_PATH.read_bytes()
    schema_sha = hashlib.sha256(schema_bytes).hexdigest()
    report.envelope_schema_digest = schema_sha == v01.ENVELOPE_SCHEMA_SHA256
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

    supersession_errors = _supersession_errors(receipt)
    report.supersession_binding = not supersession_errors
    report.failure_codes.extend(supersession_errors)

    raw_errors = v01._raw_content_errors(receipt)
    report.raw_content_exclusion = not raw_errors
    report.failure_codes.extend(raw_errors)

    limits = receipt.get("attestation_limits")
    required_limits = [v01.ATTESTATION_LIMIT]
    if receipt.get("standing_act") == "SUPERSEDED":
        required_limits.append(SUPERSESSION_LIMIT)
    report.attestation_limits_present = (
        isinstance(limits, list)
        and all(limit in limits for limit in required_limits)
        and all(isinstance(item, str) and item.strip() for item in limits)
    )
    if not report.attestation_limits_present:
        report.failure_codes.append("attestation.missing_required_limit")

    signature = receipt.get("receipt_signature")
    if (
        not isinstance(signature, Mapping)
        or set(signature) != v01.SIGNATURE_MEMBERS
        or signature.get("algorithm") != "Ed25519"
        or signature.get("canonicalization") != "RFC8785-JCS"
    ):
        report.failure_codes.append("signature_object_invalid")
        return _dedupe(report)

    key_id = signature.get("key_id")
    entries = keyring.get("issuers", []) if isinstance(keyring, Mapping) else []
    entry = next(
        (
            item
            for item in entries
            if isinstance(item, Mapping) and item.get("key_id") == key_id
        ),
        None,
    )
    report.issuer_key_resolved = entry is not None
    if entry is None:
        report.failure_codes.append("key_id_unresolved")
        return _dedupe(report)

    try:
        public_key = v01._b64url_decode(
            entry.get("public_key"), code="public_key_encoding_invalid"
        )
        signature_bytes = v01._b64url_decode(
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
        issued_at = v01._parse_time(receipt["issued_at"])
        report.issuer_key_trusted = bool(
            entry.get("trusted") is True
            and entry.get("issuer_id") == receipt.get("issuer_id")
            and entry.get("algorithm") in (None, "Ed25519")
            and v01._parse_time(entry["not_before"])
            <= issued_at
            <= v01._parse_time(entry["not_after"])
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

    report = verify_admission_event_v0_2_receipt(receipt, keyring)
    if args.as_json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        for key in (
            "envelope_schema_digest",
            "envelope",
            "profile",
            "supersession_binding",
            "raw_content_exclusion",
            "attestation_limits_present",
            "signature_valid",
            "issuer_key_resolved",
            "issuer_key_trusted",
        ):
            print(f"{key}: {'PASS' if getattr(report, key) else 'FAIL'}")
        for code in report.failure_codes:
            print(f"failure: {code}")
    return 0 if report.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
