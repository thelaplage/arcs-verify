"""Independent verifier for ``srs.activity.admission_event.v0.2``.

The v0.2 profile schema is vendored byte-identically from the exact arcs-srs
source blob and validated directly. Python logic below is limited to cross-field
rules JSON Schema cannot express plus verifier-owned cryptographic/raw-content
checks. No producer/runtime implementation is imported.
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

REPORT_CONTRACT = "arcs.verify.admission-event-v0.2-report/v0.1"
PROFILE = "srs.activity.admission_event.v0.2"
PROFILE_ID = "srs.activity.admission_event"
PROFILE_VERSION = "v0.2"
PROFILE_SOURCE_HEAD = "d2e0652b9e2f7b224dbaad042b53acede418b194"
PROFILE_SOURCE_PATH = (
    "schemas/activity-profiles/v0.2/"
    "srs.activity.admission_event.v0.2.schema.json"
)
PROFILE_SOURCE_BLOB_SHA1 = "a91eb860688d4a449d0042174a55706e344a304a"
PROFILE_SCHEMA_PATH = (
    Path(__file__).resolve().parent
    / "data"
    / "srs.activity.admission_event.v0.2.schema.json"
)

SUPERSESSION_LIMIT = (
    "A SUPERSEDED admission-event receipt records replacement by the named "
    "successor admission event. It does not establish that the predecessor was "
    "false, invalid, deleted, or retired; terminal withdrawal without a "
    "replacement is outside this profile."
)

AUTHORITY_SHAPED_KEYS = frozenset(
    {
        "aggregate_verdict",
        "aggregate_activity_verdict",
        "trust_score",
        "reputation",
        "reputation_score",
        "activity_score",
        "reliance_score",
        "standing_score",
        "truth",
        "verified",
        "authority_effect",
        "authority_movement",
        "admission_effect",
        "standing_effect",
        "truth_effect",
        "evidentiary_weight",
        "verdict_weight",
        "corroboration_weight",
    }
)


@dataclass
class AdmissionEventV02VerificationReport:
    envelope_schema_digest: bool = False
    envelope: bool = False
    profile_schema_digest: bool = False
    profile: bool = False
    supersession_binding: bool = False
    authority_field_exclusion: bool = False
    raw_content_exclusion: bool = False
    attestation_limits_present: bool = False
    signature_valid: bool = False
    issuer_key_resolved: bool = False
    issuer_key_trusted: bool = False
    profile_schema_sha256: str | None = None
    verified_receipt_id: str | None = None
    verified_receipt_canonical_json_sha256: str | None = None
    verified_receipt_profile_id: str | None = None
    verified_receipt_profile_version: str | None = None
    verified_subject_record_ref: str | None = None
    verified_subject_edition_ref: str | None = None
    verified_supersession: dict[str, Any] | None = None
    failure_codes: list[str] = field(default_factory=list)
    details: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(
            (
                self.envelope_schema_digest,
                self.envelope,
                self.profile_schema_digest,
                self.profile,
                self.supersession_binding,
                self.authority_field_exclusion,
                self.raw_content_exclusion,
                self.attestation_limits_present,
                self.signature_valid,
                self.issuer_key_resolved,
                self.issuer_key_trusted,
            )
        )

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["report_contract"] = REPORT_CONTRACT
        data["passed"] = self.passed
        data["profile_identity"] = PROFILE
        data["profile_source_head"] = PROFILE_SOURCE_HEAD
        data["profile_source_path"] = PROFILE_SOURCE_PATH
        data["profile_source_blob_sha1"] = PROFILE_SOURCE_BLOB_SHA1
        return data


def _dedupe(report: AdmissionEventV02VerificationReport) -> AdmissionEventV02VerificationReport:
    report.failure_codes = list(dict.fromkeys(report.failure_codes))
    report.details = list(dict.fromkeys(report.details))
    return report


def _git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def _profile_schema(report: AdmissionEventV02VerificationReport) -> dict[str, Any] | None:
    try:
        data = PROFILE_SCHEMA_PATH.read_bytes()
    except OSError as exc:
        report.failure_codes.append("profile_schema.unreadable")
        report.details.append(str(exc))
        return None
    report.profile_schema_sha256 = "sha256:" + hashlib.sha256(data).hexdigest()
    report.profile_schema_digest = _git_blob_sha1(data) == PROFILE_SOURCE_BLOB_SHA1
    if not report.profile_schema_digest:
        report.failure_codes.append("profile_schema.source_blob_mismatch")
        return None
    try:
        schema = json.loads(data)
        Draft202012Validator.check_schema(schema)
    except Exception as exc:
        report.failure_codes.append("profile_schema.invalid")
        report.details.append(str(exc))
        return None
    return schema


def _walk_keys(value: Any):
    if isinstance(value, Mapping):
        for key, item in value.items():
            yield str(key)
            yield from _walk_keys(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_keys(item)


def _authority_errors(receipt: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    for key in _walk_keys(receipt):
        normalized = v01._normalize_key(key)
        if normalized in AUTHORITY_SHAPED_KEYS:
            errors.append(f"authority_field.forbidden:{key}")
    return errors


def _supersession_errors(receipt: Mapping[str, Any]) -> list[str]:
    if receipt.get("subject_ref") != receipt.get("subject_edition_ref"):
        return ["admission_event_v02.subject_binding_mismatch"]

    extensions = receipt.get("extensions")
    supersession = extensions.get("supersession") if isinstance(extensions, Mapping) else None
    if receipt.get("standing_act") != "SUPERSEDED":
        return []
    if not isinstance(supersession, Mapping):
        return ["admission_event_v02.supersession_extension_missing"]

    errors: list[str] = []
    predecessor = supersession.get("predecessor_event_ref")
    successor = supersession.get("successor_event_ref")
    successor_record = supersession.get("successor_subject_record_ref")
    successor_edition = supersession.get("successor_subject_edition_ref")
    owner_binding_ref = supersession.get("semantic_owner_binding_ref")

    if predecessor == successor:
        errors.append("admission_event_v02.supersession_same_event")
    if receipt.get("subject_edition_ref") == successor_edition:
        errors.append("admission_event_v02.supersession_same_edition")
    if receipt.get("subject_record_ref") != successor_record:
        errors.append("admission_event_v02.supersession_cross_record")

    basis = receipt.get("basis_refs")
    if not isinstance(basis, list) or predecessor not in basis:
        errors.append("admission_event_v02.predecessor_ref_not_in_basis")
    if not isinstance(basis, list) or successor not in basis:
        errors.append("admission_event_v02.successor_ref_not_in_basis")
    if not isinstance(basis, list) or owner_binding_ref not in basis:
        errors.append("admission_event_v02.semantic_owner_binding_ref_not_in_basis")
    return errors


def _capture_verified_identity(
    report: AdmissionEventV02VerificationReport,
    receipt: Mapping[str, Any],
) -> None:
    try:
        report.verified_receipt_canonical_json_sha256 = (
            "sha256:" + hashlib.sha256(rfc8785.dumps(dict(receipt))).hexdigest()
        )
    except Exception:
        report.failure_codes.append("verified_receipt_canonicalization_failed")
        return
    report.verified_receipt_id = receipt.get("receipt_id") if isinstance(receipt.get("receipt_id"), str) else None
    report.verified_receipt_profile_id = receipt.get("profile_id") if isinstance(receipt.get("profile_id"), str) else None
    report.verified_receipt_profile_version = receipt.get("profile_version") if isinstance(receipt.get("profile_version"), str) else None
    report.verified_subject_record_ref = receipt.get("subject_record_ref") if isinstance(receipt.get("subject_record_ref"), str) else None
    report.verified_subject_edition_ref = receipt.get("subject_edition_ref") if isinstance(receipt.get("subject_edition_ref"), str) else None
    if receipt.get("standing_act") == "SUPERSEDED" and report.profile and report.supersession_binding:
        extensions = receipt.get("extensions")
        if isinstance(extensions, Mapping) and isinstance(extensions.get("supersession"), Mapping):
            report.verified_supersession = copy.deepcopy(dict(extensions["supersession"]))


def verify_admission_event_v0_2_receipt(
    receipt: Mapping[str, Any],
    keyring: Mapping[str, Any],
) -> AdmissionEventV02VerificationReport:
    report = AdmissionEventV02VerificationReport()

    envelope_bytes = v01.ENVELOPE_SCHEMA_PATH.read_bytes()
    envelope_sha = hashlib.sha256(envelope_bytes).hexdigest()
    report.envelope_schema_digest = envelope_sha == v01.ENVELOPE_SCHEMA_SHA256
    if not report.envelope_schema_digest:
        report.failure_codes.append("schema.digest_mismatch")

    try:
        envelope_schema = json.loads(envelope_bytes)
        envelope_errors = sorted(
            Draft202012Validator(envelope_schema).iter_errors(dict(receipt)),
            key=lambda error: list(error.path),
        )
    except Exception as exc:
        report.failure_codes.append("envelope.schema_unreadable")
        report.details.append(str(exc))
        return _dedupe(report)
    report.envelope = not envelope_errors
    for error in envelope_errors:
        report.failure_codes.append("envelope.schema_invalid")
        report.details.append(error.message)

    schema = _profile_schema(report)
    if schema is not None:
        profile_errors = sorted(
            Draft202012Validator(schema).iter_errors(dict(receipt)),
            key=lambda error: list(error.path),
        )
        report.profile = not profile_errors
        for error in profile_errors:
            report.failure_codes.append("admission_event_v02.profile_schema_invalid")
            report.details.append(error.message)

    supersession_errors = _supersession_errors(receipt)
    report.supersession_binding = not supersession_errors
    report.failure_codes.extend(supersession_errors)

    authority_errors = _authority_errors(receipt)
    report.authority_field_exclusion = not authority_errors
    report.failure_codes.extend(authority_errors)

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
        _capture_verified_identity(report, receipt)
        return _dedupe(report)

    key_id = signature.get("key_id")
    entries = keyring.get("issuers", []) if isinstance(keyring, Mapping) else []
    entry = next(
        (item for item in entries if isinstance(item, Mapping) and item.get("key_id") == key_id),
        None,
    )
    report.issuer_key_resolved = entry is not None
    if entry is None:
        report.failure_codes.append("key_id_unresolved")
        _capture_verified_identity(report, receipt)
        return _dedupe(report)

    try:
        public_key = v01._b64url_decode(entry.get("public_key"), code="public_key_encoding_invalid")
        signature_bytes = v01._b64url_decode(signature.get("signature"), code="signature_encoding_invalid")
        if len(public_key) != 32:
            raise ValueError("public_key_encoding_invalid")
        if len(signature_bytes) != 64:
            raise ValueError("signature_encoding_invalid")
    except ValueError as exc:
        report.failure_codes.append(str(exc))
        _capture_verified_identity(report, receipt)
        return _dedupe(report)

    preimage = copy.deepcopy(dict(receipt))
    del preimage["receipt_signature"]["signature"]
    try:
        canonical = rfc8785.dumps(preimage)
    except Exception:
        report.failure_codes.append("preimage_canonicalization_failed")
        _capture_verified_identity(report, receipt)
        return _dedupe(report)

    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature_bytes, canonical)
        report.signature_valid = True
    except InvalidSignature:
        report.failure_codes.append("signature_invalid")

    try:
        issued_at = v01._parse_time(receipt["issued_at"])
        report.issuer_key_trusted = bool(
            entry.get("trusted") is True
            and entry.get("issuer_id") == receipt.get("issuer_id")
            and entry.get("algorithm") in (None, "Ed25519")
            and v01._parse_time(entry["not_before"]) <= issued_at <= v01._parse_time(entry["not_after"])
        )
    except Exception:
        report.issuer_key_trusted = False
    if not report.issuer_key_trusted:
        report.failure_codes.append("key_untrusted")

    _capture_verified_identity(report, receipt)
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
            "envelope_schema_digest", "envelope", "profile_schema_digest", "profile",
            "supersession_binding", "authority_field_exclusion", "raw_content_exclusion",
            "attestation_limits_present", "signature_valid", "issuer_key_resolved", "issuer_key_trusted",
        ):
            print(f"{key}: {'PASS' if getattr(report, key) else 'FAIL'}")
        if report.profile_schema_sha256:
            print(f"profile_schema_sha256: {report.profile_schema_sha256}")
        if report.verified_receipt_canonical_json_sha256:
            print(f"verified_receipt_canonical_json_sha256: {report.verified_receipt_canonical_json_sha256}")
        for code in report.failure_codes:
            print(f"failure: {code}")
    return 0 if report.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
