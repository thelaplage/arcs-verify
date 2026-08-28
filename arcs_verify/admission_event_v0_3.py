"""Independent verifier for ``srs.activity.admission_event.v0.3``.

The v0.3 profile schema is vendored byte-identically from the exact arcs-srs
source blob and validated directly. v0.3 is an additive successor to v0.2: it
adds two OPTIONAL, top-level-promoted fields to the supersession extension --
``predecessor_captured_bytes_digest`` / ``successor_captured_bytes_digest`` --
plus optional per-side evidence qualifiers (``*_captured_bytes_digest_source``,
``*_bytes_currently_retrievable``). See
``schemas/activity-profiles/v0.3/srs.activity.admission_event.v0.3.schema.json``
(arcs-srs) and ``docs/profiles/SRS_ACTIVITY_ADMISSION_EVENT_PROFILE_v0_3.md``:
"This profile performs no comparison, divergence classification, or
interpretation of the content-digest fields; that is exclusively the
independent verifier's responsibility (arcs-verify), never this profile's or
the producer's."

This module is that independent verifier's responsibility. It adds a single
new output, ``content_digest_comparison`` (tri-state: DIVERGED / MATCH /
NOT_EVALUATED) with a ``content_digest_comparison_reason``
(CONTENT_DIGEST_ABSENT / CONTENT_DIGEST_MALFORMED /
CONTENT_DIGEST_PROVENANCE_ABSENT / null). The comparison is computed by
independent, literal-string comparison of the two wire values exactly as they
appear on the receipt -- it imports no cp/producer canonicalization code and
performs no re-hashing.

Provenance gate: MATCH/DIVERGED are returned only when *all four* of
predecessor digest, successor digest, predecessor
``captured_bytes_digest_source``, and successor ``captured_bytes_digest_source``
are present. A present-but-unsourced digest pair is NOT_EVALUATED
(CONTENT_DIGEST_PROVENANCE_ABSENT), never MATCH/DIVERGED. This gate checks
only *presence* of the digest_source field -- ``bytes_currently_retrievable``
is never part of the gate: ``bytes_currently_retrievable=false`` (the honest
HISTORICAL_CAPTURE_RECORD case, e.g. TH-S09's successor bytes no longer being
fetchable) is evidence-strength disclosure, not a failure or a downgrade, and
must still resolve to DIVERGED/MATCH with the qualifier surfaced verbatim.

READMISSION-CONTENT-BASIS1 ID0 s1.2/s1.4: a content-digest comparison is a
DISCLOSED STRUCTURAL FACT ("these two digests differ/match/were not both
present, sourced, and well-formed"). It is NEVER an authenticity, verification,
admission, standing, or truth verdict, and it never participates in this
report's overall ``passed`` axis. Absence of either digest or either
digest_source is NEVER read as equality -- a NOT_EVALUATED result is never
upgraded to MATCH. No standing/authority-shaped field is emitted from the
comparison itself; the scope of this module stops at the one comparison plus
disclosure of the per-side evidence qualifiers already present on the wire. No
producer/runtime implementation is imported.
"""
from __future__ import annotations

import argparse
import copy
from dataclasses import asdict, dataclass, field
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator

from arcs_verify import admission_event as v01
from arcs_verify import admission_event_v0_2 as v02

REPORT_CONTRACT = "arcs.verify.admission-event-v0.3-report/v0.1"
PROFILE = "srs.activity.admission_event.v0.3"
PROFILE_ID = "srs.activity.admission_event"
PROFILE_VERSION = "v0.3"
# Pinned to the live arcs-srs PR #54 branch head (thelaplage/arcs-srs,
# feat/supersession-content-digest0), matching the existing precedent of
# pinning to a live, unmerged PR head established for v0.2 (VERIFY1-RECONCILE).
PROFILE_SOURCE_HEAD = "965d080c6fd2e2378221eaaad2862b1ec0e17f47"
PROFILE_SOURCE_PATH = (
    "schemas/activity-profiles/v0.3/"
    "srs.activity.admission_event.v0.3.schema.json"
)
PROFILE_SOURCE_BLOB_SHA1 = "6f0f4228187137ebbf2b8486d982f1ebc6291d59"
PROFILE_SCHEMA_PATH = (
    Path(__file__).resolve().parent
    / "data"
    / "srs.activity.admission_event.v0.3.schema.json"
)

# Independent, verifier-owned digest-shape check. Deliberately re-declared
# here (rather than imported) so this comparison never depends on the vendored
# profile schema's own `sha256_ref` pattern object -- the two must agree by
# construction, not by reuse, so a schema mutation cannot silently change what
# "well-formed" means for the tri-state comparison.
CONTENT_DIGEST_REF = re.compile(r"^sha256:[0-9a-f]{64}$")

DIVERGED = "DIVERGED"
MATCH = "MATCH"
NOT_EVALUATED = "NOT_EVALUATED"
CONTENT_DIGEST_ABSENT = "CONTENT_DIGEST_ABSENT"
CONTENT_DIGEST_MALFORMED = "CONTENT_DIGEST_MALFORMED"
CONTENT_DIGEST_PROVENANCE_ABSENT = "CONTENT_DIGEST_PROVENANCE_ABSENT"

CONTENT_DIGEST_DISCLOSURE_LIMIT = (
    "The content_digest_comparison and content_digest_comparison_reason fields "
    "record a literal structural comparison of two OPTIONAL, self-reported "
    "digest strings. They are not a verification, authenticity check, "
    "admission, standing, or truth determination, and they do not establish "
    "that either digest is bound to a genuine capture, that any bytes were "
    "re-hashed by this verifier, or that a governed trigger occurred."
)


@dataclass
class AdmissionEventV03VerificationReport:
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
    # Disclosed structural fact -- see module docstring. Deliberately outside
    # the `passed` axis: DIVERGED (or NOT_EVALUATED) never fails an otherwise
    # valid, correctly signed v0.3 admission-event receipt.
    content_digest_comparison: str = NOT_EVALUATED
    content_digest_comparison_reason: str | None = CONTENT_DIGEST_ABSENT
    predecessor_captured_bytes_digest_source: str | None = None
    successor_captured_bytes_digest_source: str | None = None
    predecessor_bytes_currently_retrievable: bool | None = None
    successor_bytes_currently_retrievable: bool | None = None
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


def _dedupe(report: AdmissionEventV03VerificationReport) -> AdmissionEventV03VerificationReport:
    report.failure_codes = list(dict.fromkeys(report.failure_codes))
    report.details = list(dict.fromkeys(report.details))
    return report


def _profile_schema(report: AdmissionEventV03VerificationReport) -> dict[str, Any] | None:
    try:
        data = PROFILE_SCHEMA_PATH.read_bytes()
    except OSError as exc:
        report.failure_codes.append("profile_schema.unreadable")
        report.details.append(str(exc))
        return None
    report.profile_schema_sha256 = "sha256:" + hashlib.sha256(data).hexdigest()
    report.profile_schema_digest = v02._git_blob_sha1(data) == PROFILE_SOURCE_BLOB_SHA1
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


def _extract_supersession(receipt: Mapping[str, Any]) -> Mapping[str, Any] | None:
    extensions = receipt.get("extensions")
    if not isinstance(extensions, Mapping):
        return None
    supersession = extensions.get("supersession")
    return supersession if isinstance(supersession, Mapping) else None


# Internal digest-shape classification (not verifier failure codes -- these
# never reach `failure_codes`/`report.to_dict()`; named as constants rather
# than inlined string literals purely so the repo's structural failure-code
# sweep does not mistake an internal classification return for an emitted
# code).
_SHAPE_ABSENT = "absent"
_SHAPE_MALFORMED = "malformed"
_SHAPE_WELL_FORMED = "well_formed"


def _digest_shape(value: Any) -> str:
    """Classify a single raw digest value as absent / malformed / well_formed.

    A value counts as "present" only if it is a non-empty string; anything
    else (missing key, None, non-string) is treated as absent, never as an
    implicit match or an implicit malformed value.
    """
    if not isinstance(value, str) or value == "":
        return _SHAPE_ABSENT
    if CONTENT_DIGEST_REF.fullmatch(value) is None:
        return _SHAPE_MALFORMED
    return _SHAPE_WELL_FORMED


def _source_present(value: Any) -> bool:
    """Presence-only check for a per-side ``captured_bytes_digest_source``.

    This is deliberately a presence check, not a format/enum check: the
    provenance gate cares only whether a digest_source was disclosed at all,
    not the specific value. It never inspects ``bytes_currently_retrievable``
    -- that qualifier is evidence-strength disclosure, never part of the gate.
    """
    return isinstance(value, str) and value != ""


def compare_content_digests(receipt: Mapping[str, Any]) -> tuple[str, str | None]:
    """Independently compute the tri-state content-digest comparison.

    Reads only ``extensions.supersession.predecessor_captured_bytes_digest``,
    ``...successor_captured_bytes_digest``, and the two
    ``*_captured_bytes_digest_source`` qualifiers directly off the receipt and
    performs a literal Python string comparison. No hashing, no
    canonicalization, no producer code. Absence on either side is NEVER
    reported as MATCH.

    Provenance gate: MATCH/DIVERGED are returned only when both digests are
    present + well-formed AND both digest_source qualifiers are present.
    ``bytes_currently_retrievable`` is never consulted here -- a digest pair
    whose bytes are no longer retrievable (source=HISTORICAL_CAPTURE_RECORD,
    retrievable=false) still resolves to MATCH/DIVERGED as long as both
    digests and both sources are present; only a *missing* digest_source
    triggers CONTENT_DIGEST_PROVENANCE_ABSENT.
    """
    supersession = _extract_supersession(receipt)
    predecessor = supersession.get("predecessor_captured_bytes_digest") if supersession else None
    successor = supersession.get("successor_captured_bytes_digest") if supersession else None

    predecessor_shape = _digest_shape(predecessor)
    successor_shape = _digest_shape(successor)

    if predecessor_shape == _SHAPE_ABSENT or successor_shape == _SHAPE_ABSENT:
        return NOT_EVALUATED, CONTENT_DIGEST_ABSENT
    if predecessor_shape == _SHAPE_MALFORMED or successor_shape == _SHAPE_MALFORMED:
        return NOT_EVALUATED, CONTENT_DIGEST_MALFORMED

    predecessor_source = supersession.get("predecessor_captured_bytes_digest_source") if supersession else None
    successor_source = supersession.get("successor_captured_bytes_digest_source") if supersession else None
    if not _source_present(predecessor_source) or not _source_present(successor_source):
        return NOT_EVALUATED, CONTENT_DIGEST_PROVENANCE_ABSENT

    if predecessor == successor:
        return MATCH, None
    return DIVERGED, None


def _capture_content_digest_comparison(
    report: AdmissionEventV03VerificationReport,
    receipt: Mapping[str, Any],
) -> None:
    comparison, reason = compare_content_digests(receipt)
    report.content_digest_comparison = comparison
    report.content_digest_comparison_reason = reason

    supersession = _extract_supersession(receipt)
    if supersession is None:
        return
    pred_source = supersession.get("predecessor_captured_bytes_digest_source")
    report.predecessor_captured_bytes_digest_source = (
        pred_source if isinstance(pred_source, str) else None
    )
    succ_source = supersession.get("successor_captured_bytes_digest_source")
    report.successor_captured_bytes_digest_source = (
        succ_source if isinstance(succ_source, str) else None
    )
    pred_retrievable = supersession.get("predecessor_bytes_currently_retrievable")
    report.predecessor_bytes_currently_retrievable = (
        pred_retrievable if isinstance(pred_retrievable, bool) else None
    )
    succ_retrievable = supersession.get("successor_bytes_currently_retrievable")
    report.successor_bytes_currently_retrievable = (
        succ_retrievable if isinstance(succ_retrievable, bool) else None
    )


def verify_admission_event_v0_3_receipt(
    receipt: Mapping[str, Any],
    keyring: Mapping[str, Any],
) -> AdmissionEventV03VerificationReport:
    report = AdmissionEventV03VerificationReport()

    # The tri-state comparison is computed independently of, and prior to, all
    # other checks below: it must never be gated on (or upgraded by) schema,
    # supersession-binding, or signature outcomes.
    _capture_content_digest_comparison(report, receipt)

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
            report.failure_codes.append("admission_event_v03.profile_schema_invalid")
            report.details.append(error.message)

    supersession_errors = v02._supersession_errors(receipt)
    report.supersession_binding = not supersession_errors
    report.failure_codes.extend(supersession_errors)

    authority_errors = v02._authority_errors(receipt)
    report.authority_field_exclusion = not authority_errors
    report.failure_codes.extend(authority_errors)

    raw_errors = v01._raw_content_errors(receipt)
    report.raw_content_exclusion = not raw_errors
    report.failure_codes.extend(raw_errors)

    limits = receipt.get("attestation_limits")
    required_limits = [v01.ATTESTATION_LIMIT]
    if receipt.get("standing_act") == "SUPERSEDED":
        required_limits.append(v02.SUPERSESSION_LIMIT)
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
        v02._capture_verified_identity(report, receipt)
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
        v02._capture_verified_identity(report, receipt)
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
        v02._capture_verified_identity(report, receipt)
        return _dedupe(report)

    preimage = copy.deepcopy(dict(receipt))
    del preimage["receipt_signature"]["signature"]
    try:
        canonical = rfc8785.dumps(preimage)
    except Exception:
        report.failure_codes.append("preimage_canonicalization_failed")
        v02._capture_verified_identity(report, receipt)
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

    v02._capture_verified_identity(report, receipt)
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

    report = verify_admission_event_v0_3_receipt(receipt, keyring)
    if args.as_json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        for key in (
            "envelope_schema_digest", "envelope", "profile_schema_digest", "profile",
            "supersession_binding", "authority_field_exclusion", "raw_content_exclusion",
            "attestation_limits_present", "signature_valid", "issuer_key_resolved", "issuer_key_trusted",
        ):
            print(f"{key}: {'PASS' if getattr(report, key) else 'FAIL'}")
        print(f"content_digest_comparison: {report.content_digest_comparison}")
        print(f"content_digest_comparison_reason: {report.content_digest_comparison_reason}")
        if report.profile_schema_sha256:
            print(f"profile_schema_sha256: {report.profile_schema_sha256}")
        if report.verified_receipt_canonical_json_sha256:
            print(f"verified_receipt_canonical_json_sha256: {report.verified_receipt_canonical_json_sha256}")
        for code in report.failure_codes:
            print(f"failure: {code}")
    return 0 if report.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
