"""Deterministic findings projection over already-computed ARCS Verify reports.

This module does not verify receipts. It projects the fields already computed
by an independent verifier into a compact read-only observation surface.
PASS/FAIL here means only that the named verifier check passed/failed.
It never means truth, source quality, authenticity of a real-world claim,
admission, standing, publication eligibility, authorization, or certification.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Literal

from arcs_verify import admission_event as v01
from arcs_verify import admission_event_v0_2 as v02
from arcs_verify.admission_event_v0_3 import (
    AdmissionEventV03VerificationReport,
    CONTENT_DIGEST_ABSENT,
    CONTENT_DIGEST_DISCLOSURE_LIMIT,
    CONTENT_DIGEST_MALFORMED,
    CONTENT_DIGEST_PROVENANCE_ABSENT,
    CONTENT_DIGEST_PROVENANCE_INVALID,
    DIVERGED,
    MATCH,
    NOT_EVALUATED,
)

FINDINGS_CONTRACT = "arcs.verify.findings/v0.1"

_V03_CHECK_FIELDS: tuple[str, ...] = (
    "envelope_schema_digest",
    "envelope",
    "profile_schema_digest",
    "profile",
    "supersession_binding",
    "authority_field_exclusion",
    "raw_content_exclusion",
    "attestation_limits_present",
    "signature_valid",
    "issuer_key_resolved",
    "issuer_key_trusted",
)

_V03_NOT_EVALUATED_REASONS = frozenset(
    {
        CONTENT_DIGEST_ABSENT,
        CONTENT_DIGEST_MALFORMED,
        CONTENT_DIGEST_PROVENANCE_ABSENT,
        CONTENT_DIGEST_PROVENANCE_INVALID,
    }
)

# Exact non-parameterized failure identities emitted by the v0.3 verifier and
# the v0.1/v0.2 verifier-owned helpers it explicitly calls. The parameterized
# authority/raw-content families are validated structurally below against the
# same verifier-owned key vocabularies; arbitrary future strings never become
# reassuring generic findings by accident.
_V03_FIXED_FAILURE_CODES = frozenset(
    {
        "schema.digest_mismatch",
        "envelope.schema_unreadable",
        "envelope.schema_invalid",
        "profile_schema.unreadable",
        "profile_schema.source_blob_mismatch",
        "profile_schema.invalid",
        "admission_event_v03.profile_schema_invalid",
        "admission_event_v02.subject_binding_mismatch",
        "admission_event_v02.supersession_extension_missing",
        "admission_event_v02.supersession_same_event",
        "admission_event_v02.supersession_same_edition",
        "admission_event_v02.supersession_cross_record",
        "admission_event_v02.predecessor_ref_not_in_basis",
        "admission_event_v02.successor_ref_not_in_basis",
        "admission_event_v02.semantic_owner_binding_ref_not_in_basis",
        "raw_content.prohibited_value",
        "attestation.missing_required_limit",
        "signature_object_invalid",
        "key_id_unresolved",
        "public_key_encoding_invalid",
        "signature_encoding_invalid",
        "preimage_canonicalization_failed",
        "signature_invalid",
        "key_untrusted",
        "verified_receipt_canonicalization_failed",
    }
)

_RAW_DYNAMIC_PREFIXES = frozenset(
    {
        "raw_content.invalid_digest_evidence",
        "raw_content.invalid_reference_evidence",
        "raw_content.invalid_identifier_evidence",
        "raw_content.forbidden_key",
    }
)


@dataclass(frozen=True)
class VerificationFinding:
    check_id: str
    status: Literal["PASS", "FAIL"]


@dataclass(frozen=True)
class VerificationDisclosure:
    disclosure_id: str
    state: Literal["MATCH", "DIVERGED", "NOT_EVALUATED"]
    reason: str | None


@dataclass(frozen=True)
class VerificationFindingsProjection:
    contract: str
    verifier_family: str
    overall_passed: bool
    findings: tuple[VerificationFinding, ...]
    failure_codes: tuple[str, ...]
    disclosures: tuple[VerificationDisclosure, ...]
    boundary: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract": self.contract,
            "verifier_family": self.verifier_family,
            "overall_passed": self.overall_passed,
            "findings": [asdict(item) for item in self.findings],
            "failure_codes": list(self.failure_codes),
            "disclosures": [asdict(item) for item in self.disclosures],
            "boundary": self.boundary,
        }


def _is_owned_dynamic_failure_code(code: str) -> bool:
    prefix, separator, key = code.partition(":")
    if separator != ":" or not key:
        return False

    normalized = v01._normalize_key(key)
    if prefix == "authority_field.forbidden":
        return normalized in v02.AUTHORITY_SHAPED_KEYS

    if prefix not in _RAW_DYNAMIC_PREFIXES or v01.RAW_KEY_RE.search(normalized) is None:
        return False

    if normalized.endswith(("_digest", "_hash")):
        expected = "raw_content.invalid_digest_evidence"
    elif normalized.endswith(("_ref", "_refs")):
        expected = "raw_content.invalid_reference_evidence"
    elif normalized.endswith(("_id", "_ids")):
        expected = "raw_content.invalid_identifier_evidence"
    else:
        expected = "raw_content.forbidden_key"
    return prefix == expected


def _is_owned_v03_failure_code(code: str) -> bool:
    return code in _V03_FIXED_FAILURE_CODES or _is_owned_dynamic_failure_code(code)


def _validate_disclosure(comparison: str, reason: str | None) -> None:
    if comparison not in {MATCH, DIVERGED, NOT_EVALUATED}:
        raise ValueError(f"unknown content_digest_comparison state: {comparison!r}")
    if comparison in {MATCH, DIVERGED}:
        if reason is not None:
            raise ValueError(
                "MATCH/DIVERGED content_digest_comparison must carry reason=None"
            )
        return
    if reason not in _V03_NOT_EVALUATED_REASONS:
        raise ValueError(
            f"unregistered NOT_EVALUATED content_digest_comparison_reason: {reason!r}"
        )


def project_admission_event_v03_findings(
    report: AdmissionEventV03VerificationReport,
) -> VerificationFindingsProjection:
    """Project a completed v0.3 report without re-running any verifier logic."""

    if not isinstance(report, AdmissionEventV03VerificationReport):
        raise TypeError("expected AdmissionEventV03VerificationReport")

    check_values: dict[str, bool] = {}
    for field_name in _V03_CHECK_FIELDS:
        value = getattr(report, field_name)
        if type(value) is not bool:
            raise ValueError(
                f"v0.3 verifier check {field_name!r} must be an exact bool, got {type(value).__name__}"
            )
        check_values[field_name] = value

    failure_codes: list[str] = []
    for code in report.failure_codes:
        if not isinstance(code, str) or not code.strip():
            raise ValueError("verifier failure_codes must contain non-empty strings")
        if not _is_owned_v03_failure_code(code):
            raise ValueError(f"unregistered v0.3 verifier failure_code: {code!r}")
        failure_codes.append(code)

    comparison = report.content_digest_comparison
    reason = report.content_digest_comparison_reason
    _validate_disclosure(comparison, reason)

    findings = tuple(
        VerificationFinding(
            check_id=field_name,
            status="PASS" if check_values[field_name] else "FAIL",
        )
        for field_name in _V03_CHECK_FIELDS
    )

    # Failure-code identity is carried verbatim from the verifier report.
    # Canonical projection order is lexical and deduplicated; no code is
    # translated into a score, severity, truth label, or semantic synonym.
    carried_codes = tuple(sorted(set(failure_codes)))

    disclosures = (
        VerificationDisclosure(
            disclosure_id="content_digest_comparison",
            state=comparison,
            reason=reason,
        ),
    )

    return VerificationFindingsProjection(
        contract=FINDINGS_CONTRACT,
        verifier_family="srs.activity.admission_event.v0.3",
        overall_passed=report.passed,
        findings=findings,
        failure_codes=carried_codes,
        disclosures=disclosures,
        boundary=CONTENT_DIGEST_DISCLOSURE_LIMIT,
    )
