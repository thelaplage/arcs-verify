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

from arcs_verify.admission_event_v0_3 import (
    AdmissionEventV03VerificationReport,
    CONTENT_DIGEST_DISCLOSURE_LIMIT,
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


def project_admission_event_v03_findings(
    report: AdmissionEventV03VerificationReport,
) -> VerificationFindingsProjection:
    """Project a completed v0.3 report without re-running any verifier logic."""

    if not isinstance(report, AdmissionEventV03VerificationReport):
        raise TypeError("expected AdmissionEventV03VerificationReport")

    failure_codes: list[str] = []
    for code in report.failure_codes:
        if not isinstance(code, str) or not code.strip():
            raise ValueError("verifier failure_codes must contain non-empty strings")
        failure_codes.append(code)

    comparison = report.content_digest_comparison
    if comparison not in {MATCH, DIVERGED, NOT_EVALUATED}:
        raise ValueError(f"unknown content_digest_comparison state: {comparison!r}")

    findings = tuple(
        VerificationFinding(
            check_id=field_name,
            status="PASS" if getattr(report, field_name) is True else "FAIL",
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
            reason=report.content_digest_comparison_reason,
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
