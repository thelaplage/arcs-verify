from __future__ import annotations

import pytest

from arcs_verify.admission_event_v0_3 import (
    AdmissionEventV03VerificationReport,
    CONTENT_DIGEST_ABSENT,
    DIVERGED,
    MATCH,
    NOT_EVALUATED,
)
from arcs_verify.findings import project_admission_event_v03_findings


_CHECK_FIELDS = (
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


def _passing_report() -> AdmissionEventV03VerificationReport:
    report = AdmissionEventV03VerificationReport()
    for field_name in _CHECK_FIELDS:
        setattr(report, field_name, True)
    report.content_digest_comparison = MATCH
    report.content_digest_comparison_reason = None
    return report


def test_non_boolean_check_value_fails_closed() -> None:
    report = _passing_report()
    report.signature_valid = 1  # type: ignore[assignment]
    with pytest.raises(ValueError, match="must be an exact bool"):
        project_admission_event_v03_findings(report)


def test_match_or_diverged_cannot_carry_an_unowned_reason() -> None:
    for state in (MATCH, DIVERGED):
        report = _passing_report()
        report.content_digest_comparison = state
        report.content_digest_comparison_reason = "SOME_REASON"
        with pytest.raises(ValueError, match="must carry reason=None"):
            project_admission_event_v03_findings(report)


def test_not_evaluated_accepts_only_verifier_owned_reason_vocabulary() -> None:
    valid = _passing_report()
    valid.content_digest_comparison = NOT_EVALUATED
    valid.content_digest_comparison_reason = CONTENT_DIGEST_ABSENT
    projection = project_admission_event_v03_findings(valid)
    assert projection.disclosures[0].state == NOT_EVALUATED
    assert projection.disclosures[0].reason == CONTENT_DIGEST_ABSENT

    invalid = _passing_report()
    invalid.content_digest_comparison = NOT_EVALUATED
    invalid.content_digest_comparison_reason = "UNKNOWN_REASON"
    with pytest.raises(ValueError, match="unregistered NOT_EVALUATED"):
        project_admission_event_v03_findings(invalid)
