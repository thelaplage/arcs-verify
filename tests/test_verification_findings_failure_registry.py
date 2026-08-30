from __future__ import annotations

import pytest

from arcs_verify.admission_event_v0_3 import AdmissionEventV03VerificationReport, MATCH
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


def _report(*codes: str) -> AdmissionEventV03VerificationReport:
    report = AdmissionEventV03VerificationReport()
    for field_name in _CHECK_FIELDS:
        setattr(report, field_name, True)
    report.content_digest_comparison = MATCH
    report.content_digest_comparison_reason = None
    report.failure_codes = list(codes)
    return report


def test_unknown_future_failure_code_fails_closed() -> None:
    with pytest.raises(ValueError, match="unregistered v0.3 verifier failure_code"):
        project_admission_event_v03_findings(_report("future.reassuring_unknown"))


def test_verifier_owned_parameterized_failure_families_remain_projectable() -> None:
    projection = project_admission_event_v03_findings(
        _report(
            "authority_field.forbidden:trust_score",
            "raw_content.forbidden_key:prompt_text",
            "raw_content.invalid_digest_evidence:result_hash",
        )
    )
    assert projection.failure_codes == (
        "authority_field.forbidden:trust_score",
        "raw_content.forbidden_key:prompt_text",
        "raw_content.invalid_digest_evidence:result_hash",
    )


def test_parameterized_prefix_cannot_smuggle_unowned_key() -> None:
    with pytest.raises(ValueError, match="unregistered v0.3 verifier failure_code"):
        project_admission_event_v03_findings(
            _report("authority_field.forbidden:not_an_authority_shaped_key")
        )
