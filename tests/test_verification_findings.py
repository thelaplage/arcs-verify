from arcs_verify.admission_event_v0_3 import (
    AdmissionEventV03VerificationReport,
    DIVERGED,
    MATCH,
)
from arcs_verify.findings import (
    FINDINGS_CONTRACT,
    project_admission_event_v03_findings,
)


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


def test_projects_all_verifier_checks_without_reverification() -> None:
    report = _passing_report()
    projection = project_admission_event_v03_findings(report)

    assert projection.contract == FINDINGS_CONTRACT
    assert projection.overall_passed is True
    assert [item.check_id for item in projection.findings] == list(_CHECK_FIELDS)
    assert all(item.status == "PASS" for item in projection.findings)


def test_failure_codes_are_carried_verbatim_deduped_and_order_stable() -> None:
    report = _passing_report()
    report.signature_valid = False
    report.failure_codes = ["signature_invalid", "key_untrusted", "signature_invalid"]

    projection = project_admission_event_v03_findings(report)

    assert projection.overall_passed is False
    assert projection.failure_codes == ("key_untrusted", "signature_invalid")
    signature = next(item for item in projection.findings if item.check_id == "signature_valid")
    assert signature.status == "FAIL"


def test_content_divergence_is_disclosure_not_failure() -> None:
    report = _passing_report()
    report.content_digest_comparison = DIVERGED
    report.content_digest_comparison_reason = None

    projection = project_admission_event_v03_findings(report)

    assert projection.overall_passed is True
    assert all(item.status == "PASS" for item in projection.findings)
    assert projection.disclosures[0].state == "DIVERGED"
    assert "truth determination" in projection.boundary


def test_projection_is_deterministic_under_failure_code_input_order() -> None:
    left = _passing_report()
    right = _passing_report()
    left.failure_codes = ["signature_invalid", "key_untrusted"]
    right.failure_codes = ["key_untrusted", "signature_invalid"]

    assert project_admission_event_v03_findings(left).to_dict() == project_admission_event_v03_findings(right).to_dict()


def test_invalid_failure_code_fails_closed() -> None:
    report = _passing_report()
    report.failure_codes = [""]

    try:
        project_admission_event_v03_findings(report)
    except ValueError as exc:
        assert "non-empty strings" in str(exc)
    else:
        raise AssertionError("empty failure code must fail closed")


def test_unknown_disclosure_state_fails_closed() -> None:
    report = _passing_report()
    report.content_digest_comparison = "SAME_ENOUGH"

    try:
        project_admission_event_v03_findings(report)
    except ValueError as exc:
        assert "unknown content_digest_comparison" in str(exc)
    else:
        raise AssertionError("unknown comparison state must fail closed")
