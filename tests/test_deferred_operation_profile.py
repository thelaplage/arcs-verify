"""Single-receipt profile conformance tests for srs.deferred_operation.v0.1.

Tests verify that:
- Valid fixtures pass profile and envelope findings.
- Invalid fixtures produce the expected failure codes.
- Non-equivalences from the profile spec are not violated.
- Existing verifier profiles are unaffected.
- NOT_EVALUATED is preserved for signature findings when signature is invalid.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from arcs_verify.verifier import (
    DEFERRED_OPERATION_PROFILE,
    MCP_PROFILE,
    verify_receipt,
)

ROOT = Path(__file__).resolve().parents[1]
# The deferred_operation profile requires srs-envelope-v0.2.1 (per manifest
# compatible_envelope_identities). The digest is pinned in verifier.py.
SCHEMA_V021 = ROOT / "arcs_verify" / "data" / "srs-envelope-v0.2.1.schema.json"

# Fixtures sourced from the arcs-srs W2-02 conformance corpus (copied
# verbatim; unsigned placeholder signatures).
ARCS_SRS_VALID = Path(__file__).resolve().parent / "fixtures" / "deferred_srs"
FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures" / "deferred_sequence"
SIGNED_KEYRING = FIXTURE_ROOT / "issuer-keys.json"

EMPTY_KEYRING: dict = {"issuers": []}

BASE_LIMIT = (
    "The receipt establishes the declared event role and associated metadata "
    "at the time of issuance. It does not independently establish that the "
    "governed operation executed, that conditions were actually met, or that "
    "the sequence is complete. Receipt presence is not equivalent to "
    "operational compliance."
)


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def verify(receipt: dict, keyring: dict = EMPTY_KEYRING) -> object:
    return verify_receipt(
        receipt,
        keyring,
        schema_path=SCHEMA_V021,
        selected_profile=DEFERRED_OPERATION_PROFILE,
    )


# ---------------------------------------------------------------------------
# 1. Valid signed fixtures pass profile and envelope
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "fixture_name",
    [
        "defer-signed.json",
        "condition-response-signed.json",
        "terminal-admitted-signed.json",
        "execution-outcome-signed.json",
    ],
    ids=lambda n: n,
)
def test_valid_signed_fixture_passes_profile_and_envelope(fixture_name: str):
    receipt = load(FIXTURE_ROOT / fixture_name)
    report = verify(receipt, load(SIGNED_KEYRING))
    assert report.envelope is True, (fixture_name, report.failure_codes)
    assert report.profile is True, (fixture_name, report.failure_codes)
    assert report.raw_content_exclusion is True, (fixture_name, report.failure_codes)
    assert report.attestation_limits_present is True, (fixture_name, report.failure_codes)
    assert report.signature_valid is True, (fixture_name, report.failure_codes)
    assert report.issuer_key_resolved is True, (fixture_name, report.failure_codes)
    assert report.issuer_key_trusted is True, (fixture_name, report.failure_codes)


# ---------------------------------------------------------------------------
# 2. Invalid receipt_kind fails profile
# ---------------------------------------------------------------------------

def test_invalid_receipt_kind_fails_profile():
    """receipt_kind=admission is not a valid deferred_operation kind."""
    receipt = load(FIXTURE_ROOT / "defer-signed.json")
    receipt = copy.deepcopy(receipt)
    receipt["receipt_kind"] = "admission"
    report = verify(receipt)
    assert report.profile is False
    assert "deferred_operation.invalid_receipt_kind" in report.failure_codes


# ---------------------------------------------------------------------------
# 3. Wrong profile_id fails profile
# ---------------------------------------------------------------------------

def test_wrong_profile_id_fails_profile():
    receipt = copy.deepcopy(load(FIXTURE_ROOT / "defer-signed.json"))
    receipt["profile_id"] = "srs.mcp.sdk_enforcement"
    report = verify(receipt)
    assert report.profile is False
    assert "deferred_operation.invalid_profile_id" in report.failure_codes


# ---------------------------------------------------------------------------
# 4. Wrong receipt_type fails profile
# ---------------------------------------------------------------------------

def test_wrong_receipt_type_fails_profile():
    receipt = copy.deepcopy(load(FIXTURE_ROOT / "defer-signed.json"))
    receipt["receipt_type"] = "sdk_enforcement"
    report = verify(receipt)
    assert report.profile is False
    assert "deferred_operation.invalid_receipt_type" in report.failure_codes


# ---------------------------------------------------------------------------
# 5. Missing sequence_id fails profile
# ---------------------------------------------------------------------------

def test_missing_sequence_id_fails_profile():
    receipt = copy.deepcopy(load(FIXTURE_ROOT / "defer-signed.json"))
    del receipt["sequence_id"]
    report = verify(receipt)
    assert report.profile is False
    assert "deferred_operation.missing_sequence_id" in report.failure_codes


# ---------------------------------------------------------------------------
# 6. Missing base attestation limit fails profile
# ---------------------------------------------------------------------------

def test_missing_base_attestation_limit_fails_profile():
    receipt = copy.deepcopy(load(FIXTURE_ROOT / "defer-signed.json"))
    receipt["attestation_limits"] = ["some other limit"]
    report = verify(receipt)
    assert report.profile is False
    assert "deferred_operation.missing_base_attestation_limit" in report.failure_codes


# ---------------------------------------------------------------------------
# 7. Missing required exclusion fails profile
# ---------------------------------------------------------------------------

def test_missing_required_exclusion_fails_profile():
    receipt = copy.deepcopy(load(FIXTURE_ROOT / "defer-signed.json"))
    receipt["artifact_classes_excluded"] = [
        "raw_prompt",
        "raw_output",
        "raw_tool_result",
        # raw_tool_arguments omitted
    ]
    report = verify(receipt)
    assert report.profile is False
    assert "deferred_operation.missing_required_exclusions" in report.failure_codes


# ---------------------------------------------------------------------------
# 8. defer_request: missing operation_digest fails profile
# ---------------------------------------------------------------------------

def test_defer_request_missing_operation_digest_fails_profile():
    receipt = copy.deepcopy(load(FIXTURE_ROOT / "defer-signed.json"))
    del receipt["operation_digest"]
    report = verify(receipt)
    assert report.profile is False
    assert (
        "deferred_operation.defer_request_missing_operation_digest"
        in report.failure_codes
    )


# ---------------------------------------------------------------------------
# 9. defer_request: invalid disposition fails profile
# ---------------------------------------------------------------------------

def test_defer_request_invalid_disposition_fails_profile():
    receipt = copy.deepcopy(load(FIXTURE_ROOT / "defer-signed.json"))
    receipt["disposition"] = "admitted"
    report = verify(receipt)
    assert report.profile is False
    assert (
        "deferred_operation.defer_request_invalid_disposition"
        in report.failure_codes
    )


# ---------------------------------------------------------------------------
# 10. defer_request: invalid retry_contract fails profile
# ---------------------------------------------------------------------------

def test_defer_request_invalid_retry_contract_fails_profile():
    receipt = copy.deepcopy(load(FIXTURE_ROOT / "defer-signed.json"))
    receipt["retry_contract"] = "retry_after_approval"
    report = verify(receipt)
    assert report.profile is False
    assert (
        "deferred_operation.defer_request_invalid_retry_contract"
        in report.failure_codes
    )


# ---------------------------------------------------------------------------
# 11. condition_response: missing condition_digest fails profile
# ---------------------------------------------------------------------------

def test_condition_response_missing_condition_digest_fails_profile():
    receipt = copy.deepcopy(load(FIXTURE_ROOT / "condition-response-signed.json"))
    del receipt["condition_digest"]
    report = verify(receipt)
    assert report.profile is False
    assert (
        "deferred_operation.condition_response_missing_condition_digest"
        in report.failure_codes
    )


# ---------------------------------------------------------------------------
# 12. condition_response: invalid response_status fails profile
# ---------------------------------------------------------------------------

def test_condition_response_invalid_response_status_fails_profile():
    receipt = copy.deepcopy(
        load(FIXTURE_ROOT / "condition-response-signed.json")
    )
    receipt["response_status"] = "maybe"
    report = verify(receipt)
    assert report.profile is False
    assert (
        "deferred_operation.condition_response_invalid_response_status"
        in report.failure_codes
    )


# ---------------------------------------------------------------------------
# 13. terminal_admission: deferred_for_review disposition fails profile
# ---------------------------------------------------------------------------

def test_terminal_admission_deferred_disposition_fails_profile():
    """disposition=deferred_for_review is not valid at the terminal event."""
    receipt = copy.deepcopy(load(FIXTURE_ROOT / "terminal-admitted-signed.json"))
    receipt["disposition"] = "deferred_for_review"
    report = verify(receipt)
    assert report.profile is False
    assert (
        "deferred_operation.terminal_admission_invalid_disposition"
        in report.failure_codes
    )


# ---------------------------------------------------------------------------
# 14. execution_outcome: invalid outcome value fails profile
# ---------------------------------------------------------------------------

def test_execution_outcome_invalid_outcome_fails_profile():
    receipt = copy.deepcopy(
        load(FIXTURE_ROOT / "execution-outcome-signed.json")
    )
    receipt["outcome"] = "completed_successfully"
    report = verify(receipt)
    assert report.profile is False
    assert (
        "deferred_operation.execution_outcome_invalid_outcome"
        in report.failure_codes
    )


# ---------------------------------------------------------------------------
# 15. execution_outcome: missing terminal_admission_ref fails profile
# ---------------------------------------------------------------------------

def test_execution_outcome_missing_terminal_admission_ref_fails_profile():
    receipt = copy.deepcopy(
        load(FIXTURE_ROOT / "execution-outcome-signed.json")
    )
    del receipt["terminal_admission_ref"]
    report = verify(receipt)
    assert report.profile is False
    assert (
        "deferred_operation.execution_outcome_missing_terminal_admission_ref"
        in report.failure_codes
    )


# ---------------------------------------------------------------------------
# 16. Non-equivalence: approved condition_response ≠ admissible
#     Profile=True for approved condition_response does NOT mean admitted.
# ---------------------------------------------------------------------------

def test_approved_condition_response_not_admission_verdict():
    """
    Non-equivalence (profile spec §7): condition_response.response_status ==
    approved does NOT make the operation admissible. profile=True here does
    not constitute an admission verdict.
    """
    receipt = load(FIXTURE_ROOT / "condition-response-signed.json")
    assert receipt["response_status"] == "approved"
    report = verify(receipt, load(SIGNED_KEYRING))
    # Profile passes structurally — that is correct behavior.
    assert report.profile is True, report.failure_codes
    # BUT: profile=True does NOT mean the operation is admissible.
    # The attestation_limits field contains the explicit disclaimer.
    limits = receipt.get("attestation_limits", [])
    disclaimer_present = any("approved" in lim for lim in limits)
    assert disclaimer_present, (
        "condition_response with response_status=approved must carry an "
        "explicit attestation_limit disclaiming admissibility"
    )


# ---------------------------------------------------------------------------
# 17. NOT_EVALUATED is preserved for signature findings with invalid sig
# ---------------------------------------------------------------------------

def test_not_evaluated_not_promoted_on_bad_signature():
    """
    A structurally valid receipt with a bad signature produces
    signature_valid=False but profile and envelope findings are independent.
    NOT_EVALUATED chain_status is not promoted.
    """
    receipt = copy.deepcopy(load(FIXTURE_ROOT / "defer-signed.json"))
    # Corrupt the signature
    receipt["receipt_signature"]["signature"] = (
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    )
    report = verify(receipt, load(SIGNED_KEYRING))
    # Structural findings are independent of signature
    assert report.profile is True, report.failure_codes
    assert report.envelope is True, report.failure_codes
    # Signature must fail
    assert report.signature_valid is False
    # chain_status is not_applicable (standalone receipt)
    assert report.chain_status == "not_applicable"


# ---------------------------------------------------------------------------
# 18. Existing MCP profile is unaffected by new profile addition
# ---------------------------------------------------------------------------

def test_mcp_profile_unaffected():
    """The existing MCP profile must continue to work after adding deferred_operation."""
    from arcs_verify.verifier import ACCEPTED_SCHEMA_SHA256

    mcp_pack = ROOT / "packs" / "srs.mcp.sdk_enforcement" / "v0.1"
    impl_dir = mcp_pack / "implementation" / "dagr-mcp-fastmcp-demo"
    admission_path = impl_dir / "admission-admitted.json"
    keyring_path = impl_dir / "issuer-keys.json"

    if not admission_path.is_file():
        pytest.skip("MCP fixture pack not present")

    receipt = json.loads(admission_path.read_text(encoding="utf-8"))
    keyring = json.loads(keyring_path.read_text(encoding="utf-8"))
    schema_path = ROOT / "arcs_verify" / "data" / "srs-envelope-v0.2.0.schema.json"
    report = verify_receipt(
        receipt, keyring, schema_path=schema_path, selected_profile=MCP_PROFILE
    )
    assert report.profile is True, report.failure_codes
    assert report.signature_valid is True, report.failure_codes


# ---------------------------------------------------------------------------
# 19. receipt_gap: missing gap_reason fails profile
# ---------------------------------------------------------------------------

def test_receipt_gap_missing_gap_reason_fails_profile():
    receipt = {
        "receipt_version": "srs.core.v5.1",
        "profile_id": "srs.deferred_operation",
        "profile_version": "v0.1",
        "receipt_id": "gap-no-reason-0001",
        "receipt_type": "provenance",
        "receipt_kind": "receipt_gap",
        "boundary_type": "mcp_tool_call",
        "protocol_binding": "mcp",
        "subject_ref": "fixture:gap-subject",
        "issuer_id": "issuer.test/deferred-op/2026-01",
        "issued_at": "2026-01-01T00:00:00Z",
        "sequence_id": "test-gap-seq-0001",
        "artifact_classes_covered": ["trace"],
        "artifact_classes_excluded": [
            "raw_prompt",
            "raw_output",
            "raw_tool_arguments",
            "raw_tool_result",
        ],
        "attestation_limits": [BASE_LIMIT],
        "extensions": {},
        "receipt_signature": {
            "algorithm": "Ed25519",
            "canonicalization": "RFC8785-JCS",
            "key_id": "issuer.test/deferred-op/2026-01",
            "signature": (
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            ),
        },
    }
    report = verify(receipt)
    assert report.profile is False
    assert "deferred_operation.receipt_gap_missing_gap_reason" in report.failure_codes


# ---------------------------------------------------------------------------
# 20. No master status: eight Booleans reported independently
# ---------------------------------------------------------------------------

def test_eight_booleans_reported_independently():
    """No single master status replaces the eight Boolean findings."""
    receipt = copy.deepcopy(load(FIXTURE_ROOT / "defer-signed.json"))
    report = verify(receipt, load(SIGNED_KEYRING))
    report_dict = report.to_dict()
    for field in (
        "schema_digest",
        "envelope",
        "profile",
        "raw_content_exclusion",
        "signature_valid",
        "issuer_key_resolved",
        "issuer_key_trusted",
        "attestation_limits_present",
    ):
        assert field in report_dict, f"missing Boolean finding: {field}"
        assert isinstance(report_dict[field], bool), (
            f"{field} must be a bool, got {type(report_dict[field])}"
        )
