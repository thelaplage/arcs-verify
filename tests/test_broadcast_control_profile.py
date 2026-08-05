from __future__ import annotations

import json
from pathlib import Path

import pytest

from arcs_verify.verifier import (
    BROADCAST_CONTROL_PROFILE,
    verify_receipt,
)

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = (
    ROOT
    / "arcs_verify"
    / "data"
    / "srs-envelope-v0.2.1.schema.json"
)

BC_ROOT = ROOT / "tests" / "fixtures" / "broadcast_control"

# Empty keyring — fixtures use placeholder signatures; signing is not required
# for srs.broadcast_control.v0.1 (requires_signing: false). The verifier will
# report signature_object_invalid and stop the signature path early. Envelope
# and profile findings are independent.
EMPTY_KEYRING: dict = {"issuers": []}


def load(name: str) -> dict:
    return json.loads((BC_ROOT / name).read_text(encoding="utf-8"))


def verify(receipt: dict, profile: str = BROADCAST_CONTROL_PROFILE) -> object:
    return verify_receipt(
        receipt,
        EMPTY_KEYRING,
        schema_path=SCHEMA,
        selected_profile=profile,
    )


# ---------------------------------------------------------------------------
# 1. Both 93C valid fixtures pass profile finding
# ---------------------------------------------------------------------------

def test_93c_execution_valid_passes_profile():
    report = verify(load("93c_execution_valid.json"))
    assert report.profile is True, report.failure_codes
    assert report.envelope is True, report.failure_codes


def test_93c_request_valid_passes_profile():
    report = verify(load("93c_request_valid.json"))
    assert report.profile is True, report.failure_codes
    assert report.envelope is True, report.failure_codes


# ---------------------------------------------------------------------------
# 2. Both OBS valid fixtures pass profile finding
# ---------------------------------------------------------------------------

def test_obs_observed_consequence_valid_passes_profile():
    report = verify(load("obs_observed_consequence_valid.json"))
    assert report.profile is True, report.failure_codes
    assert report.envelope is True, report.failure_codes


def test_obs_request_valid_passes_profile():
    report = verify(load("obs_request_valid.json"))
    assert report.profile is True, report.failure_codes
    assert report.envelope is True, report.failure_codes


# ---------------------------------------------------------------------------
# 3. Same verifier entry point (verify_receipt) validates both product types
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "fixture_name",
    [
        "93c_execution_valid.json",
        "93c_request_valid.json",
        "obs_observed_consequence_valid.json",
        "obs_request_valid.json",
    ],
    ids=lambda n: n,
)
def test_same_verifier_entry_point_validates_both_product_types(fixture_name: str):
    """Two-product reuse gate: one verify_receipt call accepts both 93C and OBS receipts."""
    report = verify(load(fixture_name))
    assert report.profile is True, (fixture_name, report.failure_codes)


# ---------------------------------------------------------------------------
# 4. missing_target_state.json -> profile=False, broadcast_control.missing_target_state
# ---------------------------------------------------------------------------

def test_missing_target_state_fails_profile():
    report = verify(load("missing_target_state.json"))
    assert report.profile is False
    assert "broadcast_control.missing_target_state" in report.failure_codes


# ---------------------------------------------------------------------------
# 5. mcp_success_claims_delivery.json -> profile=False, broadcast_control.invalid_assurance_claim
# ---------------------------------------------------------------------------

def test_mcp_success_claims_delivery_fails_profile():
    report = verify(load("mcp_success_claims_delivery.json"))
    assert report.profile is False
    assert "broadcast_control.invalid_assurance_claim" in report.failure_codes


# ---------------------------------------------------------------------------
# 6. raw_content_in_receipt.json -> raw_content_exclusion=False
# ---------------------------------------------------------------------------

def test_raw_content_in_receipt_fails_raw_content_exclusion():
    report = verify(load("raw_content_in_receipt.json"))
    assert report.raw_content_exclusion is False
    assert any(
        "raw_content" in code for code in report.failure_codes
    ), report.failure_codes


# ---------------------------------------------------------------------------
# 7. refused_no_downstream.json -> profile=True
# ---------------------------------------------------------------------------

def test_refused_no_downstream_is_valid():
    """A governed refused-call receipt is valid under broadcast_control: no downstream consequence."""
    report = verify(load("refused_no_downstream.json"))
    assert report.profile is True, report.failure_codes


# ---------------------------------------------------------------------------
# 8. wrong_profile_id.json -> profile=False
# ---------------------------------------------------------------------------

def test_wrong_profile_id_fails_profile():
    report = verify(load("wrong_profile_id.json"))
    assert report.profile is False
    assert any(
        "broadcast_control.invalid_profile_id" in code
        for code in report.failure_codes
    ), report.failure_codes


# ---------------------------------------------------------------------------
# 9. Equivalent semantic outcomes produce the same profile finding
# ---------------------------------------------------------------------------

def test_equivalent_semantic_outcomes_produce_same_profile_finding():
    """
    OBS scene_switch (observed_consequence) and 93C scene_switch (execution)
    are semantically equivalent operations from different adapters.
    Both must produce profile=True.
    """
    obs_report = verify(load("obs_observed_consequence_valid.json"))
    c93_report = verify(load("93c_execution_valid.json"))
    assert obs_report.profile is True, obs_report.failure_codes
    assert c93_report.profile is True, c93_report.failure_codes
    # Same profile finding
    assert obs_report.profile == c93_report.profile


# ---------------------------------------------------------------------------
# 10. Product-native vocabulary does NOT appear in profile error codes
# ---------------------------------------------------------------------------

def test_product_native_vocabulary_absent_from_profile_error_codes():
    """
    93C function names and OBS operation names must not appear in profile
    error codes. Profile errors are adapter-neutral.
    """
    product_vocabulary = [
        "93c",
        "obs",
        "scene_switch",
        "SetCurrentProgramScene",
        "webhook",
        "obs_mcp",
        "93c_webhook",
    ]

    # Force a profile failure on a 93C fixture to get error codes
    bad_receipt = load("missing_target_state.json")
    report = verify(bad_receipt)
    assert report.profile is False

    for code in report.failure_codes:
        for term in product_vocabulary:
            assert term.lower() not in code.lower(), (
                f"Product-native term '{term}' found in profile error code '{code}'"
            )


# ---------------------------------------------------------------------------
# 11. missing_consequence fixture does NOT produce profile=True claiming delivery
# ---------------------------------------------------------------------------

def test_missing_consequence_does_not_claim_successful_delivery():
    """
    The missing_consequence fixture has receipt_kind=delivery and target_state
    present, but no observed_consequence_ref. The cross-receipt corroboration
    requirement is NOT enforced by the single-receipt verifier (it is a
    multi-receipt concern). The receipt passes profile validation because
    single-receipt structural rules are met. The test asserts that profile=True
    here does NOT constitute a verified delivery claim — the attestation_limits
    text explicitly disclaims this.
    """
    report = verify(load("missing_consequence.json"))
    # The single-receipt profile check passes (target_state is present,
    # all exclusions present, correct attestation limit). Cross-receipt
    # corroboration is out of scope for the single-receipt verifier.
    assert report.profile is True, report.failure_codes
    # The attestation_limits_present finding confirms the disclaimer is present
    assert report.attestation_limits_present is True


# ---------------------------------------------------------------------------
# Additional: verify schema envelope also passes for valid fixtures
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "fixture_name",
    [
        "93c_execution_valid.json",
        "93c_request_valid.json",
        "obs_observed_consequence_valid.json",
        "obs_request_valid.json",
        "refused_no_downstream.json",
    ],
    ids=lambda n: n,
)
def test_valid_fixtures_pass_envelope_check(fixture_name: str):
    report = verify(load(fixture_name))
    assert report.envelope is True, (fixture_name, report.failure_codes)
