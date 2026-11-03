"""C2PA-05-SIGNED-PROOF: real unsigned EMIT0 bytes -> ephemeral signed test derivative.

This is a cross-repository integration harness, not a runtime dependency.
dagr_ingest is imported ONLY by this test harness; arcs-verify production code
never imports the emitter. The source bytes and native evidence are the already
reviewed, frozen arcs-verify#18 specimens. A missing signer checkout or pinned
native validator is NOT_EXERCISED, not a passing integrated replay.
"""
from __future__ import annotations

import json
import os

import pytest

from arcs_verify.c2pa_test_signature0 import (
    TEST_ISSUER, TestReceiverKey,
    verify_and_replay_test_signed_observation,
    verify_test_signed_observation,
)
from .test_produced_replay import evidence, observation_bytes

try:
    from dagr_ingest.srs.c2pa_test_signing0 import sign_approved_test_observation
except ImportError as exc:
    SIGNER_IMPORT_FAILURE = str(exc)
    sign_approved_test_observation = None
else:
    SIGNER_IMPORT_FAILURE = None

LIVE = os.environ.get("ARCS_VERIFY_C2PATOOL")
NAMES = ("positive", "negative_native_invalid_exit0", "negative_remote_manifest_missing")


def signed(name):
    if sign_approved_test_observation is None:
        reason = "NOT_EXERCISED: install dagr-ingest[signed-proof] exact SIGN0 candidate: " + str(SIGNER_IMPORT_FAILURE)
        if os.environ.get("C2PA_SIGN0_REQUIRED") == "1":
            pytest.fail(reason)
        pytest.skip(reason)
    artifact = sign_approved_test_observation(
        observation_bytes(name), acknowledge_test_signing=True,
    )
    selected = {
        artifact.key_id: TestReceiverKey(
            issuer_id=TEST_ISSUER,
            public_key_raw=artifact.public_key_raw,
            trusted_for_test=True,
        )
    }
    return artifact, selected


@pytest.mark.parametrize("name", NAMES)
def test_cryptographically_signed_real_producer_specimen_is_test_only(name):
    artifact, selected = signed(name)
    result = verify_test_signed_observation(
        artifact.receipt_bytes, selected_test_keys=selected,
    ).as_dict()
    assert result["signature_valid"] == "pass"
    assert result["issuer_key_resolved"] == "pass"
    assert result["issuer_key_trusted"] == "pass"
    assert result["issuer_standing"] == "not_evaluated"
    assert result["native_c2pa_signer_trust"] == "not_evaluated"
    assert result["independent_tsa_trust"] == "not_evaluated"
    assert result["operational_issuance"] == "not_authorized"


@pytest.mark.parametrize("name", NAMES)
def test_signed_real_producer_receipt_follows_existing_profile_and_native_pipeline(name):
    artifact, selected = signed(name)
    combined = verify_and_replay_test_signed_observation(
        artifact.receipt_bytes, evidence(name),
        selected_test_keys=selected, executable=None,
    )
    assert combined["signature_test"]["signature_valid"] == "pass"
    assert combined["native_replay"]["pipeline"]["stages"]["input_correspondence"]["status"] == "completed"
    assert combined["native_replay"]["pipeline"]["stages"]["profile_conformance"]["status"] == "completed"
    assert combined["native_replay"]["pipeline"]["stages"]["native_recomputation"]["status"] == "not_evaluated"
    assert combined["native_replay"]["axes"]["srs_receipt_authentication"]["issuance_authentication"] == "not_evaluated"
    assert combined["scope"] == "independent_axes_no_aggregate_result"
    assert combined["operational_issuer"] == "none_selected"


@pytest.mark.parametrize("name", ("positive", "negative_native_invalid_exit0"))
def test_wrong_key_or_tampered_signature_never_grants_receipt_authentication(name):
    artifact, selected = signed(name)
    wrong = artifact.key_id
    bogus = TestReceiverKey(TEST_ISSUER, b"\x01" * 32, trusted_for_test=True)
    result = verify_test_signed_observation(
        artifact.receipt_bytes, selected_test_keys={wrong: bogus},
    )
    assert result.signature_valid == "fail"
    assert "signature_invalid" in result.failure_codes
    unsigned_decision = verify_test_signed_observation(
        artifact.receipt_bytes, selected_test_keys={},
    )
    assert unsigned_decision.issuer_key_resolved == "fail"
    assert unsigned_decision.signature_valid == "not_evaluated"

    doc = json.loads(artifact.receipt_bytes)
    doc["receipt_id"] = doc["receipt_id"] + "-tampered"
    tampered = json.dumps(doc, sort_keys=True).encode("utf-8")
    altered = verify_test_signed_observation(tampered, selected_test_keys=selected)
    assert altered.signature_valid == "fail"


@pytest.mark.skipif(not LIVE, reason="NOT_EXERCISED: pinned c2patool must be selected as ARCS_VERIFY_C2PATOOL")
@pytest.mark.parametrize("name", NAMES)
def test_real_signed_specimen_is_independently_recomputed_without_trust_promotion(name):
    artifact, selected = signed(name)
    combined = verify_and_replay_test_signed_observation(
        artifact.receipt_bytes, evidence(name),
        selected_test_keys=selected, executable=LIVE,
    )
    assert combined["signature_test"]["signature_valid"] == "pass"
    native = combined["native_replay"]
    assert native["pipeline"]["stages"]["profile_conformance"]["status"] == "completed"
    assert native["pipeline"]["stages"]["input_correspondence"]["status"] == "completed"
    assert native["axes"]["srs_receipt_authentication"]["issuance_authentication"] == "not_evaluated"
    assert combined["operational_issuer"] == "none_selected"
    if name == "positive":
        assert native["axes"]["native_validation_state"]["observed_verbatim"] == "Valid"
        assert native["axes"]["timestamp"]["reliance"]["independent_tsa_appraisal"] == "not_evaluated"
        assert native["axes"]["comparability_restriction"]["scope"] == "receipt_wide"
        assert native["pipeline"]["stages"]["comparison"]["status"] == "restricted"
    elif name == "negative_native_invalid_exit0":
        assert native["axes"]["native_validation_state"]["observed_verbatim"] == "Invalid"
    else:
        assert native["pipeline"]["stages"]["native_recomputation"]["status"] in ("completed", "not_evaluated")
