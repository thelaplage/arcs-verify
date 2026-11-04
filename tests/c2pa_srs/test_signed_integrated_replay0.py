"""C2PA-05-SIGNED-PROOF: real unsigned EMIT0 bytes -> ephemeral signed test derivative.

This is a cross-repository integration harness, not a runtime dependency.
dagr_ingest is imported ONLY by this test harness; arcs-verify production code
never imports the emitter. The source bytes and native evidence are the already
reviewed, frozen arcs-verify#18 specimens. A missing signer checkout or pinned
native validator is NOT_EXERCISED, not a passing integrated replay.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from arcs_verify.c2pa_test_signature0 import (
    TEST_ISSUER, TestReceiverKey,
    verify_and_replay_test_signed_observation,
    verify_test_signed_observation,
)
from .test_produced_replay import PROV, evidence, observation_bytes

try:
    from dagr_ingest.srs.c2pa_test_signing0 import sign_approved_test_observation
except ImportError as exc:
    SIGNER_IMPORT_FAILURE = str(exc)
    sign_approved_test_observation = None
else:
    SIGNER_IMPORT_FAILURE = None

LIVE = os.environ.get("ARCS_VERIFY_C2PATOOL")
NAMES = ("positive", "negative_native_invalid_exit0", "negative_remote_manifest_missing")


def _retain_test_proof(name: str, artifact, combined: dict) -> None:
    """Explicit, local-only evidence export: signed bytes and PUBLIC key, never private."""
    target = os.environ.get("C2PA_SIGNED_TEST_EVIDENCE_DIR")
    if not target:
        return
    base = Path(target).resolve(strict=True)
    assert base.is_dir(), "evidence target must be an existing directory"
    repo_root = Path(__file__).resolve().parents[2]
    assert not base.is_relative_to(repo_root), "test evidence must stay outside the source tree"
    files = {
        f"{name}.signed-observation.json": artifact.receipt_bytes,
        f"{name}.test-public-key.bin": artifact.public_key_raw,
    }
    for filename in files:
        assert not (base / filename).exists(), "evidence overwrite is refused"
    proof = {
        "status": "OFFLINE_SIGNED_TEST_PROOF_NOT_OPERATIONAL_ISSUANCE",
        "specimen": name,
        "original_unsigned_observation_sha256": artifact.original_observation_sha256,
        "signed_observation_sha256": "sha256:" + hashlib.sha256(artifact.receipt_bytes).hexdigest(),
        "test_public_key_sha256": "sha256:" + hashlib.sha256(artifact.public_key_raw).hexdigest(),
        "test_key_id": artifact.key_id,
        "source_integrity": combined["signature_test"]["source_integrity"],
        "receipt_identity": combined["signature_test"]["receipt_identity"],
        "supplied_source_sha256": combined["signature_test"]["supplied_source_sha256"],
        "cryptographic_finding": combined["signature_test"],
        "native_replay": combined["native_replay"],
        "native_stopped_at": combined["native_stopped_at"],
        "authority_movement": 0,
        "operational_issuer": "none_selected",
        "private_key_retained": False,
    }
    proof_filename = f"{name}.proof.json"
    assert not (base / proof_filename).exists(), "evidence overwrite is refused"
    # Persist only after the test has completed its positive/negative assertions.
    for filename, data in files.items():
        (base / filename).write_bytes(data)
    (base / proof_filename).write_text(json.dumps(proof, sort_keys=True, indent=2) + "\n")


@pytest.mark.skipif(not LIVE, reason="NOT_EXERCISED: exact pinned c2patool required")
def test_selected_validator_is_the_exact_frozen_binary_not_version_only():
    """The producer's recorded binary digest, not its version string, pins this replay."""
    assert LIVE is not None
    path = Path(LIVE)
    assert path.is_file(), "a concrete local validator file is required"
    records = PROV["run_records"]["by_specimen"].values()
    pins = {record["validator_binary_sha256"] for record in records}
    assert len(pins) == 1, "all original producer runs must agree on a binary pin"
    assert "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest() == next(iter(pins))


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
        source_bytes=observation_bytes(name),
    ).as_dict()
    assert result["signature_valid"] == "pass"
    assert result["issuer_key_resolved"] == "pass"
    assert result["issuer_key_trusted"] == "pass"
    assert result["source_integrity"] == "pass"
    assert result["receipt_identity"] == "pass"
    assert result["supplied_source_sha256"] == artifact.original_observation_sha256
    assert result["issuer_standing"] == "not_evaluated"
    assert result["native_c2pa_signer_trust"] == "not_evaluated"
    assert result["independent_tsa_trust"] == "not_evaluated"
    assert result["operational_issuance"] == "not_authorized"


@pytest.mark.parametrize("name", NAMES)
def test_signed_real_producer_receipt_follows_existing_profile_and_native_pipeline(name):
    artifact, selected = signed(name)
    combined = verify_and_replay_test_signed_observation(
        artifact.receipt_bytes, evidence(name),
        selected_test_keys=selected, source_bytes=observation_bytes(name), executable=None,
    )
    assert combined["signature_test"]["signature_valid"] == "pass"
    assert combined["signature_test"]["source_integrity"] == "pass"
    assert combined["signature_test"]["receipt_identity"] == "pass"
    assert combined["native_replay"]["pipeline"]["stages"]["input_correspondence"]["status"] == "completed"
    assert combined["native_replay"]["pipeline"]["stages"]["profile_conformance"]["status"] == "completed"
    assert combined["native_replay"]["pipeline"]["stages"]["native_recomputation"]["status"] == "not_evaluated"
    assert combined["native_replay"]["axes"]["srs_receipt_authentication"]["issuance_authentication"] == "not_evaluated"
    assert combined["scope"] == "independent_axes_no_aggregate_result"
    assert combined["operational_issuer"] == "none_selected"


@pytest.mark.parametrize("name", NAMES)
def test_verified_signature_never_substitutes_for_source_bytes(name):
    """A valid signature with no source bytes is not source verification."""
    artifact, selected = signed(name)
    result = verify_test_signed_observation(
        artifact.receipt_bytes, selected_test_keys=selected,
    ).as_dict()
    assert result["signature_valid"] == "pass"
    assert result["source_integrity"] == "not_evaluated"
    assert result["source_failure_codes"] == ["source_bytes_missing"]
    assert result["receipt_identity"] == "not_evaluated"


@pytest.mark.parametrize("name", ("positive", "negative_native_invalid_exit0"))
def test_substituted_or_modified_source_bytes_are_refused_on_genuine_artifacts(name):
    artifact, selected = signed(name)
    other = next(n for n in NAMES if n != name)
    substituted = verify_test_signed_observation(
        artifact.receipt_bytes, selected_test_keys=selected,
        source_bytes=observation_bytes(other),
    )
    assert substituted.signature_valid == "pass"
    assert substituted.source_integrity == "fail"
    assert substituted.source_failure_codes == ("source_digest_mismatch",)
    assert substituted.receipt_identity == "not_evaluated"

    genuine = bytearray(observation_bytes(name))
    genuine[len(genuine) // 3] ^= 0x20
    modified = verify_test_signed_observation(
        artifact.receipt_bytes, selected_test_keys=selected, source_bytes=bytes(genuine),
    )
    assert modified.signature_valid == "pass"
    assert modified.source_integrity == "fail"
    assert modified.source_failure_codes == ("source_digest_mismatch",)



@pytest.mark.parametrize("name", ("positive", "negative_native_invalid_exit0"))
def test_wrong_key_or_tampered_signature_never_grants_receipt_authentication(name):
    artifact, selected = signed(name)
    wrong = artifact.key_id
    bogus = TestReceiverKey(TEST_ISSUER, b"\x01" * 32, trusted_for_test=True)
    result = verify_test_signed_observation(
        artifact.receipt_bytes, selected_test_keys={wrong: bogus},
    )
    assert result.signature_valid == "not_evaluated"
    assert result.issuer_key_resolved == "fail"
    assert "key_id_public_key_mismatch" in result.failure_codes
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
        selected_test_keys=selected, source_bytes=observation_bytes(name), executable=LIVE,
    )
    assert combined["signature_test"]["signature_valid"] == "pass"
    assert combined["signature_test"]["source_integrity"] == "pass"
    assert combined["signature_test"]["receipt_identity"] == "pass"
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
    _retain_test_proof(name, artifact, combined)
