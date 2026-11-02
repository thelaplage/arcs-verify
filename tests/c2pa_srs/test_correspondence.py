"""Step 1: every digest the observation names is checked against the retained bytes.

SYNTHETIC observations and evidence only (see material.py)."""
import pytest

from arcs_verify import c2pa_srs_observed as adapter

from . import material as m


def stage1(obs, evidence):
    return adapter._stage_correspondence(obs, evidence)[1]


def codes(outcome):
    return {r.code for r in outcome.refusals}


def fields(outcome):
    return {r.field for r in outcome.refusals}


def full_evidence(**kw):
    return m.evidence_for(manifest_store=m.SYNTHETIC_MANIFEST_STORE, configuration=m.HERMETIC_CONFIG, **kw)


def test_exact_correspondence_completes_and_lists_what_it_could_not_check():
    outcome = stage1(m.synthetic_observation(), m.evidence_for())
    assert outcome.status == "completed" and not outcome.refusals
    matched = {c["field"] for c in outcome.detail["checks"] if c["status"] == "match"}
    assert {"asset_digest", "subject_ref", "native_report.report_digest"} <= matched
    unchecked = {u["field"] for u in outcome.detail["unchecked"]}
    assert "native_validator.build_digest" in unchecked
    assert "manifest_store.digest" in unchecked  # named, but no manifest bytes were retained
    assert "native_validator.configuration_digest" in unchecked


def test_supplying_every_retained_input_checks_all_five_slots():
    outcome = stage1(m.synthetic_observation(), full_evidence())
    matched = {c["field"] for c in outcome.detail["checks"] if c["status"] == "match"}
    assert matched == {
        "asset_digest",
        "subject_ref",
        "manifest_store.digest",
        "native_report.report_digest",
        "native_validator.configuration_digest",
    }
    assert {u["field"] for u in outcome.detail["unchecked"]} == {"native_validator.build_digest"}


def test_every_named_digest_is_accounted_for_as_checked_or_unchecked():
    obs = m.synthetic_observation(mode="external_supplied")
    obs["signer_trust"].update(
        trust_basis="custom_allowed_list",
        trust_material_refs=[{"role": "allowed_list", "digest": m.ALLOWED_LIST_DIGEST, "source_identity": "SYNTHETIC", "source_pin": "pin"}],
    )
    obs["trusted_timestamp"]["tsa_trust_material_ref"] = m.ANCHORS_DIGEST
    obs["hermetic_replay"]["replay_report_digest"] = m.ANCHORS_DIGEST
    obs["prior_producer_report"] = {"present": True, "report_digest": m.ALLOWED_LIST_DIGEST, "comparison_posture": "comparable"}
    outcome = stage1(obs, m.evidence_for(manifest_store=m.SYNTHETIC_MANIFEST_STORE))
    census = {path for path, _ in adapter._iter_named_digests(obs)}
    accounted = {c["field"] for c in outcome.detail["checks"]} | {u["field"] for u in outcome.detail["unchecked"]}
    assert len(census) == outcome.detail["named_digest_count"] == 10
    assert census <= accounted
    assert "signer_trust.trust_material_refs[0].digest" in accounted


def test_asset_digest_mismatch_alone():  # GUARD CORR-ASSET-DIGEST
    obs = m.mutated(m.synthetic_observation(), "asset_digest", "sha256:" + "0" * 64)
    outcome = stage1(obs, m.evidence_for())
    assert codes(outcome) == {"CORR_ASSET_DIGEST_MISMATCH"}


def test_subject_ref_mismatch_alone():  # GUARD CORR-SUBJECT-REF
    obs = m.mutated(m.synthetic_observation(), "subject_ref", "sha256:" + "0" * 64)
    assert codes(stage1(obs, m.evidence_for())) == {"CORR_SUBJECT_REF_MISMATCH"}


def test_altered_asset_bytes_break_both_asset_bindings():
    outcome = stage1(m.synthetic_observation(), m.evidence_for(asset=m.SYNTHETIC_OTHER_ASSET))
    assert codes(outcome) == {"CORR_ASSET_DIGEST_MISMATCH", "CORR_SUBJECT_REF_MISMATCH"}


def test_asset_digest_not_named_is_refused():  # GUARD CORR-ASSET-NOT-NAMED
    obs = m.without(m.synthetic_observation(), "asset_digest")
    assert "CORR_ASSET_DIGEST_NOT_NAMED" in codes(stage1(obs, m.evidence_for()))


def test_malformed_digest_with_trailing_newline_is_refused_even_where_no_bytes_exist():  # GUARD CORR-DIGEST-FORMAT
    obs = m.mutated(m.synthetic_observation(), "native_validator.build_digest", "sha256:" + "0" * 64 + "\n")
    outcome = stage1(obs, m.evidence_for())
    assert codes(outcome) == {"CORR_DIGEST_MALFORMED"}
    assert fields(outcome) == {"native_validator.build_digest"}


def test_upstream_schema_pattern_tolerates_a_trailing_newline_so_the_adapter_hardens_it():
    """Probe: the pinned field schema's sha256_ref pattern ends in `$`, which Python's regex
    matches before a trailing newline. The adapter's own strict check is what refuses it."""
    contract = adapter._load_contract()
    digest = "sha256:" + "0" * 64 + "\n"
    errors = list(contract.field_validator.evolve(schema={"$ref": "#/$defs/sha256_ref", "$defs": contract.field_schema["$defs"]}).iter_errors(digest))
    assert errors == []
    assert adapter._is_digest(digest) is False


def test_manifest_store_bytes_must_match_the_named_digest():  # GUARD CORR-MANIFEST-DIGEST
    ev = m.evidence_for(manifest_store=m.SYNTHETIC_OTHER_MANIFEST_STORE)
    assert codes(stage1(m.synthetic_observation(), ev)) == {"CORR_MANIFEST_STORE_DIGEST_MISMATCH"}


def test_manifest_store_bytes_the_observation_does_not_name_are_refused():  # GUARD CORR-MANIFEST-UNNAMED
    obs = m.synthetic_observation()
    obs["manifest_store"] = {"state": "absent"}
    outcome = stage1(obs, m.evidence_for(manifest_store=m.SYNTHETIC_MANIFEST_STORE))
    assert codes(outcome) == {"CORR_EVIDENCE_NOT_NAMED"} and fields(outcome) == {"manifest_store.digest"}


def test_native_report_digest_mismatch():  # GUARD CORR-REPORT-DIGEST
    ev = m.evidence_for(m.REPORT_INVALID_CLAIM)  # retained bytes are a different report
    assert codes(stage1(m.synthetic_observation(m.REPORT_VALID_UNTRUSTED), ev)) == {"CORR_NATIVE_REPORT_DIGEST_MISMATCH"}


def test_report_swapped_in_from_another_asset_is_refused():
    obs_a = m.synthetic_observation(m.REPORT_VALID_UNTRUSTED, asset=m.SYNTHETIC_ASSET)
    swapped = m.evidence_for(m.REPORT_TRUSTED_ALLOWED, asset=m.SYNTHETIC_ASSET)  # report produced for another asset
    assert "CORR_NATIVE_REPORT_DIGEST_MISMATCH" in codes(stage1(obs_a, swapped))


def test_retained_report_the_observation_does_not_name_is_refused():  # GUARD CORR-REPORT-UNNAMED
    obs = m.without(m.synthetic_observation(), "native_report")
    outcome = stage1(obs, m.evidence_for())
    assert codes(outcome) == {"CORR_EVIDENCE_NOT_NAMED"} and fields(outcome) == {"native_report"}


def test_named_report_with_no_retained_bytes_is_refused():  # GUARD CORR-REPORT-MISSING
    outcome = stage1(m.synthetic_observation(), m.evidence_for(include_report=False))
    assert codes(outcome) == {"CORR_NATIVE_REPORT_BYTES_MISSING"}


def test_unsupported_report_format_is_refused_not_guessed():  # GUARD CORR-REPORT-FORMAT
    obs = m.mutated(m.synthetic_observation(), "native_report.report_format", "c2patool.cbor")
    assert codes(stage1(obs, m.evidence_for())) == {"CORR_NATIVE_REPORT_FORMAT_UNSUPPORTED"}


def test_retained_report_that_is_not_a_native_report_is_refused():  # GUARD CORR-REPORT-PARSE
    junk = b"not json at all"
    obs = m.mutated(m.synthetic_observation(), "native_report.report_digest", m.sha(junk))
    ev = m.RetainedEvidence(asset=m.SYNTHETIC_ASSET, asset_name=m.ASSET_NAME, native_report=junk)
    assert codes(stage1(obs, ev)) == {"CORR_NATIVE_REPORT_UNPARSEABLE"}


def test_report_without_validation_results_is_not_a_native_report():
    bare = b'{"validation_state": "Valid"}'
    obs = m.mutated(m.synthetic_observation(), "native_report.report_digest", m.sha(bare))
    ev = m.RetainedEvidence(asset=m.SYNTHETIC_ASSET, asset_name=m.ASSET_NAME, native_report=bare)
    assert codes(stage1(obs, ev)) == {"CORR_NATIVE_REPORT_UNPARSEABLE"}


def test_claimed_native_state_must_equal_the_retained_report():  # GUARD CORR-STATE
    obs = m.mutated(m.synthetic_observation(), "native_report.native_validation_state", "Invalid")
    assert codes(stage1(obs, m.evidence_for())) == {"CORR_VALIDATION_STATE_MISMATCH"}


def test_claimed_findings_must_equal_the_retained_report():  # GUARD CORR-FINDINGS
    obs = m.synthetic_observation()
    obs["native_findings"] = [f for f in obs["native_findings"] if f["code"] != "signingCredential.untrusted"]
    assert codes(stage1(obs, m.evidence_for())) == {"CORR_NATIVE_FINDINGS_MISMATCH"}


def test_an_invented_finding_is_refused():
    obs = m.synthetic_observation()
    obs["native_findings"].append({"scope": "activeManifest", "severity": "success", "code": "claimSignature.insideValidity"})
    assert codes(stage1(obs, m.evidence_for())) == {"CORR_NATIVE_FINDINGS_MISMATCH"}


def test_a_finding_uri_the_report_does_not_carry_is_refused():
    obs = m.synthetic_observation()
    obs["native_findings"][0]["uri"] = "self#jumbf=/c2pa/synthetic/elsewhere"
    assert codes(stage1(obs, m.evidence_for())) == {"CORR_NATIVE_FINDINGS_MISMATCH"}


def test_a_finding_without_a_uri_still_corresponds_to_the_report():
    obs = m.synthetic_observation()
    for item in obs["native_findings"]:
        del item["uri"]
    assert stage1(obs, m.evidence_for()).status == "completed"


def test_legacy_flattened_status_array_is_not_a_source():
    """The synthetic report's legacy `validation_status` carries a code that is not in
    validation_results. Findings that follow validation_results correspond; findings that
    follow the legacy array do not."""
    ok = m.synthetic_observation()
    assert stage1(ok, m.evidence_for()).status == "completed"
    legacy = m.synthetic_observation()
    legacy["native_findings"].append({"scope": "activeManifest", "severity": "failure", "code": "misleading.legacy.flattened.code"})
    assert codes(stage1(legacy, m.evidence_for())) == {"CORR_NATIVE_FINDINGS_MISMATCH"}


def test_native_exit_code_is_never_part_of_correspondence():
    inv = m.synthetic_observation(m.REPORT_INVALID_CLAIM, exit_code=0)
    assert stage1(inv, m.evidence_for(m.REPORT_INVALID_CLAIM)).status == "completed"


def test_configuration_bytes_must_match_the_named_digest():  # GUARD CORR-CONFIG-DIGEST
    ev = m.evidence_for(configuration=b"remote_manifest_fetch = true\n")
    assert codes(stage1(m.synthetic_observation(), ev)) == {"CORR_CONFIGURATION_DIGEST_MISMATCH"}


def test_configuration_bytes_the_observation_does_not_name_are_refused():  # GUARD CORR-CONFIG-UNNAMED
    obs = m.synthetic_observation()
    obs["native_validator"]["configuration_posture"] = "validator_defaults"
    obs["native_validator"]["configuration_digest"] = None
    outcome = stage1(obs, m.evidence_for(configuration=m.HERMETIC_CONFIG))
    assert codes(outcome) == {"CORR_EVIDENCE_NOT_NAMED"}


def test_evidence_must_be_retained_evidence_with_bytes():
    with pytest.raises(TypeError):
        adapter.consume_observation(b"{}", "not evidence")
    with pytest.raises(TypeError):
        adapter.consume_observation("{}", m.evidence_for())
