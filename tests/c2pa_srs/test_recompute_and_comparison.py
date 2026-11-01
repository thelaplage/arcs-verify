"""Recomputation with the verifier's own native-validator path, and the axis-by-axis comparison.

SYNTHETIC observations; the native validator is a TEST DOUBLE that prints a canned report for a
given asset digest (see material.install_fake_validator). It stands in for the pinned
c2patool so that exit-status, version and hermetic-settings handling can be driven; it is not
evidence about c2patool. The real pinned validator is exercised by test_live_pinned_validator.py
when ARCS_VERIFY_C2PATOOL is set."""
import copy
import json
import os
import stat

import pytest

from arcs_verify import c2pa_native
from arcs_verify import c2pa_srs_observed as adapter

from . import material as m

BUNDLE = c2pa_native.load_bundle()


def consume(tmp_path, obs, *, validator_report=m.REPORT_VALID_UNTRUSTED, validator_exit=0, evidence=None, version=m.PINNED_VERSION, scenarios=None):
    if scenarios is None:
        scenarios = {m.SYNTHETIC_ASSET: (validator_report, validator_exit)}
    fake = m.install_fake_validator(tmp_path, scenarios, version=version)
    ev = evidence or m.evidence_for()
    return adapter.consume_observation(m.encode(obs), ev, executable=fake.path), fake


def per_axis(result):
    return {item["axis"]: item for item in result.report["axes"]["independent_comparison"]["per_axis"]}


def test_matching_sides_compare_axis_by_axis_with_no_aggregate(tmp_path):
    result, fake = consume(tmp_path, m.synthetic_observation())
    assert result.stopped_at is None
    axes = per_axis(result)
    assert [a for a in axes] == list(c2pa_native.AXIS_ORDER)
    for name in ("asset_binding", "claim_signature", "signer_trust"):
        assert axes[name]["state"] == "match" and axes[name]["agreement_basis"] == "same_status"
    assert axes["signer_trust"]["observed_status"] == axes["signer_trust"]["recomputed_status"] == "failed"
    # Where neither side evaluated an axis, the existing comparison still says `match`;
    # the report names that basis so absence on both sides is not read as agreement.
    assert axes["manifest_structure"]["state"] == "match"
    assert axes["manifest_structure"]["agreement_basis"] == "both_sides_not_evaluated"
    assert axes["revocation"]["state"] == "not_comparable" and axes["revocation"]["comparison_reason"] == "revocation_basis_delta"
    assert not any(a["integrity_posture"] == "possible_substantive_divergence" for a in axes.values())
    check = result.report["pipeline"]["stages"]["comparison"]["detail"]["report_contract_check"]
    assert check["findings"] == []
    assert result.report["native_comparison_report"]["comparability"] == {
        "validator_identity_match": True,
        "validator_version_match": True,
        "asset_digest_match": True,
        "manifest_store_digest_match": True,
        "trust_basis_match": True,
        "settings_match": True,
    }


def test_independent_recomputation_disagreeing_with_the_producer_is_a_mismatch_on_the_deterministic_axis(tmp_path):
    obs = m.synthetic_observation(m.REPORT_VALID_UNTRUSTED)  # producer says the claim signature validated
    result, _ = consume(tmp_path, obs, validator_report=m.REPORT_INVALID_CLAIM)  # the verifier's own run says mismatch
    axes = per_axis(result)
    assert axes["claim_signature"]["state"] == "mismatch"
    assert axes["claim_signature"]["observed_status"] == "satisfied" and axes["claim_signature"]["recomputed_status"] == "failed"
    assert axes["claim_signature"]["integrity_posture"] == "possible_substantive_divergence"
    assert axes["asset_binding"]["state"] == "match"
    codes = result.report["axes"]["native_failure_codes"]
    assert codes["only_in_recomputed"] == ["claimSignature.mismatch"] and codes["only_in_observed"] == []
    states = result.report["axes"]["native_validation_state"]
    assert (states["observed_verbatim"], states["recomputed_verbatim"]) == ("Valid", "Invalid")


def test_the_producers_report_is_never_the_independent_result(tmp_path):
    """The retained producer report says Valid. The verifier's own run says Invalid. The
    comparison must follow the verifier's run."""
    result, fake = consume(tmp_path, m.synthetic_observation(m.REPORT_VALID_UNTRUSTED), validator_report=m.REPORT_INVALID_CLAIM)
    assert result.report["native_recomputation"]["recomputed"]["native_validation_state"] == "Invalid"
    assert result.report["native_recomputation"]["recomputed"]["evidence_class"] == "live_native_invocation"
    assert len(fake.calls()) == 1


def test_native_invalid_with_process_exit_zero_is_failed_on_both_sides_never_satisfied(tmp_path):
    obs = m.synthetic_observation(m.REPORT_INVALID_CLAIM, exit_code=0)
    result, _ = consume(tmp_path, obs, validator_report=m.REPORT_INVALID_CLAIM, validator_exit=0, evidence=m.evidence_for(m.REPORT_INVALID_CLAIM))
    axes = per_axis(result)
    assert axes["claim_signature"]["observed_status"] == axes["claim_signature"]["recomputed_status"] == "failed"
    assert axes["claim_signature"]["state"] == "match"
    assert result.report["native_recomputation"]["recomputed"]["evaluation_status"] == "evaluated"
    assert result.report["producer_asserted"]["process_exit_code"] == 0
    assert result.report["producer_asserted"]["process_exit_code_semantics"] == "observation_only_never_a_verdict"


def test_validator_exit_status_does_not_decide_the_outcome(tmp_path):
    result, _ = consume(tmp_path, m.synthetic_observation(), validator_exit=3)
    assert result.report["native_recomputation"]["recomputed"]["evaluation_status"] == "evaluated"
    assert per_axis(result)["claim_signature"]["state"] == "match"


def test_valid_state_alongside_an_untrusted_signer_is_not_promoted(tmp_path):
    result, _ = consume(tmp_path, m.synthetic_observation())
    states = result.report["axes"]["native_validation_state"]
    assert states["recomputed_verbatim"] == "Valid"
    trust = result.report["axes"]["signer_trust"]
    assert trust["recomputed_axis_status"] == "failed" and trust["observed_axis_status"] == "failed"
    assert "never_a_verdict" in states["semantics"]


def test_missing_manifest_store_is_input_unavailable_and_the_comparison_is_not_evaluated(tmp_path):  # GUARD CMP-BOTH-EVALUATED
    """The producer claims findings over an asset for which the verifier's own validator finds
    no manifest store. That is not a mismatch: a run with no report is not a finding."""
    result, fake = consume(tmp_path, m.synthetic_observation(), scenarios={})  # no scenario: "No claim found", exit 1
    assert result.stopped_at == "comparison"
    recomputed = result.report["native_recomputation"]["recomputed"]
    assert recomputed["evaluation_status"] == "input_unavailable"
    assert all(a["status"] == "not_evaluated" for a in recomputed["axes"])
    comparison = result.stages["comparison"]
    assert comparison.status == "not_evaluated"
    assert [r.code for r in comparison.refusals] == ["COMPARISON_SIDE_NOT_EVALUATED"]
    assert comparison.detail["evaluation_status"] == {"observed": "evaluated", "recomputed": "input_unavailable"}
    assert result.report["native_comparison_report"] is None
    assert result.report["axes"]["independent_comparison"]["per_axis"] == []
    assert "mismatch" not in json.dumps(result.report["axes"])
    assert len(fake.calls()) == 1


def test_two_unavailable_sides_are_not_reported_as_matching(tmp_path):
    obs = m.synthetic_observation()
    obs["evaluation_posture"] = "input_unavailable"
    del obs["native_report"], obs["native_findings"]
    obs["manifest_store"] = {"state": "inaccessible"}
    obs["manifest_acquisition"].update(mode="remote_reference", remote_manifest_uri="https://synthetic.invalid/m/1")
    result, _ = consume(tmp_path, obs, scenarios={}, evidence=m.evidence_for(include_report=False))
    assert result.stopped_at == "comparison"
    assert result.stages["comparison"].status == "not_evaluated"
    assert result.report["axes"]["independent_comparison"]["per_axis"] == []


def test_changed_validator_version_is_not_comparable_never_a_divergence(tmp_path):
    obs = m.synthetic_observation(version="0.27.14")  # the observation names a different version than the pin
    result, _ = consume(tmp_path, obs)
    axes = per_axis(result)
    for name, item in axes.items():
        if name == "revocation":
            continue
        assert item["state"] == "not_comparable" and item["comparison_reason"] == "validator_version_delta", name
        assert item["integrity_posture"] == "no_integrity_inference"
    assert result.report["native_comparison_report"]["comparability"]["validator_version_match"] is False


def test_verifier_running_a_different_build_than_its_pin_is_reported(tmp_path):
    obs = m.synthetic_observation(version="9.9.9")
    result, _ = consume(tmp_path, obs, version="0.99.0")
    pin = result.stages["native_recomputation"].detail["validator_pin"]
    assert pin["version"] == "0.27.15" and pin["detected_version"] == "0.99.0" and pin["detected_version_equals_pin"] is False
    assert per_axis(result)["claim_signature"]["comparison_reason"] == "validator_version_delta"


def test_a_different_producer_configuration_is_a_policy_delta(tmp_path):
    other = b"remote_manifest_fetch = false\n"
    obs = m.synthetic_observation(config=other)
    result, _ = consume(tmp_path, obs, evidence=m.evidence_for(configuration=other))
    axes = per_axis(result)
    assert axes["claim_signature"]["comparison_reason"] == "policy_delta" and axes["claim_signature"]["state"] == "not_comparable"
    assert result.report["native_comparison_report"]["comparability"]["settings_match"] is False


def test_producer_trust_basis_the_verifier_cannot_replicate_is_not_comparable_on_trust(tmp_path):
    obs = m.synthetic_observation(m.REPORT_TRUSTED_ALLOWED)
    obs["signer_trust"].update(
        trust_basis="custom_allowed_list",
        trust_material_refs=[{"role": "allowed_list", "digest": m.ALLOWED_LIST_DIGEST, "source_identity": "SYNTHETIC", "source_pin": "pin-0001"}],
    )
    result, _ = consume(tmp_path, obs, evidence=m.evidence_for(m.REPORT_TRUSTED_ALLOWED), validator_report=m.REPORT_VALID_UNTRUSTED)
    trust = result.report["axes"]["signer_trust"]
    assert trust["independent_comparison"]["state"] == "not_comparable"
    assert trust["independent_comparison"]["comparison_reason"] == "trust_basis_delta"
    assert trust["observed_axis_status"] == "satisfied" and trust["recomputed_axis_status"] == "failed"
    asserted = result.report["producer_asserted"]["signer_trust"]
    assert asserted["trust_observation"] == "trusted"
    assert result.report["producer_asserted"]["provenance"] == "producer_asserted"
    # the byte-deterministic axes are still compared on identical inputs
    assert per_axis(result)["claim_signature"]["state"] == "match"


def test_time_dependent_difference_without_a_trusted_timestamp_is_never_an_integrity_finding(tmp_path):
    obs = m.synthetic_observation(m.REPORT_EXPIRED)
    result, _ = consume(tmp_path, obs, evidence=m.evidence_for(m.REPORT_EXPIRED), validator_report=m.REPORT_VALID_UNTRUSTED)
    item = per_axis(result)["signer_validity"]
    assert item["observed_status"] == "failed" and item["recomputed_status"] == "not_evaluated"
    assert item["state"] == "not_comparable" and item["comparison_reason"] == "validation_clock_delta"
    assert item["integrity_posture"] == "no_integrity_inference"


def test_revocation_is_not_evaluated_on_both_sides_and_stays_that_way(tmp_path):
    obs = m.synthetic_observation()
    obs["revocation"] = {"observation": "not_revoked", "mechanism": "none"}  # a producer claim the hermetic contract cannot carry
    result, _ = consume(tmp_path, obs)
    rev = result.report["axes"]["revocation"]
    assert rev["observed_status"] == rev["recomputed_status"] == "not_evaluated"
    assert rev["producer_asserted"] == {"observation": "not_revoked", "mechanism": "none"}
    assert rev["independent_comparison"]["state"] == "not_comparable"


def test_two_runs_on_byte_identical_inputs_are_deterministic(tmp_path):
    def normalized(result):
        text = json.dumps(result.report, sort_keys=True)
        data = json.loads(text)
        data["native_recomputation"]["recomputed"]["validation_clock"]["instant"] = None
        data["native_comparison_report"]["recomputed"]["validation_clock"]["instant"] = None
        data["axes"]["source_digest_pin"]["recomputation_validator"] = None
        return json.dumps(data, sort_keys=True)

    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    first, _ = consume(tmp_path / "a", m.synthetic_observation())
    second, _ = consume(tmp_path / "b", m.synthetic_observation())
    assert normalized(first) == normalized(second)
    assert first.report["axes"]["independent_comparison"] == second.report["axes"]["independent_comparison"]


def test_no_native_validator_supplied_is_not_evaluated_and_never_falls_back_to_path(tmp_path, monkeypatch):  # GUARD REC-VALIDATOR-REQUIRED
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    marker = tmp_path / "ambient-validator-was-run"
    ambient = bin_dir / "c2patool"
    ambient.write_text(f'#!/bin/sh\ntouch "{marker}"\necho "c2patool 0.27.15"\n')
    ambient.chmod(ambient.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    result = adapter.consume_observation(m.encode(m.synthetic_observation()), m.evidence_for(), executable=None)
    assert result.stopped_at == "native_recomputation"
    assert result.stages["native_recomputation"].status == "not_evaluated"
    assert [r.code for r in result.stages["native_recomputation"].refusals] == ["RECOMPUTE_VALIDATOR_NOT_SUPPLIED"]
    assert result.stages["comparison"].status == "not_run"
    assert not marker.exists()
    assert result.report["axes"]["independent_comparison"]["per_axis"] == []


def test_non_embedded_acquisition_needs_the_retained_store_bytes(tmp_path):  # GUARD REC-MANIFEST-BYTES-REQUIRED
    obs = m.synthetic_observation(mode="external_supplied")
    result, fake = consume(tmp_path, obs)  # no manifest-store bytes retained
    assert result.stopped_at == "native_recomputation"
    assert [r.code for r in result.stages["native_recomputation"].refusals] == ["RECOMPUTE_MANIFEST_STORE_BYTES_NOT_RETAINED"]
    assert fake.calls() == []


def test_retained_store_bytes_are_handed_to_the_validator_and_compared_by_digest(tmp_path):
    obs = m.synthetic_observation(mode="external_supplied")
    ev = m.evidence_for(manifest_store=m.SYNTHETIC_MANIFEST_STORE)
    result, fake = consume(tmp_path, obs, evidence=ev)
    assert result.stopped_at is None
    (call,) = fake.calls()
    assert "--external-manifest" in call["argv"]
    assert call["external_sha256"] == m.sha(m.SYNTHETIC_MANIFEST_STORE).split(":")[1]
    recomputed = result.report["native_recomputation"]["recomputed"]
    assert recomputed["inputs"]["manifest_store_digest"] == obs["manifest_store"]["digest"]
    assert result.report["native_comparison_report"]["comparability"]["manifest_store_digest_match"] is True


def test_embedded_acquisition_passes_no_external_manifest(tmp_path):
    result, fake = consume(tmp_path, m.synthetic_observation(), evidence=m.evidence_for(manifest_store=m.SYNTHETIC_MANIFEST_STORE))
    (call,) = fake.calls()
    assert "--external-manifest" not in call["argv"]


@pytest.mark.parametrize("name", ["../escape.jpg", "a/b.jpg", "-flag.jpg", "", "x" * 200, "with space.jpg"])
def test_unsafe_asset_names_are_refused_before_the_validator_runs(tmp_path, name):  # GUARD REC-ASSET-NAME
    ev = m.RetainedEvidence(asset=m.SYNTHETIC_ASSET, asset_name=name, native_report=m.report_bytes(m.REPORT_VALID_UNTRUSTED))
    result, fake = consume(tmp_path, m.synthetic_observation(), evidence=ev)
    assert result.stopped_at == "native_recomputation"
    assert [r.code for r in result.stages["native_recomputation"].refusals] == ["RECOMPUTE_ASSET_NAME_INVALID"]
    assert fake.calls() == []


def test_validator_is_invoked_hermetically_with_the_verifiers_own_settings_and_no_url(tmp_path):
    obs = m.synthetic_observation(mode="remote_reference")
    obs["signer_trust"]["trust_pointer_uri"] = "https://synthetic.invalid/trustlist.json"
    ev = m.evidence_for(manifest_store=m.SYNTHETIC_MANIFEST_STORE)
    result, fake = consume(tmp_path, obs, evidence=ev)
    assert result.stopped_at is None
    (call,) = fake.calls()
    assert not any("://" in token for token in call["argv"])
    assert call["settings_text"] == c2pa_native.HERMETIC_SETTINGS_TOML
    for line in ("remote_manifest_fetch = false", "ocsp_fetch = false", "allowed_network_hosts = []"):
        assert line in call["settings_text"]
    assert result.report["observed_finding"]["inputs"]["remote_manifest_uri"] == "https://synthetic.invalid/manifests/0001"


def test_recompute_stage_reports_the_settings_it_used_are_the_verifiers_not_the_producers(tmp_path):
    result, _ = consume(tmp_path, m.synthetic_observation())
    assert "verifier-owned" in result.stages["native_recomputation"].detail["settings"]


# -- the comparison's source-digest gates -------------------------------------------------


def _sides():
    observed = adapter.construct_observed_side(
        m.synthetic_observation(),
        adapter.StageOutcome("input_correspondence", "completed"),
        adapter.StageOutcome("profile_conformance", "completed"),
        bundle=BUNDLE,
    )[0]
    recomputed = copy.deepcopy(observed)
    recomputed["side"] = "recomputed"
    recomputed["evidence_class"] = "live_native_invocation"
    return observed, recomputed


def test_source_digest_gate_passes_when_both_sides_saw_the_same_bytes():
    observed, recomputed = _sides()
    assert adapter.source_digest_refusals(observed, recomputed) == []


def test_source_digest_gate_refuses_different_asset_bytes():  # GUARD CMP-ASSET-DIGEST
    observed, recomputed = _sides()
    recomputed["inputs"]["asset_digest"] = m.sha(m.SYNTHETIC_OTHER_ASSET)
    assert [r.code for r in adapter.source_digest_refusals(observed, recomputed)] == ["COMPARISON_ASSET_DIGEST_MISMATCH"]


def test_source_digest_gate_refuses_different_manifest_store_bytes():  # GUARD CMP-MANIFEST-DIGEST
    observed, recomputed = _sides()
    recomputed["inputs"]["manifest_store_digest"] = m.sha(m.SYNTHETIC_OTHER_MANIFEST_STORE)
    assert [r.code for r in adapter.source_digest_refusals(observed, recomputed)] == ["COMPARISON_MANIFEST_STORE_DIGEST_MISMATCH"]


def test_comparison_stage_refuses_when_the_sides_saw_different_bytes(monkeypatch, tmp_path):  # GUARD CMP-GATE-REFUSES
    real = adapter._stage_recompute

    def swapped(obs, evidence, executable, bundle):
        report, outcome = real(obs, evidence, executable, bundle)
        report["recomputed"]["inputs"]["asset_digest"] = m.sha(m.SYNTHETIC_OTHER_ASSET)
        return report, outcome

    monkeypatch.setattr(adapter, "_stage_recompute", swapped)
    result, _ = consume(tmp_path, m.synthetic_observation())
    assert result.stopped_at == "comparison"
    assert result.stages["comparison"].status == "refused"
    assert [r.code for r in result.stages["comparison"].refusals] == ["COMPARISON_ASSET_DIGEST_MISMATCH"]
    assert result.report["native_comparison_report"] is None


def test_existing_comparison_marks_every_axis_input_delta_when_asset_digests_differ():
    """Regression for the contract's own source-digest predicate (the C2PA-05 falsifier): the
    existing compare_sides must refuse to compare sides evaluated over different asset bytes."""
    observed, recomputed = _sides()
    recomputed["inputs"]["asset_digest"] = m.sha(m.SYNTHETIC_OTHER_ASSET)
    comparisons, comparability = c2pa_native.compare_sides(observed, recomputed, bundle=BUNDLE)
    assert comparability["asset_digest_match"] is False
    for item in comparisons:
        if item["axis"] == "revocation":
            continue
        assert (item["state"], item["comparison_reason"]) == ("not_comparable", "input_delta"), item["axis"]


def test_existing_comparison_marks_every_axis_input_delta_when_manifest_store_digests_differ():
    observed, recomputed = _sides()
    recomputed["inputs"]["manifest_store_digest"] = m.sha(m.SYNTHETIC_OTHER_MANIFEST_STORE)
    comparisons, comparability = c2pa_native.compare_sides(observed, recomputed, bundle=BUNDLE)
    assert comparability["manifest_store_digest_match"] is False
    assert all((i["state"], i["comparison_reason"]) == ("not_comparable", "input_delta") for i in comparisons if i["axis"] != "revocation")


def test_assembled_report_that_fails_its_own_contract_is_not_relied_on(monkeypatch, tmp_path):
    def broken(report, *, bundle=None):
        result = c2pa_native.ConformanceResult()
        result.fail("C2PA_SYNTHETIC", "forced non-conformance")
        return result

    monkeypatch.setattr(c2pa_native, "check_report", broken)
    result, _ = consume(tmp_path, m.synthetic_observation())
    assert result.stopped_at == "comparison"
    assert result.stages["comparison"].status == "refused"
    assert [r.code for r in result.stages["comparison"].refusals] == ["COMPARISON_REPORT_NONCONFORMANT"]


def test_an_unexpected_error_in_recomputation_is_a_refusal_never_a_pass(monkeypatch, tmp_path):
    def boom(*_a, **_k):
        raise RuntimeError("synthetic internal failure")

    monkeypatch.setattr(c2pa_native, "recompute", boom)
    result, _ = consume(tmp_path, m.synthetic_observation())
    assert result.stopped_at == "native_recomputation"
    assert result.stages["native_recomputation"].status == "refused"
    assert [r.code for r in result.stages["native_recomputation"].refusals] == ["RECOMPUTE_INTERNAL_ERROR"]
    assert result.report["axes"]["independent_comparison"]["per_axis"] == []


def test_an_unexpected_error_in_the_comparison_is_a_refusal_never_a_pass(monkeypatch, tmp_path):
    real = c2pa_native.build_report

    def boom(*args, **kwargs):
        if kwargs.get("observed") is not None:  # recompute() builds its own observation-free report first
            raise RuntimeError("synthetic internal failure")
        return real(*args, **kwargs)

    monkeypatch.setattr(c2pa_native, "build_report", boom)
    result, _ = consume(tmp_path, m.synthetic_observation())
    assert result.stopped_at == "comparison"
    assert result.stages["comparison"].status == "refused"
    assert [r.code for r in result.stages["comparison"].refusals] == ["COMPARISON_INTERNAL_ERROR"]
    assert result.report["native_comparison_report"] is None


def test_a_different_validator_implementation_is_not_comparable(tmp_path):
    obs = m.mutated(m.synthetic_observation(), "native_validator.implementation", "other-native-validator")
    result, _ = consume(tmp_path, obs)
    axes = per_axis(result)
    for name, item in axes.items():
        if name == "revocation":
            continue
        assert (item["state"], item["comparison_reason"]) == ("not_comparable", "validator_implementation_delta"), name
        assert item["integrity_posture"] == "no_integrity_inference"


# -- a producer-declared (or disclosed) non-comparability is honoured ------------------------


def not_comparable_axes(result):
    return {a: i for a, i in per_axis(result).items() if i["effective_state_source"] == "adapter"}


def test_producer_declared_not_comparable_stops_trust_and_clock_axes_from_being_compared(tmp_path):  # GUARD CMP-DECLARED-NOT-COMPARABLE
    obs = m.mutated(m.synthetic_observation(), "later_comparison_posture", "not_comparable")
    result, _ = consume(tmp_path, obs)
    axes = per_axis(result)
    for name in ("signer_trust", "signer_validity", "timestamp"):
        assert axes[name]["state"] == "not_comparable" and axes[name]["comparison_reason"] == "producer_declared_not_comparable", name
        assert axes[name]["integrity_posture"] == "no_integrity_inference"
        assert axes[name]["contract_comparison"]["state"] == "match"
    for name in ("manifest_structure", "asset_binding", "claim_signature", "ingredient"):
        assert axes[name]["state"] == "match" and axes[name]["effective_state_source"] == "contract", name
    assert set(not_comparable_axes(result)) == {"signer_trust", "signer_validity", "timestamp"}


def test_a_declared_not_comparable_axis_is_not_a_mismatch_either(tmp_path):
    obs = m.mutated(m.synthetic_observation(m.REPORT_EXPIRED), "later_comparison_posture", "not_comparable")
    result, _ = consume(tmp_path, obs, evidence=m.evidence_for(m.REPORT_EXPIRED), validator_report=m.REPORT_VALID_UNTRUSTED)
    entry = per_axis(result)["signer_validity"]
    assert entry["state"] == "not_comparable" and entry["integrity_posture"] == "no_integrity_inference"


def test_tsa_trust_material_disclosure_alone_makes_only_the_timestamp_axis_not_comparable(tmp_path):  # GUARD CMP-TSA-NOT-CAPTURED
    obs = m.synthetic_observation(m.REPORT_ANCHORED)
    obs["trusted_timestamp"] = {"present": True, "observation": "validated_and_trusted"}
    obs["unavailable_inputs"].append({"input": "tsa_trust_material", "reason": "any producer wording"})
    result, _ = consume(tmp_path, obs, evidence=m.evidence_for(m.REPORT_ANCHORED), validator_report=m.REPORT_ANCHORED)
    axes = per_axis(result)
    assert axes["timestamp"]["state"] == "not_comparable" and axes["timestamp"]["comparison_reason"] == "tsa_trust_material_not_captured"
    assert axes["timestamp"]["contract_comparison"]["state"] == "match"
    assert set(not_comparable_axes(result)) == {"timestamp"}
    assert result.report["axes"]["timestamp"]["reading"] == "producer_observed_tsa_trust_material_unavailable"


def test_without_a_disclosure_or_declaration_a_matching_timestamp_stays_a_contract_match(tmp_path):
    obs = m.synthetic_observation(m.REPORT_ANCHORED)
    result, _ = consume(tmp_path, obs, evidence=m.evidence_for(m.REPORT_ANCHORED), validator_report=m.REPORT_ANCHORED)
    entry = per_axis(result)["timestamp"]
    assert entry["state"] == "match" and entry["effective_state_source"] == "contract"
    assert not_comparable_axes(result) == {}


def test_a_comparable_declaration_changes_nothing(tmp_path):
    result, _ = consume(tmp_path, m.mutated(m.synthetic_observation(), "later_comparison_posture", "comparable"))
    assert not_comparable_axes(result) == {}
