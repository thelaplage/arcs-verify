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


# -- a producer-declared (or disclosed) non-comparability is honoured -------------------------
#
# Owner rule: a conservative RECEIPT-WIDE comparability restriction. Every supported axis is still
# recomputed and reported independently; none is reported as an effective match; there is no overall
# result; the separate reasons are kept separate and never inferred from not_comparable alone.


def restricted(result):
    return result.report["axes"]["comparability_restriction"]


def reason_names(result):
    return [r["reason"] for r in restricted(result)["reasons"]]


def declared(obs, posture="not_comparable"):
    return m.mutated(obs, "later_comparison_posture", posture)


def with_tsa_disclosure(obs):
    out = json.loads(json.dumps(obs))
    out["unavailable_inputs"].append({"input": "tsa_trust_material", "reason": "any producer wording"})
    return out


def anchored(obs):
    out = json.loads(json.dumps(obs))
    out["trusted_timestamp"] = {"present": True, "observation": "validated_and_trusted"}
    return out


def signer_basis_missing(obs):
    out = json.loads(json.dumps(obs))
    out["signer_trust"].update(trust_basis="unknown_not_captured", trust_observation="not_evaluated")
    out["machine_limitations"].append({"code": "C2PA_TRUST_BASIS_NOT_CAPTURED"})
    out["later_comparison_posture"] = "not_comparable"  # the pinned profile forces this
    return out


ANCHORED_BASE = anchored(m.synthetic_observation(m.REPORT_ANCHORED))


def run_anchored(tmp_path, obs):
    return consume(tmp_path, obs, evidence=m.evidence_for(m.REPORT_ANCHORED), validator_report=m.REPORT_ANCHORED)[0]


def test_case_tsa_material_missing_restricts_the_whole_receipt_with_only_its_own_reason(tmp_path):  # GUARD CMP-RESTRICTED-RECEIPT-WIDE
    result = run_anchored(tmp_path, declared(with_tsa_disclosure(ANCHORED_BASE)))
    assert reason_names(result) == ["tsa_trust_material_uncaptured"]
    assert restricted(result)["scope"] == "receipt_wide"
    assert result.stages["comparison"].status == "restricted" and result.stopped_at == "comparison"
    entries = per_axis(result)
    assert list(entries) == list(c2pa_native.AXIS_ORDER)  # every supported axis is still reported
    for name, item in entries.items():
        assert item["state"] == "restricted_receipt_wide", name
        assert item["effective_state_source"] == "adapter" and item["integrity_posture"] == "no_integrity_inference"
        assert item["observed_status"] is not None and item["recomputed_status"] is not None
    # a byte-deterministic agreement is visible as the contract's own entry, never as the effective state
    assert entries["asset_binding"]["contract_comparison"]["state"] == "match"
    assert not [i for i in entries.values() if i["state"] in ("match", "mismatch")]
    assert "agreement_basis" not in entries["asset_binding"]


def test_case_signer_basis_missing_restricts_the_whole_receipt_with_only_its_own_reason(tmp_path):  # GUARD RESTRICT-REASON-SIGNER
    result, fake = consume(tmp_path, signer_basis_missing(ANCHORED_BASE), evidence=m.evidence_for(m.REPORT_ANCHORED), validator_report=m.REPORT_ANCHORED)
    assert reason_names(result) == ["signer_trust_inputs_uncaptured"]
    assert restricted(result)["scope"] == "receipt_wide"
    # the observed side has no canonical form (no trust-basis mode), yet the recomputation still happened
    assert result.stages["observed_finding_construction"].status == "refused"
    assert result.stages["native_recomputation"].status == "completed" and len(fake.calls()) == 1
    recomputation = result.report["axes"]["independent_recomputation"]
    assert {a["axis"]: a["recomputed_status"] for a in recomputation["per_axis"]}["asset_binding"] == "satisfied"
    assert result.report["axes"]["independent_comparison"]["per_axis"] == []
    # the producer's native findings are preserved as observations
    observed = result.report["producer_asserted"]["native_findings_as_observations"]
    assert {"scope": "activeManifest", "severity": "success", "code": "timeStamp.trusted"} == {k: observed[2][k] for k in ("scope", "severity", "code")} or any(
        f["code"] == "timeStamp.trusted" for f in observed
    )


def test_case_both_missing_lists_both_reasons_separately_in_a_stable_order(tmp_path):  # GUARD RESTRICT-REASON-TSA
    result, _ = consume(tmp_path, with_tsa_disclosure(signer_basis_missing(ANCHORED_BASE)), evidence=m.evidence_for(m.REPORT_ANCHORED), validator_report=m.REPORT_ANCHORED)
    assert reason_names(result) == ["signer_trust_inputs_uncaptured", "tsa_trust_material_uncaptured"]
    assert {r["stated_by"] for r in restricted(result)["reasons"]} == {"signer_trust.trust_basis", "unavailable_inputs[tsa_trust_material]"}
    assert restricted(result)["scope"] == "receipt_wide"


def test_case_tsa_material_present_is_not_restricted_but_is_still_not_independent_tsa_trust(tmp_path):
    obs = json.loads(json.dumps(ANCHORED_BASE))
    obs["trusted_timestamp"]["tsa_trust_material_ref"] = m.ANCHORS_DIGEST
    result = run_anchored(tmp_path, obs)
    assert restricted(result)["scope"] == "none" and restricted(result)["reasons"] == []
    assert result.stopped_at is None and result.stages["comparison"].status == "completed"
    entry = per_axis(result)["timestamp"]
    assert entry["state"] == "match" and entry["effective_state_source"] == "contract"
    timestamp = result.report["axes"]["timestamp"]
    assert timestamp["reading"] == "producer_observed_tsa_trust_material_digest_named_unchecked"
    assert timestamp["reliance"] == {"status": "not_established", "restricted_by": ["tsa_trust_material_named_but_unchecked"], "independent_tsa_appraisal": "not_evaluated"}


def test_case_no_native_trusted_timestamp_claim_is_not_restricted_and_claims_nothing(tmp_path):
    result, _ = consume(tmp_path, m.synthetic_observation())
    assert restricted(result)["scope"] == "none" and restricted(result)["reasons"] == []
    assert result.stopped_at is None
    timestamp = result.report["axes"]["timestamp"]
    assert timestamp["reading"] == "no_trusted_timestamp_claimed"
    assert timestamp["reliance"]["status"] == "no_native_trusted_timestamp_claimed"
    assert timestamp["reliance"]["independent_tsa_appraisal"] == "not_evaluated"


def test_not_comparable_with_no_stated_reason_is_reported_as_exactly_that(tmp_path):  # GUARD RESTRICT-UNSTATED
    result, _ = consume(tmp_path, declared(m.synthetic_observation()))
    assert reason_names(result) == ["declared_without_a_stated_reason"]  # neither specific reason is inferred
    assert restricted(result)["scope"] == "receipt_wide"


def test_the_two_reasons_are_never_inferred_from_each_other_or_from_the_posture(tmp_path):
    only_tsa = run_anchored(tmp_path, with_tsa_disclosure(ANCHORED_BASE))  # disclosure, posture left comparable
    assert reason_names(only_tsa) == ["tsa_trust_material_uncaptured"]
    assert restricted(only_tsa)["scope"] == "none"  # the disclosure does not make the receipt not_comparable
    assert restricted(only_tsa)["axis_level"] == {"timestamp": ["tsa_trust_material_uncaptured"]}


def test_a_disclosure_without_a_declared_posture_restricts_only_the_timestamp_axis(tmp_path):  # GUARD CMP-TSA-AXIS-LEVEL
    result = run_anchored(tmp_path, with_tsa_disclosure(ANCHORED_BASE))
    entries = per_axis(result)
    assert entries["timestamp"]["state"] == "not_comparable" and entries["timestamp"]["comparison_reason"] == "tsa_trust_material_not_captured"
    assert entries["timestamp"]["contract_comparison"]["state"] == "match"
    assert entries["asset_binding"]["state"] == "match" and entries["asset_binding"]["effective_state_source"] == "contract"
    assert result.stages["comparison"].status == "completed"


def test_tsa_disclosure_preserves_timestamp_mismatch_under_nonconformant_contract(tmp_path):
    obs = with_tsa_disclosure(ANCHORED_BASE)
    recomputed = m.native_report(
        "Valid",
        success=("claimSignature.validated", "assertion.dataHash.match", "timeStamp.validated", "timeStamp.trusted"),
        failure=("signingCredential.untrusted", "timeStamp.mismatch"),
    )
    result, _ = consume(
        tmp_path,
        obs,
        evidence=m.evidence_for(m.REPORT_ANCHORED),
        validator_report=recomputed,
    )
    timestamp = per_axis(result)["timestamp"]
    assert timestamp["state"] == "not_comparable"
    assert timestamp["contract_comparison"]["state"] == "mismatch"
    assert timestamp["comparison_reason"] == "tsa_trust_material_not_captured"
    assert result.stages["comparison"].status == "refused"
    assert [r.code for r in result.stages["comparison"].refusals] == ["COMPARISON_REPORT_NONCONFORMANT"]


def test_a_restricted_receipt_still_surfaces_an_independent_divergence(tmp_path):
    obs = declared(m.synthetic_observation(m.REPORT_VALID_UNTRUSTED))
    result, _ = consume(tmp_path, obs, validator_report=m.REPORT_INVALID_CLAIM)  # the verifier's own run disagrees
    claim = per_axis(result)["claim_signature"]
    assert claim["state"] == "restricted_receipt_wide"
    assert (claim["observed_status"], claim["recomputed_status"]) == ("satisfied", "failed")
    assert claim["contract_comparison"]["state"] == "mismatch"  # the restriction hides agreement, never divergence


def test_a_comparable_declaration_changes_nothing(tmp_path):
    result, _ = consume(tmp_path, declared(m.synthetic_observation(), "comparable"))
    assert restricted(result)["scope"] == "none"
    assert result.stopped_at is None


# -- NAMED NEGATIVE: neither removing unavailable_inputs nor ignoring not_comparable yields reliance --


def reliance(result):
    return result.report["axes"]["timestamp"]["reliance"]


def test_removing_unavailable_inputs_or_ignoring_not_comparable_cannot_yield_reliance_on_a_trusted_timestamp(tmp_path):
    base = ANCHORED_BASE
    only_posture = declared(base)  # not_comparable, no disclosure
    only_disclosure = with_tsa_disclosure(base)  # disclosure, posture comparable
    neither = base
    both = declared(with_tsa_disclosure(base))
    cases = {
        "only_posture": (only_posture, ["tsa_trust_basis_not_disclosed", "receipt_not_comparable"]),
        "only_disclosure": (only_disclosure, ["tsa_trust_material_uncaptured"]),
        "neither": (neither, ["tsa_trust_basis_not_disclosed"]),
        "both": (both, ["tsa_trust_material_uncaptured", "receipt_not_comparable"]),
    }
    results = {}
    for label, (obs, expected) in cases.items():
        sub = tmp_path / label
        sub.mkdir()
        result = results[label] = run_anchored(sub, obs)
        got = reliance(result)
        assert got["status"] == "not_established", label
        assert got["restricted_by"] == expected, label
        assert got["independent_tsa_appraisal"] == "not_evaluated", label
        reading = result.report["axes"]["timestamp"]["reading"]
        assert "independent" not in reading and reading != "no_trusted_timestamp_claimed", label
    # each restriction stands on its own field: ignoring the posture is visible, removing the disclosure is visible
    posture_only = results["only_posture"]
    assert restricted(posture_only)["scope"] == "receipt_wide"
    assert per_axis(posture_only)["timestamp"]["state"] == "restricted_receipt_wide"
    disclosure_only = results["only_disclosure"]
    assert per_axis(disclosure_only)["timestamp"]["state"] == "not_comparable"
    assert per_axis(disclosure_only)["timestamp"]["comparison_reason"] == "tsa_trust_material_not_captured"
