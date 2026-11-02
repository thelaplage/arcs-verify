"""Step 3: the untrusted observed-side canonical finding, and what is refused instead.

SYNTHETIC observations only. A value with no canonical representation is a typed refusal;
a trust value the producer asserted never becomes an independent finding."""
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from arcs_verify import c2pa_native
from arcs_verify import c2pa_srs_observed as adapter

from . import material as m

VECTORS = Path(__file__).resolve().parent / "pinned_vectors"
CORR = adapter.StageOutcome("input_correspondence", "completed")
CONF = adapter.StageOutcome("profile_conformance", "completed")
BUNDLE = c2pa_native.load_bundle()
GOOD_REF = {"role": "allowed_list", "digest": m.ALLOWED_LIST_DIGEST, "source_identity": "SYNTHETIC", "source_pin": "pin-0001"}


def build(obs):
    return adapter.construct_observed_side(obs, CORR, CONF, bundle=BUNDLE)


def codes(outcome):
    return {r.code for r in outcome.refusals}


def vector(kind, name):
    raw = json.loads((VECTORS / kind / name).read_text())
    return {k: v for k, v in raw.items() if not k.startswith("_")}


def allowed_list_obs(report=m.REPORT_TRUSTED_ALLOWED, **kw):
    obs = m.synthetic_observation(report, **kw)
    obs["signer_trust"]["trust_basis"] = "custom_allowed_list"
    obs["signer_trust"]["trust_material_refs"] = [GOOD_REF]
    return obs


def test_default_basis_observation_maps_to_a_schema_valid_observed_side():
    finding, outcome = build(m.synthetic_observation())
    assert outcome.status == "completed"
    Draft202012Validator(BUNDLE.finding_schema).validate(finding)
    assert finding["side"] == "observed"
    assert finding["evidence_class"] == "supplied_producer_assertion"
    assert finding["trust_basis"] == {
        "mode": "default",
        "material_digest": None,
        "material_source": None,
        "material_source_pin": None,
        "on_official_c2pa_trust_list": "not_established",
    }
    assert finding["native_validation_state"] == "Valid"


@pytest.mark.parametrize(
    "basis,mode,material",
    [
        ("default_no_trust_material", "default", False),
        ("explicit_anchors", "anchors_supplied", True),
        ("custom_allowed_list", "allowed_list_supplied", True),
        ("trust_verification_disabled", "trust_disabled", False),
    ],
)
def test_each_supported_trust_basis_maps_to_its_own_canonical_mode(basis, mode, material):
    obs = m.synthetic_observation()
    obs["signer_trust"]["trust_basis"] = basis
    if material:
        obs["signer_trust"]["trust_material_refs"] = [dict(GOOD_REF, role="trust_anchors" if basis == "explicit_anchors" else "allowed_list")]
    finding, outcome = build(obs)
    assert outcome.status == "completed", outcome.refusals
    assert finding["trust_basis"]["mode"] == mode
    assert finding["trust_basis"]["material_digest"] == (m.ALLOWED_LIST_DIGEST if material else None)
    assert finding["trust_basis"]["on_official_c2pa_trust_list"] == "not_established"


@pytest.mark.parametrize(
    "kind,name",
    [
        ("valid", "f06-official-trust-list-basis.json"),
        ("valid", "f05-trust-basis-not-captured-not-comparable.json"),
    ],
)
def test_trust_bases_with_no_canonical_mode_are_refused_not_approximated(kind, name):  # GUARD MAP-TRUST-BASIS-UNMAPPED
    obs = vector(kind, name)
    assert adapter._stage_conformance(obs)[1].status == "completed"  # profile-valid, still unmappable
    finding, outcome = build(obs)
    assert finding is None and outcome.status == "refused"
    assert "MAP_TRUST_BASIS_UNMAPPED" in codes(outcome)


def test_more_than_one_trust_material_digest_is_refused():  # GUARD MAP-TRUST-MATERIAL-COUNT
    obs = allowed_list_obs()
    obs["signer_trust"]["trust_material_refs"] = [GOOD_REF, dict(GOOD_REF, digest=m.ANCHORS_DIGEST)]
    assert codes(build(obs)[1]) == {"MAP_TRUST_MATERIAL_COUNT_UNMAPPED"}


def test_trust_material_under_a_basis_that_supplies_none_is_refused():  # GUARD MAP-TRUST-MATERIAL-UNEXPECTED
    obs = m.synthetic_observation()
    obs["signer_trust"]["trust_material_refs"] = [GOOD_REF]
    assert adapter._stage_conformance(obs)[1].status == "completed"
    assert codes(build(obs)[1]) == {"MAP_TRUST_MATERIAL_UNEXPECTED"}


def test_posture_with_no_native_evaluation_is_refused():  # GUARD MAP-POSTURE
    obs = vector("valid", "f09-no-manifest-store-no-digest.json")
    _, outcome = build(obs)
    assert "MAP_EVALUATION_POSTURE_UNMAPPED" in codes(outcome)


def test_acquisition_mode_none_has_no_canonical_mode():  # GUARD MAP-ACQUISITION-MODE
    obs = vector("valid", "f09-no-manifest-store-no-digest.json")
    assert obs["manifest_acquisition"]["mode"] == "none"
    assert "MAP_ACQUISITION_MODE_UNMAPPED" in codes(build(obs)[1])


def test_validator_defaults_leave_no_settings_digest_to_map():  # GUARD MAP-SETTINGS-DIGEST
    obs = m.synthetic_observation()
    obs["native_validator"]["configuration_posture"] = "validator_defaults"
    obs["native_validator"]["configuration_digest"] = None
    assert codes(build(obs)[1]) == {"MAP_SETTINGS_DIGEST_UNAVAILABLE"}


@pytest.mark.parametrize(
    "mutate",
    [
        lambda o: m.without(o, "hermetic_replay"),
        lambda o: m.mutated(o, "hermetic_replay.performed", False),
        lambda o: m.mutated(o, "hermetic_replay.performed", False) | {"hermetic_replay": {"performed": False, "remote_manifest_fetch_applied": True, "ocsp_fetch_applied": False}},
        lambda o: m.mutated(o, "hermetic_replay.ocsp_fetch_applied", True),
        lambda o: m.mutated(o, "hermetic_replay.allowed_network_hosts", ["synthetic.invalid"]),
        lambda o: m.without(o, "hermetic_replay.allowed_network_hosts"),
    ],
    ids=["absent", "not-performed", "fetch-applied-unperformed", "ocsp-applied", "hosts-allowed", "hosts-unstated"],
)
def test_hermeticity_that_is_not_stated_or_not_established_is_refused(mutate):  # GUARD MAP-HERMETICITY
    obs = mutate(m.synthetic_observation())
    assert codes(build(obs)[1]) == {"MAP_HERMETICITY_NOT_ESTABLISHED"}


def test_a_pinned_validation_clock_has_no_canonical_representation():  # GUARD MAP-VALIDATION-TIME
    obs = m.mutated(m.synthetic_observation(), "validation_time.validation_time_control", "supported_and_pinned")
    assert codes(build(obs)[1]) == {"MAP_VALIDATION_TIME_PINNED_UNSUPPORTED"}


def test_a_native_state_outside_the_canonical_set_is_refused_not_passed_through():  # GUARD MAP-NATIVE-STATE
    obs = m.mutated(m.synthetic_observation(), "native_report.native_validation_state", "Mostly Valid")
    assert codes(build(obs)[1]) == {"MAP_NATIVE_VALIDATION_STATE_UNMAPPED"}


def test_trusted_assertion_contradicted_by_an_untrusted_native_finding_is_refused():  # GUARD MAP-TRUST-CONTRADICTS-TRUSTED
    obs = allowed_list_obs(m.REPORT_VALID_UNTRUSTED)  # native findings: signingCredential.untrusted
    obs["signer_trust"]["trust_observation"] = "trusted"
    assert codes(build(obs)[1]) == {"MAP_TRUST_OBSERVATION_CONTRADICTS_FINDINGS"}


def test_untrusted_assertion_contradicted_by_a_trusted_native_finding_is_refused():  # GUARD MAP-TRUST-CONTRADICTS-UNTRUSTED
    obs = allowed_list_obs(m.REPORT_TRUSTED_ALLOWED)  # native findings: signingCredential.trusted
    obs["signer_trust"]["trust_observation"] = "untrusted"
    assert codes(build(obs)[1]) == {"MAP_TRUST_OBSERVATION_CONTRADICTS_FINDINGS"}


# A real expired-signing-certificate report carries claimSignature.insideValidity (validity at signing
# time) and signingCredential.expired (validity at validation time) together. That pair is two facts on
# two axes, never a contradiction, whatever scalar the producer summarised it as.
EXPIRED_PAIR_REPORT = m.native_report(
    "Invalid",
    success=("claimSignature.insideValidity", "claimSignature.validated", "assertion.dataHash.match"),
    failure=("signingCredential.expired", "signingCredential.untrusted"),
)


@pytest.mark.parametrize(
    "scalar,expected",
    [
        ("expired", "consistent"),
        ("inside_validity", "time_basis_differs"),
        ("not_evaluated", "not_evaluated_by_producer"),
    ],
)
def test_expired_certificate_pair_is_never_a_contradiction_and_never_refused(scalar, expected):
    obs = m.synthetic_observation(EXPIRED_PAIR_REPORT)
    obs["signer_validity"]["observation"] = scalar
    finding, outcome = build(obs)
    assert outcome.status == "completed", outcome.refusals
    by_axis = {a["axis"]: a["status"] for a in finding["axes"]}
    assert by_axis["claim_signature"] == "satisfied"  # signing-time validity
    assert by_axis["signer_validity"] == "failed"  # validation-time expiry, from the native finding
    asserted = adapter._producer_asserted(obs)["signer_validity"]
    assert asserted["consistency_with_native_findings"] == expected
    assert "contradict" not in json.dumps(asserted).lower()
    assert "contradict" not in json.dumps(outcome.to_dict()).lower()


def test_signer_validity_scalar_never_feeds_the_canonical_axis():
    quiet = m.native_report("Valid", success=("claimSignature.validated", "assertion.dataHash.match"))
    inside, _ = build(m.mutated(m.synthetic_observation(quiet), "signer_validity.observation", "inside_validity"))
    expired, _ = build(m.mutated(m.synthetic_observation(quiet), "signer_validity.observation", "expired"))
    assert inside["axes"] == expired["axes"]
    assert {a["axis"]: a["status"] for a in inside["axes"]}["signer_validity"] == "not_evaluated"
    assert adapter._producer_asserted(m.mutated(m.synthetic_observation(quiet), "signer_validity.observation", "inside_validity"))[
        "signer_validity"
    ]["consistency_with_native_findings"] == "uncorroborated"
    assert adapter._producer_asserted(m.mutated(m.synthetic_observation(quiet), "signer_validity.observation", "expired"))[
        "signer_validity"
    ]["consistency_with_native_findings"] == "uncorroborated"


def test_a_producer_trust_claim_with_no_native_trust_finding_does_not_become_an_axis_result():
    """`trusted` asserted under an allowed list, but the native findings carry no trust code
    at all. The canonical signer_trust axis comes from native findings only, so it stays
    not_evaluated; the claim is reported as producer_asserted and uncorroborated."""
    quiet = m.native_report("Valid", success=("claimSignature.validated", "assertion.dataHash.match"))
    obs = allowed_list_obs(quiet)
    obs["signer_trust"]["trust_observation"] = "trusted"
    finding, outcome = build(obs)
    assert outcome.status == "completed"
    axis = {a["axis"]: a for a in finding["axes"]}["signer_trust"]
    assert axis["status"] == "not_evaluated" and axis["native_findings"] == []
    asserted = adapter._producer_asserted(obs)
    assert asserted["provenance"] == "producer_asserted"
    assert asserted["independent_finding"] == "not_evaluated"
    assert asserted["signer_trust"]["trust_observation"] == "trusted"
    assert asserted["signer_trust"]["consistency_with_native_findings"] == "uncorroborated"


def test_a_corroborated_producer_claim_is_still_only_producer_asserted():
    obs = allowed_list_obs(m.REPORT_TRUSTED_ALLOWED)
    obs["signer_trust"]["trust_observation"] = "trusted"
    asserted = adapter._producer_asserted(obs)
    assert asserted["signer_trust"]["consistency_with_native_findings"] == "consistent"
    assert asserted["independent_finding"] == "not_evaluated"


def test_observed_axes_follow_the_native_findings_not_the_producer_scalar_fields():
    obs = m.synthetic_observation(m.REPORT_INVALID_CLAIM)
    finding, _ = build(obs)
    by_axis = {a["axis"]: a["status"] for a in finding["axes"]}
    assert by_axis["claim_signature"] == "failed"
    assert by_axis["asset_binding"] == "satisfied"
    assert by_axis["signer_trust"] == "failed"
    assert by_axis["revocation"] == "not_evaluated"
    assert finding["native_validation_state"] == "Invalid"  # verbatim native field, not a verdict


def test_process_exit_code_never_enters_the_canonical_finding():
    zero, _ = build(m.synthetic_observation(m.REPORT_INVALID_CLAIM, exit_code=0))
    other, _ = build(m.synthetic_observation(m.REPORT_INVALID_CLAIM, exit_code=7))
    assert zero == other
    assert "exit" not in json.dumps(zero).lower().replace("hermeticity", "")


def test_embedded_store_digest_is_not_separate_bytes_in_the_canonical_finding():
    finding, _ = build(m.synthetic_observation(mode="embedded"))
    assert finding["inputs"]["manifest_store_digest"] is None


def test_captured_store_digest_is_carried_for_non_embedded_acquisition():
    obs = m.synthetic_observation(mode="external_supplied")
    finding, _ = build(obs)
    assert finding["inputs"]["manifest_store_digest"] == obs["manifest_store"]["digest"]


def test_remote_uri_is_recorded_as_text_only():
    obs = m.synthetic_observation(mode="remote_reference")
    finding, _ = build(obs)
    assert finding["inputs"]["remote_manifest_uri"] == "https://synthetic.invalid/manifests/0001"
    assert finding["inputs"]["manifest_acquisition_mode"] == "remote_reference"


def test_settings_are_derived_from_the_observation_not_copied_from_the_verifier():
    finding, _ = build(m.synthetic_observation())
    assert "verify_trust" not in finding["settings"] and "verify_timestamp_trust" not in finding["settings"]
    assert finding["settings"]["settings_digest"] == m.synthetic_observation()["native_validator"]["configuration_digest"]
    assert set(finding["settings"]["hermeticity"]) == {
        "network_access_permitted",
        "remote_resource_fetch_attempted",
        "trust_list_uri_dereferenced",
        "ocsp_fetch_permitted",
    }


def test_validator_identity_comes_from_the_observation():
    finding, _ = build(m.synthetic_observation(version="0.27.14"))
    assert finding["validator"] == {"implementation": "c2patool", "version": "0.27.14", "c2pa_specification_version": "2.4"}


def test_input_unavailable_posture_maps_to_an_unavailable_finding_not_a_failure():
    obs = vector("valid", "f12-input-unavailable-not-validation-failure.json")
    assert adapter._stage_conformance(obs)[1].status == "completed"
    finding, outcome = build(obs)
    assert outcome.status == "completed", outcome.refusals
    Draft202012Validator(BUNDLE.finding_schema).validate(finding)
    assert finding["evaluation_status"] == "input_unavailable"
    assert all(a["status"] == "not_evaluated" for a in finding["axes"])
    assert finding["native_validation_state"] is None


def test_input_unavailable_synthetic_observation_maps_to_all_axes_not_evaluated():
    obs = m.synthetic_observation()
    obs["evaluation_posture"] = "input_unavailable"
    del obs["native_report"], obs["native_findings"]
    obs["manifest_store"] = {"state": "inaccessible"}
    obs["manifest_acquisition"].update(mode="remote_reference", remote_manifest_uri="https://synthetic.invalid/m/1")
    assert adapter._stage_conformance(obs)[1].status == "completed"
    finding, outcome = build(obs)
    assert outcome.status == "completed"
    Draft202012Validator(BUNDLE.finding_schema).validate(finding)
    assert finding["evaluation_status"] == "input_unavailable"
    assert all(a["status"] == "not_evaluated" for a in finding["axes"])
    assert finding["native_validation_state"] is None and finding["native_report_digest"] is None
    assert finding["settings"]["hermeticity"]["remote_resource_required_but_unavailable"] is True
    assert finding["validator"]["implementation"] == "c2patool"


def test_unmapped_native_codes_are_surfaced_not_dropped():
    odd = m.native_report("Valid", success=("claimSignature.validated",), failure=("some.future.native.code",))
    finding, outcome = build(m.synthetic_observation(odd))
    assert [e["code"] for e in finding["unmapped_native_codes"]] == ["some.future.native.code"]
    assert outcome.detail["unmapped_native_codes"] == finding["unmapped_native_codes"]


def test_ingredient_scoped_findings_stay_in_the_ingredient_axis():
    rep = m.native_report("Invalid", success=("assertion.dataHash.match",), ingredient_failure=("ingredient.manifest.missing",))
    finding, _ = build(m.synthetic_observation(rep))
    axis = {a["axis"]: a for a in finding["axes"]}["ingredient"]
    assert axis["status"] == "failed"
    assert axis["native_findings"][0]["scope"] == "ingredientDeltas"


def test_internal_error_in_construction_is_a_refusal(monkeypatch):
    def boom(*_a, **_k):
        raise RuntimeError("synthetic internal failure")

    monkeypatch.setattr(c2pa_native, "canonical_finding_from_native_report", boom)
    finding, outcome = adapter._stage_construct(m.synthetic_observation(), CORR, CONF, BUNDLE)
    assert finding is None and codes(outcome) == {"OBSERVED_FINDING_INTERNAL_ERROR"}


def test_observed_settings_mirror_the_observations_own_hermetic_statement():
    obs = m.synthetic_observation()
    finding, _ = build(obs)
    replay = obs["hermetic_replay"]
    assert finding["settings"]["remote_manifest_fetch"] is replay["remote_manifest_fetch_applied"] is False
    assert finding["settings"]["ocsp_fetch"] is replay["ocsp_fetch_applied"] is False
    assert finding["settings"]["allowed_network_hosts"] == replay["allowed_network_hosts"] == []
    assert finding["settings"]["hermeticity"]["trust_list_uri_dereferenced"] is obs["signer_trust"]["trust_pointer_dereferenced"] is False


def test_producer_asserted_exposes_both_comparability_fields_on_the_native_validation_path():
    """Owner code finding at 4d34abad: the producer-asserted block exposed neither field."""
    obs = m.synthetic_observation(m.REPORT_ANCHORED)
    obs["later_comparison_posture"] = "not_comparable"
    obs["unavailable_inputs"].append({"input": "tsa_trust_material", "reason": "any wording"})
    asserted = adapter._producer_asserted(obs)
    assert asserted["later_comparison_posture"] == "not_comparable"
    assert [i["input"] for i in asserted["unavailable_inputs"]] == ["certificate_revocation_evidence", "tsa_trust_material"]
    assert {f["code"] for f in asserted["native_findings_as_observations"]} >= {"timeStamp.trusted", "claimSignature.validated"}
    assert all(set(f) <= {"scope", "severity", "code", "uri"} for f in asserted["native_findings_as_observations"])
