"""Offline replay over bytes a REAL producer emitted (Phase B).

The bytes under tests/c2pa_srs/produced/ are the unmodified output of the C2PA-EMIT0 producer
(dagr-ingest) over a pinned asset and the machine report the pinned c2patool emitted; see
produced/PROVENANCE.json for the producing commit, command, per-file digests and licence. Every
expected digest comes from PROVENANCE.json alone, so replacing the bytes is: re-run the
vendoring tool, re-run these tests.

Two tiers:
* always on, bytes only: provenance integrity, correspondence, profile conformance, construction of
  the observed side, the typed not-evaluated outcome when no validator is supplied, and in-test
  MUTATIONS of the vendored bytes (each labelled TEST MUTATION; the vendored bytes are never edited);
* NOT_EXERCISED unless ARCS_VERIFY_C2PATOOL names the pinned build (c2patool 0.27.15): the verifier's
  own recomputation over the frozen inputs and the per-axis comparison, twice, to show determinism.

This is offline TECHNICAL interoperability only. The observation is unsigned and provisional,
emitted under a test issuer identity; operational issuance readiness is not established.
"""
import hashlib
import json
import os
from pathlib import Path

import pytest

from arcs_verify import c2pa_native
from arcs_verify import c2pa_srs_observed as adapter

from . import material as m

PRODUCED = Path(__file__).resolve().parent / "produced"
PROV = json.loads((PRODUCED / "PROVENANCE.json").read_text())
LIVE = os.environ.get("ARCS_VERIFY_C2PATOOL")
live_only = pytest.mark.skipif(not LIVE, reason="NOT_EXERCISED: set ARCS_VERIFY_C2PATOOL to the pinned c2patool 0.27.15")
NAMES = sorted(PROV["specimens"])


def read(rel):
    return (PRODUCED / rel).read_bytes() if rel else None


def evidence(name, **override):
    spec = PROV["specimens"][name]
    fields = dict(
        asset=read(spec["asset"]),
        asset_name=Path(spec["asset"]).name,
        native_report=read(spec["native_report"]),
        manifest_store=read(spec["manifest_store"]),
        configuration=read("hermetic.toml"),
    )
    fields.update(override)
    return m.RetainedEvidence(**fields)


def observation_bytes(name):
    return read(PROV["specimens"][name]["observation"])


def run(name, *, obs=None, ev=None, executable=None):
    data = observation_bytes(name) if obs is None else (obs if isinstance(obs, bytes) else json.dumps(obs).encode())
    return adapter.consume_observation(data, ev or evidence(name), executable=executable)


def per_axis(result):
    return {i["axis"]: i for i in result.report["axes"]["independent_comparison"]["per_axis"]}


def normalized(result):
    data = json.loads(json.dumps(result.report, sort_keys=True))
    if data.get("native_recomputation"):
        data["native_recomputation"]["recomputed"]["validation_clock"]["instant"] = None
    if data.get("native_comparison_report"):
        data["native_comparison_report"]["recomputed"]["validation_clock"]["instant"] = None
    data["axes"]["source_digest_pin"]["recomputation_validator"] = None
    return json.dumps(data, sort_keys=True)


# -- provenance and the producer's own facts ----------------------------------------------


def test_every_vendored_byte_matches_the_provenance_file_and_nothing_else_is_vendored():
    on_disk = {p.relative_to(PRODUCED).as_posix() for p in PRODUCED.rglob("*") if p.is_file()} - {"PROVENANCE.json"}
    assert on_disk == set(PROV["files"])
    for rel, entry in PROV["files"].items():
        data = read(rel)
        assert "sha256:" + hashlib.sha256(data).hexdigest() == entry["sha256"], rel
        assert len(data) == entry["bytes"], rel
    assert PROV["bytes_are_unmodified"] is True


def test_provenance_names_the_producer_commit_the_command_the_validator_and_the_licence():
    producer = PROV["producer"]
    assert len(producer["producing_commit"]) == 40 and len(producer["head_commit"]) == 40
    assert producer["repository"].endswith("/dagr-ingest")
    assert PROV["command"]["validator_argv_template"][0] == "c2patool"
    assert "Apache-2.0 OR MIT" in PROV["licence"]["assets"]
    for logical, record in PROV["run_records"]["by_specimen"].items():
        assert record["producer_commit"] == producer["producing_commit"], logical
        assert record["checkout_dirty"] is False, logical
        assert record["os_network_deny"] is True, logical
        assert record["validator_version_line"] == "c2patool " + c2pa_native.PINNED_VALIDATOR["version"], logical
        assert record["settings_sha256"] == m.sha(read("hermetic.toml")), logical
    assert "/Users/" not in json.dumps(PROV) and "/home/" not in json.dumps(PROV)


def test_producer_configuration_digest_equals_the_verifiers_own_hermetic_settings_digest():
    assert read("hermetic.toml") == c2pa_native.HERMETIC_SETTINGS_TOML.encode("utf-8")
    assert m.sha(read("hermetic.toml")) == m.sha(m.HERMETIC_CONFIG)


@pytest.mark.parametrize("name", NAMES)
def test_vendored_observation_is_the_one_the_producer_index_names(name):
    spec = PROV["specimens"][name]
    assert m.sha(observation_bytes(name)) == spec["index_observation_sha256"] == PROV["files"][spec["observation"]]["sha256"]


# -- bytes-only stages over the produced observation --------------------------------------


@pytest.mark.parametrize("name", NAMES)
def test_produced_observation_passes_correspondence_profile_and_construction(name):
    result = run(name)
    for stage in ("input_parse", "input_correspondence", "profile_conformance", "observed_finding_construction"):
        assert result.stages[stage].status == "completed", (stage, [r.to_dict() for r in result.stages[stage].refusals])
    checks = result.stages["input_correspondence"].detail
    assert not [c for c in checks["checks"] if c["status"] == "mismatch"]
    assert {u["field"] for u in checks["unchecked"]} <= {"native_validator.build_digest"}


@pytest.mark.parametrize("name", [n for n in NAMES if PROV["specimens"][n]["native_report"]])
def test_every_digest_the_producer_named_is_checked_against_the_retained_bytes(name):
    detail = run(name).stages["input_correspondence"].detail
    matched = {c["field"] for c in detail["checks"] if c["status"] == "match"}
    assert matched == {
        "asset_digest",
        "subject_ref",
        "manifest_store.digest",
        "native_report.report_digest",
        "native_validator.configuration_digest",
    }


@pytest.mark.parametrize("name", NAMES)
def test_without_a_validator_the_recomputation_is_a_typed_not_evaluated(name):
    result = run(name, executable=None)
    assert result.stopped_at == "native_recomputation"
    assert result.stages["native_recomputation"].status == "not_evaluated"
    assert [r.code for r in result.stages["native_recomputation"].refusals] == ["RECOMPUTE_VALIDATOR_NOT_SUPPLIED"]
    assert result.report["axes"]["independent_comparison"]["per_axis"] == []


@pytest.mark.parametrize("name", NAMES)
def test_produced_observation_is_unsigned_provisional_and_authenticates_nothing(name):
    result = run(name)
    auth = result.report["axes"]["srs_receipt_authentication"]
    assert auth["receipt_signature_present"] is False
    assert {auth[a] for a in ("signature_shape", "signature_valid", "key_resolved", "key_trusted", "issuance_authentication")} == {"not_evaluated"}
    assert result.report["axes"]["operational_issuance_readiness"]["status"] == "not_established"
    assert "NON-OPERATIONAL" in result.report["producer_asserted"]["issuer_id"]
    produced = json.loads(observation_bytes(name))
    assert result.report["producer_asserted"]["extensions"]["content"] == produced["extensions"]  # carried, uninterpreted
    assert result.report["authority_movement"] == 0


@pytest.mark.parametrize("name", [n for n in NAMES if PROV["specimens"][n]["native_report"]])
def test_tsa_trust_material_disclosure_is_kept_and_timestamp_trust_is_never_independent(name):
    """The producer disclosed in-band that TSA trust material was not captured. The bridge keeps
    that disclosure; the reason wording is the producer's and is not asserted here."""
    result = run(name)
    timestamp = result.report["axes"]["timestamp"]
    produced = json.loads(observation_bytes(name))
    assert any(i["input"] == "tsa_trust_material" for i in produced["unavailable_inputs"])
    assert [d["input"] for d in timestamp["trust_material_disclosure"]] == ["tsa_trust_material"]
    assert timestamp["trust_material_disclosure"][0]["provenance"] == "producer_disclosed"
    assert timestamp["reading"] == "producer_observed_tsa_trust_material_unavailable"
    assert timestamp["qualification"] and "not independent trust" in timestamp["qualification"]
    assert timestamp["observed_axis_status"] == "satisfied"  # a native finding, still not independent trust
    flat = json.dumps(timestamp).lower()
    assert "independently_trusted" not in flat and "independently trusted" not in flat


def test_tsa_disclosure_is_keyed_on_the_input_name_not_the_reason_wording():
    produced = json.loads(observation_bytes("positive"))
    for item in produced["unavailable_inputs"]:
        if item["input"] == "tsa_trust_material":
            item["reason"] = "completely different producer wording"
    result = run("positive", obs=produced)  # nothing the bridge checks depends on the reason text
    assert result.report["axes"]["timestamp"]["reading"] == "producer_observed_tsa_trust_material_unavailable"
    assert result.report["axes"]["timestamp"]["trust_material_disclosure"][0]["reason"] == "completely different producer wording"


def test_removing_the_disclosure_does_not_make_the_timestamp_independently_trusted():  # TEST MUTATION of the parsed observation
    produced = json.loads(observation_bytes("positive"))
    produced["unavailable_inputs"] = [i for i in produced["unavailable_inputs"] if i["input"] != "tsa_trust_material"]
    result = run("positive", obs=produced)
    timestamp = result.report["axes"]["timestamp"]
    assert timestamp["trust_material_disclosure"] == []
    assert timestamp["reading"] == "producer_observed_tsa_trust_basis_not_disclosed"
    assert "independent" not in timestamp["reading"]


def test_missing_manifest_specimen_claims_no_timestamp_and_stops_without_a_native_evaluation():
    result = run("negative_remote_manifest_missing")
    assert result.report["axes"]["timestamp"]["reading"] == "no_trusted_timestamp_claimed"
    finding = result.report["observed_finding"]
    assert finding["evaluation_status"] == "input_unavailable" and all(a["status"] == "not_evaluated" for a in finding["axes"])
    assert finding["native_validation_state"] is None


def test_tampered_derivative_observation_maps_the_producers_native_invalid_with_exit_zero():
    result = run("negative_native_invalid_exit0")
    finding = result.report["observed_finding"]
    assert finding["native_validation_state"] == "Invalid"
    assert {a["axis"]: a["status"] for a in finding["axes"]}["asset_binding"] == "failed"
    assert result.report["producer_asserted"]["process_exit_code"] == 0
    assert result.report["producer_asserted"]["process_exit_code_semantics"] == "observation_only_never_a_verdict"


@pytest.mark.parametrize("name", NAMES)
def test_bytes_only_stages_are_deterministic_on_byte_identical_inputs(name):
    first, second = run(name), run(name)
    assert json.dumps(first.report, sort_keys=True) == json.dumps(second.report, sort_keys=True)


# -- TEST MUTATIONS of the vendored bytes (the vendored bytes are never edited) ----------


def test_mutation_one_flipped_asset_byte_is_refused_at_correspondence():  # TEST MUTATION
    asset = bytearray(read(PROV["specimens"]["positive"]["asset"]))
    asset[100000] ^= 0x01
    result = run("positive", ev=evidence("positive", asset=bytes(asset)))
    assert result.stopped_at == "input_correspondence"
    assert {r.code for r in result.stages["input_correspondence"].refusals} == {"CORR_ASSET_DIGEST_MISMATCH", "CORR_SUBJECT_REF_MISMATCH"}


def test_the_producers_real_tampered_derivative_paired_with_the_positive_observation_is_refused():
    tampered = read(PROV["specimens"]["negative_native_invalid_exit0"]["asset"])
    result = run("positive", ev=evidence("positive", asset=tampered, asset_name="cloud.TAMPERED-DERIVATIVE.jpg"))
    assert result.stopped_at == "input_correspondence"
    assert "CORR_ASSET_DIGEST_MISMATCH" in {r.code for r in result.stages["input_correspondence"].refusals}


def test_the_other_specimens_real_report_paired_with_the_positive_observation_is_refused():
    foreign = read(PROV["specimens"]["negative_native_invalid_exit0"]["native_report"])
    result = run("positive", ev=evidence("positive", native_report=foreign))
    assert result.stopped_at == "input_correspondence"
    assert {r.code for r in result.stages["input_correspondence"].refusals} == {"CORR_NATIVE_REPORT_DIGEST_MISMATCH"}


def forged_foreign_pairing():
    """TEST MUTATION: the positive observation re-pointed at the OTHER specimen's real report, with the
    report digest, state and findings rewritten to match it, so every digest and claim corresponds to
    the bytes retained. Report-to-asset binding is caller-composed; correspondence cannot see it."""
    positive = json.loads(observation_bytes("positive"))
    other = json.loads(observation_bytes("negative_native_invalid_exit0"))
    forged = json.loads(json.dumps(positive))
    forged["native_report"] = other["native_report"]
    forged["native_findings"] = other["native_findings"]
    return forged, evidence("positive", native_report=read(PROV["specimens"]["negative_native_invalid_exit0"]["native_report"]))


def test_mutation_forged_foreign_report_pairing_passes_every_bytes_only_check():  # TEST MUTATION
    forged, ev = forged_foreign_pairing()
    result = run("positive", obs=forged, ev=ev)
    assert result.stages["input_correspondence"].status == "completed"  # the gap
    assert result.stages["profile_conformance"].status == "completed"
    assert result.stopped_at == "native_recomputation"  # and only the verifier's own run can close it


# -- the verifier's own recomputation over the frozen inputs (needs the pinned validator) --


@live_only
def test_positive_replay_per_axis_and_deterministic_on_byte_identical_inputs():
    first = run("positive", executable=LIVE)
    second = run("positive", executable=LIVE)
    assert first.stopped_at is None, [(n, [r.code for r in s.refusals]) for n, s in first.stages.items() if s.refusals]
    assert normalized(first) == normalized(second)
    axes = per_axis(first)
    expected = {
        "manifest_structure": ("match", "satisfied", "satisfied"),
        "asset_binding": ("match", "satisfied", "satisfied"),
        "claim_signature": ("match", "satisfied", "satisfied"),
        "signer_trust": ("match", "failed", "failed"),
        "signer_validity": ("match", "not_evaluated", "not_evaluated"),
        "timestamp": ("match", "satisfied", "satisfied"),
        "revocation": ("not_comparable", "not_evaluated", "not_evaluated"),
        "ingredient": ("match", "indeterminate", "indeterminate"),
    }
    assert {k: (v["state"], v["observed_status"], v["recomputed_status"]) for k, v in axes.items()} == expected
    assert axes["revocation"]["comparison_reason"] == "revocation_basis_delta"
    assert axes["signer_validity"]["agreement_basis"] == "both_sides_not_evaluated"
    assert not [a for a in axes.values() if a["integrity_posture"] == "possible_substantive_divergence"]
    ax = first.report["axes"]
    assert (ax["native_validation_state"]["observed_verbatim"], ax["native_validation_state"]["recomputed_verbatim"]) == ("Valid", "Valid")
    assert ax["native_failure_codes"]["observed"] == ax["native_failure_codes"]["recomputed"] == ["signingCredential.untrusted"]
    assert ax["timestamp"]["reading"] == "producer_observed_tsa_trust_material_unavailable"
    recomputed = first.report["native_recomputation"]["recomputed"]
    assert recomputed["evidence_class"] == "live_native_invocation"
    assert recomputed["validator"]["version"] == c2pa_native.PINNED_VALIDATOR["version"]
    assert first.report["native_comparison_report"]["comparability"] == {
        "validator_identity_match": True,
        "validator_version_match": True,
        "asset_digest_match": True,
        "manifest_store_digest_match": True,
        "trust_basis_match": True,
        "settings_match": True,
    }
    assert ax["operational_issuance_readiness"]["status"] == "not_established"


@live_only
def test_tampered_derivative_replay_native_invalid_exit_zero_is_failed_on_both_sides():
    result = run("negative_native_invalid_exit0", executable=LIVE)
    assert result.stopped_at is None
    axes = per_axis(result)
    assert (axes["asset_binding"]["state"], axes["asset_binding"]["observed_status"], axes["asset_binding"]["recomputed_status"]) == ("match", "failed", "failed")
    states = result.report["axes"]["native_validation_state"]
    assert (states["observed_verbatim"], states["recomputed_verbatim"]) == ("Invalid", "Invalid")
    codes = result.report["axes"]["native_failure_codes"]
    assert "assertion.dataHash.mismatch" in codes["observed"] and codes["observed"] == codes["recomputed"]
    assert result.report["producer_asserted"]["process_exit_code"] == 0


@live_only
def test_remote_manifest_missing_replay_has_no_native_evaluation_on_either_side():
    result = run("negative_remote_manifest_missing", executable=LIVE)
    assert result.stages["native_recomputation"].status == "completed"
    assert result.report["native_recomputation"]["recomputed"]["evaluation_status"] == "input_unavailable"
    assert result.stages["comparison"].status == "not_evaluated"
    assert result.report["axes"]["independent_comparison"]["per_axis"] == []
    assert result.report["native_comparison_report"] is None


@live_only
def test_mutation_forged_foreign_report_pairing_is_a_mismatch_never_a_match():  # TEST MUTATION
    forged, ev = forged_foreign_pairing()
    result = run("positive", obs=forged, ev=ev, executable=LIVE)
    assert result.stages["input_correspondence"].status == "completed"
    assert result.stopped_at is None
    entry = per_axis(result)["asset_binding"]
    assert entry["state"] == "mismatch" and (entry["observed_status"], entry["recomputed_status"]) == ("failed", "satisfied")
    assert entry["integrity_posture"] == "possible_substantive_divergence"
    states = result.report["axes"]["native_validation_state"]
    assert (states["observed_verbatim"], states["recomputed_verbatim"]) == ("Invalid", "Valid")


@live_only
def test_mutation_digest_consistent_tampered_asset_with_the_producers_valid_report_is_a_mismatch():  # TEST MUTATION
    asset = bytearray(read(PROV["specimens"]["positive"]["asset"]))
    asset[100000] ^= 0x01
    asset = bytes(asset)
    forged = json.loads(observation_bytes("positive"))
    forged["asset_digest"] = forged["subject_ref"] = m.sha(asset)
    result = run("positive", obs=forged, ev=evidence("positive", asset=asset, asset_name="cloud.mutated.jpg"), executable=LIVE)
    assert result.stages["input_correspondence"].status == "completed"
    entry = per_axis(result)["asset_binding"]
    assert entry["state"] == "mismatch" and (entry["observed_status"], entry["recomputed_status"]) == ("satisfied", "failed")
