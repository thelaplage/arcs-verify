"""The fixed order: correspondence, then profile conformance, then the observed-side finding.

SYNTHETIC observations only. Each test records which stages actually ran and whether the
native validator was ever invoked."""
import pytest

from arcs_verify import c2pa_srs_observed as adapter

from . import material as m

STAGE_FUNCS = {
    "parse": "_stage_parse",
    "correspondence": "_stage_correspondence",
    "conformance": "_stage_conformance",
    "construct": "_stage_construct",
    "recompute": "_stage_recompute",
    "compare": "_stage_compare",
}


@pytest.fixture
def trace(monkeypatch):
    calls: list[str] = []
    for label, attr in STAGE_FUNCS.items():
        original = getattr(adapter, attr)

        def wrapper(*args, _o=original, _l=label, **kwargs):
            calls.append(_l)
            return _o(*args, **kwargs)

        monkeypatch.setattr(adapter, attr, wrapper)
    return calls


def run(tmp_path, obs, evidence=None, report=m.REPORT_VALID_UNTRUSTED):
    fake = m.install_fake_validator(tmp_path, {m.SYNTHETIC_ASSET: (report, 0)})
    result = adapter.consume_observation(m.encode(obs), evidence or m.evidence_for(report), executable=fake.path)
    return result, fake


def test_full_run_executes_every_stage_in_the_fixed_order(tmp_path, trace):
    result, fake = run(tmp_path, m.synthetic_observation())
    assert result.stopped_at is None
    assert trace == ["parse", "correspondence", "conformance", "construct", "recompute", "compare"]
    assert [result.stages[s].status for s in adapter.STAGES] == ["completed"] * 6
    assert result.report["pipeline"]["order"] == list(adapter.STAGES)
    assert len(fake.calls()) == 1


def test_correspondence_failure_stops_before_profile_conformance(tmp_path, trace):
    obs = m.mutated(m.synthetic_observation(), "asset_digest", "sha256:" + "0" * 64)
    result, fake = run(tmp_path, obs)
    assert result.stopped_at == "input_correspondence"
    assert trace == ["parse", "correspondence"]
    assert result.stages["profile_conformance"].status == "not_run"
    assert result.stages["observed_finding_construction"].status == "not_run"
    assert result.report["observed_finding"] is None
    assert fake.calls() == []


def test_when_both_steps_would_fail_the_first_step_is_the_one_reported(tmp_path, trace):
    obs = m.mutated(m.mutated(m.synthetic_observation(), "asset_digest", "sha256:" + "0" * 64), "profile_id", "srs.other")
    result, _ = run(tmp_path, obs)
    assert result.stopped_at == "input_correspondence"
    assert trace == ["parse", "correspondence"]
    assert result.stages["profile_conformance"].status == "not_run"


def test_profile_violation_stops_before_the_observed_finding_exists(tmp_path, trace):
    obs = m.mutated(m.synthetic_observation(), "native_report.verdict_source", "process_exit_code")
    result, fake = run(tmp_path, obs)
    assert result.stopped_at == "profile_conformance"
    assert trace == ["parse", "correspondence", "conformance"]
    assert result.report["observed_finding"] is None
    assert result.report["axes"]["independent_comparison"]["status"] == "not_run"
    assert result.report["axes"]["observation_conformance"]["status"] == "refused"
    assert result.report["axes"]["observation_conformance"]["refusal_codes"] == ["EXIT_CODE_AS_VERDICT", "FIELD_SCHEMA"]
    assert fake.calls() == []


def test_mapping_refusal_stops_before_any_recomputation(tmp_path, trace):
    obs = m.mutated(m.synthetic_observation(), "validation_time.validation_time_control", "supported_and_pinned")
    result, fake = run(tmp_path, obs)
    assert result.stopped_at == "observed_finding_construction"
    assert trace == ["parse", "correspondence", "conformance", "construct"]
    assert result.report["native_recomputation"] is None
    assert fake.calls() == []


def test_the_observed_finding_cannot_be_built_before_step_one_completes():  # GUARD ORDER-CONSTRUCT-PRECONDITION
    obs = m.synthetic_observation()
    done_conf = adapter.StageOutcome("profile_conformance", "completed")
    for bad in (
        adapter.StageOutcome("input_correspondence", "refused"),
        adapter.StageOutcome("input_correspondence", "not_run"),
        adapter.StageOutcome("profile_conformance", "completed"),  # wrong stage in the right slot
        None,
        "completed",
    ):
        with pytest.raises(adapter.OrderingViolation):
            adapter.construct_observed_side(obs, bad, done_conf)


def test_the_observed_finding_cannot_be_built_before_step_two_completes():
    obs = m.synthetic_observation()
    done_corr = adapter.StageOutcome("input_correspondence", "completed")
    for bad in (
        adapter.StageOutcome("profile_conformance", "refused"),
        adapter.StageOutcome("profile_conformance", "not_run"),
        adapter.StageOutcome("input_correspondence", "completed"),
        None,
    ):
        with pytest.raises(adapter.OrderingViolation):
            adapter.construct_observed_side(obs, done_corr, bad)


def test_an_ordering_violation_is_never_converted_into_a_refusal(monkeypatch):
    refused = adapter.StageOutcome("input_correspondence", "refused")
    done = adapter.StageOutcome("profile_conformance", "completed")
    with pytest.raises(adapter.OrderingViolation):
        adapter._stage_construct(m.synthetic_observation(), refused, done, adapter.c2pa_native.load_bundle())


def test_parse_failure_is_the_first_and_only_stage_that_runs(tmp_path, trace):
    result = adapter.consume_observation(b"not json", m.evidence_for())
    assert result.stopped_at == "input_parse"
    assert trace == ["parse"]


def test_a_stage_that_did_not_run_is_reported_as_not_run_never_as_completed(tmp_path):
    result, _ = run(tmp_path, m.mutated(m.synthetic_observation(), "profile_id", "srs.other"))
    statuses = {name: result.report["pipeline"]["stages"][name]["status"] for name in adapter.STAGES}
    assert statuses == {
        "input_parse": "completed",
        "input_correspondence": "completed",
        "profile_conformance": "refused",
        "observed_finding_construction": "not_run",
        "native_recomputation": "not_run",
        "comparison": "not_run",
    }
