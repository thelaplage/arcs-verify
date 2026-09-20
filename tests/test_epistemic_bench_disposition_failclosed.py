"""
EPISTEMIC-BENCH-DISPOSITION-FAILCLOSED0
========================================
Hostile regression tests for the disposition-scoring fail-open defect in
benchmark/adapters/{amnesiac,counterpedia}.py and benchmark/runner.py.

Contract under test (owner ruling):
    missing disposition / unknown disposition / non-string disposition
        -> the SUT response is INVALID for disposition scoring
        -> ZERO disposition credit
        -> NEVER coerced to admitted / refused / deferred_for_review

    valid admitted / refused / deferred_for_review
        -> unchanged behavior

These tests do not touch arcs_verify/ production verifier paths; they are
scoped entirely to benchmark/.
"""

from __future__ import annotations

import sys
from pathlib import Path

BENCHMARK_ROOT = Path(__file__).parent.parent / "benchmark"
sys.path.insert(0, str(BENCHMARK_ROOT))

from runner import (  # noqa: E402
    BenchmarkCase,
    EpistemicEvaluator,
    EpistemicInput,
    ExpectedOutput,
    INVALID_DISPOSITION,
    SUTResponse,
    VALID_DISPOSITIONS,
    normalize_disposition,
)

sys.path.insert(0, str(BENCHMARK_ROOT / "adapters"))
from amnesiac import AmnesiacAdapter  # noqa: E402
from counterpedia import CounterpediaAdapter  # noqa: E402


def _case(disposition_expected: str) -> BenchmarkCase:
    return BenchmarkCase(
        id="eb-999",
        category="unsupported_inference",
        input=EpistemicInput(
            evidence=["ev1"],
            source_metadata={},
            candidate_claim="claim",
        ),
        expected=ExpectedOutput(
            allowed_conclusion="the evidence is insufficient",
            forbidden_conclusion="the claim is definitely true",
            uncertainty_state="declared",
            receipt_shape={"disposition": disposition_expected},
        ),
    )


def _response(disposition: str) -> SUTResponse:
    return SUTResponse(
        case_id="eb-999",
        stated_conclusion="the evidence is insufficient to confirm the claim",
        disposition=disposition,
        uncertainty_declared=True,
        reasoning_trace=None,
        raw_output=None,
    )


# ---------------------------------------------------------------------------
# normalize_disposition — centralized closed-set check
# ---------------------------------------------------------------------------

def test_normalize_disposition_passes_through_valid_values():
    for v in VALID_DISPOSITIONS:
        assert normalize_disposition(v) == v


def test_normalize_disposition_missing_is_invalid():
    assert normalize_disposition(None) == INVALID_DISPOSITION


def test_normalize_disposition_unknown_string_is_invalid():
    assert normalize_disposition("banana") == INVALID_DISPOSITION


def test_normalize_disposition_non_string_is_invalid():
    assert normalize_disposition(7) == INVALID_DISPOSITION
    assert normalize_disposition({"disposition": "admitted"}) == INVALID_DISPOSITION
    assert normalize_disposition([]) == INVALID_DISPOSITION


def test_invalid_disposition_sentinel_not_in_valid_set():
    assert INVALID_DISPOSITION not in VALID_DISPOSITIONS


# ---------------------------------------------------------------------------
# EpistemicEvaluator — zero credit for invalid disposition, never redirected
# ---------------------------------------------------------------------------

def test_missing_disposition_does_not_score_admitted_when_should_admit_true():
    evaluator = EpistemicEvaluator()
    case = _case("admitted")
    response = _response(normalize_disposition(None))  # simulates raw {} response
    result = evaluator.evaluate(case, response)
    assert result.admitted_when_should_admit is not True
    assert result.admitted_when_should_admit is False


def test_unknown_disposition_does_not_score_admitted_when_should_admit_true():
    evaluator = EpistemicEvaluator()
    case = _case("admitted")
    response = _response(normalize_disposition("banana"))
    result = evaluator.evaluate(case, response)
    assert result.admitted_when_should_admit is not True
    assert result.admitted_when_should_admit is False


def test_non_string_disposition_earns_no_credit():
    evaluator = EpistemicEvaluator()
    case = _case("admitted")
    response = _response(normalize_disposition(7))
    result = evaluator.evaluate(case, response)
    assert result.admitted_when_should_admit is False
    # disposition portion of score must be 0, not the 0.15 weight nor the
    # 0.5 partial-credit fraction of it
    disposition_only_evaluator = EpistemicEvaluator()
    baseline = disposition_only_evaluator.evaluate(case, _response("admitted"))
    assert result.score == round(baseline.score - EpistemicEvaluator.DISPOSITION_WEIGHT, 4)


def test_invalid_disposition_does_not_earn_refused_credit_either():
    """Invalid disposition must not be redirected to the OTHER bucket: an
    invalid response scored against an 'admitted'-expected case must not
    accidentally earn refused_when_should_refuse=True, and vice versa."""
    evaluator = EpistemicEvaluator()

    case_admit = _case("admitted")
    result_admit = evaluator.evaluate(case_admit, _response(INVALID_DISPOSITION))
    assert result_admit.admitted_when_should_admit is False
    assert result_admit.refused_when_should_refuse is None  # not applicable, not faked True

    case_refuse = _case("refused")
    result_refuse = evaluator.evaluate(case_refuse, _response(INVALID_DISPOSITION))
    assert result_refuse.refused_when_should_refuse is False
    assert result_refuse.admitted_when_should_admit is None


def test_invalid_disposition_with_no_applicable_expected_state_earns_zero_not_partial():
    """When expected_disposition isn't 'admitted'/'refused' (e.g. deferred),
    a VALID disposition gets 0.5x partial credit for the disposition weight,
    but an INVALID disposition must get zero, never partial credit."""
    evaluator = EpistemicEvaluator()
    case = _case("deferred_for_review")

    valid_result = evaluator.evaluate(case, _response("deferred_for_review"))
    invalid_result = evaluator.evaluate(case, _response(INVALID_DISPOSITION))

    assert invalid_result.score == round(
        valid_result.score - (EpistemicEvaluator.DISPOSITION_WEIGHT * 0.5), 4
    )


def test_valid_admitted_disposition_still_scores_credit_unchanged():
    evaluator = EpistemicEvaluator()
    case = _case("admitted")
    result = evaluator.evaluate(case, _response("admitted"))
    assert result.admitted_when_should_admit is True


def test_valid_refused_disposition_still_scores_credit_unchanged():
    evaluator = EpistemicEvaluator()
    case = _case("refused")
    result = evaluator.evaluate(case, _response("refused"))
    assert result.refused_when_should_refuse is True


def test_valid_deferred_for_review_disposition_unchanged():
    evaluator = EpistemicEvaluator()
    case = _case("deferred_for_review")
    result = evaluator.evaluate(case, _response("deferred_for_review"))
    # Neither dedicated verdict field applies to deferred_for_review (matches
    # pre-existing behavior); this is a regression guard, not new behavior.
    assert result.admitted_when_should_admit is None
    assert result.refused_when_should_refuse is None


# ---------------------------------------------------------------------------
# Adapters — {} and malformed raw output must not become "admitted"
# ---------------------------------------------------------------------------

def test_amnesiac_adapter_empty_dict_response_is_invalid_not_admitted():
    adapter = AmnesiacAdapter()
    response = adapter._parse_response("eb-999", {})
    assert response.disposition != "admitted"
    assert response.disposition == INVALID_DISPOSITION


def test_amnesiac_adapter_unknown_disposition_is_invalid_not_admitted():
    adapter = AmnesiacAdapter()
    response = adapter._parse_response("eb-999", {"disposition": "banana"})
    assert response.disposition != "admitted"
    assert response.disposition == INVALID_DISPOSITION


def test_amnesiac_adapter_non_string_disposition_is_invalid():
    adapter = AmnesiacAdapter()
    response = adapter._parse_response("eb-999", {"disposition": 7})
    assert response.disposition == INVALID_DISPOSITION


def test_amnesiac_adapter_valid_disposition_passes_through_unchanged():
    adapter = AmnesiacAdapter()
    for v in VALID_DISPOSITIONS:
        response = adapter._parse_response("eb-999", {"disposition": v})
        assert response.disposition == v


def test_counterpedia_adapter_empty_dict_response_is_invalid_not_admitted():
    adapter = CounterpediaAdapter()
    response = adapter._parse_response("eb-999", {})
    assert response.disposition != "admitted"
    assert response.disposition == INVALID_DISPOSITION


def test_counterpedia_adapter_unknown_disposition_is_invalid_not_admitted():
    adapter = CounterpediaAdapter()
    response = adapter._parse_response("eb-999", {"disposition": "banana"})
    assert response.disposition != "admitted"
    assert response.disposition == INVALID_DISPOSITION


def test_counterpedia_adapter_malformed_cli_json_does_not_become_admitted():
    """Non-JSON CLI stdout must not silently score as admitted."""
    adapter = CounterpediaAdapter()
    # Directly exercise the malformed-JSON branch's output shape via
    # _parse_response, mirroring what _call_cli returns on JSONDecodeError.
    malformed_raw = {"stated_conclusion": "not json at all", "uncertainty_declared": False}
    response = adapter._parse_response("eb-999", malformed_raw)
    assert response.disposition != "admitted"
    assert response.disposition == INVALID_DISPOSITION


def test_counterpedia_adapter_valid_disposition_passes_through_unchanged():
    adapter = CounterpediaAdapter()
    for v in VALID_DISPOSITIONS:
        response = adapter._parse_response("eb-999", {"disposition": v})
        assert response.disposition == v


def test_counterpedia_call_cli_malformed_json_stdout_end_to_end(monkeypatch):
    """Exercise the real _call_cli JSONDecodeError branch (not just its
    documented shape): fake subprocess.run to return non-JSON stdout, and
    assert the resulting raw dict carries no disposition key, so downstream
    normalize_disposition marks it invalid rather than 'admitted'."""
    import counterpedia as counterpedia_module

    class _FakeCompletedProcess:
        returncode = 0
        stdout = "this is not json"
        stderr = ""

    def _fake_run(*args, **kwargs):
        return _FakeCompletedProcess()

    monkeypatch.setattr(counterpedia_module.subprocess, "run", _fake_run)

    adapter = CounterpediaAdapter()
    raw = adapter._call_cli({"mode": "epistemic_query"})
    assert "disposition" not in raw

    response = adapter._parse_response("eb-999", raw)
    assert response.disposition != "admitted"
    assert response.disposition == INVALID_DISPOSITION
