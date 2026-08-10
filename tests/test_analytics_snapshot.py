"""V1 — independent arcs-verify recount of DAGR Analytics C1 snapshots."""
from __future__ import annotations

import ast
import copy
import json
from pathlib import Path

import pytest

from arcs_verify import analytics_snapshot as A

ROOT = Path(__file__).resolve().parents[1]
V = ROOT / "vendor" / "dagr-analytics"
GOLDEN = json.loads((V / "c1" / "fixtures" / "expected_snapshots.json").read_text())
PARTITION = json.loads((V / "c1" / "fixtures" / "observations.json").read_text())
SCHED = json.loads((V / "ret1" / "retention_default.v0.1.json").read_text())
ORDER = ["http_request_count", "page_render_count", "page_view_count",
         "api_object_read_count", "mcp_resource_read_count"]


def _defn(mid):
    return json.loads((V / "c1" / "metrics" / f"{mid}.v0.1.json").read_text())


def _snap(mid):
    return next(s for s in GOLDEN["snapshots"] if s["metric_id"] == mid)


def _run(snap, defn, partition, status, as_of):
    return A.verify(snap, defn, partition, SCHED, status, as_of)


# --- independence -----------------------------------------------------------

def test_no_producer_import():
    src = (ROOT / "arcs_verify" / "analytics_snapshot.py").read_text()
    tree = ast.parse(src)
    mods = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            mods += [a.name for a in n.names]
        elif isinstance(n, ast.ImportFrom):
            mods.append(n.module or "")
    for m in mods:
        assert not m.startswith("dagr_analytics"), m
        assert "counterpedia" not in m.lower()
        assert "retention_reference" not in m and "route_classifier" not in m and "canonical_json" not in m


# --- recount + digests (the five goldens, independently) --------------------

@pytest.mark.parametrize("mid", ORDER)
def test_recount_and_all_digests(mid):
    r = _run(_snap(mid), _defn(mid), PARTITION, "supplied", "2026-08-15T00:00:00Z")
    assert r["conclusions"]["value_recomputation"] == "PASS"
    assert r["conclusions"]["metric_definition_digest"] == "PASS"
    assert r["conclusions"]["metric_definition_pin"] == "PASS"
    assert r["conclusions"]["input_partition_digest"] == "PASS"
    assert r["conclusions"]["snapshot_digest"] == "PASS"
    assert r["metric_integrity"] == "PASS"
    assert r["recomputed"]["value"] == _snap(mid)["value"]


def test_five_values_are_4_4_3_2_3():
    vals = [A.recount(m, PARTITION["observations"]) for m in ORDER]
    assert vals == [4, 4, 3, 2, 3]


def test_definition_pins_exact():
    for mid in ORDER:
        assert A.digest(_defn(mid)) == A.DEF_PINS[mid]


def test_common_partition_digest():
    r = _run(_snap("http_request_count"), _defn("http_request_count"), PARTITION, "supplied", "2026-08-15T00:00:00Z")
    assert r["recomputed"]["input_partition_digest"] == GOLDEN["input_partition_digest"]


# --- tamper / adversarial ---------------------------------------------------

def test_shuffled_observation_order_same_digest():
    p2 = {"observations": list(reversed(PARTITION["observations"])),
          "window_start": PARTITION["window_start"], "window_end": PARTITION["window_end"]}
    r = _run(_snap("http_request_count"), _defn("http_request_count"), p2, "supplied", "2026-08-15T00:00:00Z")
    assert r["conclusions"]["input_partition_digest"] == "PASS"


def test_duplicate_event_id_fails_closed():
    p2 = copy.deepcopy(PARTITION)
    p2["observations"].append(copy.deepcopy(p2["observations"][0]))  # duplicate e1
    r = _run(_snap("http_request_count"), _defn("http_request_count"), p2, "supplied", "2026-08-15T00:00:00Z")
    assert r["conclusions"]["event_id_uniqueness"] == "FAIL"
    assert "analytics_snapshot.duplicate_event_id" in r["failure_codes"]


def test_changed_observation_same_value_changes_digest():
    p2 = copy.deepcopy(PARTITION)
    p2["observations"][0]["object_ref"] = "record:TAMPERED"  # value unchanged, bytes changed
    r = _run(_snap("http_request_count"), _defn("http_request_count"), p2, "supplied", "2026-08-15T00:00:00Z")
    assert r["conclusions"]["input_partition_digest"] == "FAIL"  # partition digest no longer matches snapshot


def test_changed_definition_same_version_fails_pin():
    d2 = _defn("http_request_count")
    d2["description"] = d2["description"] + " (tampered)"
    r = _run(_snap("http_request_count"), d2, PARTITION, "supplied", "2026-08-15T00:00:00Z")
    assert "analytics_snapshot.metric_definition_pin_mismatch" in r["failure_codes"]


def test_wrong_window_mismatch():
    p2 = copy.deepcopy(PARTITION); p2["window_end"] = "2027-01-01T00:00:00Z"
    r = _run(_snap("http_request_count"), _defn("http_request_count"), p2, "supplied", "2026-08-15T00:00:00Z")
    assert r["conclusions"]["window_binding"] == "FAIL"


def test_wrong_privacy_class():
    s2 = copy.deepcopy(_snap("http_request_count")); s2["privacy_class"] = "PUBLIC_AGGREGATE"
    r = _run(s2, _defn("http_request_count"), PARTITION, "supplied", "2026-08-15T00:00:00Z")
    assert r["conclusions"]["privacy_class_binding"] == "FAIL"


def test_unsupported_metric_profile():
    s2 = copy.deepcopy(_snap("http_request_count")); s2["metric_id"] = "made_up_metric"
    r = _run(s2, _defn("http_request_count"), PARTITION, "supplied", "2026-08-15T00:00:00Z")
    assert "analytics_snapshot.unsupported_metric_profile" in r["failure_codes"]


def test_crawler_excluded_from_all_five():
    # the synthetic partition contains a crawler_read (e14); none of the five count it
    assert A.recount("http_request_count", PARTITION["observations"]) == 4  # e14 not counted


def test_page_view_dedupe_semantics():
    obs = [
        {"event_id": "a", "action": "page_render", "transport": "web", "session_ref": "s1", "object_ref": "o1"},
        {"event_id": "b", "action": "page_render", "transport": "web", "session_ref": "s1", "object_ref": "o1"},  # dup
        {"event_id": "c", "action": "page_render", "transport": "web", "session_ref": "s1", "object_ref": "o2"},  # diff obj
        {"event_id": "d", "action": "page_render", "transport": "web", "session_ref": None, "object_ref": "o1"},  # null
        {"event_id": "e", "action": "page_render", "transport": "web", "session_ref": None, "object_ref": "o1"},  # null again
    ]
    # (s1,o1)->1 + (s1,o2)->1 + 2 null renders = 4
    assert A.recount("page_view_count", obs) == 4


# --- canonicalization equivalence over the C1 domain ------------------------

def test_canonicalization_equivalence_vectors():
    # rfc8785 (arcs-verify native) reproduces committed goldens => equivalent to
    # dagr.canonical-json.v0.1 over the C1 domain
    r = _run(_snap("http_request_count"), _defn("http_request_count"), PARTITION, "supplied", "2026-08-15T00:00:00Z")
    assert r["recomputed"]["snapshot_digest"] == _snap("http_request_count")["snapshot_digest"]
    # integral-float normalization inside the domain
    assert A.canonical_bytes({"n": 2.0}) == A.canonical_bytes({"n": 2}) == b'{"n":2}'
    # non-integer / non-ASCII key rejected by the domain guard
    with pytest.raises(A._Canon):
        A.canonical_bytes({"x": 1e-7})
    with pytest.raises(A._Canon):
        A.canonical_bytes({"\U0001F600": 1})


# --- source-status postures / RET1 ------------------------------------------

def test_supplied_before_deadline_conforming():
    r = _run(_snap("http_request_count"), _defn("http_request_count"), PARTITION, "supplied", "2026-08-15T00:00:00Z")
    assert r["retention"]["source_status_basis"] == "SUPPLIED_BYTES"
    assert r["retention"]["retention_conformance"] == "CONFORMING"


def test_supplied_after_deadline_recounts_but_nonconforming():
    r = _run(_snap("http_request_count"), _defn("http_request_count"), PARTITION, "supplied", "2026-10-01T00:00:00Z")
    assert r["retention"]["source_recomputability_state"] == "FULL_RECOMPUTATION_AVAILABLE"
    assert r["retention"]["retention_conformance"] == "NONCONFORMING"
    assert r["conclusions"]["value_recomputation"] == "PASS"
    assert "analytics_snapshot.retention_nonconforming" in r["failure_codes"]


def test_absent_expired_after_deadline_not_evaluated_recount():
    r = _run(_snap("http_request_count"), _defn("http_request_count"), None, "absent-expired", "2026-10-01T00:00:00Z")
    assert r["retention"]["source_status_basis"] == "DECLARED"
    assert r["retention"]["source_recomputability_state"] == "PROVENANCE_BOUND_SOURCE_EXPIRED"
    assert r["conclusions"]["value_recomputation"] == "NOT_EVALUATED"


def test_absent_unexplained_before_deadline():
    r = _run(_snap("http_request_count"), _defn("http_request_count"), None, "absent-unexplained", "2026-08-15T00:00:00Z")
    assert r["retention"]["source_recomputability_state"] == "SOURCE_UNAVAILABLE_UNEXPLAINED"
    assert r["retention"]["retention_conformance"] == "NOT_EVALUATED"


def test_not_supplied_is_declared_not_evaluated():
    r = _run(_snap("http_request_count"), _defn("http_request_count"), None, "not-supplied", "2026-10-01T00:00:00Z")
    assert r["retention"]["source_recomputability_state"] == "NOT_EVALUATED"
    assert r["retention"]["retention_conformance"] == "NOT_EVALUATED"
    assert r["retention"]["source_status_basis"] == "DECLARED"


def test_absent_expired_before_deadline_is_contradiction():
    with pytest.raises(A._Contradiction):
        _run(_snap("http_request_count"), _defn("http_request_count"), None, "absent-expired", "2026-08-15T00:00:00Z")


def test_retention_schedule_pin():
    assert A.digest(SCHED) == A.RET_SCHED_PIN


def test_report_carries_canonicalization_profile_and_provisional():
    r = _run(_snap("http_request_count"), _defn("http_request_count"), PARTITION, "supplied", "2026-08-15T00:00:00Z")
    assert r["canonicalization_profile"] == "dagr.canonical-json.v0.1"
    assert r["upstream_contract_posture"] == "PROVISIONAL"
