"""
tests/test_cg_replay0.py — CG-REPLAY0 Lane 4: independent digest-binding verifier
for countergraph.execution-packet/v0.1 (flat schema).

Coverage:
  T01  valid packet → all digest fields True, execution_reproduced=True
  T02  truth_verified always "not_evaluated" even on full match
  T03  authority_conferred always False even on full match
  T04  all four non_equivalences present on valid packet
  T05  tampered result_digest → result_digest_valid=False, execution_reproduced=False
  T06  tampered query_digest → query_binding_valid=False, execution_reproduced=False
  T07  tampered execution_packet_digest → execution_packet_digest_valid=False
  T08  tampered execution_digest → execution_digest_valid=False, execution_reproduced=False
  T09  missing projection_digest → projection_integrity_valid=None
  T10  malformed projection_digest → projection_integrity_valid=False
  T11  missing required field (result) → graceful failure, not a crash
  T12  wrong schema → failure_code set, all digest findings False
  T13  non-dict packet → graceful failure
  T14  all four non_equivalences present on failure path too
  T15  independence: no countergraph import in the verifier module
  T16  tampered result content (not the declared digest) → result_digest_valid=False
"""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from typing import Any

import pytest

from arcs_verify.cg_replay import (
    CGReplayFinding,
    EXECUTION_PACKET_SCHEMA,
    _PERMANENT_NON_EQUIVALENCES,
    verify_execution_packet,
)


# ── helper: canonical SHA256 matching the module's own profile ────────────────

def _sha256(value: Any) -> str:
    raw = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


# ── fixture: build a fully-valid execution packet ─────────────────────────────

_QUERY = {"namespace": "test", "ref": "entity:1", "op": "get_object"}
_RESULT = {"nodes": [{"id": "entity:1", "label": "Test"}], "edges": [], "posture": "open"}
_PROJECTION = {"projection": "test/v0.1"}


def _build_valid_packet() -> dict[str, Any]:
    """Construct a valid execution packet with correct digests."""
    query_digest = _sha256(_QUERY)
    result_digest = _sha256(_RESULT)
    projection_digest = _sha256(_PROJECTION)
    execution_digest = _sha256(
        {
            "projection_digest": projection_digest,
            "query_digest": query_digest,
            "result_digest": result_digest,
        }
    )
    packet_without_epd = {
        "schema": EXECUTION_PACKET_SCHEMA,
        "packet_id": "pkt-001",
        "query": _QUERY,
        "query_digest": query_digest,
        "projection_digest": projection_digest,
        "result": _RESULT,
        "result_digest": result_digest,
        "execution_digest": execution_digest,
        "authority_effect": "none",
    }
    execution_packet_digest = _sha256(packet_without_epd)
    return {**packet_without_epd, "execution_packet_digest": execution_packet_digest}


@pytest.fixture()
def valid_packet() -> dict[str, Any]:
    return _build_valid_packet()


# ── T01: valid packet → all digest fields True ────────────────────────────────

def test_valid_packet_all_digest_fields_true(valid_packet):
    finding = verify_execution_packet(valid_packet)
    assert finding.query_binding_valid is True
    assert finding.result_digest_valid is True
    assert finding.execution_digest_valid is True
    assert finding.execution_packet_digest_valid is True
    assert finding.projection_integrity_valid is True
    assert finding.execution_reproduced is True
    assert finding.failure_code is None
    assert finding.failure_detail is None


# ── T02: truth_verified always "not_evaluated" ────────────────────────────────

def test_truth_verified_always_not_evaluated_on_full_match(valid_packet):
    finding = verify_execution_packet(valid_packet)
    assert finding.truth_verified == "not_evaluated"


# ── T03: authority_conferred always False ─────────────────────────────────────

def test_authority_conferred_always_false_on_full_match(valid_packet):
    finding = verify_execution_packet(valid_packet)
    assert finding.authority_conferred is False


# ── T04: all four non_equivalences present on valid packet ────────────────────

def test_all_four_non_equivalences_present_on_valid_packet(valid_packet):
    finding = verify_execution_packet(valid_packet)
    for neq in _PERMANENT_NON_EQUIVALENCES:
        assert neq in finding.non_equivalences, f"missing non-equivalence: {neq!r}"


# ── T05: tampered result_digest ───────────────────────────────────────────────

def test_tampered_result_digest_fails(valid_packet):
    packet = copy.deepcopy(valid_packet)
    packet["result_digest"] = "sha256:" + "a" * 64
    finding = verify_execution_packet(packet)
    assert finding.result_digest_valid is False
    assert finding.execution_reproduced is False


# ── T06: tampered query_digest ────────────────────────────────────────────────

def test_tampered_query_digest_fails(valid_packet):
    packet = copy.deepcopy(valid_packet)
    packet["query_digest"] = "sha256:" + "b" * 64
    finding = verify_execution_packet(packet)
    assert finding.query_binding_valid is False
    assert finding.execution_reproduced is False


# ── T07: tampered execution_packet_digest ─────────────────────────────────────

def test_tampered_execution_packet_digest_fails(valid_packet):
    packet = copy.deepcopy(valid_packet)
    packet["execution_packet_digest"] = "sha256:" + "c" * 64
    finding = verify_execution_packet(packet)
    assert finding.execution_packet_digest_valid is False


# ── T08: tampered execution_digest ────────────────────────────────────────────

def test_tampered_execution_digest_fails(valid_packet):
    packet = copy.deepcopy(valid_packet)
    packet["execution_digest"] = "sha256:" + "d" * 64
    finding = verify_execution_packet(packet)
    assert finding.execution_digest_valid is False
    assert finding.execution_reproduced is False


# ── T09: missing projection_digest → projection_integrity_valid=None ──────────

def test_missing_projection_digest_yields_none(valid_packet):
    packet = copy.deepcopy(valid_packet)
    del packet["projection_digest"]
    # Remove execution_packet_digest and recompute so the packet itself is valid
    # aside from the missing projection_digest.
    # (execution_digest will fail too since we don't have projection_digest,
    #  but the key finding we test is projection_integrity_valid=None)
    finding = verify_execution_packet(packet)
    assert finding.projection_integrity_valid is None


# ── T10: malformed projection_digest → projection_integrity_valid=False ───────

def test_malformed_projection_digest_fails(valid_packet):
    packet = copy.deepcopy(valid_packet)
    packet["projection_digest"] = "not-a-valid-sha256"
    finding = verify_execution_packet(packet)
    assert finding.projection_integrity_valid is False


# ── T11: missing required field (result) → graceful failure, not a crash ─────

def test_missing_result_field_graceful_failure(valid_packet):
    packet = copy.deepcopy(valid_packet)
    del packet["result"]
    finding = verify_execution_packet(packet)
    assert isinstance(finding, CGReplayFinding)
    assert finding.failure_code is not None
    assert finding.result_digest_valid is False


# ── T12: wrong schema → failure_code set, all digest findings False ───────────

def test_wrong_schema_returns_failure():
    packet = {"schema": "countergraph.other-schema/v0.1", "packet_id": "x"}
    finding = verify_execution_packet(packet)
    assert finding.failure_code == "wrong_packet_schema"
    assert finding.query_binding_valid is False
    assert finding.result_digest_valid is False
    assert finding.execution_digest_valid is False
    assert finding.execution_packet_digest_valid is False
    assert finding.execution_reproduced is False


# ── T13: non-dict packet → graceful failure ───────────────────────────────────

def test_non_dict_packet_graceful_failure():
    for bad in [None, "string", 42, [1, 2, 3]]:
        finding = verify_execution_packet(bad)  # type: ignore[arg-type]
        assert isinstance(finding, CGReplayFinding), f"expected CGReplayFinding for {bad!r}"
        assert finding.failure_code is not None


# ── T14: non_equivalences present on failure path ─────────────────────────────

def test_non_equivalences_present_on_failure():
    finding = verify_execution_packet("not-a-dict")  # type: ignore[arg-type]
    for neq in _PERMANENT_NON_EQUIVALENCES:
        assert neq in finding.non_equivalences, f"missing non-equivalence on failure: {neq!r}"


# ── T15: independence — no countergraph import in verifier module ─────────────

def test_no_countergraph_import_in_verifier():
    """Verifier must not import countergraph code — producer/verifier independence."""
    import arcs_verify.cg_replay  # noqa: F401
    for name in sys.modules:
        if name == "countergraph" or name.startswith("countergraph."):
            pytest.fail(f"countergraph module {name!r} imported — independence violated")


# ── T16: tampered result content → result_digest_valid=False ─────────────────

def test_tampered_result_content_fails(valid_packet):
    """Mutating the result dict (not the stored digest) must fail the binding check."""
    packet = copy.deepcopy(valid_packet)
    packet["result"]["nodes"].append({"id": "entity:injected", "label": "Injected"})
    finding = verify_execution_packet(packet)
    assert finding.result_digest_valid is False
    assert finding.execution_reproduced is False
