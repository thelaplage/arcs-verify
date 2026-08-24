"""
tests/test_cg_execution_replay_v0_2.py — CG-REPLAY0 execution-packet verifier,
v0.2 pack (CG-REPLAY-PRODUCER-REFRESH0 correction).

packs/cg.execution.replay/v0.1/vectors.json carried literal countergraph
producer bytes whose content_v02_projection field included an authority-shaped
`authority_movement: 0` scalar baked into carried content. This v0.2 pack
re-derives the same two packets (get_object on the NYT-OPENAI-LITIGATION-0001
record; get_neighborhood outgoing depth=1 from the same root) from a corrected
countergraph capture that structurally OMITS that key — see
countergraph's fixtures/counterpedia_graph_nytoai_litigation_0001_v0_2.provenance.json
for the correction record on the producer side.

v0.1 is preserved untouched as historical producer evidence; see
tests/test_cg_execution_replay.py. This file is a parallel gate for v0.2, not
a replacement — it repeats the same digest-binding/mutation/independence
coverage against the new pack, plus two tests specific to the correction
itself.

Producer commit: 607b7352eb1c13e7a634f3dfa4970462263a1bad (countergraph,
CG-REPLAY-PRODUCER-REFRESH0)
Fixture: packs/cg.execution.replay/v0.2/vectors.json
"""

from __future__ import annotations

import copy
import json
import pathlib

import pytest

from arcs_verify.cg_execution_replay import (
    CGExecutionReplayReport,
    EXECUTION_PACKET_SCHEMA,
    QUERY_EXECUTION_SCHEMA,
    verify_cg_execution_packet,
)

# ── fixtures ──────────────────────────────────────────────────────────────────

REPO_ROOT = pathlib.Path(__file__).parent.parent
VECTORS_PATH = REPO_ROOT / "packs" / "cg.execution.replay" / "v0.2" / "vectors.json"


def _pack() -> dict:
    return json.loads(VECTORS_PATH.read_text(encoding="utf-8"))


def _vectors() -> dict:
    return _pack()["vectors"]


@pytest.fixture(scope="module")
def get_object_packet() -> dict:
    return _vectors()["get_object_record"]


@pytest.fixture(scope="module")
def neighborhood_packet() -> dict:
    return _vectors()["get_neighborhood_record_outgoing_d1"]


# ── independence check ────────────────────────────────────────────────────────

def test_no_countergraph_import_in_verifier() -> None:
    """Verifier must not import countergraph code — issuer/verifier independence."""
    import arcs_verify.cg_execution_replay as mod
    import sys
    for name in sys.modules:
        if name == "countergraph" or name.startswith("countergraph."):
            assert False, f"countergraph module {name!r} was imported — independence violated"


# ── correction-specific checks ────────────────────────────────────────────────

def test_meta_documents_the_correction() -> None:
    meta = _pack()["meta"]
    assert meta["producer"] == "countergraph"
    assert meta["producer_repo"] == "thelaplage/countergraph"
    assert meta["corrects_pack"] == "packs/cg.execution.replay/v0.1/vectors.json"
    assert "authority_movement" in meta["correction_reason"]


def test_authority_movement_is_structurally_absent(get_object_packet, neighborhood_packet) -> None:
    """The whole point of this refresh: the key itself must not appear anywhere
    in either packet, not merely be null or zero."""
    for packet in (get_object_packet, neighborhood_packet):
        blob = json.dumps(packet)
        assert "authority_movement" not in blob


# ── golden-vector: get_object ─────────────────────────────────────────────────

class TestGetObjectPacket:
    def test_all_findings_pass(self, get_object_packet):
        report = verify_cg_execution_packet(get_object_packet)
        assert report.execution_reproduced is True
        assert report.packet_digest_valid is True
        assert report.packet_id_valid is True
        assert report.projection_integrity_valid is True
        assert report.query_binding_valid is True
        assert report.result_digest_valid is True
        assert report.execution_digest_valid is True

    def test_permanent_non_findings(self, get_object_packet):
        report = verify_cg_execution_packet(get_object_packet)
        assert report.truth_verified == "not_evaluated"
        assert report.authority_conferred is False

    def test_no_failure_code(self, get_object_packet):
        report = verify_cg_execution_packet(get_object_packet)
        assert report.failure_code is None
        assert report.failure_detail is None

    def test_all_digest_bindings_valid_property(self, get_object_packet):
        report = verify_cg_execution_packet(get_object_packet)
        assert report.all_digest_bindings_valid is True

    def test_to_dict_shape(self, get_object_packet):
        d = verify_cg_execution_packet(get_object_packet).to_dict()
        assert d["truth_verified"] == "not_evaluated"
        assert d["authority_conferred"] is False
        assert d["execution_reproduced"] is True
        for key in (
            "packet_digest_valid", "packet_id_valid", "projection_integrity_valid",
            "query_binding_valid", "result_digest_valid", "execution_digest_valid",
        ):
            assert d[key] is True, f"{key} must be True in to_dict()"


# ── golden-vector: get_neighborhood ──────────────────────────────────────────

class TestNeighborhoodPacket:
    def test_all_findings_pass(self, neighborhood_packet):
        report = verify_cg_execution_packet(neighborhood_packet)
        assert report.execution_reproduced is True

    def test_permanent_non_findings(self, neighborhood_packet):
        report = verify_cg_execution_packet(neighborhood_packet)
        assert report.truth_verified == "not_evaluated"
        assert report.authority_conferred is False


# ── mutation tests: each digest binding ──────────────────────────────────────

class TestMutatedDigests:
    """Each mutation independently corrupts one digest field.
    The corresponding finding must flip to False; others are not required to hold."""

    def test_corrupted_packet_digest(self, get_object_packet):
        pkt = copy.deepcopy(get_object_packet)
        pkt["packet_digest"] = "sha256:" + "0" * 64
        report = verify_cg_execution_packet(pkt)
        assert report.packet_digest_valid is False
        assert report.execution_reproduced is False

    def test_corrupted_packet_id(self, get_object_packet):
        pkt = copy.deepcopy(get_object_packet)
        pkt["packet_id"] = "cg:execution-packet:sha256:" + "0" * 64
        report = verify_cg_execution_packet(pkt)
        assert report.packet_id_valid is False
        assert report.execution_reproduced is False

    def test_corrupted_projection_digest(self, get_object_packet):
        pkt = copy.deepcopy(get_object_packet)
        req = pkt["root_execution"]["query"]["source_requirement"]
        req["projection_digest"] = "not-a-sha256"
        report = verify_cg_execution_packet(pkt)
        assert report.projection_integrity_valid is False
        assert report.execution_reproduced is False

    def test_corrupted_query_digest(self, get_object_packet):
        pkt = copy.deepcopy(get_object_packet)
        pkt["root_execution"]["query"]["query_digest"] = "sha256:" + "1" * 64
        report = verify_cg_execution_packet(pkt)
        assert report.query_binding_valid is False
        assert report.execution_reproduced is False

    def test_corrupted_result_digest(self, get_object_packet):
        pkt = copy.deepcopy(get_object_packet)
        pkt["root_execution"]["read_result"]["result_digest"] = "sha256:" + "2" * 64
        report = verify_cg_execution_packet(pkt)
        assert report.result_digest_valid is False
        assert report.execution_reproduced is False

    def test_corrupted_execution_digest(self, get_object_packet):
        pkt = copy.deepcopy(get_object_packet)
        pkt["root_execution"]["execution_digest"] = "sha256:" + "3" * 64
        report = verify_cg_execution_packet(pkt)
        assert report.execution_digest_valid is False
        assert report.execution_reproduced is False


# ── structural rejection paths ────────────────────────────────────────────────

class TestStructuralRejection:
    def test_wrong_type_returns_failure(self):
        report = verify_cg_execution_packet("not a dict")  # type: ignore[arg-type]
        assert report.failure_code == "invalid_packet"
        assert report.execution_reproduced is False

    def test_wrong_packet_schema_returns_failure(self, get_object_packet):
        pkt = copy.deepcopy(get_object_packet)
        pkt["schema"] = "countergraph.something-else/v0.1"
        report = verify_cg_execution_packet(pkt)
        assert report.failure_code == "wrong_packet_schema"

    def test_wrong_packet_kind_returns_failure(self, get_object_packet):
        pkt = copy.deepcopy(get_object_packet)
        pkt["packet_kind"] = "join_execution"
        report = verify_cg_execution_packet(pkt)
        assert report.failure_code == "unsupported_packet_kind"

    def test_missing_packet_digest_returns_failure(self, get_object_packet):
        pkt = copy.deepcopy(get_object_packet)
        del pkt["packet_digest"]
        report = verify_cg_execution_packet(pkt)
        assert report.failure_code == "invalid_packet_digest"

    def test_malformed_packet_digest_returns_failure(self, get_object_packet):
        pkt = copy.deepcopy(get_object_packet)
        pkt["packet_digest"] = "not-a-digest"
        report = verify_cg_execution_packet(pkt)
        assert report.failure_code == "invalid_packet_digest"

    def test_missing_root_execution_returns_failure(self, get_object_packet):
        pkt = copy.deepcopy(get_object_packet)
        pkt["root_execution"] = "not a dict"
        report = verify_cg_execution_packet(pkt)
        assert report.failure_code == "missing_root_execution"

    def test_wrong_root_execution_schema_returns_failure(self, get_object_packet):
        pkt = copy.deepcopy(get_object_packet)
        pkt["root_execution"]["schema"] = "some.other.schema/v1"
        report = verify_cg_execution_packet(pkt)
        assert report.failure_code == "wrong_execution_schema"

    def test_empty_dict_returns_wrong_schema_failure(self):
        report = verify_cg_execution_packet({})
        assert report.failure_code == "wrong_packet_schema"


# ── non-findings are invariant ────────────────────────────────────────────────

class TestPermanentNonFindings:
    """truth_verified and authority_conferred must be correct on every code path."""

    def test_structural_failure_still_sets_non_findings(self):
        report = verify_cg_execution_packet({"schema": "wrong"})
        assert report.truth_verified == "not_evaluated"
        assert report.authority_conferred is False

    def test_digest_failure_still_sets_non_findings(self, get_object_packet):
        pkt = copy.deepcopy(get_object_packet)
        pkt["packet_digest"] = "sha256:" + "f" * 64
        report = verify_cg_execution_packet(pkt)
        assert report.truth_verified == "not_evaluated"
        assert report.authority_conferred is False
