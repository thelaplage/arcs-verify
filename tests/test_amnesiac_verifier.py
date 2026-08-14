"""Verifier conformance tests over real serialized Heppner producer bytes."""

from __future__ import annotations

import copy
import json
from pathlib import Path

from arcs_verify.amnesiac import Conclusion, bundle_from_proof_stage, verify_bundle
from arcs_verify.amnesiac import canonical
from arcs_verify.amnesiac.replay import replay_render, reproduce_inspection

FIXTURE = (
    Path(__file__).parent.parent
    / "packs"
    / "amnesiac.heppner_public_proof"
    / "v0.1"
    / "producer"
    / "proof_bundle.json"
)


def _proof() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _stage(name: str = "revised") -> dict:
    return copy.deepcopy(bundle_from_proof_stage(_proof(), name))


def _rehash_receipt(bundle: dict) -> None:
    receipt = bundle["receipt"]
    receipt["context_packet_ref"] = {
        "context_packet_id": bundle["packet"]["packet_id"],
        "content_hash": bundle["packet"]["packet_hash"],
    }
    receipt["packet_walk_ref"] = {
        "packet_walk_id": bundle["walk"]["walk_id"],
        "operation_log_hash": bundle["walk"]["walk_hash"],
    }
    receipt["subject_ref"] = bundle["rendered"]["render_hash"]
    receipt["subject_type"] = "render"
    hashes = receipt["artifact_hashes"]
    hashes["source_capture_hash"] = bundle["source_capture_hash"]
    hashes["context_packet_hash"] = bundle["packet"]["packet_hash"]
    hashes["packet_walk_hash"] = bundle["walk"]["walk_hash"]
    hashes["rendered_packet_hash"] = bundle["rendered"]["render_hash"]
    hashes["rendered_packet_body_sha256"] = canonical.rendered_body_sha256(
        bundle["rendered"]["body"]
    )
    hashes["packet_inspection_hash"] = bundle["inspection"]["inspection_hash"]
    receipt["receipt_hash"] = canonical.sovereignty_receipt_hash(receipt)


def _rehash_downstream(bundle: dict, *, replay_body: bool = True) -> None:
    for node in bundle["graph"]["nodes"]:
        node["content_hash"] = canonical.claim_node_content_hash(node)
    for edge in bundle["graph"]["edges"]:
        edge["content_hash"] = canonical.claim_edge_content_hash(edge)
    bundle["packet"]["substrate_state_hash"] = canonical.claim_graph_substrate_hash(
        bundle["graph"]["nodes"], bundle["graph"]["edges"]
    )
    bundle["packet"]["packet_hash"] = canonical.context_packet_hash(bundle["packet"])
    bundle["walk"]["packet_hash"] = bundle["packet"]["packet_hash"]
    bundle["walk"]["walk_hash"] = canonical.packet_walk_hash(bundle["walk"])
    bundle["rendered"]["packet_hash"] = bundle["packet"]["packet_hash"]
    bundle["rendered"]["walk_hash"] = bundle["walk"]["walk_hash"]
    if replay_body:
        replayed = replay_render(bundle["walk"], bundle["rendered"]["template_kind"])
        bundle["rendered"]["body"] = replayed["body"]
        bundle["rendered"]["operation_refs"] = replayed["operation_refs"]
        bundle["rendered"]["citations"] = replayed["citations"]
    bundle["rendered"]["render_hash"] = canonical.rendered_packet_hash(
        bundle["rendered"]
    )
    bundle["inspection"] = reproduce_inspection(
        graph=bundle["graph"],
        packet=bundle["packet"],
        walk=bundle["walk"],
        rendered=bundle["rendered"],
    )
    _rehash_receipt(bundle)


def test_real_initial_and_revised_heppner_stages_pass() -> None:
    for name in ("initial", "revised"):
        report = verify_bundle(_stage(name))
        assert report.passed, report.to_dict()
        assert report.integrity_valid is Conclusion.TRUE
        assert report.producer_artifacts_consistent is Conclusion.TRUE
        assert report.packet_time_bindings_valid is Conclusion.TRUE
        assert report.inspection_reproduced is Conclusion.TRUE
        assert report.receipt_hashes_valid is Conclusion.TRUE
        payload = report.to_dict()
        assert payload["verified_artifacts"]["context_packet_hash"] == (
            _stage(name)["packet"]["packet_hash"]
        )
        assert payload["report_hash"].startswith("sha256:")


def test_authenticity_and_signature_remain_reserved() -> None:
    report = verify_bundle(_stage())
    assert report.authenticity_verified is Conclusion.NOT_EVALUATED
    assert report.signature_verified is Conclusion.NOT_EVALUATED


def test_graph_is_required_for_full_pass() -> None:
    bundle = _stage()
    del bundle["graph"]
    report = verify_bundle(bundle)
    assert not report.passed
    assert any(item.code == "missing_required_artifact" for item in report.findings)


def test_existing_node_text_mutation_is_detected() -> None:
    bundle = _stage()
    bundle["graph"]["nodes"][0]["normalized_text"] = "Altered after production."
    report = verify_bundle(bundle)
    assert not report.passed
    assert any(item.code == "claim_node_hash_mismatch" for item in report.findings)


def test_node_mutation_with_self_consistent_rehash_is_detected() -> None:
    bundle = _stage()
    node = bundle["graph"]["nodes"][0]
    node["normalized_text"] = "Altered with a matching node hash."
    node["content_hash"] = canonical.claim_node_content_hash(node)
    report = verify_bundle(bundle)
    assert not report.passed
    assert any(
        item.code in {"substrate_hash_mismatch", "graph_drift_from_binding"}
        for item in report.findings
    )


def test_forged_node_and_packet_lists_are_detected() -> None:
    bundle = _stage()
    forged = copy.deepcopy(bundle["graph"]["nodes"][0])
    forged["claim_id"] = "claim:forged"
    forged["normalized_text"] = "Forged admitted content."
    forged["content_hash"] = canonical.claim_node_content_hash(forged)
    bundle["graph"]["nodes"].append(forged)
    bundle["packet"]["admitted_claim_ids"].append("claim:forged")
    bundle["packet"]["evidence_manifest"]["claim_ids"].append("claim:forged")
    report = verify_bundle(bundle)
    assert not report.passed
    assert any(
        item.code in {"substrate_hash_mismatch", "packet_binding_shape_mismatch"}
        for item in report.findings
    )


def test_claim_edge_hash_and_endpoints_are_verified() -> None:
    bundle = _stage()
    bundle["graph"]["edges"].append(
        {
            "edge_id": "edge:forged",
            "from_claim_id": bundle["graph"]["nodes"][0]["claim_id"],
            "to_claim_id": "claim:absent",
            "edge_type": "supports",
            "lifecycle_state": "active",
            "support_refs": [],
            "anchor_refs": [],
            "content_hash": "sha256:" + "0" * 64,
            "created_at": "2026-07-12T00:00:00Z",
        }
    )
    report = verify_bundle(bundle)
    assert not report.passed
    codes = {item.code for item in report.findings}
    assert "claim_edge_hash_mismatch" in codes
    assert "edge_endpoint_missing" in codes


def test_packet_walk_render_and_inspection_hashes_are_recomputed() -> None:
    mutations = (
        ("packet", "packet_hash", "packet_hash_mismatch"),
        ("walk", "walk_hash", "walk_hash_mismatch"),
        ("rendered", "render_hash", "render_hash_mismatch"),
        ("inspection", "inspection_hash", "inspection_hash_mismatch"),
    )
    for object_key, hash_key, finding_code in mutations:
        bundle = _stage()
        bundle[object_key][hash_key] = "sha256:" + "0" * 64
        report = verify_bundle(bundle)
        assert not report.passed
        assert any(item.code == finding_code for item in report.findings)


def test_quote_content_and_refs_must_match_packet_time_binding() -> None:
    bundle = _stage()
    quote = next(item for item in bundle["walk"]["operations"] if item["kind"] == "quote")
    quote["quote_text"] = "Substituted quote text."
    quote["anchor_refs"] = ["anchor:substituted"]
    _rehash_downstream(bundle)
    report = verify_bundle(bundle)
    assert not report.passed
    assert report.packet_time_bindings_valid is Conclusion.FALSE
    assert any(item.code == "quote_content_differs_from_binding" for item in report.findings)


def test_quote_without_select_fails_even_when_all_hashes_are_consistent() -> None:
    bundle = _stage("initial")
    operations = bundle["walk"]["operations"]
    operations[0], operations[1] = operations[1], operations[0]
    _rehash_downstream(bundle)
    report = verify_bundle(bundle)
    assert not report.passed
    assert report.integrity_valid is Conclusion.TRUE
    assert report.inspection_reproduced is Conclusion.TRUE
    assert any(item.code == "quote_without_select" for item in report.findings)


def test_packet_binding_shape_fails_even_when_downstream_hashes_are_consistent() -> None:
    bundle = _stage()
    bundle["packet"]["admitted_claim_ids"].pop()
    _rehash_downstream(bundle)
    report = verify_bundle(bundle)
    assert not report.passed
    assert any(item.code == "packet_binding_shape_mismatch" for item in report.findings)


def test_independent_renderer_replay_rejects_arbitrary_consistently_hashed_body() -> None:
    bundle = _stage()
    bundle["rendered"]["body"] = "ARBITRARY BUT SELF-CONSISTENT BODY"
    _rehash_downstream(bundle, replay_body=False)
    report = verify_bundle(bundle)
    assert not report.passed
    assert report.integrity_valid is Conclusion.TRUE
    assert any(item.code == "render_replay_mismatch" for item in report.findings)


def test_full_inspection_projection_is_reproduced_not_only_has_blockers() -> None:
    bundle = _stage()
    bundle["inspection"]["issues"] = [
        {
            "code": "packet_hash_mismatch",
            "severity": "blocker",
            "message": "fabricated inspection issue",
            "ref": "fabricated",
        }
    ]
    bundle["inspection"]["has_blockers"] = True
    bundle["inspection"]["inspection_hash"] = canonical.packet_inspection_hash(
        bundle["inspection"]
    )
    _rehash_receipt(bundle)
    report = verify_bundle(bundle)
    assert not report.passed
    assert report.inspection_reproduced is Conclusion.FALSE
    assert any(item.code == "inspection_reproduction_mismatch" for item in report.findings)


def test_receipt_verifies_all_heppner_artifact_hashes_and_refs() -> None:
    bundle = _stage()
    cases = (
        "source_capture_hash",
        "context_packet_hash",
        "packet_walk_hash",
        "rendered_packet_hash",
        "rendered_packet_body_sha256",
        "packet_inspection_hash",
    )
    for key in cases:
        candidate = _stage()
        candidate["receipt"]["artifact_hashes"][key] = "sha256:" + "f" * 64
        candidate["receipt"]["receipt_hash"] = canonical.sovereignty_receipt_hash(
            candidate["receipt"]
        )
        report = verify_bundle(candidate)
        assert not report.passed
        assert any(item.code == "receipt_artifact_hash_mismatch" for item in report.findings)
    assert verify_bundle(bundle).receipt_hashes_valid is Conclusion.TRUE


def test_unverified_receipt_schema_is_rejected() -> None:
    bundle = _stage()
    bundle["receipt"]["schema"] = "garp.sovereignty_receipt.v0.2"
    bundle["receipt"]["receipt_hash"] = canonical.sovereignty_receipt_hash(
        bundle["receipt"]
    )
    report = verify_bundle(bundle)
    assert not report.passed
    assert any(item.code == "unsupported_receipt_schema" for item in report.findings)


def test_unsupported_integrity_profile_is_rejected() -> None:
    bundle = _stage()
    bundle["schema"] = "packet_time_claim_binding.v9_9"
    report = verify_bundle(bundle)
    assert not report.passed
    assert any(item.code == "unsupported_schema" for item in report.findings)


def test_fully_coherent_rewrite_passes_structural_not_authenticity_verification() -> None:
    bundle = _stage()
    node = bundle["graph"]["nodes"][0]
    node["normalized_text"] = "A rewritten but internally coherent claim."
    node["content_hash"] = canonical.claim_node_content_hash(node)
    binding = next(
        item
        for item in bundle["packet"]["claim_bindings"]
        if item["claim_id"] == node["claim_id"]
    )
    binding["normalized_text"] = node["normalized_text"]
    binding["content_hash"] = canonical.claim_binding_content_hash(binding)
    quote = next(
        item
        for item in bundle["walk"]["operations"]
        if item.get("kind") == "quote" and item.get("claim_id") == node["claim_id"]
    )
    quote["quote_text"] = binding["normalized_text"]
    quote["claim_content_hash"] = binding["content_hash"]
    _rehash_downstream(bundle)

    report = verify_bundle(bundle)
    assert report.passed, report.to_dict()
    assert report.authenticity_verified is Conclusion.NOT_EVALUATED
    assert report.signature_verified is Conclusion.NOT_EVALUATED


# --- v0.2 PacketInspectionProjection schema (mode/graph_comparison_status/
# schema bound into inspection_hash). Real, literal producer bytes from the
# first genuine TH-S09/CA9 proof run -- not a synthetic bundle -- matching
# this repo's own literal-bytes testing convention. See
# packs/amnesiac.theranos_ca9_public_proof/v0.1/README (producer bytes +
# expected verify report) for provenance.

CA9_FIXTURE = (
    Path(__file__).parent.parent
    / "packs"
    / "amnesiac.theranos_ca9_public_proof"
    / "v0.1"
    / "producer"
    / "proof_bundle.json"
)
CA9_EXPECTED_REPORT = (
    Path(__file__).parent.parent
    / "packs"
    / "amnesiac.theranos_ca9_public_proof"
    / "v0.1"
    / "expected"
    / "verify-report.json"
)


def _ca9_bundle() -> dict:
    return json.loads(CA9_FIXTURE.read_text(encoding="utf-8"))


def test_ca9_v0_2_inspection_bundle_passes_and_matches_expected_report() -> None:
    """Real producer bytes, schema amnesiac.packet_inspection_projection.v0_2.

    This is the exact bundle that first exposed the v0.1/v0.2 hash-shape gap
    (inspection_hash_mismatch even though every content field reproduced
    correctly) -- pinned here so the gap cannot silently regress.
    """
    bundle = _ca9_bundle()
    assert bundle["inspection"]["schema"] == "amnesiac.packet_inspection_projection.v0_2"
    report = verify_bundle(bundle).to_dict()
    expected = json.loads(CA9_EXPECTED_REPORT.read_text(encoding="utf-8"))
    assert report["passed"] is True
    assert report["schema"] == expected["schema"]
    assert report["verification_profile"] == expected["verification_profile"]
    assert report["conclusions"] == expected["conclusions"]
    assert report["verified_artifacts"] == expected["verified_artifacts"]
    assert report["report_hash"] == expected["report_hash"]
    assert report["conclusions"]["authenticity_verified"] == "not_evaluated"
    assert report["conclusions"]["signature_verified"] == "not_evaluated"


def test_ca9_v0_2_inspection_hash_recomputes_with_bound_fields() -> None:
    bundle = _ca9_bundle()
    inspection = bundle["inspection"]
    assert inspection["inspection_hash"] == canonical.packet_inspection_hash(inspection)


def test_ca9_v0_2_tampered_graph_comparison_status_is_rejected() -> None:
    """A producer cannot silently claim 'clean' by editing only the field --
    graph_comparison_status is bound into inspection_hash for v0.2, so
    editing it without recomputing the hash is caught by the hash check; the
    independent replay in reproduce_inspection separately re-derives the
    correct status from the graph, so it cannot be laundered even via a
    self-consistent hash recompute of a false value."""
    bundle = _ca9_bundle()
    bundle["inspection"]["graph_comparison_status"] = "drift_detected"
    bundle["inspection"]["inspection_hash"] = canonical.packet_inspection_hash(
        bundle["inspection"]
    )
    report = verify_bundle(bundle)
    assert not report.passed
    assert any(item.code == "inspection_reproduction_mismatch" for item in report.findings)


def test_ca9_v0_2_tampered_mode_is_rejected() -> None:
    bundle = _ca9_bundle()
    bundle["inspection"]["mode"] = "historical_only"
    bundle["inspection"]["inspection_hash"] = canonical.packet_inspection_hash(
        bundle["inspection"]
    )
    report = verify_bundle(bundle)
    assert not report.passed
    assert any(item.code == "inspection_reproduction_mismatch" for item in report.findings)


def test_ca9_v0_2_stale_inspection_hash_after_field_edit_is_rejected() -> None:
    """Editing a v0.2-bound field WITHOUT recomputing inspection_hash (the
    naive tamper attempt) is caught by the hash check specifically."""
    bundle = _ca9_bundle()
    bundle["inspection"]["graph_comparison_status"] = "drift_detected"
    report = verify_bundle(bundle)
    assert not report.passed
    assert any(item.code == "inspection_hash_mismatch" for item in report.findings)


def test_v0_1_inspection_hash_unaffected_by_v0_2_schema_branch() -> None:
    """A v0.1-shaped inspection (no schema key) must hash identically to
    before this change -- the v0.2 branch must never leak into v0.1 bytes."""
    bundle = _stage()
    inspection = bundle["inspection"]
    assert "schema" not in inspection
    assert inspection["inspection_hash"] == canonical.packet_inspection_hash(inspection)
    expected = reproduce_inspection(
        graph=bundle["graph"], packet=bundle["packet"], walk=bundle["walk"],
        rendered=bundle["rendered"],
    )
    assert "schema" not in expected
    assert "mode" not in expected
    assert "graph_comparison_status" not in expected


def test_runtime_package_contains_no_producer_imports() -> None:
    package = Path(__file__).parent.parent / "arcs_verify" / "amnesiac"
    source = "\n".join(path.read_text(encoding="utf-8") for path in package.glob("*.py"))
    assert "import arcs_amnesiac" not in source
    assert "from arcs_amnesiac" not in source
    assert "import garp_sdk" not in source
    assert "from garp_sdk" not in source
