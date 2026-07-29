"""Conformance tests for the two-stage public proof envelope entrypoint."""

from __future__ import annotations

import copy
import json
from pathlib import Path

from arcs_verify.amnesiac import Conclusion, verify_public_proof_bundle
from arcs_verify.amnesiac.public_proof import SUPPORTED_PUBLIC_PROOF_SCHEMAS

ROOT = Path(__file__).parent.parent
PACK = ROOT / "packs" / "amnesiac.heppner_public_proof" / "v0.1"
PROOF_PATH = PACK / "producer" / "proof_bundle.json"


def _proof() -> dict:
    return json.loads(PROOF_PATH.read_text(encoding="utf-8"))


def test_real_heppner_public_proof_bundle_passes_in_full() -> None:
    report = verify_public_proof_bundle(_proof())
    assert report.passed, report.to_dict()
    assert report.initial.passed
    assert report.revised.passed
    assert report.cross_stage.passed
    assert report.cross_stage.source_identity_continuous is Conclusion.TRUE
    assert report.cross_stage.reconsiderable_to_admitted_transition_valid is Conclusion.TRUE
    assert report.cross_stage.initial_reported_stale_against_revised_graph is Conclusion.TRUE
    assert report.findings == []
    assert report.cross_stage.findings == []


def test_report_shape_has_separate_initial_revised_and_cross_stage_sections() -> None:
    payload = verify_public_proof_bundle(_proof()).to_dict()
    assert set(payload["sections"]) == {"initial", "revised", "cross_stage"}
    assert payload["passed"] is True
    assert "verified" not in payload
    assert "Historical authenticity requires" in payload["boundary_note"]
    assert payload["report_hash"].startswith("sha256:")


def test_report_is_byte_deterministic() -> None:
    first = json.dumps(verify_public_proof_bundle(_proof()).to_dict(), sort_keys=True)
    second = json.dumps(verify_public_proof_bundle(_proof()).to_dict(), sort_keys=True)
    assert first == second


def test_non_dict_bundle_fails_closed() -> None:
    report = verify_public_proof_bundle(["not", "a", "dict"])
    assert not report.passed
    assert any(item.code == "malformed_proof_bundle" for item in report.findings)


def test_unsupported_schema_is_rejected() -> None:
    proof = _proof()
    proof["schema"] = "some_other_bundle.v0_1"
    report = verify_public_proof_bundle(proof)
    assert not report.passed
    assert any(item.code == "unsupported_proof_bundle_schema" for item in report.findings)
    assert "some_other_bundle.v0_1" not in SUPPORTED_PUBLIC_PROOF_SCHEMAS


def test_missing_revised_stage_fails_closed() -> None:
    proof = _proof()
    del proof["revised"]
    report = verify_public_proof_bundle(proof)
    assert not report.passed
    assert any(item.code == "missing_revised_stage" for item in report.findings)
    assert not report.cross_stage.passed


def test_missing_initial_stage_fails_closed() -> None:
    proof = _proof()
    del proof["initial"]
    report = verify_public_proof_bundle(proof)
    assert not report.passed
    assert any(item.code == "missing_initial_stage" for item in report.findings)


def test_altered_initial_stage_fails_that_section_only() -> None:
    proof = _proof()
    proof["initial"]["claim_graph"]["nodes"][0]["normalized_text"] = "tampered"
    report = verify_public_proof_bundle(proof)
    assert not report.passed
    assert not report.initial.passed
    assert any(item.code == "claim_node_hash_mismatch" for item in report.initial.findings)


def test_altered_revised_stage_fails_that_section_only() -> None:
    proof = _proof()
    proof["revised"]["claim_graph"]["nodes"][0]["normalized_text"] = "tampered"
    report = verify_public_proof_bundle(proof)
    assert not report.passed
    assert not report.revised.passed


def test_forged_reopening_candidate_ref_fails_transition_check() -> None:
    proof = _proof()
    proof["reopening"]["outcome"]["candidate_ref"] = "candidate:heppner:ruling"
    report = verify_public_proof_bundle(proof)
    assert not report.passed
    assert report.cross_stage.reconsiderable_to_admitted_transition_valid is Conclusion.FALSE
    assert any(
        item.code == "candidate_not_reconsiderable_in_initial"
        for item in report.cross_stage.findings
    )


def test_reopening_request_outcome_disagreement_fails_transition_check() -> None:
    proof = _proof()
    proof["reopening"]["request"]["candidate_ref"] = "candidate:heppner:ruling"
    report = verify_public_proof_bundle(proof)
    assert not report.passed
    assert report.cross_stage.reconsiderable_to_admitted_transition_valid is Conclusion.FALSE
    assert any(
        item.code == "reopening_candidate_ref_mismatch" for item in report.cross_stage.findings
    )


def test_candidate_left_in_revised_rejected_refs_fails_transition_check() -> None:
    proof = _proof()
    proof["revised"]["rejected_candidate_refs"].append("candidate:heppner:work-product-behest")
    report = verify_public_proof_bundle(proof)
    assert not report.passed
    assert report.cross_stage.reconsiderable_to_admitted_transition_valid is Conclusion.FALSE
    assert any(
        item.code == "candidate_still_rejected_in_revised" for item in report.cross_stage.findings
    )


def test_revised_admission_receipt_removed_fails_transition_check() -> None:
    proof = _proof()
    proof["revised"]["admission_receipts"] = [
        item
        for item in proof["revised"]["admission_receipts"]
        if not (
            item.get("candidate_ref") == "candidate:heppner:work-product-behest"
            and item.get("decision") == "admit"
        )
    ]
    report = verify_public_proof_bundle(proof)
    assert not report.passed
    assert report.cross_stage.reconsiderable_to_admitted_transition_valid is Conclusion.FALSE
    assert any(
        item.code == "candidate_not_admitted_in_revised" for item in report.cross_stage.findings
    )


def test_forged_stale_inspection_block_is_detected() -> None:
    proof = _proof()
    proof["stale_initial_inspection_against_revised_graph"]["has_blockers"] = False
    proof["stale_initial_inspection_against_revised_graph"]["issues"] = []
    report = verify_public_proof_bundle(proof)
    assert not report.passed
    assert report.cross_stage.initial_reported_stale_against_revised_graph is Conclusion.FALSE
    assert any(
        item.code == "stale_inspection_mismatch" for item in report.cross_stage.findings
    )


def test_missing_stale_inspection_block_fails_closed() -> None:
    proof = _proof()
    del proof["stale_initial_inspection_against_revised_graph"]
    report = verify_public_proof_bundle(proof)
    assert not report.passed
    assert any(
        item.code == "missing_stale_inspection_block" for item in report.cross_stage.findings
    )


def test_mismatched_corpus_scope_fails_source_identity_check() -> None:
    proof = _proof()
    proof["revised"]["context_packet"]["scope"] = dict(
        proof["revised"]["context_packet"]["scope"]
    )
    proof["revised"]["context_packet"]["scope"]["corpus_ref"] = "public_case:some_other_case:doc1"
    report = verify_public_proof_bundle(proof)
    assert not report.passed
    assert report.cross_stage.source_identity_continuous is Conclusion.FALSE
    assert any(item.code == "scope_mismatch" for item in report.cross_stage.findings)


def test_spliced_in_foreign_proofcase_packet_id_fails_source_identity_check() -> None:
    proof = _proof()
    proof["revised"]["context_packet"]["packet_id"] = (
        "context_packet:some-other-proofcase.v0_1:revised"
    )
    report = verify_public_proof_bundle(proof)
    assert not report.passed
    assert report.cross_stage.source_identity_continuous is Conclusion.FALSE
    assert any(
        item.code == "packet_id_proofcase_mismatch" for item in report.cross_stage.findings
    )


def test_no_producer_or_amnesiac_repo_imports() -> None:
    source = (ROOT / "arcs_verify" / "amnesiac" / "public_proof.py").read_text(encoding="utf-8")
    assert "import arcs_amnesiac" not in source
    assert "from arcs_amnesiac" not in source
