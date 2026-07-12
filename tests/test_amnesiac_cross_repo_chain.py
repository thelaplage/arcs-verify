"""Cross-repository acceptance over the real Heppner canonical proof bundle."""

from __future__ import annotations

import copy
import json
from pathlib import Path

from arcs_verify.amnesiac import bundle_from_proof_stage, project_report, verify_bundle
from arcs_verify.amnesiac import canonical

ROOT = Path(__file__).parent.parent
PACK = ROOT / "packs" / "amnesiac.heppner_public_proof" / "v0.1"
PROOF_PATH = PACK / "producer" / "proof_bundle.json"
PROJECTION_PATH = PACK / "producer" / "garpedia_projection.json"


def _proof() -> dict:
    return json.loads(PROOF_PATH.read_text(encoding="utf-8"))


def _bundle(stage_name: str) -> dict:
    return copy.deepcopy(bundle_from_proof_stage(_proof(), stage_name))


def test_real_heppner_produce_verify_chain_passes_both_stages() -> None:
    for stage_name in ("initial", "revised"):
        report = verify_bundle(_bundle(stage_name))
        assert report.passed, report.to_dict()


def test_real_heppner_tamper_fails_in_same_chain() -> None:
    bundle = _bundle("revised")
    bundle["graph"]["nodes"][0]["normalized_text"] = "tampered"
    report = verify_bundle(bundle)
    assert not report.passed


def test_report_is_byte_deterministic_for_same_serialized_input() -> None:
    bundle = _bundle("revised")
    first = json.dumps(verify_bundle(bundle).to_dict(), sort_keys=True, separators=(",", ":"))
    second = json.dumps(
        verify_bundle(copy.deepcopy(bundle)).to_dict(),
        sort_keys=True,
        separators=(",", ":"),
    )
    assert first == second
    initial = verify_bundle(_bundle("initial")).to_dict()
    revised = verify_bundle(_bundle("revised")).to_dict()
    assert initial["report_hash"] != revised["report_hash"]
    assert initial["report_hash"] == canonical.verification_report_hash(initial)
    assert revised["report_hash"] == canonical.verification_report_hash(revised)


def test_projection_is_separately_owned_and_carries_conclusions_unchanged() -> None:
    report = verify_bundle(_bundle("revised"))
    projected = project_report(report.to_dict())
    assert projected["owned_by"] == "arcs-verify"
    assert projected["produced_by"] == "arcs-verify"
    assert projected["not_produced_by"] == "garpedia"
    assert projected["conclusions"] == report.to_dict()["conclusions"]
    assert projected["report_hash"] == report.to_dict()["report_hash"]
    assert projected["verified_artifacts"] == report.to_dict()["verified_artifacts"]
    assert projected["structural_pass"] is True
    assert projected["authenticity_claimed"] is False
    assert projected["signature_claimed"] is False


def test_existing_garpedia_projection_links_to_the_exact_producer_artifacts() -> None:
    proof = _proof()
    public_projection = json.loads(PROJECTION_PATH.read_text(encoding="utf-8"))
    for stage_name, projection_key in (
        ("initial", "initial_state"),
        ("revised", "revised_state"),
    ):
        stage = proof[stage_name]
        projected = public_projection[projection_key]
        assert projected["capture_hash"] == stage["capture_hash"]
        assert projected["render_hash"] == stage["rendered_packet"]["render_hash"]
        assert projected["inspection_hash"] == stage["packet_inspection"]["inspection_hash"]
        assert projected["receipt_hash"] == stage["sovereignty_receipt"]["receipt_hash"]



def test_committed_verify_reports_and_projection_regenerate_byte_identically() -> None:
    proof = _proof()
    for stage_name in ("initial", "revised"):
        generated = verify_bundle(
            bundle_from_proof_stage(proof, stage_name)
        ).to_dict()
        committed_path = PACK / "expected" / f"{stage_name}-verify-report.json"
        committed = json.loads(committed_path.read_text(encoding="utf-8"))
        assert generated == committed

    projected = project_report(
        json.loads(
            (PACK / "expected" / "revised-verify-report.json").read_text(
                encoding="utf-8"
            )
        )
    )
    committed_projection = json.loads(
        (PACK / "expected" / "revised-verify-projection.json").read_text(
            encoding="utf-8"
        )
    )
    assert projected == committed_projection


def test_full_produce_verify_project_chain_preserves_claim_boundary() -> None:
    report = verify_bundle(_bundle("revised"))
    projected = project_report(report.to_dict())
    assert report.passed
    assert projected["structural_pass"] is True
    assert projected["authenticity_claimed"] is False
    assert "Historical authenticity requires" in projected["boundary_note"]


def test_pack_manifest_hashes_every_committed_artifact() -> None:
    import hashlib

    manifest = json.loads((PACK / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["source_commit"] == "1dc7660"
    assert manifest["source_pull_request"] == 43
    assert manifest["expected_report_hashes"] == {
        "initial": "sha256:1ee1fccd38c53678aeee15363e0579cee19a0a19c8455afe2d385b0f3a18a3a2",
        "revised": "sha256:80c18726679e72c53bd13e0b56bc36f98fa21d0f6ad4a5da929746f7cb315fcf",
    }
    for entry in manifest["entries"]:
        payload = (PACK / entry["path"]).read_bytes()
        assert hashlib.sha256(payload).hexdigest() == entry["sha256"]
