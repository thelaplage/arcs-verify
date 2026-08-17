from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path


def _load_verifier():
    path = Path(__file__).with_name("verify_bundle.py")
    spec = importlib.util.spec_from_file_location("mona0_verify3", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


VERIFY = _load_verifier()
PRODUCER_REVISION = "1" * 40
VERIFIER_REVISION = "2" * 40
ORIGINAL = "https://upload.wikimedia.org/wikipedia/commons/7/76/Leonardo_da_Vinci_-_Mona_Lisa.jpg"
RENDITION = "https://upload.wikimedia.org/wikipedia/commons/thumb/7/76/Leonardo_da_Vinci_-_Mona_Lisa.jpg/960px-Leonardo_da_Vinci_-_Mona_Lisa.jpg"


def _address(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _source_id(url: str) -> str:
    preimage = json.dumps(
        {"url": url},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return "src_" + hashlib.sha256(preimage).hexdigest()[:32]


def _relative_path(address: str) -> str:
    digest = address.removeprefix("sha256:")
    return f"{digest[:2]}/{digest[2:]}"


def _write_object(root: Path, data: bytes) -> tuple[str, str]:
    address = _address(data)
    relative = _relative_path(address)
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return address, relative


def _capture(label: str, url: str, capture_id: str, address: str, byte_count: int) -> dict:
    source_id = _source_id(url)
    receipt = {
        "capture_id": capture_id,
        "source_id": source_id,
        "source_locator": url,
        "captured_at": "2026-08-17T05:00:00+00:00",
        "http_metadata": {
            "status_code": 200,
            "content_type": "image/jpeg",
            "content_length": byte_count,
            "last_modified": None,
            "etag": None,
            "final_url": url,
        },
        "exact_bytes_sha256": address,
        "byte_count": byte_count,
        "schema_version": "acquisition.capture.v0.1",
    }
    return {
        "tool": "acquisition.capture_url",
        "surface_schema": "acquisition.mcp_surface.v0.1",
        "capture_status": "captured",
        "capture_receipt": receipt,
        "capture_id": capture_id,
        "source_id": source_id,
        "source_locator": url,
        "captured_object_address": address,
        "byte_count": byte_count,
        "failure_detail": None,
        "attempt_label": label,
        "required_for_gate": True,
    }


def _bundle(tmp_path: Path, *, original_bytes: bytes = b"original", rendition_bytes: bytes = b"rendition"):
    store = tmp_path / "objects"
    original_address, original_relative = _write_object(store, original_bytes)
    rendition_address, rendition_relative = _write_object(store, rendition_bytes)

    first = _capture(
        "commons-original-a",
        ORIGINAL,
        "cap_11111111-1111-4111-8111-111111111111",
        original_address,
        len(original_bytes),
    )
    second = _capture(
        "commons-original-b",
        ORIGINAL,
        "cap_22222222-2222-4222-8222-222222222222",
        original_address,
        len(original_bytes),
    )
    rendition = _capture(
        "commons-960",
        RENDITION,
        "cap_33333333-3333-4333-8333-333333333333",
        rendition_address,
        len(rendition_bytes),
    )

    artifacts = [
        {
            "artifact_ref": original_address,
            "byte_count": len(original_bytes),
            "observation_refs": [first["capture_id"], second["capture_id"]],
            "source_locators": [ORIGINAL],
        },
        {
            "artifact_ref": rendition_address,
            "byte_count": len(rendition_bytes),
            "observation_refs": [rendition["capture_id"]],
            "source_locators": [RENDITION],
        },
    ]
    artifacts.sort(key=lambda row: row["artifact_ref"])

    facts = {
        "schema_version": "counterpedia.mona0.capture1.v0.1",
        "proofcase_id": "MONA0-CAPTURE1",
        "generated_at": "2026-08-17T05:00:00+00:00",
        "producer": {
            "repository": "thelaplage/counterpedia-acquisition",
            "revision": PRODUCER_REVISION,
            "surface": "acquisition.mcp_surface.v0.1",
            "tool": "acquisition.capture_url",
            "authority_movement": 0,
        },
        "summary": {
            "attempt_count": 3,
            "captured_count": 3,
            "failed_count": 0,
            "distinct_artifact_count": 2,
            "repeat_observation_preserved": True,
            "repeat_exact_bytes_reused": True,
            "distinct_rendition_separated": True,
            "claim_admission_decisions": 0,
        },
        "attempts": [first, second, rendition],
        "artifacts": artifacts,
        "negative_assertions": {
            "locator_count_is_not_independence": True,
            "capture_is_not_claim_support": True,
            "capture_is_not_admission": True,
            "artifact_digest_is_not_truth_verification": True,
        },
    }

    manifest_objects = [
        {
            "artifact_ref": original_address,
            "byte_count": len(original_bytes),
            "relative_path": original_relative,
        },
        {
            "artifact_ref": rendition_address,
            "byte_count": len(rendition_bytes),
            "relative_path": rendition_relative,
        },
    ]
    manifest_objects.sort(key=lambda row: row["artifact_ref"])
    manifest = {
        "schema_version": "counterpedia.mona0.capture1_object_manifest.v0.1",
        "proofcase_id": "MONA0-CAPTURE1",
        "producer": {
            "repository": "thelaplage/counterpedia-acquisition",
            "revision": PRODUCER_REVISION,
            "object_store_implementation": "acquisition.fs_store.FilesystemObjectStore",
            "authority_movement": 0,
        },
        "store_root": "generated/mona0-object-store",
        "layout": "<root>/<sha256_hex[:2]>/<sha256_hex[2:]>",
        "object_count": 2,
        "total_unique_bytes": len(original_bytes) + len(rendition_bytes),
        "max_bundle_bytes": 40 * 1024 * 1024,
        "producer_side_integrity_reread": True,
        "independent_verification": False,
        "objects": manifest_objects,
    }
    return facts, manifest, store


def test_valid_bundle_passes_but_reserved_conclusions_stay_not_evaluated(tmp_path: Path) -> None:
    facts, manifest, store = _bundle(tmp_path)
    report = VERIFY.verify_bundle(
        facts, manifest, store, verifier_revision=VERIFIER_REVISION
    )

    assert report["passed"] is True
    assert report["failure_codes"] == []
    for field in VERIFY.GATING_FIELDS:
        assert report["conclusions"][field] is True
    assert report["conclusions"]["authenticity_verified"] == "not_evaluated"
    assert report["conclusions"]["claim_truth_verified"] == "not_evaluated"
    assert report["conclusions"]["source_independence_verified"] == "not_evaluated"
    assert report["conclusions"]["signature_verified"] == "not_evaluated"
    assert report["verifier"]["imports_producer_implementation"] is False


def test_tampered_object_bytes_fail_independent_digest_check(tmp_path: Path) -> None:
    facts, manifest, store = _bundle(tmp_path)
    original = manifest["objects"][0]
    path = store / original["relative_path"]
    path.write_bytes(path.read_bytes() + b"tamper")

    report = VERIFY.verify_bundle(
        facts, manifest, store, verifier_revision=VERIFIER_REVISION
    )

    assert report["passed"] is False
    assert report["conclusions"]["object_bytes_integrity_valid"] is False
    assert "object.digest_mismatch" in report["failure_codes"]


def test_fully_coherent_rewrite_can_pass_but_does_not_gain_authenticity(tmp_path: Path) -> None:
    facts, manifest, store = _bundle(
        tmp_path,
        original_bytes=b"fully-rewritten-original",
        rendition_bytes=b"fully-rewritten-rendition",
    )

    report = VERIFY.verify_bundle(
        facts, manifest, store, verifier_revision=VERIFIER_REVISION
    )

    assert report["passed"] is True
    assert report["conclusions"]["authenticity_verified"] == "not_evaluated"
    assert report["conclusions"]["claim_truth_verified"] == "not_evaluated"
    assert report["conclusions"]["signature_verified"] == "not_evaluated"


def test_manifest_cannot_claim_its_producer_check_was_independent(tmp_path: Path) -> None:
    facts, manifest, store = _bundle(tmp_path)
    manifest["independent_verification"] = True

    report = VERIFY.verify_bundle(
        facts, manifest, store, verifier_revision=VERIFIER_REVISION
    )

    assert report["passed"] is False
    assert report["conclusions"]["authority_boundary_valid"] is False
    assert "manifest.independent_verification_overclaim" in report["failure_codes"]


def test_capture_bundle_cannot_smuggle_claim_admission(tmp_path: Path) -> None:
    facts, manifest, store = _bundle(tmp_path)
    facts["summary"]["claim_admission_decisions"] = 1

    report = VERIFY.verify_bundle(
        facts, manifest, store, verifier_revision=VERIFIER_REVISION
    )

    assert report["passed"] is False
    assert report["conclusions"]["authority_boundary_valid"] is False
    assert "authority.claim_admission_present" in report["failure_codes"]


def test_unmanifested_object_file_breaks_closed_bundle(tmp_path: Path) -> None:
    facts, manifest, store = _bundle(tmp_path)
    extra = store / "ff" / ("0" * 62)
    extra.parent.mkdir(parents=True, exist_ok=True)
    extra.write_bytes(b"unmanifested")

    report = VERIFY.verify_bundle(
        facts, manifest, store, verifier_revision=VERIFIER_REVISION
    )

    assert report["passed"] is False
    assert report["conclusions"]["object_bytes_integrity_valid"] is False
    assert "object_store.file_set_mismatch" in report["failure_codes"]


def test_forged_url_derived_source_id_is_rejected(tmp_path: Path) -> None:
    facts, manifest, store = _bundle(tmp_path)
    facts["attempts"][0]["source_id"] = "src_00000000000000000000000000000000"
    facts["attempts"][0]["capture_receipt"]["source_id"] = facts["attempts"][0]["source_id"]

    report = VERIFY.verify_bundle(
        facts, manifest, store, verifier_revision=VERIFIER_REVISION
    )

    assert report["passed"] is False
    assert report["conclusions"]["receipt_object_bindings_valid"] is False
    assert "receipt.source_id_derivation_mismatch" in report["failure_codes"]


def test_invalid_verifier_revision_is_source_error(tmp_path: Path) -> None:
    facts, manifest, store = _bundle(tmp_path)
    try:
        VERIFY.verify_bundle(facts, manifest, store, verifier_revision="main")
    except VERIFY.SourceError as exc:
        assert "exact 40-hex" in str(exc)
    else:
        raise AssertionError("moving verifier revision was accepted")
