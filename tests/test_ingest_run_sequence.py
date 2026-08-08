"""Tests for arcs_verify.ingest_run_sequence — dagr.ingest_run.v0.1 sequence verifier.

Tests verify that:
- Valid complete sequences produce Conclusion.TRUE for all structural findings.
- Every mutation in the adversarial corpus is rejected with the correct finding code.
- Failure codes from the new module appear in the registry.
- Producer packages (dagr_ingest, garp_ingest) are not importable.
- NOT_EVALUATED is preserved and not promoted to PASS.
- CWD-independent CLI path works.

Fixture data is self-contained within this repository; no path dependencies on
sibling repositories.
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from arcs_verify.ingest_run_sequence import (
    Conclusion,
    IngestRunSequenceReport,
    RECEIPT_SET_MANIFEST_SCHEMA,
    RUN_DOC_SCHEMA,
    SEQUENCE_PROFILE,
    SEQUENCE_SCHEMA,
    verify_ingest_run_sequence,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures" / "ingest_run_sequence"
RECEIPTS_DIR = FIXTURE_ROOT / "receipts"
PROFILE_MANIFEST_PATH = FIXTURE_ROOT / "profile.manifest.json"

# Ensure subprocess calls use the worktree source rather than any installed
# version of arcs-verify that may not yet include this lane's code.
_CLI_ENV = {**os.environ, "PYTHONPATH": str(ROOT)}


def load_run_doc() -> dict:
    return json.loads((FIXTURE_ROOT / "run_doc.json").read_text(encoding="utf-8"))


def load_manifest() -> dict:
    return json.loads((FIXTURE_ROOT / "manifest.json").read_text(encoding="utf-8"))


def load_receipt(name: str) -> dict:
    return json.loads((RECEIPTS_DIR / name).read_text(encoding="utf-8"))


def _write_tmp(tmp: Path, name: str, content: dict) -> Path:
    p = tmp / name
    p.write_text(json.dumps(content, indent=2), encoding="utf-8")
    return p


def _recompute_profile_sha256(profile_manifest_path: Path) -> str:
    return hashlib.sha256(profile_manifest_path.read_bytes()).hexdigest()


def verify_from_dicts(
    run_doc: dict,
    manifest: dict,
    *,
    tmp_path: Path,
    extra_receipts: dict[str, dict] | None = None,
) -> IngestRunSequenceReport:
    """Write dicts to temp files and run the verifier."""
    run_doc_path = _write_tmp(tmp_path, "run_doc.json", run_doc)
    manifest_path = _write_tmp(tmp_path, "manifest.json", manifest)
    receipts_dir = tmp_path / "receipts"
    receipts_dir.mkdir(exist_ok=True)

    # Copy the canonical receipt from the fixture dir
    for name in (RECEIPTS_DIR).iterdir():
        if name.is_file() and name.suffix == ".json":
            (receipts_dir / name.name).write_bytes(name.read_bytes())

    if extra_receipts:
        for fname, content in extra_receipts.items():
            _write_tmp(receipts_dir, fname, content)

    return verify_ingest_run_sequence(
        run_doc_path=run_doc_path,
        receipt_set_manifest_path=manifest_path,
        receipts_dir=receipts_dir,
        profile_manifest_path=PROFILE_MANIFEST_PATH,
    )


# ---------------------------------------------------------------------------
# Acceptance gate: producer packages absent
# ---------------------------------------------------------------------------

def test_producer_packages_absent():
    """dagr_ingest must not be importable in this environment.

    The D4 producer package (dagr_ingest) is the one that emits the receipts
    and manifests this verifier checks. The verifier must not import it.
    """
    spec = importlib.util.find_spec("dagr_ingest")
    assert spec is None, (
        "Producer package 'dagr_ingest' is present in the verifier environment. "
        "Producer/verifier independence is violated."
    )


def test_ingest_run_sequence_does_not_import_producer():
    """ingest_run_sequence.py must not import dagr_ingest or garp_ingest."""
    import inspect
    import arcs_verify.ingest_run_sequence as mod

    source = inspect.getsource(mod)
    import_lines = [
        line.strip() for line in source.splitlines()
        if line.strip().startswith(("import ", "from "))
    ]
    for line in import_lines:
        assert "dagr_ingest" not in line, (
            f"ingest_run_sequence imports dagr_ingest: {line!r}"
        )
        assert "garp_ingest" not in line, (
            f"ingest_run_sequence imports garp_ingest: {line!r}"
        )


# ---------------------------------------------------------------------------
# 1. Valid complete sequence — all findings PASS
# ---------------------------------------------------------------------------

def test_valid_sequence_passes(tmp_path):
    run_doc = load_run_doc()
    manifest = load_manifest()
    report = verify_from_dicts(run_doc, manifest, tmp_path=tmp_path)

    data = report.to_dict()
    c = data["conclusions"]

    assert c["run_doc_schema"] == "true", report.findings
    assert c["boundary_declarations"] == "true", report.findings
    assert c["receipt_set_manifest_schema"] == "true", report.findings
    assert c["run_id_linkage"] == "true", report.findings
    assert c["profile_manifest_pin"] == "true", report.findings
    assert c["receipt_file_present"] == "true", report.findings
    assert c["receipt_parse"] == "true", report.findings
    assert c["protocol_binding"] == "true", report.findings
    assert c["subject_ref_manifest"] == "true", report.findings
    assert c["subject_binding"] == "true", report.findings
    assert c["corpus_manifest_ref"] == "true", report.findings
    assert c["raw_content_absent"] == "true", report.findings
    assert c["artifact_classes_excluded"] == "true", report.findings
    assert c["unique_artifact_coverage"] == "true", report.findings
    assert c["duplicate_posture"] == "true", report.findings
    assert report.passed is True, report.findings


def test_valid_sequence_report_schema_fields(tmp_path):
    """to_dict() exposes named conclusions, schema, and profile fields."""
    run_doc = load_run_doc()
    manifest = load_manifest()
    report = verify_from_dicts(run_doc, manifest, tmp_path=tmp_path)
    data = report.to_dict()

    assert data["schema"] == SEQUENCE_SCHEMA
    assert data["verification_profile"] == SEQUENCE_PROFILE
    assert "conclusions" in data
    assert "findings" in data
    assert "passed" in data
    assert "limitations" in data


def test_not_evaluated_is_not_promoted_to_pass():
    """Empty/missing inputs yield NOT_EVALUATED or FALSE, never spurious PASS."""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        run_doc_path = tmp / "missing_run_doc.json"
        manifest_path = tmp / "missing_manifest.json"
        receipts_dir = tmp / "receipts"
        receipts_dir.mkdir()
        profile_manifest_path = PROFILE_MANIFEST_PATH

        report = verify_ingest_run_sequence(
            run_doc_path=run_doc_path,
            receipt_set_manifest_path=manifest_path,
            receipts_dir=receipts_dir,
            profile_manifest_path=profile_manifest_path,
        )
        assert report.passed is False
        data = report.to_dict()
        assert data["passed"] is False


# ---------------------------------------------------------------------------
# 2. run_doc["schema"] wrong → INGEST_RUN_SCHEMA_MISMATCH
# ---------------------------------------------------------------------------

def test_wrong_run_doc_schema(tmp_path):
    run_doc = load_run_doc()
    run_doc["schema"] = "dagr.ingest_run.v999.0"
    manifest = load_manifest()
    report = verify_from_dicts(run_doc, manifest, tmp_path=tmp_path)

    assert report.run_doc_schema is Conclusion.FALSE
    assert report.passed is False
    codes = [f.code for f in report.findings]
    assert "INGEST_RUN_SCHEMA_MISMATCH" in codes


# ---------------------------------------------------------------------------
# 3. boundary.no_arcs_srs: false → INGEST_RUN_BOUNDARY_VIOLATION
# ---------------------------------------------------------------------------

def test_boundary_no_arcs_srs_false(tmp_path):
    run_doc = load_run_doc()
    run_doc["boundary"]["no_arcs_srs"] = False
    manifest = load_manifest()
    report = verify_from_dicts(run_doc, manifest, tmp_path=tmp_path)

    assert report.boundary_declarations is Conclusion.FALSE
    assert report.passed is False
    codes = [f.code for f in report.findings]
    assert "INGEST_RUN_BOUNDARY_VIOLATION" in codes


def test_boundary_no_receipts_issued_false(tmp_path):
    run_doc = load_run_doc()
    run_doc["boundary"]["no_receipts_issued"] = False
    manifest = load_manifest()
    report = verify_from_dicts(run_doc, manifest, tmp_path=tmp_path)

    assert report.boundary_declarations is Conclusion.FALSE
    codes = [f.code for f in report.findings]
    assert "INGEST_RUN_BOUNDARY_VIOLATION" in codes


def test_boundary_no_network_false(tmp_path):
    run_doc = load_run_doc()
    run_doc["boundary"]["no_network"] = False
    manifest = load_manifest()
    report = verify_from_dicts(run_doc, manifest, tmp_path=tmp_path)

    assert report.boundary_declarations is Conclusion.FALSE
    codes = [f.code for f in report.findings]
    assert "INGEST_RUN_BOUNDARY_VIOLATION" in codes


def test_boundary_absent(tmp_path):
    run_doc = load_run_doc()
    del run_doc["boundary"]
    manifest = load_manifest()
    report = verify_from_dicts(run_doc, manifest, tmp_path=tmp_path)

    assert report.boundary_declarations is Conclusion.FALSE
    codes = [f.code for f in report.findings]
    assert "INGEST_RUN_BOUNDARY_VIOLATION" in codes


# ---------------------------------------------------------------------------
# 4. manifest["run_id"] != run_doc["run_id"] → RUN_ID_MISMATCH
# ---------------------------------------------------------------------------

def test_run_id_mismatch(tmp_path):
    run_doc = load_run_doc()
    manifest = load_manifest()
    manifest["run_id"] = "0000000000000000000000000000000000000000000000000000000000000000"
    report = verify_from_dicts(run_doc, manifest, tmp_path=tmp_path)

    assert report.run_id_linkage is Conclusion.FALSE
    assert report.passed is False
    codes = [f.code for f in report.findings]
    assert "RUN_ID_MISMATCH" in codes


# ---------------------------------------------------------------------------
# 5. profile_manifest_sha256 tampered → PROFILE_MANIFEST_PIN_MISMATCH
# ---------------------------------------------------------------------------

def test_profile_manifest_pin_mismatch(tmp_path):
    run_doc = load_run_doc()
    manifest = load_manifest()
    manifest["profile_manifest_sha256"] = "0" * 64
    report = verify_from_dicts(run_doc, manifest, tmp_path=tmp_path)

    assert report.profile_manifest_pin is Conclusion.FALSE
    assert report.passed is False
    codes = [f.code for f in report.findings]
    assert "PROFILE_MANIFEST_PIN_MISMATCH" in codes


# ---------------------------------------------------------------------------
# 6. Receipt file missing → RECEIPT_FILE_MISSING
# ---------------------------------------------------------------------------

def test_receipt_file_missing(tmp_path):
    run_doc = load_run_doc()
    manifest = load_manifest()
    # Change the receipt_file to one that won't exist
    receipts = manifest["receipts"]
    emitted = [e for e in receipts if e.get("status") == "emitted"]
    emitted[0]["receipt_file"] = "does_not_exist.json"

    report = verify_from_dicts(run_doc, manifest, tmp_path=tmp_path)

    assert report.receipt_file_present is Conclusion.FALSE
    assert report.passed is False
    codes = [f.code for f in report.findings]
    assert "RECEIPT_FILE_MISSING" in codes


# ---------------------------------------------------------------------------
# 7. protocol_binding wrong → PROTOCOL_BINDING_MISMATCH
# ---------------------------------------------------------------------------

def test_protocol_binding_mismatch(tmp_path):
    run_doc = load_run_doc()
    manifest = load_manifest()
    receipt = load_receipt("pub-ingest-001.json")
    receipt["protocol_binding"] = "dagr-mcp/v0.1"

    # Write the modified receipt
    (tmp_path / "receipts").mkdir(exist_ok=True)
    _write_tmp(tmp_path / "receipts", "pub-ingest-001.json", receipt)

    run_doc_path = _write_tmp(tmp_path, "run_doc.json", run_doc)
    manifest_path = _write_tmp(tmp_path, "manifest.json", manifest)

    report = verify_ingest_run_sequence(
        run_doc_path=run_doc_path,
        receipt_set_manifest_path=manifest_path,
        receipts_dir=tmp_path / "receipts",
        profile_manifest_path=PROFILE_MANIFEST_PATH,
    )

    assert report.protocol_binding is Conclusion.FALSE
    assert report.passed is False
    codes = [f.code for f in report.findings]
    assert "PROTOCOL_BINDING_MISMATCH" in codes


# ---------------------------------------------------------------------------
# 8. subject_ref != manifest entry subject → SUBJECT_REF_MANIFEST_MISMATCH
# ---------------------------------------------------------------------------

def test_subject_ref_manifest_mismatch(tmp_path):
    run_doc = load_run_doc()
    manifest = load_manifest()
    # Change the subject in the manifest entry so it doesn't match the receipt
    receipts = manifest["receipts"]
    emitted = [e for e in receipts if e.get("status") == "emitted"]
    emitted[0]["subject"] = "sha256:" + "f" * 64

    report = verify_from_dicts(run_doc, manifest, tmp_path=tmp_path)

    assert report.subject_ref_manifest is Conclusion.FALSE
    assert report.passed is False
    codes = [f.code for f in report.findings]
    assert "SUBJECT_REF_MANIFEST_MISMATCH" in codes


# ---------------------------------------------------------------------------
# 9. subject_ref != publication_artifact_id → SUBJECT_BINDING_MISMATCH
# ---------------------------------------------------------------------------

def test_subject_binding_mismatch(tmp_path):
    run_doc = load_run_doc()
    manifest = load_manifest()
    receipt = load_receipt("pub-ingest-001.json")
    # Make publication_artifact_id differ from subject_ref
    receipt["publication_artifact_id"] = "sha256:" + "a" * 64

    (tmp_path / "receipts").mkdir(exist_ok=True)
    _write_tmp(tmp_path / "receipts", "pub-ingest-001.json", receipt)

    run_doc_path = _write_tmp(tmp_path, "run_doc.json", run_doc)
    manifest_path = _write_tmp(tmp_path, "manifest.json", manifest)

    report = verify_ingest_run_sequence(
        run_doc_path=run_doc_path,
        receipt_set_manifest_path=manifest_path,
        receipts_dir=tmp_path / "receipts",
        profile_manifest_path=PROFILE_MANIFEST_PATH,
    )

    assert report.subject_binding is Conclusion.FALSE
    assert report.passed is False
    codes = [f.code for f in report.findings]
    assert "SUBJECT_BINDING_MISMATCH" in codes


# ---------------------------------------------------------------------------
# 10. corpus_manifest_ref wrong → CORPUS_MANIFEST_REF_MISMATCH
# ---------------------------------------------------------------------------

def test_corpus_manifest_ref_mismatch(tmp_path):
    run_doc = load_run_doc()
    manifest = load_manifest()
    receipt = load_receipt("pub-ingest-001.json")
    # Wrong corpus_manifest_ref
    receipt["corpus_manifest_ref"] = "sha256:" + "b" * 64

    (tmp_path / "receipts").mkdir(exist_ok=True)
    _write_tmp(tmp_path / "receipts", "pub-ingest-001.json", receipt)

    run_doc_path = _write_tmp(tmp_path, "run_doc.json", run_doc)
    manifest_path = _write_tmp(tmp_path, "manifest.json", manifest)

    report = verify_ingest_run_sequence(
        run_doc_path=run_doc_path,
        receipt_set_manifest_path=manifest_path,
        receipts_dir=tmp_path / "receipts",
        profile_manifest_path=PROFILE_MANIFEST_PATH,
    )

    assert report.corpus_manifest_ref is Conclusion.FALSE
    assert report.passed is False
    codes = [f.code for f in report.findings]
    assert "CORPUS_MANIFEST_REF_MISMATCH" in codes


# ---------------------------------------------------------------------------
# 11. Raw content field present in receipt → RAW_CONTENT_PRESENT
# ---------------------------------------------------------------------------

def test_raw_content_present(tmp_path):
    run_doc = load_run_doc()
    manifest = load_manifest()
    receipt = load_receipt("pub-ingest-001.json")
    # Inject a forbidden raw content field
    receipt["raw_publication_bytes"] = "some raw content that must not be here"

    (tmp_path / "receipts").mkdir(exist_ok=True)
    _write_tmp(tmp_path / "receipts", "pub-ingest-001.json", receipt)

    run_doc_path = _write_tmp(tmp_path, "run_doc.json", run_doc)
    manifest_path = _write_tmp(tmp_path, "manifest.json", manifest)

    report = verify_ingest_run_sequence(
        run_doc_path=run_doc_path,
        receipt_set_manifest_path=manifest_path,
        receipts_dir=tmp_path / "receipts",
        profile_manifest_path=PROFILE_MANIFEST_PATH,
    )

    assert report.raw_content_absent is Conclusion.FALSE
    assert report.passed is False
    codes = [f.code for f in report.findings]
    assert "RAW_CONTENT_PRESENT" in codes


def test_raw_frontmatter_yaml_present(tmp_path):
    run_doc = load_run_doc()
    manifest = load_manifest()
    receipt = load_receipt("pub-ingest-001.json")
    receipt["raw_frontmatter_yaml"] = "title: foo"

    (tmp_path / "receipts").mkdir(exist_ok=True)
    _write_tmp(tmp_path / "receipts", "pub-ingest-001.json", receipt)

    run_doc_path = _write_tmp(tmp_path, "run_doc.json", run_doc)
    manifest_path = _write_tmp(tmp_path, "manifest.json", manifest)

    report = verify_ingest_run_sequence(
        run_doc_path=run_doc_path,
        receipt_set_manifest_path=manifest_path,
        receipts_dir=tmp_path / "receipts",
        profile_manifest_path=PROFILE_MANIFEST_PATH,
    )
    codes = [f.code for f in report.findings]
    assert "RAW_CONTENT_PRESENT" in codes


# ---------------------------------------------------------------------------
# 12. Missing required exclusion in artifact_classes_excluded → MISSING_REQUIRED_EXCLUSION
# ---------------------------------------------------------------------------

def test_missing_required_exclusion(tmp_path):
    run_doc = load_run_doc()
    manifest = load_manifest()
    receipt = load_receipt("pub-ingest-001.json")
    # Remove one of the required exclusions
    receipt["artifact_classes_excluded"] = ["raw_frontmatter_yaml", "raw_body_text"]

    (tmp_path / "receipts").mkdir(exist_ok=True)
    _write_tmp(tmp_path / "receipts", "pub-ingest-001.json", receipt)

    run_doc_path = _write_tmp(tmp_path, "run_doc.json", run_doc)
    manifest_path = _write_tmp(tmp_path, "manifest.json", manifest)

    report = verify_ingest_run_sequence(
        run_doc_path=run_doc_path,
        receipt_set_manifest_path=manifest_path,
        receipts_dir=tmp_path / "receipts",
        profile_manifest_path=PROFILE_MANIFEST_PATH,
    )

    assert report.artifact_classes_excluded is Conclusion.FALSE
    assert report.passed is False
    codes = [f.code for f in report.findings]
    assert "MISSING_REQUIRED_EXCLUSION" in codes


# ---------------------------------------------------------------------------
# 13. Unique artifact in run doc not covered in manifest → UNIQUE_ARTIFACT_NOT_COVERED
# ---------------------------------------------------------------------------

def test_unique_artifact_not_covered(tmp_path):
    run_doc = load_run_doc()
    manifest = load_manifest()

    # Add a unique artifact to run_doc that has no matching emitted entry
    run_doc["unique_artifacts"].append({
        "subject": "sha256:" + "c" * 64,
        "parser_id": "dagr-editorial-corpus-parser/0.1.0",
        "is_duplicate_content": False,
        "relative_path": "publications/2024/uncovered.md",
    })

    report = verify_from_dicts(run_doc, manifest, tmp_path=tmp_path)

    assert report.unique_artifact_coverage is Conclusion.FALSE
    assert report.passed is False
    codes = [f.code for f in report.findings]
    assert "UNIQUE_ARTIFACT_NOT_COVERED" in codes


def test_unique_artifact_with_null_parser_id_not_required(tmp_path):
    """Unique artifacts with parser_id=null are NOT required to be covered."""
    run_doc = load_run_doc()
    manifest = load_manifest()

    # The run_doc already has a null-parser_id artifact; verify it doesn't
    # cause UNIQUE_ARTIFACT_NOT_COVERED
    null_parser_artifacts = [
        a for a in run_doc["unique_artifacts"] if a.get("parser_id") is None
    ]
    assert null_parser_artifacts, "Fixture must include a null parser_id artifact"

    report = verify_from_dicts(run_doc, manifest, tmp_path=tmp_path)
    codes = [f.code for f in report.findings]
    assert "UNIQUE_ARTIFACT_NOT_COVERED" not in codes
    assert report.unique_artifact_coverage is Conclusion.TRUE


def test_unique_artifact_coverage_not_evaluated_when_absent(tmp_path):
    """When unique_artifacts is absent from run_doc, coverage is NOT_EVALUATED."""
    run_doc = load_run_doc()
    del run_doc["unique_artifacts"]
    manifest = load_manifest()

    report = verify_from_dicts(run_doc, manifest, tmp_path=tmp_path)
    assert report.unique_artifact_coverage is Conclusion.NOT_EVALUATED


# ---------------------------------------------------------------------------
# 14. Duplicate-content file appears as emitted → DUPLICATE_POSTURE_VIOLATION
# ---------------------------------------------------------------------------

def test_duplicate_posture_violation(tmp_path):
    run_doc = load_run_doc()
    manifest = load_manifest()

    # The run_doc has a duplicate-content artifact. Make it appear as emitted.
    dup_artifact = next(
        a for a in run_doc["unique_artifacts"]
        if a.get("is_duplicate_content") is True
    )
    dup_subject = dup_artifact["subject"]

    # Add it as emitted to the manifest
    manifest["receipts"].append({
        "receipt_file": "dup-emitted.json",
        "subject": dup_subject,
        "status": "emitted",
    })
    # Write a minimal receipt file for it so RECEIPT_FILE_MISSING doesn't fire
    dup_receipt = load_receipt("pub-ingest-001.json")
    dup_receipt["subject_ref"] = dup_subject
    dup_receipt["publication_artifact_id"] = dup_subject
    dup_receipt["corpus_manifest_ref"] = f"sha256:{run_doc['run_id']}"

    report = verify_from_dicts(
        run_doc,
        manifest,
        tmp_path=tmp_path,
        extra_receipts={"dup-emitted.json": dup_receipt},
    )

    assert report.duplicate_posture is Conclusion.FALSE
    assert report.passed is False
    codes = [f.code for f in report.findings]
    assert "DUPLICATE_POSTURE_VIOLATION" in codes


# ---------------------------------------------------------------------------
# 15. Every new failure code appears in the registry
# ---------------------------------------------------------------------------

def test_all_new_failure_codes_in_registry():
    """Every code from ingest_run_sequence.py must appear in FAILURE_CODES.md."""
    registry = (ROOT / "docs" / "FAILURE_CODES.md").read_text(encoding="utf-8")

    expected_codes = [
        "INGEST_RUN_SCHEMA_MISMATCH",
        "INGEST_RUN_BOUNDARY_VIOLATION",
        "RECEIPT_SET_MANIFEST_SCHEMA_MISMATCH",
        "RUN_ID_MISMATCH",
        "PROFILE_MANIFEST_PIN_MISMATCH",
        "RECEIPT_FILE_MISSING",
        "RECEIPT_PARSE_ERROR",
        "PROTOCOL_BINDING_MISMATCH",
        "SUBJECT_REF_MANIFEST_MISMATCH",
        "SUBJECT_BINDING_MISMATCH",
        "CORPUS_MANIFEST_REF_MISMATCH",
        "RAW_CONTENT_PRESENT",
        "MISSING_REQUIRED_EXCLUSION",
        "UNIQUE_ARTIFACT_NOT_COVERED",
        "DUPLICATE_POSTURE_VIOLATION",
    ]

    missing = [code for code in expected_codes if f"`{code}`" not in registry]
    assert not missing, (
        "New failure codes absent from docs/FAILURE_CODES.md:\n"
        + "\n".join(missing)
    )


# ---------------------------------------------------------------------------
# 16. CLI subcommand integration
# ---------------------------------------------------------------------------

def test_cli_ingest_run_sequence_json_output(tmp_path):
    """CLI ingest-run-sequence subcommand produces JSON report from a tmp dir."""
    # Copy fixtures to tmp
    run_doc_path = tmp_path / "run_doc.json"
    run_doc_path.write_bytes((FIXTURE_ROOT / "run_doc.json").read_bytes())

    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_bytes((FIXTURE_ROOT / "manifest.json").read_bytes())

    receipts_dir = tmp_path / "receipts"
    receipts_dir.mkdir()
    for src in RECEIPTS_DIR.iterdir():
        if src.is_file():
            (receipts_dir / src.name).write_bytes(src.read_bytes())

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "arcs_verify.cli",
            "ingest-run-sequence",
            "--run-doc",
            str(run_doc_path),
            "--receipt-set-manifest",
            str(manifest_path),
            "--receipts-dir",
            str(receipts_dir),
            "--profile-manifest",
            str(PROFILE_MANIFEST_PATH),
            "--json",
        ],
        capture_output=True,
        text=True,
        cwd=str(tmp_path),
        env=_CLI_ENV,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    data = json.loads(result.stdout)
    assert data["passed"] is True
    assert data["schema"] == SEQUENCE_SCHEMA


def test_cli_ingest_run_sequence_text_output(tmp_path):
    """CLI text output includes passed: true for a valid sequence."""
    run_doc_path = tmp_path / "run_doc.json"
    run_doc_path.write_bytes((FIXTURE_ROOT / "run_doc.json").read_bytes())

    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_bytes((FIXTURE_ROOT / "manifest.json").read_bytes())

    receipts_dir = tmp_path / "receipts"
    receipts_dir.mkdir()
    for src in RECEIPTS_DIR.iterdir():
        if src.is_file():
            (receipts_dir / src.name).write_bytes(src.read_bytes())

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "arcs_verify.cli",
            "ingest-run-sequence",
            "--run-doc",
            str(run_doc_path),
            "--receipt-set-manifest",
            str(manifest_path),
            "--receipts-dir",
            str(receipts_dir),
            "--profile-manifest",
            str(PROFILE_MANIFEST_PATH),
        ],
        capture_output=True,
        text=True,
        cwd=str(tmp_path),
        env=_CLI_ENV,
    )
    assert result.returncode == 0, result.stderr
    assert "passed: true" in result.stdout


def test_cli_returns_exit_1_for_failed_sequence(tmp_path):
    """CLI returns exit code 1 for a sequence that fails verification."""
    run_doc = load_run_doc()
    run_doc["schema"] = "wrong.schema"

    run_doc_path = tmp_path / "run_doc.json"
    run_doc_path.write_text(json.dumps(run_doc), encoding="utf-8")

    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_bytes((FIXTURE_ROOT / "manifest.json").read_bytes())

    receipts_dir = tmp_path / "receipts"
    receipts_dir.mkdir()
    for src in RECEIPTS_DIR.iterdir():
        if src.is_file():
            (receipts_dir / src.name).write_bytes(src.read_bytes())

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "arcs_verify.cli",
            "ingest-run-sequence",
            "--run-doc",
            str(run_doc_path),
            "--receipt-set-manifest",
            str(manifest_path),
            "--receipts-dir",
            str(receipts_dir),
            "--profile-manifest",
            str(PROFILE_MANIFEST_PATH),
        ],
        capture_output=True,
        text=True,
        cwd=str(tmp_path),
        env=_CLI_ENV,
    )
    assert result.returncode == 1


def test_cli_returns_exit_2_for_missing_input(tmp_path):
    """CLI returns exit code 2 when a required input file is missing."""
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "arcs_verify.cli",
            "ingest-run-sequence",
            "--run-doc",
            str(tmp_path / "nonexistent.json"),
            "--receipt-set-manifest",
            str(tmp_path / "manifest.json"),
            "--receipts-dir",
            str(tmp_path),
            "--profile-manifest",
            str(PROFILE_MANIFEST_PATH),
        ],
        capture_output=True,
        text=True,
        cwd=str(tmp_path),
        env=_CLI_ENV,
    )
    assert result.returncode == 2


# ---------------------------------------------------------------------------
# 17. Limitations must be present and non-empty
# ---------------------------------------------------------------------------

def test_report_includes_limitations(tmp_path):
    run_doc = load_run_doc()
    manifest = load_manifest()
    report = verify_from_dicts(run_doc, manifest, tmp_path=tmp_path)
    data = report.to_dict()

    assert "limitations" in data
    limitations = data["limitations"]
    assert isinstance(limitations, list)
    assert len(limitations) >= 3
    text = " ".join(limitations).lower()
    assert "not_evaluated" in text or "not evaluated" in text


# ---------------------------------------------------------------------------
# 18. Manifest schema wrong → RECEIPT_SET_MANIFEST_SCHEMA_MISMATCH
# ---------------------------------------------------------------------------

def test_wrong_manifest_schema(tmp_path):
    run_doc = load_run_doc()
    manifest = load_manifest()
    manifest["schema"] = "dagr-ingest.wrong.v0.1"
    report = verify_from_dicts(run_doc, manifest, tmp_path=tmp_path)

    assert report.receipt_set_manifest_schema is Conclusion.FALSE
    assert report.passed is False
    codes = [f.code for f in report.findings]
    assert "RECEIPT_SET_MANIFEST_SCHEMA_MISMATCH" in codes
