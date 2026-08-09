"""Tests for arcs_verify.ingest_run_sequence — dagr.ingest_run.v0.1 sequence verifier.

The fixtures in tests/fixtures/ingest_run_sequence/ are GENUINE real-tool output:
  - run_doc.json      : `dagr-ingest run scan` output (dagr.ingest_run.v0.1)
  - manifest.json     : `dagr-ingest srs emit-editorial` receipt-set manifest
                        (dagr-ingest.srs-receipt-set-manifest.v0.1)
  - receipts/<id>.json: the `srs emit-editorial` publication_ingest receipt
  - profile.manifest.json : the arcs-srs production
                        srs.editorial.publication_ingest.v0.1 profile manifest
                        (sha256 ec3871e4…), the production authority

They were produced by driving merged dagr-ingest (a83ef96) over the merged #9
"valid Counterpedia content specimen" (plus a byte-identical duplicate and an
unrecognized JSON blob), so the fixture exercises the emitted / skipped_duplicate
/ profile_not_applicable / incomplete postures at once. No fixture is
hand-authored.

Tests verify that:
- The genuine DAGR output passes the reconciled sequence verifier.
- Each independent mutation is rejected with the intended finding code.
- Producer packages (dagr_ingest, garp_ingest) are not importable and are
  never imported by the verifier module.
- NOT_EVALUATED is preserved and not promoted to PASS.
- CWD-independent CLI path works.
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
    EXPECTED_PROFILE_MANIFEST_SHA256,
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

# Identity of the single emitted receipt in the genuine fixture.
REAL_RECEIPT_ID = "dagr-ingest-pub-ingest-134ecb40cb8b73f4"
REAL_RECEIPT_FILE = f"{REAL_RECEIPT_ID}.json"
REAL_SUBJECT = (
    "sha256:134ecb40cb8b73f4f26f63c0956103bd7236cd8c5da40127ff6e0c27b77ac9bf"
)

# Ensure subprocess calls use the worktree source rather than any installed
# version of arcs-verify that may not yet include this lane's code.
_CLI_ENV = {**os.environ, "PYTHONPATH": str(ROOT)}


def load_run_doc() -> dict:
    return json.loads((FIXTURE_ROOT / "run_doc.json").read_text(encoding="utf-8"))


def load_manifest() -> dict:
    return json.loads((FIXTURE_ROOT / "manifest.json").read_text(encoding="utf-8"))


def load_receipt() -> dict:
    return json.loads((RECEIPTS_DIR / REAL_RECEIPT_FILE).read_text(encoding="utf-8"))


def _write_tmp(tmp: Path, name: str, content: dict) -> Path:
    p = tmp / name
    p.write_text(json.dumps(content, indent=2), encoding="utf-8")
    return p


def verify_from_dicts(
    run_doc: dict,
    manifest: dict,
    *,
    tmp_path: Path,
    receipt_overrides: dict[str, dict] | None = None,
    profile_manifest_path: Path | None = None,
) -> IngestRunSequenceReport:
    """Write dicts to temp files and run the verifier.

    Copies the genuine fixture receipts into a tmp receipts dir; ``receipt_overrides``
    maps a receipt filename to a dict written after the copy (to mutate or add
    a receipt).
    """
    run_doc_path = _write_tmp(tmp_path, "run_doc.json", run_doc)
    manifest_path = _write_tmp(tmp_path, "manifest.json", manifest)
    receipts_dir = tmp_path / "receipts"
    receipts_dir.mkdir(exist_ok=True)

    for src in RECEIPTS_DIR.iterdir():
        if src.is_file() and src.suffix == ".json":
            (receipts_dir / src.name).write_bytes(src.read_bytes())

    if receipt_overrides:
        for fname, content in receipt_overrides.items():
            _write_tmp(receipts_dir, fname, content)

    return verify_ingest_run_sequence(
        run_doc_path=run_doc_path,
        receipt_set_manifest_path=manifest_path,
        receipts_dir=receipts_dir,
        profile_manifest_path=profile_manifest_path or PROFILE_MANIFEST_PATH,
    )


# ---------------------------------------------------------------------------
# Acceptance gate: producer independence
# ---------------------------------------------------------------------------

def test_producer_packages_absent():
    """dagr_ingest must not be importable in the verifier environment."""
    assert importlib.util.find_spec("dagr_ingest") is None, (
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
        assert "dagr_ingest" not in line, f"imports dagr_ingest: {line!r}"
        assert "garp_ingest" not in line, f"imports garp_ingest: {line!r}"


# ---------------------------------------------------------------------------
# Fixture provenance: the vendored bytes are the real production shapes
# ---------------------------------------------------------------------------

def test_profile_manifest_is_production_authority():
    """The vendored profile manifest is the arcs-srs production manifest."""
    actual = hashlib.sha256(PROFILE_MANIFEST_PATH.read_bytes()).hexdigest()
    assert actual == EXPECTED_PROFILE_MANIFEST_SHA256


def test_manifest_uses_real_producer_schema():
    manifest = load_manifest()
    assert manifest["schema"] == RECEIPT_SET_MANIFEST_SCHEMA
    assert manifest["schema"] == "dagr-ingest.srs-receipt-set-manifest.v0.1"
    # Real producer artifact shape: emitted_receipts objects + rel_path skip lists.
    assert isinstance(manifest["emitted_receipts"], list)
    entry = manifest["emitted_receipts"][0]
    assert set(entry) >= {"receipt_id", "subject_ref", "rel_path", "output_path", "incomplete"}
    for key in ("skipped_duplicate", "skipped_no_parser", "profile_not_applicable"):
        assert isinstance(manifest[key], list)


def test_run_doc_unique_artifacts_lack_producer_fields():
    """Real dagr.ingest_run.v0.1: unique_artifacts carry no parser_id / subject /
    is_duplicate_content; those live on file_occurrences."""
    run_doc = load_run_doc()
    assert isinstance(run_doc["file_occurrences"], list)
    for ua in run_doc["unique_artifacts"]:
        assert "parser_id" not in ua
        assert "subject" not in ua
        assert "is_duplicate_content" not in ua
    # file_occurrences carry the producer fields coverage operates on.
    occ = run_doc["file_occurrences"][0]
    assert {"rel_path", "content_hash", "source_type", "is_duplicate_content", "parser_id"} <= set(occ)


# ---------------------------------------------------------------------------
# 1. The genuine DAGR output passes the reconciled verifier
# ---------------------------------------------------------------------------

def test_valid_sequence_passes(tmp_path):
    run_doc = load_run_doc()
    manifest = load_manifest()
    report = verify_from_dicts(run_doc, manifest, tmp_path=tmp_path)
    c = report.to_dict()["conclusions"]

    for name in (
        "run_doc_schema",
        "boundary_declarations",
        "receipt_set_manifest_schema",
        "run_id_linkage",
        "profile_manifest_pin",
        "profile_manifest_authority",
        "receipt_file_present",
        "receipt_parse",
        "protocol_binding",
        "receipt_id_binding",
        "subject_ref_manifest",
        "subject_binding",
        "rel_path_binding",
        "corpus_manifest_ref",
        "raw_content_absent",
        "artifact_classes_excluded",
        "occurrence_accounting",
        "duplicate_posture",
        "null_parser_posture",
    ):
        assert c[name] == "true", (name, report.findings)
    assert report.passed is True, report.findings


def test_valid_sequence_replay_on_vendored_fixture_dir():
    """Replay the verifier directly on the vendored fixture directory (no tmp
    copy, no mutation) — the real dagr-ingest -> arcs-verify path."""
    report = verify_ingest_run_sequence(
        run_doc_path=FIXTURE_ROOT / "run_doc.json",
        receipt_set_manifest_path=FIXTURE_ROOT / "manifest.json",
        receipts_dir=RECEIPTS_DIR,
        profile_manifest_path=PROFILE_MANIFEST_PATH,
    )
    assert report.passed is True, report.findings


def test_valid_sequence_report_schema_fields(tmp_path):
    report = verify_from_dicts(load_run_doc(), load_manifest(), tmp_path=tmp_path)
    data = report.to_dict()
    assert data["schema"] == SEQUENCE_SCHEMA
    assert data["verification_profile"] == SEQUENCE_PROFILE
    assert {"conclusions", "findings", "passed", "limitations"} <= set(data)


def test_output_path_absolute_is_not_trusted(tmp_path):
    """The manifest's output_path points at a generation-time absolute dir that
    does not exist here; resolution by receipt_id under receipts_dir still
    succeeds."""
    manifest = load_manifest()
    assert manifest["emitted_receipts"][0]["output_path"].startswith("/")
    report = verify_from_dicts(load_run_doc(), manifest, tmp_path=tmp_path)
    assert report.receipt_file_present is Conclusion.TRUE
    assert report.passed is True, report.findings


def test_not_evaluated_is_not_promoted_to_pass():
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        receipts_dir = tmp / "receipts"
        receipts_dir.mkdir()
        report = verify_ingest_run_sequence(
            run_doc_path=tmp / "missing_run_doc.json",
            receipt_set_manifest_path=tmp / "missing_manifest.json",
            receipts_dir=receipts_dir,
            profile_manifest_path=PROFILE_MANIFEST_PATH,
        )
        assert report.passed is False
        assert report.to_dict()["passed"] is False


# ---------------------------------------------------------------------------
# Permanent negatives
# ---------------------------------------------------------------------------

def _codes(report: IngestRunSequenceReport) -> list[str]:
    return [f.code for f in report.findings]


def test_wrong_run_doc_schema(tmp_path):
    run_doc = load_run_doc()
    run_doc["schema"] = "dagr.ingest_run.v999.0"
    report = verify_from_dicts(run_doc, load_manifest(), tmp_path=tmp_path)
    assert report.run_doc_schema is Conclusion.FALSE
    assert report.passed is False
    assert "INGEST_RUN_SCHEMA_MISMATCH" in _codes(report)


@pytest.mark.parametrize("key", ["no_arcs_srs", "no_receipts_issued", "no_network"])
def test_boundary_declaration_false(tmp_path, key):
    run_doc = load_run_doc()
    run_doc["boundary"][key] = False
    report = verify_from_dicts(run_doc, load_manifest(), tmp_path=tmp_path)
    assert report.boundary_declarations is Conclusion.FALSE
    assert report.passed is False
    assert "INGEST_RUN_BOUNDARY_VIOLATION" in _codes(report)


def test_boundary_absent(tmp_path):
    run_doc = load_run_doc()
    del run_doc["boundary"]
    report = verify_from_dicts(run_doc, load_manifest(), tmp_path=tmp_path)
    assert report.boundary_declarations is Conclusion.FALSE
    assert "INGEST_RUN_BOUNDARY_VIOLATION" in _codes(report)


def test_wrong_manifest_schema(tmp_path):
    manifest = load_manifest()
    manifest["schema"] = "dagr-ingest.srs-receipt-set.v0.1"  # the old invented shape
    report = verify_from_dicts(load_run_doc(), manifest, tmp_path=tmp_path)
    assert report.receipt_set_manifest_schema is Conclusion.FALSE
    assert report.passed is False
    assert "RECEIPT_SET_MANIFEST_SCHEMA_MISMATCH" in _codes(report)


def test_emitted_receipts_absent(tmp_path):
    manifest = load_manifest()
    del manifest["emitted_receipts"]
    report = verify_from_dicts(load_run_doc(), manifest, tmp_path=tmp_path)
    assert report.receipt_set_manifest_schema is Conclusion.FALSE
    assert "RECEIPT_SET_MANIFEST_SCHEMA_MISMATCH" in _codes(report)


def test_run_id_mismatch(tmp_path):
    manifest = load_manifest()
    manifest["run_id"] = "sha256:" + "0" * 64
    report = verify_from_dicts(load_run_doc(), manifest, tmp_path=tmp_path)
    assert report.run_id_linkage is Conclusion.FALSE
    assert report.passed is False
    assert "RUN_ID_MISMATCH" in _codes(report)


def test_profile_manifest_pin_mismatch(tmp_path):
    """Declared digest does not match the recomputed sha256 of the supplied
    profile-manifest bytes — pin integrity fails."""
    manifest = load_manifest()
    manifest["profile_manifest_sha256"] = "0" * 64
    report = verify_from_dicts(load_run_doc(), manifest, tmp_path=tmp_path)
    assert report.profile_manifest_pin is Conclusion.FALSE
    assert report.passed is False
    assert "PROFILE_MANIFEST_PIN_MISMATCH" in _codes(report)


def test_profile_manifest_authority_mismatch(tmp_path):
    """A self-consistent manifest+profile pair that pins a NON-production
    manifest still fails the production-authority check. This is the negative
    that rejects the arcs-verify test-only profile manifest as an authority."""
    # A stand-in non-production profile manifest with its own self-consistent pin.
    non_prod = tmp_path / "non_production.profile.manifest.json"
    non_prod.write_text(
        json.dumps({"profile_slug": "srs.editorial.publication_ingest.v0.1",
                    "note": "not a production manifest"}),
        encoding="utf-8",
    )
    non_prod_sha = hashlib.sha256(non_prod.read_bytes()).hexdigest()
    assert non_prod_sha != EXPECTED_PROFILE_MANIFEST_SHA256

    manifest = load_manifest()
    manifest["profile_manifest_sha256"] = non_prod_sha
    report = verify_from_dicts(
        load_run_doc(), manifest, tmp_path=tmp_path, profile_manifest_path=non_prod
    )
    # Pin integrity holds (declared == recomputed), production authority fails.
    assert report.profile_manifest_pin is Conclusion.TRUE
    assert report.profile_manifest_authority is Conclusion.FALSE
    assert report.passed is False
    assert "PROFILE_MANIFEST_AUTHORITY_MISMATCH" in _codes(report)


def test_receipt_file_missing(tmp_path):
    manifest = load_manifest()
    manifest["emitted_receipts"][0]["receipt_id"] = "does-not-exist-id"
    report = verify_from_dicts(load_run_doc(), manifest, tmp_path=tmp_path)
    assert report.receipt_file_present is Conclusion.FALSE
    assert report.passed is False
    assert "RECEIPT_FILE_MISSING" in _codes(report)


def test_protocol_binding_mismatch(tmp_path):
    receipt = load_receipt()
    receipt["protocol_binding"] = "dagr-mcp/v0.1"
    report = verify_from_dicts(
        load_run_doc(), load_manifest(), tmp_path=tmp_path,
        receipt_overrides={REAL_RECEIPT_FILE: receipt},
    )
    assert report.protocol_binding is Conclusion.FALSE
    assert report.passed is False
    assert "PROTOCOL_BINDING_MISMATCH" in _codes(report)


def test_receipt_id_mismatch(tmp_path):
    """The resolved receipt file declares a different receipt_id than the
    manifest entry (a substituted receipt body)."""
    receipt = load_receipt()
    receipt["receipt_id"] = "dagr-ingest-pub-ingest-deadbeefdeadbeef"
    report = verify_from_dicts(
        load_run_doc(), load_manifest(), tmp_path=tmp_path,
        receipt_overrides={REAL_RECEIPT_FILE: receipt},
    )
    assert report.receipt_id_binding is Conclusion.FALSE
    assert report.passed is False
    assert "RECEIPT_ID_MISMATCH" in _codes(report)


def test_subject_ref_manifest_mismatch(tmp_path):
    manifest = load_manifest()
    manifest["emitted_receipts"][0]["subject_ref"] = "sha256:" + "f" * 64
    report = verify_from_dicts(load_run_doc(), manifest, tmp_path=tmp_path)
    assert report.subject_ref_manifest is Conclusion.FALSE
    assert report.passed is False
    assert "SUBJECT_REF_MANIFEST_MISMATCH" in _codes(report)


def test_subject_binding_mismatch(tmp_path):
    receipt = load_receipt()
    receipt["publication_artifact_id"] = "sha256:" + "a" * 64
    report = verify_from_dicts(
        load_run_doc(), load_manifest(), tmp_path=tmp_path,
        receipt_overrides={REAL_RECEIPT_FILE: receipt},
    )
    assert report.subject_binding is Conclusion.FALSE
    assert report.passed is False
    assert "SUBJECT_BINDING_MISMATCH" in _codes(report)


def test_rel_path_mismatch(tmp_path):
    manifest = load_manifest()
    manifest["emitted_receipts"][0]["rel_path"] = "publications/elsewhere.json"
    report = verify_from_dicts(load_run_doc(), manifest, tmp_path=tmp_path)
    assert report.rel_path_binding is Conclusion.FALSE
    assert report.passed is False
    assert "REL_PATH_MISMATCH" in _codes(report)


def test_corpus_manifest_ref_mismatch(tmp_path):
    receipt = load_receipt()
    receipt["corpus_manifest_ref"] = "sha256:" + "b" * 64
    report = verify_from_dicts(
        load_run_doc(), load_manifest(), tmp_path=tmp_path,
        receipt_overrides={REAL_RECEIPT_FILE: receipt},
    )
    assert report.corpus_manifest_ref is Conclusion.FALSE
    assert report.passed is False
    assert "CORPUS_MANIFEST_REF_MISMATCH" in _codes(report)


@pytest.mark.parametrize("raw_field", ["raw_publication_bytes", "raw_frontmatter_yaml", "raw_body_text"])
def test_raw_content_present(tmp_path, raw_field):
    receipt = load_receipt()
    receipt[raw_field] = "content that must never appear in a receipt"
    report = verify_from_dicts(
        load_run_doc(), load_manifest(), tmp_path=tmp_path,
        receipt_overrides={REAL_RECEIPT_FILE: receipt},
    )
    assert report.raw_content_absent is Conclusion.FALSE
    assert report.passed is False
    assert "RAW_CONTENT_PRESENT" in _codes(report)


def test_missing_required_exclusion(tmp_path):
    receipt = load_receipt()
    receipt["artifact_classes_excluded"] = ["raw_frontmatter_yaml", "raw_body_text"]
    report = verify_from_dicts(
        load_run_doc(), load_manifest(), tmp_path=tmp_path,
        receipt_overrides={REAL_RECEIPT_FILE: receipt},
    )
    assert report.artifact_classes_excluded is Conclusion.FALSE
    assert report.passed is False
    assert "MISSING_REQUIRED_EXCLUSION" in _codes(report)


def test_omitted_eligible_occurrence(tmp_path):
    """Drop the emitted receipt entry without moving its occurrence to any skip
    list: the emitted-eligible occurrence is now unaccounted for."""
    manifest = load_manifest()
    manifest["emitted_receipts"] = []
    manifest["incomplete_receipt_ids"] = []
    report = verify_from_dicts(load_run_doc(), manifest, tmp_path=tmp_path)
    assert report.occurrence_accounting is Conclusion.FALSE
    assert report.passed is False
    assert "OCCURRENCE_NOT_ACCOUNTED" in _codes(report)


def test_emitted_duplicate_occurrence(tmp_path):
    """A duplicate-content occurrence (article.json) appears as emitted."""
    manifest = load_manifest()
    # Remove it from skipped_duplicate and emit it instead.
    manifest["skipped_duplicate"] = [
        p for p in manifest["skipped_duplicate"] if p != "article.json"
    ]
    manifest["emitted_receipts"].append({
        "receipt_id": REAL_RECEIPT_ID,
        "subject_ref": REAL_SUBJECT,
        "rel_path": "article.json",
        "output_path": "/generation/time/path/ignored.json",
        "incomplete": True,
    })
    report = verify_from_dicts(load_run_doc(), manifest, tmp_path=tmp_path)
    assert report.duplicate_posture is Conclusion.FALSE
    assert report.passed is False
    assert "DUPLICATE_POSTURE_VIOLATION" in _codes(report)


def test_emitted_null_parser_occurrence(tmp_path):
    """A null-parser occurrence (arbitrary.json) appears as emitted."""
    manifest = load_manifest()
    manifest["profile_not_applicable"] = [
        p for p in manifest["profile_not_applicable"] if p != "arbitrary.json"
    ]
    manifest["emitted_receipts"].append({
        "receipt_id": REAL_RECEIPT_ID,
        "subject_ref": REAL_SUBJECT,
        "rel_path": "arbitrary.json",
        "output_path": "/generation/time/path/ignored.json",
        "incomplete": True,
    })
    report = verify_from_dicts(load_run_doc(), manifest, tmp_path=tmp_path)
    assert report.null_parser_posture is Conclusion.FALSE
    assert report.passed is False
    assert "NULL_PARSER_POSTURE_VIOLATION" in _codes(report)


def test_malformed_skip_category(tmp_path):
    manifest = load_manifest()
    manifest["skipped_duplicate"] = "article.json"  # a string, not a list
    report = verify_from_dicts(load_run_doc(), manifest, tmp_path=tmp_path)
    assert report.occurrence_accounting is Conclusion.FALSE
    assert report.passed is False
    assert "SKIP_CATEGORY_MALFORMED" in _codes(report)


def test_receipt_substitution(tmp_path):
    """Overwrite the resolved receipt file with a foreign receipt (different
    subject and id). Substitution is caught by the receipt/manifest bindings."""
    foreign = load_receipt()
    other = "sha256:" + "e" * 64
    foreign["receipt_id"] = "dagr-ingest-pub-ingest-eeeeeeeeeeeeeeee"
    foreign["subject_ref"] = other
    foreign["publication_artifact_id"] = other
    report = verify_from_dicts(
        load_run_doc(), load_manifest(), tmp_path=tmp_path,
        receipt_overrides={REAL_RECEIPT_FILE: foreign},
    )
    assert report.passed is False
    codes = _codes(report)
    assert "RECEIPT_ID_MISMATCH" in codes
    assert "SUBJECT_REF_MANIFEST_MISMATCH" in codes


def test_occurrence_coverage_not_evaluated_when_absent(tmp_path):
    run_doc = load_run_doc()
    del run_doc["file_occurrences"]
    report = verify_from_dicts(run_doc, load_manifest(), tmp_path=tmp_path)
    assert report.occurrence_accounting is Conclusion.NOT_EVALUATED
    assert report.duplicate_posture is Conclusion.NOT_EVALUATED
    assert report.null_parser_posture is Conclusion.NOT_EVALUATED


# ---------------------------------------------------------------------------
# Failure-code registry coverage
# ---------------------------------------------------------------------------

def test_all_new_failure_codes_in_registry():
    registry = (ROOT / "docs" / "FAILURE_CODES.md").read_text(encoding="utf-8")
    expected_codes = [
        "INGEST_RUN_SCHEMA_MISMATCH",
        "INGEST_RUN_BOUNDARY_VIOLATION",
        "RECEIPT_SET_MANIFEST_SCHEMA_MISMATCH",
        "RUN_ID_MISMATCH",
        "PROFILE_MANIFEST_PIN_MISMATCH",
        "PROFILE_MANIFEST_AUTHORITY_MISMATCH",
        "RECEIPT_FILE_MISSING",
        "RECEIPT_PARSE_ERROR",
        "PROTOCOL_BINDING_MISMATCH",
        "RECEIPT_ID_MISMATCH",
        "SUBJECT_REF_MANIFEST_MISMATCH",
        "SUBJECT_BINDING_MISMATCH",
        "REL_PATH_MISMATCH",
        "CORPUS_MANIFEST_REF_MISMATCH",
        "RAW_CONTENT_PRESENT",
        "MISSING_REQUIRED_EXCLUSION",
        "OCCURRENCE_NOT_ACCOUNTED",
        "SKIP_CATEGORY_MALFORMED",
        "DUPLICATE_POSTURE_VIOLATION",
        "NULL_PARSER_POSTURE_VIOLATION",
    ]
    missing = [code for code in expected_codes if f"`{code}`" not in registry]
    assert not missing, "codes absent from docs/FAILURE_CODES.md:\n" + "\n".join(missing)


# ---------------------------------------------------------------------------
# CLI subcommand integration (CWD-independent)
# ---------------------------------------------------------------------------

def _copy_fixtures_to(tmp_path: Path) -> tuple[Path, Path, Path]:
    run_doc_path = tmp_path / "run_doc.json"
    run_doc_path.write_bytes((FIXTURE_ROOT / "run_doc.json").read_bytes())
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_bytes((FIXTURE_ROOT / "manifest.json").read_bytes())
    receipts_dir = tmp_path / "receipts"
    receipts_dir.mkdir()
    for src in RECEIPTS_DIR.iterdir():
        if src.is_file():
            (receipts_dir / src.name).write_bytes(src.read_bytes())
    return run_doc_path, manifest_path, receipts_dir


def _run_cli(run_doc_path, manifest_path, receipts_dir, tmp_path, *extra):
    return subprocess.run(
        [
            sys.executable, "-m", "arcs_verify.cli", "ingest-run-sequence",
            "--run-doc", str(run_doc_path),
            "--receipt-set-manifest", str(manifest_path),
            "--receipts-dir", str(receipts_dir),
            "--profile-manifest", str(PROFILE_MANIFEST_PATH),
            *extra,
        ],
        capture_output=True, text=True, cwd=str(tmp_path), env=_CLI_ENV,
    )


def test_cli_json_output_pass(tmp_path):
    run_doc_path, manifest_path, receipts_dir = _copy_fixtures_to(tmp_path)
    result = _run_cli(run_doc_path, manifest_path, receipts_dir, tmp_path, "--json")
    assert result.returncode == 0, result.stderr + result.stdout
    data = json.loads(result.stdout)
    assert data["passed"] is True
    assert data["schema"] == SEQUENCE_SCHEMA


def test_cli_text_output_pass(tmp_path):
    run_doc_path, manifest_path, receipts_dir = _copy_fixtures_to(tmp_path)
    result = _run_cli(run_doc_path, manifest_path, receipts_dir, tmp_path)
    assert result.returncode == 0, result.stderr
    assert "passed: true" in result.stdout


def test_cli_returns_exit_1_for_failed_sequence(tmp_path):
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
    result = _run_cli(run_doc_path, manifest_path, receipts_dir, tmp_path)
    assert result.returncode == 1


def test_cli_returns_exit_2_for_missing_input(tmp_path):
    result = _run_cli(
        tmp_path / "nonexistent.json", tmp_path / "manifest.json", tmp_path, tmp_path
    )
    assert result.returncode == 2


# ---------------------------------------------------------------------------
# Limitations
# ---------------------------------------------------------------------------

def test_report_includes_limitations(tmp_path):
    report = verify_from_dicts(load_run_doc(), load_manifest(), tmp_path=tmp_path)
    limitations = report.to_dict()["limitations"]
    assert isinstance(limitations, list)
    assert len(limitations) >= 3
    text = " ".join(limitations).lower()
    assert "not_evaluated" in text or "not evaluated" in text
