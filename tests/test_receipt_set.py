"""Workflow receipt-set verifier."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

if importlib.util.find_spec("rfc8785") is None:
    spec = importlib.util.spec_from_file_location(
        "receipt_set_standalone", ROOT / "arcs_verify" / "receipt_set.py"
    )
    assert spec is not None and spec.loader is not None
    receipt_set_module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = receipt_set_module
    spec.loader.exec_module(receipt_set_module)
else:
    from arcs_verify import receipt_set as receipt_set_module

_safe_relative = receipt_set_module._safe_relative
FIXTURE = ROOT / "packs" / "srs.mcp.sdk_enforcement" / "v0.1" / "implementation" / "dagr-mcp-fastmcp-demo"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _workflow(tmp_path: Path) -> Path:
    for name in (
        "admission-admitted.json",
        "outcome-result-returned.json",
        "issuer-keys.json",
    ):
        shutil.copy2(FIXTURE / name, tmp_path / name)
    payload = {
        "schema": "dagr.amnesiac.governed_memory_demo.v0.1",
        "service_mode": "native",
        "profile": "srs.mcp.sdk_enforcement.v0.1",
        "receipt_set": [
            {"path": name, "sha256": _sha(tmp_path / name)}
            for name in ("admission-admitted.json", "outcome-result-returned.json")
        ],
        "trust_bundle": {
            "path": "issuer-keys.json",
            "sha256": _sha(tmp_path / "issuer-keys.json"),
        },
    }
    path = tmp_path / "governed-memory-workflow.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_safe_relative_refuses_escape_and_absolute_paths(tmp_path: Path):
    for value in ("../receipt.json", "/tmp/receipt.json", "a/../receipt.json", "./x"):
        with pytest.raises(ValueError):
            _safe_relative(tmp_path, value)


def test_safe_relative_accepts_nested_artifact(tmp_path: Path):
    assert _safe_relative(tmp_path, "receipts/a.json") == (tmp_path / "receipts/a.json").resolve()


@pytest.mark.skipif(
    importlib.util.find_spec("rfc8785") is None,
    reason="runtime verifier dependencies are not installed",
)
def test_valid_receipt_set_passes_and_links_outcome(tmp_path: Path):
    report = receipt_set_module.verify_receipt_set(_workflow(tmp_path))
    assert report.passed is True
    assert report.manifest_integrity is True
    assert report.receipt_linkage_valid is True
    assert len(report.receipt_reports) == 2

    admission_report = next(
        item
        for item in report.receipt_reports
        if item["receipt_kind"] == "admission"
    )
    outcome_report = next(
        item
        for item in report.receipt_reports
        if item["receipt_kind"] == "outcome"
    )

    assert admission_report["requested_tool_name"] == "records_lookup"
    assert outcome_report["requested_tool_name"] is None


@pytest.mark.skipif(
    importlib.util.find_spec("rfc8785") is None,
    reason="runtime verifier dependencies are not installed",
)
def test_digest_mutation_fails_manifest_integrity(tmp_path: Path):
    workflow = _workflow(tmp_path)
    payload = json.loads(workflow.read_text())
    payload["receipt_set"][0]["sha256"] = "0" * 64
    workflow.write_text(json.dumps(payload))
    report = receipt_set_module.verify_receipt_set(workflow)
    assert report.passed is False
    assert report.manifest_integrity is False
    assert any(item["code"] == "receipt_integrity_failed" for item in report.findings)


@pytest.mark.skipif(
    importlib.util.find_spec("rfc8785") is None,
    reason="runtime verifier dependencies are not installed",
)
def test_unresolved_admission_link_fails_set(tmp_path: Path):
    workflow = _workflow(tmp_path)
    payload = json.loads(workflow.read_text())
    payload["receipt_set"] = [payload["receipt_set"][1]]
    workflow.write_text(json.dumps(payload))
    report = receipt_set_module.verify_receipt_set(workflow)
    assert report.passed is False
    assert report.receipt_linkage_valid is False
    assert any(item["code"] == "admission_receipt_unresolved" for item in report.findings)


@pytest.mark.skipif(
    importlib.util.find_spec("rfc8785") is None,
    reason="runtime verifier dependencies are not installed",
)
def test_logical_call_id_mismatch_fails_linkage(tmp_path: Path):
    workflow = _workflow(tmp_path)

    outcome_path = tmp_path / "outcome-result-returned.json"
    outcome = json.loads(outcome_path.read_text(encoding="utf-8"))
    outcome["logical_call_id"] = "call:dagr:different"
    outcome_path.write_text(json.dumps(outcome), encoding="utf-8")

    payload = json.loads(workflow.read_text(encoding="utf-8"))
    for entry in payload["receipt_set"]:
        if entry["path"] == outcome_path.name:
            entry["sha256"] = _sha(outcome_path)
    workflow.write_text(json.dumps(payload), encoding="utf-8")

    report = receipt_set_module.verify_receipt_set(workflow)

    assert report.passed is False
    assert report.receipt_linkage_valid is False
    assert any(
        item["code"] == "admission_outcome_linkage_mismatch"
        and "logical_call_id" in item["detail"]
        for item in report.findings
    )
