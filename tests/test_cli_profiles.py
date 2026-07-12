from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from arcs_verify.cli import main

ROOT = Path(__file__).resolve().parents[1]
PACK = ROOT / "packs" / "amnesiac.heppner_public_proof" / "v0.1"
VECTORS = ROOT / "vendor" / "arcs-srs" / "vectors" / "signed-receipt-v0.1"
SCHEMA = ROOT / "vendor" / "arcs-srs" / "schemas" / "srs-envelope" / "v0.2.0" / "srs-envelope.schema.json"


def test_existing_srs_cli_shape_remains_default(capsys) -> None:
    code = main([
        str(VECTORS / "valid" / "admission-admitted.json"),
        "--keyring",
        str(VECTORS / "trust" / "issuer-keys.json"),
        "--profile",
        "srs.mcp.sdk_enforcement.v0.1",
        "--schema",
        str(SCHEMA),
        "--json",
    ])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["passed"] is True
    assert payload["signature_valid"] is True


def test_amnesiac_chain_subcommand_verifies_real_revised_stage(capsys) -> None:
    code = main([
        "amnesiac-chain",
        str(PACK / "producer" / "proof_bundle.json"),
        "--stage",
        "revised",
    ])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["passed"] is True
    assert payload["report_hash"] == "sha256:80c18726679e72c53bd13e0b56bc36f98fa21d0f6ad4a5da929746f7cb315fcf"
    assert payload["conclusions"]["authenticity_verified"] == "not_evaluated"


def test_amnesiac_chain_cli_returns_input_error_for_missing_bundle(capsys) -> None:
    code = main(["amnesiac-chain", str(PACK / "producer" / "missing.json")])
    assert code == 2
    assert "bundle not found" in capsys.readouterr().err


def test_amnesiac_chain_cli_returns_verification_failure_for_tamper(
    tmp_path, capsys
) -> None:
    payload = json.loads((PACK / "producer" / "proof_bundle.json").read_text())
    payload["revised"]["claim_graph"]["nodes"][0]["normalized_text"] = "tampered"
    path = tmp_path / "tampered.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    code = main(["amnesiac-chain", str(path), "--stage", "revised"])
    assert code == 1
    report = json.loads(capsys.readouterr().out)
    assert report["passed"] is False


def test_amnesiac_profile_module_execution_runs_cli() -> None:
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "arcs_verify.amnesiac.cli",
            str(PACK / "producer" / "proof_bundle.json"),
            "--stage",
            "initial",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["passed"] is True
    assert payload["report_hash"] == (
        "sha256:1ee1fccd38c53678aeee15363e0579cee19a0a19c8455afe2d385b0f3a18a3a2"
    )


def test_amnesiac_profile_module_execution_propagates_failure(tmp_path) -> None:
    payload = json.loads((PACK / "producer" / "proof_bundle.json").read_text())
    payload["initial"]["claim_graph"]["nodes"][0]["normalized_text"] = "tampered"
    path = tmp_path / "tampered.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, "-m", "arcs_verify.amnesiac.cli", str(path), "--stage", "initial"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 1, proc.stderr
    report = json.loads(proc.stdout)
    assert report["passed"] is False
    assert "claim_node_hash_mismatch" in {item["code"] for item in report["findings"]}
