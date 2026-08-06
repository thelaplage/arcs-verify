"""The two committed report schemas must describe the live CLI output.

Generates both documented reports by running the CLI in-process and validates
them against the committed schemas, so schema drift fails in CI rather than
being caught (or missed) by hand.
"""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema

from arcs_verify.cli import main

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "docs" / "schemas"
PACKS = ROOT / "packs"


def _validate(instance: dict, schema_file: str) -> None:
    schema = json.loads((SCHEMAS / schema_file).read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(instance)


def test_signed_srs_json_report_matches_committed_schema(capsys) -> None:
    code = main(
        [
            str(
                PACKS
                / "srs.mcp.sdk_enforcement"
                / "v0.1"
                / "normative"
                / "valid"
                / "admission-admitted.json"
            ),
            "--keyring",
            str(
                PACKS
                / "srs.mcp.sdk_enforcement"
                / "v0.1"
                / "normative"
                / "trust"
                / "issuer-keys.json"
            ),
            "--profile",
            "srs.mcp.sdk_enforcement.v0.1",
            "--json",
        ]
    )
    assert code == 0
    _validate(json.loads(capsys.readouterr().out), "signed-srs-report-v0.1.schema.json")


def test_amnesiac_chain_report_matches_committed_schema(capsys) -> None:
    code = main(
        [
            "amnesiac-chain",
            str(PACKS / "amnesiac.heppner_public_proof" / "v0.1" / "producer" / "proof_bundle.json"),
            "--stage",
            "revised",
        ]
    )
    assert code == 0
    _validate(
        json.loads(capsys.readouterr().out),
        "amnesiac-chain-report-v0.1.1.schema.json",
    )
