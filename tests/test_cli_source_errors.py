"""Source-integrity errors must exit 2, never 1, and never traceback.

External systems treat exit 1 as a negative verification finding. A missing
or unreadable input is not evidence that a receipt failed verification, so
the CLI maps every source problem to exit 2 with a stable message.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from arcs_verify.cli import main

ROOT = Path(__file__).resolve().parents[1]
VALID_RECEIPT = (
    ROOT
    / "packs"
    / "srs.mcp.sdk_enforcement"
    / "v0.1"
    / "normative"
    / "valid"
    / "admission-admitted.json"
)
KEYRING = (
    ROOT
    / "packs"
    / "srs.mcp.sdk_enforcement"
    / "v0.1"
    / "normative"
    / "trust"
    / "issuer-keys.json"
)


def _run(args: list[str], capsys) -> tuple[int, str, str]:
    code = main(args)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_missing_receipt_is_exit_2_not_a_verification_failure(capsys) -> None:
    code, out, err = _run(
        ["/nonexistent/receipt.json", "--keyring", str(KEYRING)], capsys
    )
    assert code == 2
    assert "source_integrity_error: receipt_not_found" in err
    assert "Traceback" not in err


def test_malformed_receipt_json_is_exit_2(tmp_path, capsys) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    code, out, err = _run([str(bad), "--keyring", str(KEYRING)], capsys)
    assert code == 2
    assert "source_integrity_error: receipt_malformed_json" in err


def test_invalid_utf8_receipt_is_exit_2(tmp_path, capsys) -> None:
    bad = tmp_path / "bad-utf8.json"
    bad.write_bytes(b'{"receipt_id": "\xff\xfe"}')
    code, out, err = _run([str(bad), "--keyring", str(KEYRING)], capsys)
    assert code == 2
    assert "source_integrity_error: receipt_not_utf8" in err


def test_directory_as_receipt_is_exit_2(tmp_path, capsys) -> None:
    code, out, err = _run([str(tmp_path), "--keyring", str(KEYRING)], capsys)
    assert code == 2
    assert "source_integrity_error: receipt_not_a_file" in err


def test_missing_keyring_is_exit_2(capsys) -> None:
    code, out, err = _run(
        [str(VALID_RECEIPT), "--keyring", "/nonexistent/keys.json"], capsys
    )
    assert code == 2
    assert "source_integrity_error: keyring_not_found" in err


def test_malformed_keyring_is_exit_2(tmp_path, capsys) -> None:
    bad = tmp_path / "keys.json"
    bad.write_text("[", encoding="utf-8")
    code, out, err = _run([str(VALID_RECEIPT), "--keyring", str(bad)], capsys)
    assert code == 2
    assert "source_integrity_error: keyring_malformed_json" in err


def test_missing_schema_is_exit_2(capsys) -> None:
    code, out, err = _run(
        [
            str(VALID_RECEIPT),
            "--keyring",
            str(KEYRING),
            "--schema",
            "/nonexistent/schema.json",
        ],
        capsys,
    )
    assert code == 2
    assert "source_integrity_error: schema_not_found" in err


def test_json_mode_source_error_is_structured(capsys) -> None:
    code, out, err = _run(
        ["/nonexistent/receipt.json", "--keyring", str(KEYRING), "--json"], capsys
    )
    assert code == 2
    payload = json.loads(out)
    assert payload["source_integrity_error"] == "receipt_not_found"
    assert payload["path"] == "/nonexistent/receipt.json"


def test_valid_inputs_still_exit_0(capsys) -> None:
    code, out, err = _run([str(VALID_RECEIPT), "--keyring", str(KEYRING)], capsys)
    assert code == 0
    assert "signature_valid: PASS" in out


def test_verification_failure_still_exit_1(tmp_path, capsys) -> None:
    tampered = json.loads(VALID_RECEIPT.read_text(encoding="utf-8"))
    tampered["disposition"] = "definitely_not_a_disposition"
    bad = tmp_path / "tampered.json"
    bad.write_text(json.dumps(tampered), encoding="utf-8")
    code, out, err = _run([str(bad), "--keyring", str(KEYRING)], capsys)
    assert code == 1
    assert "failure_code: signature_invalid" in out


def test_malformed_schema_is_exit_2(tmp_path, capsys) -> None:
    bad = tmp_path / "schema.json"
    bad.write_text("{bad", encoding="utf-8")
    code, out, err = _run(
        [str(VALID_RECEIPT), "--keyring", str(KEYRING), "--schema", str(bad)], capsys
    )
    assert code == 2
    assert "source_integrity_error: schema_malformed_json" in err


def test_non_object_receipt_is_exit_2(tmp_path, capsys) -> None:
    bad = tmp_path / "list.json"
    bad.write_text("[]", encoding="utf-8")
    code, out, err = _run([str(bad), "--keyring", str(KEYRING)], capsys)
    assert code == 2
    assert "source_integrity_error: receipt_not_an_object" in err


def test_non_object_keyring_is_exit_2(tmp_path, capsys) -> None:
    bad = tmp_path / "keys.json"
    bad.write_text('"just a string"', encoding="utf-8")
    code, out, err = _run([str(VALID_RECEIPT), "--keyring", str(bad)], capsys)
    assert code == 2
    assert "source_integrity_error: keyring_not_an_object" in err


def test_non_object_schema_is_exit_2(tmp_path, capsys) -> None:
    bad = tmp_path / "schema.json"
    bad.write_text("[1, 2, 3]", encoding="utf-8")
    code, out, err = _run(
        [str(VALID_RECEIPT), "--keyring", str(KEYRING), "--schema", str(bad)], capsys
    )
    assert code == 2
    assert "source_integrity_error: schema_not_an_object" in err
