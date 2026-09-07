from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from arcs_verify.scitt import verify_scitt


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_sums(root: Path) -> dict[str, str]:
    sums: dict[str, str] = {}
    for raw in (root / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line:
            continue
        digest, rel = line.split(maxsplit=1)
        rel = rel.lstrip("* ")
        sums[rel] = digest
    return sums


def _verify_integrity(root: Path) -> None:
    sums = _load_sums(root)
    if len(sums) != 30:
        raise AssertionError(f"expected 30 pinned vector checksums, got {len(sums)}")
    for rel, expected in sorted(sums.items()):
        path = root / rel
        if not path.is_file():
            raise AssertionError(f"missing pinned vector file: {rel}")
        actual = _sha256(path)
        if actual != expected:
            raise AssertionError(
                f"vector digest mismatch {rel}: expected {expected}, got {actual}"
            )


def _run_vector(root: Path, row: dict) -> dict:
    vector_dir = root / row["dir"]
    expected = row["expected"]
    statement = (vector_dir / "statement.cose").read_bytes()
    receipt = (vector_dir / "receipt.cose").read_bytes()
    issuer_key = (vector_dir / "issuer-key.pub").read_bytes()
    log_key = (vector_dir / "log-key.pub").read_bytes()

    report = verify_scitt(
        statement,
        statement_public_key_pem=issuer_key,
        receipt_bytes=receipt,
        transparency_service_public_key_pem=log_key,
    )

    expected_statement = bool(expected["statement_signature_valid"])
    expected_receipt = bool(expected["receipt_valid"])
    expected_passed = row["expected_result"] == "VALID"

    if report.statement_signature_valid is not expected_statement:
        raise AssertionError(
            f"{row['id']}: statement signature expected {expected_statement}, "
            f"got {report.statement_signature_valid}"
        )
    if report.receipt_verification_valid is not expected_receipt:
        raise AssertionError(
            f"{row['id']}: receipt expected {expected_receipt}, "
            f"got {report.receipt_verification_valid}"
        )
    if report.passed is not expected_passed:
        raise AssertionError(
            f"{row['id']}: overall expected {expected_passed}, got {report.passed}"
        )

    # The vector corpus carries authenticated iss/sub on every statement. A bad
    # statement signature must not expose those claims as authenticated facts.
    if expected_statement:
        if report.statement_required_cwt_claims_valid is not True:
            raise AssertionError(f"{row['id']}: required CWT claims were not authenticated")
    else:
        if report.statement_required_cwt_claims_valid is not False:
            raise AssertionError(
                f"{row['id']}: unauthenticated statement unexpectedly passed CWT claim check"
            )
        if report.statement_issuer is not None or report.statement_subject is not None:
            raise AssertionError(
                f"{row['id']}: unauthenticated issuer/subject escaped the verifier boundary"
            )

    return {
        "id": row["id"],
        "expected_result": row["expected_result"],
        "statement_signature_valid": report.statement_signature_valid,
        "receipt_verification_valid": report.receipt_verification_valid,
        "passed": report.passed,
        "failure_codes": list(report.failure_codes),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    args = parser.parse_args(argv)
    root = args.root.resolve()

    _verify_integrity(root)
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("version") != "v1":
        raise AssertionError(f"unexpected vector manifest version: {manifest.get('version')!r}")
    rows = manifest.get("vectors")
    if not isinstance(rows, list) or len(rows) != 5:
        raise AssertionError("expected exactly five SCITT v1 vectors")

    results = [_run_vector(root, row) for row in rows]
    print(json.dumps({"vectors": results}, indent=2, sort_keys=True))
    print(f"SCITT_VECTORS0_PASS: {len(results)}/{len(results)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
