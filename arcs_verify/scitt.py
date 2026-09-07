from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from scitt_cose import parse_signed_statement, verify_receipt

SCHEMA = "arcs.scitt_verification_report.v0.1"
NOT_EVALUATED = "not_evaluated"


@dataclass(frozen=True)
class ScittVerificationReport:
    """Independent SCITT verification findings over serialized artifacts.

    This report deliberately does not collapse transparency verification into
    truth, admission, support, execution, or corpus standing.  ``passed`` is
    only the conjunction of the verification checks that were actually in
    scope for this invocation.
    """

    statement_digest: str
    receipt_digest: str | None
    statement_signature_valid: bool
    statement_required_headers_valid: bool
    receipt_evaluated: bool
    receipt_verification_valid: bool | Literal["not_evaluated"]
    statement_issuer: str | None
    statement_subject: str | None
    statement_content_type: str | int | None
    statement_alg: str | int | None
    failure_codes: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return (
            self.statement_signature_valid
            and self.statement_required_headers_valid
            and (
                self.receipt_verification_valid is True
                if self.receipt_evaluated
                else True
            )
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "inputs": {
                "statement_digest": self.statement_digest,
                "receipt_digest": self.receipt_digest,
            },
            "statement": {
                "signature_valid": self.statement_signature_valid,
                "required_headers_valid": self.statement_required_headers_valid,
                "issuer": self.statement_issuer,
                "subject": self.statement_subject,
                "content_type": self.statement_content_type,
                "alg": self.statement_alg,
            },
            "receipt": {
                "evaluated": self.receipt_evaluated,
                "verification_valid": self.receipt_verification_valid,
            },
            "reserved_conclusions": {
                "underlying_content_truth": NOT_EVALUATED,
                "underlying_event_occurred": NOT_EVALUATED,
                "dagr_admission": NOT_EVALUATED,
                "counterpedia_standing": NOT_EVALUATED,
                "source_support": NOT_EVALUATED,
            },
            "failure_codes": list(self.failure_codes),
            "passed": self.passed,
        }


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _failure_code_from_result(result: Any, default: str) -> str:
    for name in ("error", "reason", "failure_reason", "failure_code"):
        value = getattr(result, name, None)
        if isinstance(value, str) and value.strip():
            return f"{default}:{value.strip()}"
    return default


def verify_scitt(
    statement_bytes: bytes,
    *,
    statement_public_key_pem: bytes,
    receipt_bytes: bytes | None = None,
    transparency_service_public_key_pem: bytes | None = None,
) -> ScittVerificationReport:
    """Verify a SCITT Signed Statement and, optionally, its COSE Receipt.

    Verification is hermetic: every byte and key is caller-supplied.  No key
    discovery, network access, registration, policy evaluation, or producer
    import occurs here.

    The receipt path intentionally delegates COSE/VDS verification to the
    neutral ``scitt-cose`` substrate.  The leaf entry is the exact serialized
    Signed Statement supplied to this function; callers presenting a
    Transparent Statement must first supply the original registered Signed
    Statement bytes (SCITT registration requires an empty unprotected header
    before insertion into the statement sequence).
    """

    failures: list[str] = []

    try:
        parsed = parse_signed_statement(
            statement_bytes,
            public_key_pem=statement_public_key_pem,
        )
    except Exception as exc:  # defensive fence around a third-party boundary
        parsed = {"signature_verified": False}
        failures.append(f"statement.verifier_error:{type(exc).__name__}")

    signature_valid = parsed.get("signature_verified") is True
    if not signature_valid:
        failures.append("statement.signature_invalid")

    issuer = parsed.get("issuer") if signature_valid else None
    subject = parsed.get("subject") if signature_valid else None
    content_type = parsed.get("content_type") if signature_valid else None
    alg = parsed.get("alg") if signature_valid else None
    required_headers_valid = (
        signature_valid
        and isinstance(issuer, str)
        and bool(issuer)
        and isinstance(subject, str)
        and bool(subject)
    )
    if signature_valid and not required_headers_valid:
        failures.append("statement.required_headers_invalid")

    receipt_evaluated = receipt_bytes is not None
    receipt_digest = _sha256(receipt_bytes) if receipt_bytes is not None else None
    receipt_valid: bool | Literal["not_evaluated"] = NOT_EVALUATED

    if receipt_bytes is not None:
        if transparency_service_public_key_pem is None:
            receipt_valid = False
            failures.append("receipt.transparency_service_key_missing")
        else:
            try:
                result = verify_receipt(
                    receipt_bytes,
                    leaf_entry_hex=statement_bytes.hex(),
                    log_public_key_pem=transparency_service_public_key_pem,
                )
                receipt_valid = bool(result.ok)
                if not receipt_valid:
                    failures.append(
                        _failure_code_from_result(result, "receipt.verification_failed")
                    )
            except Exception as exc:  # same defensive third-party fence
                receipt_valid = False
                failures.append(f"receipt.verifier_error:{type(exc).__name__}")

    return ScittVerificationReport(
        statement_digest=_sha256(statement_bytes),
        receipt_digest=receipt_digest,
        statement_signature_valid=signature_valid,
        statement_required_headers_valid=required_headers_valid,
        receipt_evaluated=receipt_evaluated,
        receipt_verification_valid=receipt_valid,
        statement_issuer=issuer,
        statement_subject=subject,
        statement_content_type=content_type,
        statement_alg=alg,
        failure_codes=tuple(dict.fromkeys(failures)),
    )


def _source_error(kind: str, path: Path, detail: str, *, as_json: bool) -> int:
    body = {"source_integrity_error": kind, "path": str(path), "detail": detail}
    if as_json:
        print(json.dumps(body, indent=2, sort_keys=True))
    else:
        print(f"source_integrity_error: {kind}", file=sys.stderr)
        print(f"path: {path}", file=sys.stderr)
        print(f"detail: {detail}", file=sys.stderr)
    return 2


def _read_bytes(path: Path, role: str, *, as_json: bool) -> tuple[bytes | None, int]:
    try:
        return path.read_bytes(), 0
    except FileNotFoundError:
        return None, _source_error(f"{role}_not_found", path, "no such file", as_json=as_json)
    except IsADirectoryError:
        return None, _source_error(f"{role}_not_a_file", path, "path is a directory", as_json=as_json)
    except OSError as exc:
        return None, _source_error(f"{role}_unreadable", path, str(exc), as_json=as_json)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="arcs-verify scitt",
        description=(
            "Independently verify a serialized SCITT Signed Statement and optional "
            "COSE Receipt. This operation performs no registration and makes no "
            "truth, admission, support, standing, or execution conclusion."
        ),
    )
    parser.add_argument("statement", type=Path)
    parser.add_argument("--statement-pubkey", required=True, type=Path)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--transparency-service-pubkey", type=Path)
    parser.add_argument("--json", action="store_true", dest="as_json")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    statement, err = _read_bytes(args.statement, "statement", as_json=args.as_json)
    if err:
        return err
    statement_key, err = _read_bytes(
        args.statement_pubkey, "statement_pubkey", as_json=args.as_json
    )
    if err:
        return err

    receipt = None
    if args.receipt is not None:
        receipt, err = _read_bytes(args.receipt, "receipt", as_json=args.as_json)
        if err:
            return err

    ts_key = None
    if args.transparency_service_pubkey is not None:
        ts_key, err = _read_bytes(
            args.transparency_service_pubkey,
            "transparency_service_pubkey",
            as_json=args.as_json,
        )
        if err:
            return err

    assert statement is not None
    assert statement_key is not None
    report = verify_scitt(
        statement,
        statement_public_key_pem=statement_key,
        receipt_bytes=receipt,
        transparency_service_public_key_pem=ts_key,
    )
    data = report.to_dict()

    if args.as_json:
        print(json.dumps(data, indent=2, sort_keys=True))
    else:
        print(
            "statement_signature_valid: "
            + ("PASS" if report.statement_signature_valid else "FAIL")
        )
        print(
            "statement_required_headers_valid: "
            + ("PASS" if report.statement_required_headers_valid else "FAIL")
        )
        if report.receipt_evaluated:
            print(
                "receipt_verification_valid: "
                + ("PASS" if report.receipt_verification_valid is True else "FAIL")
            )
        else:
            print("receipt_verification_valid: NOT_EVALUATED")
        for code in report.failure_codes:
            print(f"failure_code: {code}")

    return 0 if report.passed else 1


__all__ = ["ScittVerificationReport", "verify_scitt", "main"]


if __name__ == "__main__":
    raise SystemExit(main())
