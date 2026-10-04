"""CLI adapter for the independent EXIT-O origin-authentication verifier.

This module is transport-neutral and producer-independent. It reads explicit
serialized inputs from disk and passes them to
``verify_exit_o_origin_authentication_receipt``; it does not fetch trust
material, discover keys, provision signers, or import producer/runtime code.

Two exit modes are deliberately distinct:

* default: exit 0 only when ``exit_o_chain_satisfied`` is true;
* ``--require-key-authentication``: exit 0 only when BOTH
  ``proof_receipt_signature == "pass"`` and
  ``key_authentication_finding == "pass"``.

The second mode exists for the clean-machine trust-material journey. It is a
per-finding acceptance gate, not an EXIT-O chain verdict.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from .exit_o_origin_authentication import (
    VERDICT_PASS,
    verify_exit_o_origin_authentication_receipt,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="arcs-verify exit-o-origin",
        description=(
            "Verify an EXIT-O semantic-issuer origin-authentication receipt from "
            "explicit local inputs. This command performs no network retrieval."
        ),
    )
    parser.add_argument("receipt", type=Path, help="serialized EXIT-O receipt JSON")
    parser.add_argument(
        "--trust-bundle",
        required=True,
        type=Path,
        help="verifier-selected serialized SRS trust-bundle v0.2 JSON",
    )
    parser.add_argument(
        "--key-principal-binding",
        required=True,
        type=Path,
        help="serialized DAGR institutional key<->principal binding JSON",
    )
    parser.add_argument(
        "--genesis-evidence",
        type=Path,
        help="optional serialized genesis evidence JSON for binding linkage",
    )
    parser.add_argument(
        "--verification-time",
        help=(
            "optional offset-aware ISO-8601 verification time; when omitted, "
            "the verifier uses its current UTC time"
        ),
    )
    parser.add_argument(
        "--require-key-authentication",
        action="store_true",
        help=(
            "exit 0 iff proof_receipt_signature and key_authentication_finding "
            "both equal 'pass'; this does NOT assert exit_o_chain_satisfied"
        ),
    )
    return parser


def _source_error(kind: str, path: Path, detail: str) -> int:
    print(
        json.dumps(
            {
                "source_integrity_error": kind,
                "path": str(path),
                "detail": detail,
            },
            indent=2,
            sort_keys=True,
        ),
        file=sys.stderr,
    )
    return 2


def _load_json_object(path: Path, role: str) -> tuple[dict[str, Any] | None, int]:
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None, _source_error(f"{role}_not_found", path, "no such file")
    except IsADirectoryError:
        return None, _source_error(f"{role}_not_a_file", path, "path is a directory")
    except UnicodeDecodeError as exc:
        return None, _source_error(f"{role}_not_utf8", path, str(exc))
    except OSError as exc:
        return None, _source_error(f"{role}_unreadable", path, str(exc))

    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        return None, _source_error(f"{role}_malformed_json", path, str(exc))
    if not isinstance(value, dict):
        return None, _source_error(
            f"{role}_not_an_object",
            path,
            f"top-level JSON value is {type(value).__name__}, not an object",
        )
    return value, 0


def _parse_verification_time(value: str | None) -> tuple[datetime | None, int]:
    if value is None:
        return None, 0
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        print(
            json.dumps(
                {
                    "source_integrity_error": "verification_time_invalid",
                    "detail": str(exc),
                },
                indent=2,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return None, 2
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        print(
            json.dumps(
                {
                    "source_integrity_error": "verification_time_invalid",
                    "detail": "verification time must be offset-aware",
                },
                indent=2,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return None, 2
    return parsed, 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    verification_time, err = _parse_verification_time(args.verification_time)
    if err:
        return err

    receipt, err = _load_json_object(args.receipt, "receipt")
    if err:
        return err
    trust_bundle, err = _load_json_object(args.trust_bundle, "trust_bundle")
    if err:
        return err
    binding, err = _load_json_object(
        args.key_principal_binding, "key_principal_binding"
    )
    if err:
        return err

    genesis = None
    if args.genesis_evidence is not None:
        genesis, err = _load_json_object(args.genesis_evidence, "genesis_evidence")
        if err:
            return err

    assert receipt is not None
    assert trust_bundle is not None
    assert binding is not None

    report = verify_exit_o_origin_authentication_receipt(
        receipt,
        trust_bundle=trust_bundle,
        key_principal_binding=binding,
        genesis_evidence=genesis,
        verification_time=verification_time,
    )
    data = report.to_dict()
    print(json.dumps(data, indent=2, sort_keys=True))

    if args.require_key_authentication:
        return (
            0
            if report.proof_receipt_signature == VERDICT_PASS
            and report.key_authentication_finding == VERDICT_PASS
            else 1
        )
    return 0 if report.exit_o_chain_satisfied else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
