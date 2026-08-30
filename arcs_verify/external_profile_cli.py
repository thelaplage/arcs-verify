"""Standalone CLI for SRS vNext external-profile verification."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from arcs_verify.external_profile import verify_external_profile_receipt


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m arcs_verify.external_profile_cli",
        description="Independently verify one SRS vNext external-profile receipt.",
    )
    parser.add_argument("receipt", type=Path)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--envelope-schema", type=Path, required=True)
    parser.add_argument("--profile-schema", type=Path, required=True)
    parser.add_argument("--keyring", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        keyring = json.loads(args.keyring.read_text(encoding="utf-8"))
        report = verify_external_profile_receipt(
            args.receipt.read_bytes(),
            args.profile.read_bytes(),
            keyring,
            envelope_schema_bytes=args.envelope_schema.read_bytes(),
            profile_schema_bytes=args.profile_schema.read_bytes(),
        )
    except (OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"passed": False, "input_error": str(exc)}, sort_keys=True))
        return 2

    print(json.dumps(report.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0 if report.passed else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
