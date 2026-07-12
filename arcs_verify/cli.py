from __future__ import annotations

import argparse
import json
from pathlib import Path

from .verifier import verify_receipt


def _default_schema() -> Path:
    return Path(__file__).resolve().parents[1] / "vendor" / "arcs-srs" / "schemas" / "srs-envelope" / "v0.2.0" / "srs-envelope.schema.json"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Verify a signed ARCS/SRS receipt")
    parser.add_argument("receipt", type=Path)
    parser.add_argument("--keyring", required=True, type=Path)
    parser.add_argument("--profile", default="srs.mcp.sdk_enforcement.v0.1")
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument("--schema", type=Path, default=_default_schema())
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    receipt = json.loads(args.receipt.read_text(encoding="utf-8"))
    keyring = json.loads(args.keyring.read_text(encoding="utf-8"))
    report = verify_receipt(receipt, keyring, schema_path=args.schema, selected_profile=args.profile)
    data = report.to_dict()
    if args.as_json:
        print(json.dumps(data, indent=2, sort_keys=True))
    else:
        for name in ("schema_digest", "envelope", "profile", "raw_content_exclusion", "signature_valid", "issuer_key_resolved", "issuer_key_trusted", "attestation_limits_present"):
            print(f"{name}: {'PASS' if data[name] else 'FAIL'}")
        print(f"chain_status: {data['chain_status']}")
        for code in data["failure_codes"]:
            print(f"failure_code: {code}")
    return 0 if report.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
