from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .verifier import verify_receipt

# Named profiles the signed-SRS verifier can evaluate. Keys must match the
# constants in verifier.py; selecting any other name yields the
# profile.unsupported_selection failure code rather than a silent fallback.
SUPPORTED_PROFILES: dict[str, str] = {
    "srs.mcp.sdk_enforcement.v0.1": (
        "MCP tool-call admission receipts emitted at an SDK enforcement boundary (default)."
    ),
    "srs.connection.lifecycle.v0.1": (
        "MCP connection lifecycle receipts (connect, scope grant, revoke, disconnect)."
    ),
    "srs.broadcast_control.v0.1": (
        "Broadcast-control receipts for governed one-to-many distribution events."
    ),
    "srs.deferred_operation.v0.1": (
        "Deferred-operation receipts (deferral, review linkage, outcome, disclosed gaps)."
    ),
    "srs.editorial.publication_ingest.v0.1": (
        "Editorial corpus publication-ingest receipts (provenance of a parsed publication artifact)."
    ),
    "srs.editorial.source_capture.v0.1": (
        "Editorial source-capture receipts (digest of the bytes a referenced URL or record returned at capture time)."
    ),
    "srs.editorial.source_capture.v0.1.1": (
        "Editorial source-capture receipts, provisional v0.1.1 dialect (top-level outcome / declared_url / captured_bytes_ref with enforced cross-field null rules)."
    ),
    "srs.activity.governed_read.v0.1": (
        "Activity governed-read receipts (one governed read against a pinned basis; admitted result or typed refusal, mandatory C8 visibility)."
    ),
    "srs.editorial.citation_pack.v0.1": (
        "Editorial citation-pack assembly receipts, PROVISIONAL (arcs-srs, not ratified). Single-receipt structural verification of one pack_assembly provenance receipt: digest-reference form, subject binding, required classes/limits. A PASS attests structural conformance to the provisional contract only — not admission, trust, or correctness."
    ),
}

_EXAMPLE = (
    "example:\n"
    "  arcs-verify \\\n"
    "    packs/srs.mcp.sdk_enforcement/v0.1/normative/valid/admission-admitted.json \\\n"
    "    --keyring packs/srs.mcp.sdk_enforcement/v0.1/normative/trust/issuer-keys.json \\\n"
    "    --profile srs.mcp.sdk_enforcement.v0.1\n"
    "\n"
    "subcommands (each takes --help):\n"
    "  arcs-verify receipt-set WORKFLOW        verify every receipt in a DAGR workflow index\n"
    "  arcs-verify amnesiac-chain BUNDLE       recompute an independently serialized artifact chain\n"
    "  arcs-verify deferred-sequence ...       verify a deferred-operation receipt sequence\n"
    "  arcs-verify governed-memory-sequence    verify a governed memory read sequence bundle\n"
    "  arcs-verify ingest-run-sequence ...     verify a dagr.ingest_run.v0.1 receipt sequence\n"
    "  arcs-verify acquisition-grounding ...   verify a grounded content proposal against captured source bytes\n"
    "\n"
    "exit codes: 0 all results passed; 1 verification failed; 2 usage or\n"
    "source-integrity error (not a verification verdict)."
)


def _default_schema() -> Path:
    return Path(__file__).resolve().parent / "data" / "srs-envelope-v0.2.0.schema.json"


def _print_profiles() -> None:
    for name, description in SUPPORTED_PROFILES.items():
        print(f"{name}\n    {description}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Verify a signed ARCS/SRS receipt against the pinned SRS envelope "
            "schema and a named conformance profile. The verifier reads "
            "serialized bytes only; it imports no producer implementation."
        ),
        epilog=_EXAMPLE,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "receipt",
        type=Path,
        help="path to the serialized receipt JSON to verify",
    )
    parser.add_argument(
        "--keyring",
        required=True,
        type=Path,
        help="path to the serialized trust bundle used to resolve the signing key",
    )
    parser.add_argument(
        "--profile",
        default="srs.mcp.sdk_enforcement.v0.1",
        help=(
            "named conformance profile to evaluate (see --list-profiles); "
            "default: %(default)s"
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="emit the full machine-readable report instead of the line summary",
    )
    parser.add_argument(
        "--schema",
        type=Path,
        default=_default_schema(),
        help="override the pinned envelope schema file (the schema_digest result still applies)",
    )
    parser.add_argument(
        "--list-profiles",
        action="store_true",
        dest="list_profiles",
        help="list the named profiles this verifier evaluates, then exit",
    )
    return parser


def _source_error(kind: str, path: Path, detail: str, *, as_json: bool) -> int:
    """Report a source-integrity problem and return exit code 2.

    A missing or unreadable input is not evidence that a receipt failed
    verification, so it must never surface as exit 1. No traceback is
    printed; the message is stable text (or a stable JSON object under
    --json) suitable for automation.
    """
    if as_json:
        print(
            json.dumps(
                {
                    "source_integrity_error": kind,
                    "path": str(path),
                    "detail": detail,
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        print(f"source_integrity_error: {kind}", file=sys.stderr)
        print(f"path: {path}", file=sys.stderr)
        print(f"detail: {detail}", file=sys.stderr)
    return 2


def _load_json_input(path: Path, role: str, *, as_json: bool) -> tuple[dict | None, int]:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None, _source_error(f"{role}_not_found", path, "no such file", as_json=as_json)
    except IsADirectoryError:
        return None, _source_error(f"{role}_not_a_file", path, "path is a directory", as_json=as_json)
    except UnicodeDecodeError as exc:
        return None, _source_error(f"{role}_not_utf8", path, str(exc), as_json=as_json)
    except OSError as exc:
        return None, _source_error(f"{role}_unreadable", path, str(exc), as_json=as_json)
    try:
        return json.loads(text), 0
    except json.JSONDecodeError as exc:
        return None, _source_error(f"{role}_malformed_json", path, str(exc), as_json=as_json)


def _verify_srs(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    if "--list-profiles" in raw:
        _print_profiles()
        return 0
    args = build_parser().parse_args(raw)
    receipt, err = _load_json_input(args.receipt, "receipt", as_json=args.as_json)
    if err:
        return err
    keyring, err = _load_json_input(args.keyring, "keyring", as_json=args.as_json)
    if err:
        return err
    if not isinstance(receipt, dict):
        return _source_error(
            "receipt_not_an_object",
            args.receipt,
            f"top-level JSON value is {type(receipt).__name__}, not an object",
            as_json=args.as_json,
        )
    if not isinstance(keyring, dict):
        return _source_error(
            "keyring_not_an_object",
            args.keyring,
            f"top-level JSON value is {type(keyring).__name__}, not an object",
            as_json=args.as_json,
        )
    schema_probe, err = _load_json_input(args.schema, "schema", as_json=args.as_json)
    if err:
        return err
    if not isinstance(schema_probe, dict):
        return _source_error(
            "schema_not_an_object",
            args.schema,
            f"top-level JSON value is {type(schema_probe).__name__}, not an object",
            as_json=args.as_json,
        )
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


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] == "amnesiac-chain":
        from .amnesiac.cli import main as verify_amnesiac_chain

        return verify_amnesiac_chain(args[1:])
    if args and args[0] == "dagr-report":
        from .dagr_report import main as dagr_report_main

        return dagr_report_main(args[1:])
    if args and args[0] == "dagr-report-v0-2":
        from .dagr_report_v0_2 import main as dagr_report_v0_2_main

        return dagr_report_v0_2_main(args[1:])
    if args and args[0] == "receipt-set":
        from .receipt_set import main as receipt_set_main

        return receipt_set_main(args[1:])
    if args and args[0] == "deferred-sequence":
        from .deferred_sequence import main as deferred_sequence_main

        return deferred_sequence_main(args[1:])
    if args and args[0] == "governed-memory-sequence":
        from .governed_memory_sequence import main as governed_memory_sequence_main

        return governed_memory_sequence_main(args[1:])
    if args and args[0] == "ingest-run-sequence":
        from .ingest_run_sequence import main as ingest_run_sequence_main

        return ingest_run_sequence_main(args[1:])
    if args and args[0] == "analytics-snapshot":
        from .analytics_snapshot import main as analytics_snapshot_main

        return analytics_snapshot_main(args[1:])
    if args and args[0] == "acquisition-grounding":
        from .acquisition_grounding import main as acquisition_grounding_main

        return acquisition_grounding_main(args[1:])
    return _verify_srs(args)


if __name__ == "__main__":
    raise SystemExit(main())
