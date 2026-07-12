#!/usr/bin/env python3
"""Vendor-neutral MCP audit-trail -> SRS envelope receipt adapter.

This is a *minimal*, deterministic, file-in/file-out adapter for one pack. It is
NOT an ESE / enforcement runtime and it is NOT a product. It reads one
public-safe MCP (Model Context Protocol) custody-gateway audit-trail input file
and emits one ARCS SRS *envelope* receipt that carries the audit evidence as a
GARP body under ``extensions.garp.body``.

What it does:
  * computes the sha256 of the exact input bytes and records it under
    ``extensions.garp.body.artifact_hashes`` (the receipt binds the input
    cryptographically),
  * maps the recorded audit events into a GARP body whose ``body_kind`` names
    the shape (``mcp_audit_trail``),
  * carries any decision via ``decision_ref`` (a reference) and NEVER as a
    body-level or top-level ``verdict`` / ``status`` / ``disposition`` /
    ``decision`` / ``governance_state``. This preserves Option A
    (decision_ref) as recorded in garp-ops PR #87 and garp-sdk PR #78.

What it does NOT do:
  * it does not assert that any recorded event is true, that any tool call was
    authorized, or that any custody claim is correct. The receipt attests SRS
    envelope form and input-byte integrity only.

Determinism: output is ``json.dumps(..., indent=2, sort_keys=True)`` plus a
trailing newline, with ``issued_at`` and ``receipt_id`` derived only from the
input bytes/fields (no wall clock, no randomness), so regenerating from the same
input reproduces byte-identical output. Standard library only; imports no
garp_sdk, arcs_amnesiac, or other Vega/GARP product code.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

# Pack-local, descriptive routing label. It is NOT a newly-minted canonical
# boundary_type: the canonical boundary_type lane remains arcs-srs's to define.
# It names how this receipt routes (an audit-trail custody record) and nothing
# more. See README.md ("boundary_type").
BOUNDARY_TYPE = "audit_trail_boundary"

# receipt_type is the family axis; "provenance" is the closed-enum family this
# evidence shape belongs to (an audit trail is provenance over tool custody).
RECEIPT_TYPE = "provenance"

ATTESTATION_LIMITS = [
    "this receipt attests SRS envelope shape and input-byte integrity only",
    "it does not assert that any recorded audit event is true",
    "it does not assert that any tool call was authorized or any custody claim correct",
    "any decision is referenced via decision_ref, not asserted as a verdict",
]


def sha256_of_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def map_event(event: dict) -> dict:
    """Pass through the public-safe, digest-only fields of one audit event."""
    mapped: dict[str, Any] = {
        "seq": event["seq"],
        "kind": event["kind"],
        "tool": event["tool"],
        "server_ref": event["server_ref"],
        "custody": event["custody"],
    }
    # Audit events carry digest-only references, never raw args/results.
    if "args_digest" in event:
        mapped["args_digest"] = event["args_digest"]
    if "result_digest" in event:
        mapped["result_digest"] = event["result_digest"]
    return mapped


def build_receipt(input_path: Path) -> dict:
    raw = input_path.read_bytes()
    input_digest = sha256_of_bytes(raw)
    audit = json.loads(raw)

    events = [map_event(e) for e in audit.get("events", [])]

    body: dict[str, Any] = {
        "body_kind": "mcp_audit_trail",
        "gateway_ref": audit["gateway"],
        "session_ref": audit["session_ref"],
        "event_count": len(events),
        "events": events,
        "artifact_hashes": {
            "input/mcp_audit_trail.input.json": f"sha256:{input_digest}",
        },
    }
    # Option A: carry the decision only as a reference, never as a verdict.
    if "decision_ref" in audit:
        body["decision_ref"] = audit["decision_ref"]

    receipt: dict[str, Any] = {
        "receipt_version": "srs.core.v5.1",
        "receipt_id": f"mcp-audit-trail-{input_digest[:16]}",
        "receipt_type": RECEIPT_TYPE,
        "boundary_type": BOUNDARY_TYPE,
        "protocol_binding": "garp",
        "subject_ref": audit["session_ref"],
        "issued_at": audit["recorded_at"],
        "artifact_classes_covered": [
            "trace",
            "packet_inspection",
            "provenance",
        ],
        "artifact_classes_excluded": [
            "truth_verification",
            "automated_citation_detection",
            "external_fact_checking",
        ],
        "attestation_limits": list(ATTESTATION_LIMITS),
        "extensions": {"garp": {"body": body}},
    }
    return receipt


def render(receipt: dict) -> str:
    return json.dumps(receipt, indent=2, sort_keys=True) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build an SRS envelope receipt from a public-safe MCP "
        "audit-trail input file (envelope form + input-byte integrity only).",
    )
    parser.add_argument("input", type=Path, help="MCP audit-trail input JSON")
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="write the receipt here; default is stdout",
    )
    args = parser.parse_args(argv)

    try:
        receipt = build_receipt(args.input)
    except (OSError, json.JSONDecodeError, KeyError) as exc:
        print(f"FATAL: could not build receipt: {exc}", file=sys.stderr)
        return 2

    output = render(receipt)
    if args.out is None:
        sys.stdout.write(output)
    else:
        args.out.write_text(output, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
