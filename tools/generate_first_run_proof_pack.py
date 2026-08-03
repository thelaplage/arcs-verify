#!/usr/bin/env python3
"""Generate the derived half of the first-run proof pack.

The captured half of the pack -- three receipts, ``issuer-keys.json``,
``side_effects.json`` and ``quickstart.txt`` -- is producer output. It is
copied in byte-for-byte from an exact-commit DAGR MCP capture run and is never
written by this script.

This script writes only what is *derived* from those captured bytes:

* one mutated receipt, built from a captured receipt by changing exactly one
  signed semantic field and leaving the original signature in place;
* a verification result record for each of the three captured receipts and for
  the mutation, produced by calling the real verification path
  (``arcs_verify.verifier.verify_receipt``);
* the SHA-256 digest inventory covering every committed pack artifact.

Nothing here is hand-authored, and nothing here imports the producer. The
verifier reaches its verdicts from the captured bytes alone.

Regenerate with::

    python tools/generate_first_run_proof_pack.py

Add ``--check`` to verify the committed artifacts match what a regeneration
would produce, without writing anything.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from arcs_verify.verifier import verify_receipt

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "arcs_verify/data/srs-envelope-v0.2.0.schema.json"
PACK = ROOT / "packs" / "srs.mcp.sdk_enforcement" / "v0.1"
FIXTURES = PACK / "implementation" / "dagr-mcp-first-run"

PROFILE = "srs.mcp.sdk_enforcement.v0.1"
KEYRING = "issuer-keys.json"

ADMITTED_ADMISSION = "urn_srs_receipt_admission_first-run-capture-0001.json"
ADMITTED_OUTCOME = "urn_srs_receipt_outcome_first-run-capture-0001.json"
REFUSED_ADMISSION = "urn_srs_receipt_admission_first-run-capture-0002.json"

CAPTURED_RECEIPTS = (ADMITTED_ADMISSION, ADMITTED_OUTCOME, REFUSED_ADMISSION)

# Producer output copied in verbatim; this script must never write these.
CAPTURED_ARTIFACTS = CAPTURED_RECEIPTS + (
    KEYRING,
    "side_effects.json",
    "quickstart.txt",
)

# The mutation: one signed semantic field, on the admitted admission receipt.
# `disposition` is the field the pack's whole claim rests on, so it is the one
# worth proving cannot be forged. The signature is left untouched.
MUTATION_SOURCE = ADMITTED_ADMISSION
MUTATION_POINTER = "/disposition"
MUTATION_FROM = "admitted"
MUTATION_TO = "refused"
MUTATION_NAME = "admitted-admission-disposition-flip.json"
MUTATION_DIR = "mutations"
RESULT_DIR = "verification"

EXPECTED_MUTATION_FAILURE = "signature_invalid"


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _dump(payload: Any) -> str:
    """Stable, diff-friendly JSON: sorted keys, two-space indent, trailing NL."""
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_mutation(source: dict[str, Any]) -> dict[str, Any]:
    """Change exactly one signed semantic field, preserving the signature."""
    if source["disposition"] != MUTATION_FROM:
        raise SystemExit(
            f"mutation source {MUTATION_SOURCE} has disposition "
            f"{source['disposition']!r}, expected {MUTATION_FROM!r}"
        )
    mutated = copy.deepcopy(source)
    mutated["disposition"] = MUTATION_TO
    # The signature block is carried over untouched: that is the whole point.
    assert mutated["receipt_signature"] == source["receipt_signature"]
    return mutated


def verify(receipt: dict[str, Any], keyring: dict[str, Any]) -> dict[str, Any]:
    report = verify_receipt(
        receipt,
        keyring,
        schema_path=SCHEMA_PATH,
        selected_profile=PROFILE,
    )
    return report.to_dict()


def generate() -> dict[str, str]:
    """Return {relative path: file content} for every derived artifact."""
    keyring = _read_json(FIXTURES / KEYRING)
    outputs: dict[str, str] = {}

    # 1. The mutation, derived from captured bytes.
    source = _read_json(FIXTURES / MUTATION_SOURCE)
    mutated = build_mutation(source)
    outputs[f"{MUTATION_DIR}/{MUTATION_NAME}"] = _dump(mutated)

    # 2. Verification results for the three captured receipts.
    for name in CAPTURED_RECEIPTS:
        result = verify(_read_json(FIXTURES / name), keyring)
        outputs[f"{RESULT_DIR}/{name}"] = _dump(
            {
                "keyring": KEYRING,
                "profile": PROFILE,
                "result": result,
                "subject": name,
                "subject_role": "captured_receipt",
            }
        )

    # 3. Verification result for the mutation, from the same verifier path.
    mutation_result = verify(mutated, keyring)
    if EXPECTED_MUTATION_FAILURE not in mutation_result["failure_codes"]:
        raise SystemExit(
            f"mutation did not fail with {EXPECTED_MUTATION_FAILURE!r}; "
            f"got {mutation_result['failure_codes']!r}"
        )
    outputs[f"{RESULT_DIR}/{MUTATION_NAME}"] = _dump(
        {
            "keyring": KEYRING,
            "mutation": {
                "changed_from": MUTATION_FROM,
                "changed_to": MUTATION_TO,
                "json_pointer": MUTATION_POINTER,
                "signature_preserved": True,
                "source_receipt": MUTATION_SOURCE,
            },
            "profile": PROFILE,
            "result": mutation_result,
            "subject": f"{MUTATION_DIR}/{MUTATION_NAME}",
            "subject_role": "mutation",
        }
    )
    return outputs


def build_digest_inventory() -> str:
    """SHA-256 over every committed pack artifact, captured and derived."""
    derived = sorted(
        p.relative_to(FIXTURES).as_posix()
        for p in FIXTURES.rglob("*")
        if p.is_file() and p.parent != FIXTURES
    )
    documentation = ["README.md", "expectations.json", "manifest.json"]
    inventory = {
        "algorithm": "sha256",
        "artifacts": {
            relative: _sha256(FIXTURES / relative)
            for relative in sorted(
                [*CAPTURED_ARTIFACTS, *documentation, *derived]
            )
        },
        "note": (
            "Every committed artifact in this directory except digests.json "
            "itself. Captured artifacts reproduce byte-for-byte from the "
            "pinned producer commit; derived artifacts reproduce from "
            "tools/generate_first_run_proof_pack.py."
        ),
    }
    return _dump(inventory)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="compare committed artifacts against a regeneration; write nothing",
    )
    args = parser.parse_args()

    outputs = generate()

    if args.check:
        drift = [
            relative
            for relative, content in outputs.items()
            if not (FIXTURES / relative).is_file()
            or (FIXTURES / relative).read_text(encoding="utf-8") != content
        ]
        # The inventory is checked last: it digests everything above.
        if (FIXTURES / "digests.json").read_text(
            encoding="utf-8"
        ) != build_digest_inventory():
            drift.append("digests.json")
        if drift:
            print("drift in: " + ", ".join(sorted(drift)), file=sys.stderr)
            return 1
        print("first-run proof pack is up to date")
        return 0

    for relative, content in outputs.items():
        path = FIXTURES / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        print(f"wrote {path.relative_to(ROOT)}")

    inventory_path = FIXTURES / "digests.json"
    inventory_path.write_text(build_digest_inventory(), encoding="utf-8")
    print(f"wrote {inventory_path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
