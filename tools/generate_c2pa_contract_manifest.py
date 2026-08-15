#!/usr/bin/env python3
"""Regenerate contract.manifest.json for the c2pa-native-finding bundle.

The manifest pins ONLY the machine semantic artifacts of the bundle: the two
schemas and the comparison taxonomy. README.md is deliberately excluded.

Downstream consumers pin the digest of this manifest. They do not pin the PR
commit, which moves for reasons unrelated to semantics, and they do not pin
README bytes, which change when the prose is clarified without the machine
contract changing at all. A prose edit that bumped a consumer's pin would train
consumers to ignore pin changes.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

BUNDLE = (
    Path(__file__).resolve().parent.parent
    / "arcs_verify"
    / "contracts"
    / "c2pa-native-finding"
    / "v0.1"
)

PINNED_FILES = (
    "canonical-native-finding.schema.json",
    "comparison-taxonomy.json",
    "native-finding-report.schema.json",
)

EXCLUDED_FILES = ("README.md", "contract.manifest.json")


def main() -> int:
    manifest = {
        "contract_id": "arcs.c2pa_native_finding.v0.1",
        "contract_version": "0.1",
        "status": "PROVISIONAL",
        "digest_algorithm": "sha256",
        "authority": (
            "arcs-verify owns the C2PA independent-verification report and comparison "
            "contract. arcs-standard owns generic provenance-signal semantics; arcs-srs owns "
            "the native observation receipt serialization. This bundle claims neither."
        ),
        "scope_note": (
            "Pins only the machine semantic artifacts. Downstream consumers pin the digest of "
            "this manifest, not the implementing commit and not README bytes."
        ),
        "excluded_from_pin": {
            name: "prose; changes here do not change machine semantics" for name in EXCLUDED_FILES
        },
        "files": {
            name: hashlib.sha256((BUNDLE / name).read_bytes()).hexdigest()
            for name in PINNED_FILES
        },
        "file_count": len(PINNED_FILES),
        "native_validator_pin": {
            "implementation": "c2patool",
            "version": "0.27.15",
            "source": "crates.io",
            "install_command": "cargo install c2patool --version 0.27.15 --locked",
            "pin_rationale": (
                "The native validator version is a verdict input: the same bytes have been "
                "observed to validate differently across versions, and this crate published "
                "five patch versions inside forty-eight hours. Resolving 'latest' would make "
                "recomputation unreproducible."
            ),
        },
        "c2pa_specification_version": "2.4",
    }
    out = BUNDLE / "contract.manifest.json"
    out.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"contract.manifest.json sha256: {hashlib.sha256(out.read_bytes()).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
