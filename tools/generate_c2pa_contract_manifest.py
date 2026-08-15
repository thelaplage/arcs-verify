#!/usr/bin/env python3
"""Regenerate contract.manifest.json for the c2pa-native-finding bundle.

The manifest pins ONLY the machine semantic artifacts of the bundle: the two
schemas and the comparison taxonomy. README.md is deliberately excluded.

What downstream consumers pin is NOT the digest of this file. A manifest cannot
exempt its own bytes from a hash a consumer computes over the file, and this
manifest carries prose (``authority``, ``scope_note``, ``pin_rationale``), so a
raw-file digest would move every time the prose was clarified — training
consumers to ignore pin movement, which is the failure mode the pin exists to
avoid.

Consumers pin the SEMANTIC digest instead: sha256 over the RFC 8785 canonical
form of ``contract_semantic_projection(manifest)``, which covers the contract
identity, the digests of the three pinned machine members, and the native
semantic pins, and covers nothing else. This script prints both digests and
labels which one is the pin.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from arcs_verify.c2pa_native import (  # noqa: E402
    SEMANTIC_PROJECTION_EXCLUDED_FIELDS,
    SEMANTIC_PROJECTION_ID,
    SEMANTIC_PROJECTION_INCLUDED_FIELDS,
    contract_semantic_digest,
)

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


def build_manifest() -> dict:
    return {
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
            "Pins only the machine semantic artifacts. Downstream consumers pin the SEMANTIC "
            "DIGEST described under semantic_pin — not the digest of this file, not the "
            "implementing commit, and not README bytes. A digest over this file's bytes would "
            "move whenever the prose fields below were edited, which is why no report carries "
            "one."
        ),
        "excluded_from_pin": {
            "README.md": (
                "not a member of files; prose only. Changes here do not change machine semantics."
            ),
            "contract.manifest.json": (
                "not a member of files. This file DECLARES the pin; its own bytes are not the "
                "pin. A self-declaration cannot exempt these bytes from a digest a consumer "
                "computes over the file, so sha256(contract.manifest.json) does move when the "
                "prose fields here are edited and must never be used as a downstream pin. Pin "
                "the semantic digest instead."
            ),
        },
        "semantic_pin": {
            "projection_id": SEMANTIC_PROJECTION_ID,
            "canonicalization": "RFC 8785 (JCS)",
            "digest_algorithm": "sha256",
            "computed_by": (
                "arcs_verify.c2pa_native.contract_semantic_digest(manifest); the projection "
                "itself is arcs_verify.c2pa_native.contract_semantic_projection(manifest)"
            ),
            "covers": list(SEMANTIC_PROJECTION_INCLUDED_FIELDS),
            "does_not_cover": list(SEMANTIC_PROJECTION_EXCLUDED_FIELDS)
            + [
                "README.md bytes",
                "contract.manifest.json bytes as a whole",
                "the implementing commit",
                "the behaviour of arcs_verify/c2pa_native.py",
                "the native validator binary itself (pinned by version, not vendored)",
            ],
            "note": (
                "The semantic digest identifies the machine contract this bundle publishes. It "
                "does not attest that any evaluation occurred, that any specimen is trusted, or "
                "that the pinned validator was actually run."
            ),
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


def main() -> int:
    manifest = build_manifest()
    assert set(manifest["excluded_from_pin"]) == set(EXCLUDED_FILES)
    out = BUNDLE / "contract.manifest.json"
    out.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    file_digest = hashlib.sha256(out.read_bytes()).hexdigest()
    print(f"DOWNSTREAM PIN (semantic digest): {contract_semantic_digest(manifest)}")
    print(f"contract.manifest.json file sha256 (informational, NOT the pin): {file_digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
