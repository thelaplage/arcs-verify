"""Pin the source_capture.v0.2 + source_ingest.v0.1 verifier to arcs-srs bytes.

arcs-verify is a consumer of the arcs-srs authority (commit 1f8768d). These
tests recompute the vendored profile manifests' sha256 against the recorded pin
and assert that the verifier's expectation constants are transcribed from those
exact bytes — not a fresh local dialect. If arcs-srs re-cuts either manifest, the
vendored copy must be re-pinned deliberately rather than drift silently.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from arcs_verify import verifier

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "vendor/arcs-srs/vectors"

PINNED_ARCS_SRS_COMMIT = "1f8768d68fa46c61a6b0b20c9caad8ae7de9f683"

CAPTURE_MANIFEST = (
    VECTORS / "editorial-source-capture-v0.2/profile.manifest.json"
)
INGEST_MANIFEST = (
    VECTORS / "editorial-source-ingest-v0.1/profile.manifest.json"
)

CAPTURE_MANIFEST_SHA256 = (
    "d08730e9c9e568eccc265d7b560226d10aacd67abeca9e55fd6c101af4c5c6e9"
)
INGEST_MANIFEST_SHA256 = (
    "f71ab3238599abf86838ed2987a94e00323be2fc2389d11b6062a5445efee25f"
)

CAPTURE_DOCUMENT_SHA256 = (
    "d621fa989350c010221ed91bd78017458ed73fc419f7d0c9fbecd5471167bc86"
)
INGEST_DOCUMENT_SHA256 = (
    "0454e96ea67c5f415c57ea9b7ca624165366ea0b80914bdb6be77448bdf56b98"
)


def _load(manifest: Path, expected_sha256: str) -> dict:
    raw = manifest.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    assert digest == expected_sha256, (
        f"{manifest} drifted from pin: {digest} != {expected_sha256}"
    )
    return json.loads(raw)


def test_capture_manifest_pin_and_document_sha256() -> None:
    manifest = _load(CAPTURE_MANIFEST, CAPTURE_MANIFEST_SHA256)
    assert manifest["profile_slug"] == "srs.editorial.source_capture.v0.2"
    assert manifest["document_sha256"] == CAPTURE_DOCUMENT_SHA256


def test_ingest_manifest_pin_and_document_sha256() -> None:
    manifest = _load(INGEST_MANIFEST, INGEST_MANIFEST_SHA256)
    assert manifest["profile_slug"] == "srs.editorial.source_ingest.v0.1"
    assert manifest["document_sha256"] == INGEST_DOCUMENT_SHA256


def test_capture_verifier_constants_derive_from_manifest() -> None:
    manifest = _load(CAPTURE_MANIFEST, CAPTURE_MANIFEST_SHA256)

    fixed = dict(manifest["fixed_values"])
    # profile_version is version identity, tracked separately from fixed_values.
    assert fixed.pop("profile_version") == "v0.2"
    assert verifier.SOURCE_CAPTURE_V02_FIXED_VALUES == fixed

    assert tuple(verifier.SOURCE_CAPTURE_V02_REQUIRED_FIELDS) == tuple(
        manifest["required_fields"]
    )
    assert verifier.SOURCE_CAPTURE_V02_OUTCOME_VALUES == frozenset(
        manifest["outcome_values"]
    )
    assert verifier.SOURCE_CAPTURE_V02_REQUIRED_COVERED == frozenset(
        manifest["artifact_classes_covered_required"]
    )
    assert verifier.SOURCE_CAPTURE_V02_REQUIRED_EXCLUDED == frozenset(
        manifest["artifact_classes_excluded_required"]
    )
    assert verifier.SOURCE_CAPTURE_V02_REQUIRED_LIMITATION_CODES == frozenset(
        manifest["required_machine_limitation_codes"]
    )
    assert (
        verifier.SOURCE_CAPTURE_V02_BASE_ATTESTATION_LIMIT
        == manifest["required_attestation_limits"]["base"]
    )
    assert manifest["receipt_kinds"] == ["capture_attempt"]


def test_ingest_verifier_constants_derive_from_manifest() -> None:
    manifest = _load(INGEST_MANIFEST, INGEST_MANIFEST_SHA256)

    fixed = dict(manifest["fixed_values"])
    assert fixed.pop("profile_version") == "v0.1"
    assert verifier.SOURCE_INGEST_V01_FIXED_VALUES == fixed

    assert tuple(verifier.SOURCE_INGEST_V01_REQUIRED_FIELDS) == tuple(
        manifest["required_fields"]
    )
    assert verifier.SOURCE_INGEST_V01_REQUIRED_COVERED == frozenset(
        manifest["artifact_classes_covered_required"]
    )
    assert verifier.SOURCE_INGEST_V01_REQUIRED_EXCLUDED == frozenset(
        manifest["artifact_classes_excluded_required"]
    )
    assert verifier.SOURCE_INGEST_V01_REQUIRED_LIMITATION_CODES == frozenset(
        manifest["required_machine_limitation_codes"]
    )
    assert (
        verifier.SOURCE_INGEST_V01_BASE_ATTESTATION_LIMIT
        == manifest["required_attestation_limits"]["base"]
    )
    assert manifest["receipt_kinds"] == ["source_ingest"]


def test_v02_profile_is_distinct_identity_from_v01_and_v011() -> None:
    # No silent fallback / coercion: three distinct (profile_id, version) keys.
    assert (
        verifier.PROFILE_IDENTITIES[verifier.EDITORIAL_SOURCE_CAPTURE_PROFILE]
        == ("srs.editorial.source_capture", "v0.1")
    )
    assert (
        verifier.PROFILE_IDENTITIES[
            verifier.EDITORIAL_SOURCE_CAPTURE_PROFILE_V011
        ]
        == ("srs.editorial.source_capture", "v0.1.1")
    )
    assert (
        verifier.PROFILE_IDENTITIES[
            verifier.EDITORIAL_SOURCE_CAPTURE_PROFILE_V02
        ]
        == ("srs.editorial.source_capture", "v0.2")
    )
