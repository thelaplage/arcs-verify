"""Independent structural verifier support for the registered
srs.activity.public_publication.v0.1 SRS profile.

Authority is consumed from exact arcs-srs bytes pinned at
61dcc45414745f57b01b91e64b21d580242a8ae8. Runtime copies are packaged inside
arcs_verify so an installed wheel does not depend on the source checkout's
top-level vendor tree. The pinned Git-blob identities are unchanged. This
module does not import arcs-srs or any producer implementation and performs no
publication action.

It owns profile-specific structural conformance only. Envelope validation,
raw-content exclusion, Ed25519 verification, key resolution, and trust remain
separate findings in arcs_verify.verifier.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

PROFILE = "srs.activity.public_publication.v0.1"
SOURCE_REPOSITORY = "thelaplage/arcs-srs"
SOURCE_COMMIT = "61dcc45414745f57b01b91e64b21d580242a8ae8"

# Historical/source-checkout provenance tree. Tests and audit tooling may use
# its vectors and fixtures, but installed wheels cannot rely on this path
# existing outside the Python package.
VENDOR_ROOT = (
    Path(__file__).resolve().parents[1]
    / "vendor"
    / "arcs-srs"
    / "profiles"
    / PROFILE
)

# Runtime authority must travel with the verifier distribution. These three
# files are byte-identical copies of the pinned arcs-srs authority blobs below;
# the same Git-blob checks are recomputed before they are consumed.
PACKAGED_AUTHORITY_ROOT = (
    Path(__file__).resolve().parent
    / "data"
    / "profiles"
    / PROFILE
)
MANIFEST_PATH = PACKAGED_AUTHORITY_ROOT / "profile.manifest.json"
RULES_PATH = PACKAGED_AUTHORITY_ROOT / "conformance.rules.json"
FIELD_SCHEMA_PATH = PACKAGED_AUTHORITY_ROOT / "field.schema.json"

PINNED_GIT_BLOBS = {
    "profile.manifest.json": "ca9e6dcef54d8e8e965109fb72ac86d61eb77247",
    "conformance.rules.json": "29f40ebcff2490fb2fbeb5f25261e8671fd9efe5",
    "field.schema.json": "e7fb25d9b243e3dafd7d49b9b3932c386ff4db57",
}


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"public publication authority is not a JSON object: {path.name}")
    return value


def _git_blob_sha1(path: Path) -> str:
    raw = path.read_bytes()
    preimage = b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw
    return hashlib.sha1(preimage).hexdigest()


def load_registered_authority() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    for filename, expected in PINNED_GIT_BLOBS.items():
        path = PACKAGED_AUTHORITY_ROOT / filename
        actual = _git_blob_sha1(path)
        if actual != expected:
            raise ValueError(
                f"public publication authority blob mismatch for {filename}: "
                f"expected={expected}:actual={actual}"
            )

    manifest = _load_json(MANIFEST_PATH)
    rules = _load_json(RULES_PATH)
    field_schema = _load_json(FIELD_SCHEMA_PATH)

    if manifest.get("profile_slug") != PROFILE:
        raise ValueError("public publication manifest profile does not match")
    if manifest.get("release_stage") != "provisional":
        raise ValueError("public publication manifest release stage does not match")
    if rules.get("profile_slug") != PROFILE:
        raise ValueError("public publication rules profile does not match")
    if rules.get("extensions_policy") != "empty_only":
        raise ValueError("public publication rules extensions policy does not match")

    return manifest, rules, field_schema


def _schema_error_code(error: Any) -> str:
    path = ".".join(str(part) for part in error.path) or "$"
    return f"public_publication.field_schema:{path}:{error.validator}"


def profile_errors(receipt: dict[str, Any]) -> list[str]:
    """Return stable failure codes for supported-profile structural violations."""
    _, rules, field_schema = load_registered_authority()
    errors: list[str] = []

    schema_errors = sorted(
        Draft202012Validator(field_schema).iter_errors(receipt),
        key=lambda error: (list(error.path), error.validator),
    )
    errors.extend(_schema_error_code(error) for error in schema_errors)

    if receipt.get("subject_ref") != receipt.get("artifact_ref"):
        errors.append("public_publication.subject_ref_mismatch")

    artifact_digest = receipt.get("artifact_digest")
    manifest_digest = receipt.get("artifact_manifest_digest")
    if (
        isinstance(artifact_digest, str)
        and isinstance(manifest_digest, str)
        and artifact_digest != manifest_digest
    ):
        errors.append("public_publication.manifest_identity_mismatch")

    reference_pattern = rules.get("reference_pattern")
    max_length = rules.get("reference_max_length")

    def is_ref(value: Any) -> bool:
        if not isinstance(value, str):
            return False
        if not isinstance(max_length, int) or len(value) > max_length:
            return False
        if not isinstance(reference_pattern, str):
            return False
        import re
        return re.fullmatch(reference_pattern, value) is not None

    seats = [
        receipt.get("actor_ref"),
        receipt.get("proposal_ref"),
        receipt.get("authority_basis_ref"),
        receipt.get("decision_ref"),
        receipt.get("execution_ref"),
        receipt.get("outcome_ref"),
    ]
    present = [value for value in seats if value is not None and is_ref(value)]
    if len(present) != len(set(present)):
        errors.append("public_publication.semantic_identity_collapse")

    return list(dict.fromkeys(errors))