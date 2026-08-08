"""Tests for the srs.activity.governed_read.v0.1 profile verifier.

The governed-read profile records one governed read against a pinned basis: a
declared acting principal, a mandatory C8 visibility posture, an identity-bound
basis version, and an admitted-or-refused disposition. Content is never carried
(every digest is a ``sha256:`` reference), and no aggregate/trust/reputation/
standing field may appear (C6 no-aggregate).

Conformance is re-derived from the arcs-srs field schema (byte-pinned runtime
copy) plus the subject-binding rule; no emitter claim is trusted. These tests
drive the frozen arcs-srs #34 golden vectors, vendored under
``vendor/arcs-srs/vectors/activity-governed-read-v0.1/``.

No private keys, no producer/emitter imports: serialized receipt dicts only.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from arcs_verify.verifier import (
    ACTIVITY_GOVERNED_READ_PROFILE,
    ACTIVITY_GOVERNED_READ_SCHEMA_SHA256,
    _activity_governed_read_profile_errors,
    verify_receipt,
)

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "vendor" / "arcs-srs" / "vectors" / "activity-governed-read-v0.1"
RUNTIME_SCHEMA = (
    ROOT / "arcs_verify" / "data" / "srs.activity.governed_read.v0.1.schema.json"
)
ENVELOPE_SCHEMA = (
    ROOT / "arcs_verify" / "data" / "srs-envelope-v0.2.1.schema.json"
)

# The governed-read golden vectors are unsigned structural fixtures
# (requires_signing is false for v0.1). An empty keyring exercises the profile
# and envelope findings without asserting a signature chain.
EMPTY_KEYRING: dict[str, Any] = {"issuers": []}


def _load(name: str) -> dict[str, Any]:
    return json.loads((VECTORS / name).read_text(encoding="utf-8"))


# --- valid vectors -----------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "valid/governed-read-admitted.json",
        "valid/governed-read-refused.json",
    ],
)
def test_valid_vectors_have_no_profile_errors(name: str) -> None:
    assert _activity_governed_read_profile_errors(_load(name)) == []


@pytest.mark.parametrize(
    "name",
    [
        "valid/governed-read-admitted.json",
        "valid/governed-read-refused.json",
    ],
)
def test_valid_vectors_pass_profile_verdict(name: str) -> None:
    report = verify_receipt(
        _load(name),
        EMPTY_KEYRING,
        schema_path=ENVELOPE_SCHEMA,
        selected_profile=ACTIVITY_GOVERNED_READ_PROFILE,
    )
    assert report.profile is True
    assert report.envelope is True


# --- invalid vectors: each must fail with its exact code ---------------------


@pytest.mark.parametrize(
    "name,expected_code",
    [
        ("invalid/governed-read-missing-basis-ref.json", "MISSING_PROFILE_FIELD"),
        ("invalid/governed-read-non-c8-visibility.json", "INVALID_VISIBILITY"),
        ("invalid/governed-read-hash-malformed.json", "INVALID_DIGEST_FORMAT"),
        ("invalid/governed-read-aggregate-field.json", "AGGREGATE_FIELD_PRESENT"),
    ],
)
def test_invalid_vector_fires_exact_code(name: str, expected_code: str) -> None:
    errors = _activity_governed_read_profile_errors(_load(name))
    assert expected_code in errors, errors


@pytest.mark.parametrize(
    "name",
    [
        "invalid/governed-read-missing-basis-ref.json",
        "invalid/governed-read-non-c8-visibility.json",
        "invalid/governed-read-hash-malformed.json",
        "invalid/governed-read-aggregate-field.json",
    ],
)
def test_invalid_vector_fails_profile_verdict(name: str) -> None:
    report = verify_receipt(
        _load(name),
        EMPTY_KEYRING,
        schema_path=ENVELOPE_SCHEMA,
        selected_profile=ACTIVITY_GOVERNED_READ_PROFILE,
    )
    assert report.profile is False


# --- rules the schema states only structurally / by comment ------------------


def test_subject_binding_mismatch_fires() -> None:
    receipt = _load("valid/governed-read-admitted.json")
    receipt["subject_ref"] = "urn:dagr.basis:edition:different/2026-01@9"
    errors = _activity_governed_read_profile_errors(receipt)
    assert "governed_read.subject_binding_mismatch" in errors


def test_admitted_with_refusal_class_fires_disposition_conflict() -> None:
    receipt = _load("valid/governed-read-admitted.json")
    receipt["refusal_class"] = "POLICY_REFUSED"
    errors = _activity_governed_read_profile_errors(receipt)
    assert "governed_read.disposition_field_conflict" in errors


def test_out_of_set_refusal_class_fires() -> None:
    receipt = _load("valid/governed-read-refused.json")
    receipt["refusal_class"] = "SOME_OTHER_REASON"
    errors = _activity_governed_read_profile_errors(receipt)
    assert "governed_read.invalid_refusal_class" in errors


# --- schema sourcing / independence ------------------------------------------


def test_runtime_schema_matches_pinned_digest() -> None:
    digest = hashlib.sha256(RUNTIME_SCHEMA.read_bytes()).hexdigest()
    assert digest == ACTIVITY_GOVERNED_READ_SCHEMA_SHA256


def test_runtime_schema_is_byte_identical_to_vendored_provenance() -> None:
    vendored = (
        ROOT
        / "vendor"
        / "arcs-srs"
        / "schemas"
        / "activity-profiles"
        / "v0.1"
        / "srs.activity.governed_read.v0.1.schema.json"
    )
    assert RUNTIME_SCHEMA.read_bytes() == vendored.read_bytes()
