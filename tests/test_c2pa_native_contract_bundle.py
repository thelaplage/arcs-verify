"""Contract-bundle conformance for c2pa-native-finding v0.1.

The bundle conformance checker — not JSON Schema alone — enforces the
cross-object invariants. JSON Schema can say a comparison entry has an axis and
a state; it cannot say the axis set is exactly the canonical set with no
repeats, that a divergence attributed to a clock delta must not carry an
integrity accusation, or that a comparison must be absent rather than
synthesized. This file pins that division of labour by demonstrating, for each
invariant, a report that the schema accepts and the checker rejects.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from arcs_verify.c2pa_native import (
    AXIS_ORDER,
    BUNDLE_DIR,
    FORBIDDEN_AGGREGATE_KEYS,
    build_report,
    canonical_finding_from_native_report,
    check_report,
    load_bundle,
)

ROOT = Path(__file__).resolve().parents[1]
FROZEN = ROOT / "tests" / "fixtures" / "c2pa-native" / "frozen-native-reports"
OBSERVED = ROOT / "tests" / "fixtures" / "c2pa-native" / "observed"
BUNDLE = load_bundle()

PINNED_FILES = (
    "canonical-native-finding.schema.json",
    "comparison-taxonomy.json",
    "native-finding-report.schema.json",
)

DEFAULT_TRUST = {
    "mode": "default",
    "material_digest": None,
    "material_source": None,
    "material_source_pin": None,
    "on_official_c2pa_trust_list": "not_established",
}


def _report(case: str = "CA-default-trust", observed_name: str | None = None) -> dict:
    record = json.loads((FROZEN / f"{case}.json").read_text(encoding="utf-8"))
    recomputed = canonical_finding_from_native_report(
        record["native_report"],
        side="recomputed",
        evidence_class="replayed_frozen_native_report",
        asset_digest=record["asset_digest"],
        manifest_acquisition_mode=record["manifest_acquisition_mode"],
        settings_digest=record["settings_digest"],
        trust_basis=DEFAULT_TRUST,
        bundle=BUNDLE,
        manifest_store_digest=record["external_manifest_digest"],
        validation_instant="2026-08-15T12:00:00Z",
    )
    observed = None
    if observed_name:
        observed = json.loads((OBSERVED / f"{observed_name}.json").read_text(encoding="utf-8"))["finding"]
    return build_report(
        subject={"asset_digest": record["asset_digest"], "asset_label": record["asset"]},
        recomputed=recomputed,
        observed=observed,
        bundle=BUNDLE,
    )


def _comparison(report: dict, axis: str) -> dict:
    return next(item for item in report["comparison"] if item["axis"] == axis)


# ---------------------------------------------------------------------------
# Bundle shape and pinning
# ---------------------------------------------------------------------------


def test_bundle_contains_the_expected_artifacts():
    names = {path.name for path in BUNDLE_DIR.iterdir() if path.is_file()}
    assert names == set(PINNED_FILES) | {"contract.manifest.json", "README.md"}


def test_manifest_pins_only_machine_semantic_artifacts():
    """README bytes and the manifest itself are deliberately outside the pin.

    A consumer pins the manifest digest. If prose changed that digest, a
    clarification to the README would look identical to a semantic change, and
    consumers would learn to ignore pin movement.
    """
    manifest = BUNDLE.manifest
    assert set(manifest["files"]) == set(PINNED_FILES)
    assert "README.md" in manifest["excluded_from_pin"]
    assert "contract.manifest.json" in manifest["excluded_from_pin"]


def test_manifest_digests_match_the_bundle_bytes():
    for name, expected in BUNDLE.manifest["files"].items():
        actual = hashlib.sha256((BUNDLE_DIR / name).read_bytes()).hexdigest()
        assert actual == expected, f"{name} drifted from contract.manifest.json"


def test_reports_carry_the_manifest_digest_not_a_commit():
    report = _report()
    expected = "sha256:" + hashlib.sha256(
        (BUNDLE_DIR / "contract.manifest.json").read_bytes()
    ).hexdigest()
    assert report["contract_manifest_digest"] == expected


def test_native_validator_is_pinned_to_an_exact_version():
    pin = BUNDLE.manifest["native_validator_pin"]
    assert pin["version"] == "0.27.15"
    assert "--locked" in pin["install_command"]
    assert "latest" not in pin["install_command"]


def test_taxonomy_covers_every_axis_exactly_once():
    assert set(BUNDLE.taxonomy["axes"]) == set(AXIS_ORDER)


def test_every_axis_declares_a_reproducibility_class():
    valid = set(BUNDLE.taxonomy["reproducibility_classes"])
    for name, spec in BUNDLE.taxonomy["axes"].items():
        assert spec["reproducibility_class"] in valid, name
        for contributing in spec.get("contributing_reproducibility_classes", []):
            assert contributing in valid, (name, contributing)


def test_no_native_code_maps_to_two_axes():
    seen: dict[str, str] = {}
    for name, spec in BUNDLE.taxonomy["axes"].items():
        for code in spec.get("native_codes", {}):
            assert code not in seen, f"{code} maps to both {seen.get(code)} and {name}"
            seen[code] = name


def test_reason_posture_matrix_is_total_over_declared_states():
    matrix = BUNDLE.taxonomy["reason_posture_matrix"]
    states = set(BUNDLE.taxonomy["comparison_states"])
    reasons = set(BUNDLE.taxonomy["comparison_reasons"])
    postures = set(BUNDLE.taxonomy["integrity_postures"])
    assert states <= set(matrix)
    for state, allowed in matrix.items():
        if state.startswith("_"):
            continue
        assert set(allowed) <= reasons, state
        assert set(allowed.values()) <= postures, state


def test_only_same_inputs_same_semantics_can_accuse():
    """Exactly one reason, in exactly one state, licenses an integrity inference."""
    matrix = BUNDLE.taxonomy["reason_posture_matrix"]
    accusing = [
        (state, reason)
        for state, allowed in matrix.items()
        if not state.startswith("_")
        for reason, posture in allowed.items()
        if posture == "possible_substantive_divergence"
    ]
    assert accusing == [("mismatch", "same_inputs_same_semantics")]


def test_taxonomy_forbids_the_aggregate_boolean_by_name():
    forbidden = set(BUNDLE.taxonomy["prohibited_constructs"]["aggregate_match_boolean"]["forbidden_names"])
    assert "native_observation_matches_recomputation" in forbidden
    assert forbidden <= FORBIDDEN_AGGREGATE_KEYS


def test_report_schema_has_no_aggregate_match_property():
    schema = json.dumps(BUNDLE.report_schema)
    for name in FORBIDDEN_AGGREGATE_KEYS:
        assert f'"{name}"' not in schema


def test_unexercised_paths_are_recorded_not_claimed():
    """Paths with no specimen are named, and no input was manufactured for them."""
    unexercised = BUNDLE.taxonomy["unexercised_paths"]
    assert "signingCredential.revoked" in unexercised["codes"]
    assert any("official public C2PA trust list" in item for item in unexercised["features"])
    assert unexercised["codes"], "an empty unexercised list would be a claim of full coverage"


# ---------------------------------------------------------------------------
# The checker enforces what JSON Schema cannot
# ---------------------------------------------------------------------------


def test_baseline_reports_are_conformant():
    assert check_report(_report(), bundle=BUNDLE).conformant
    assert check_report(_report(observed_name="CA-observed-matching"), bundle=BUNDLE).conformant


def _schema_accepts(report: dict) -> bool:
    """Whether JSON Schema alone accepts this report."""
    import jsonschema
    from jsonschema import validators
    from referencing import Registry, Resource

    registry = Registry().with_resources(
        [
            (BUNDLE.finding_schema["$id"], Resource.from_contents(BUNDLE.finding_schema)),
            (BUNDLE.report_schema["$id"], Resource.from_contents(BUNDLE.report_schema)),
        ]
    )
    cls = validators.validator_for(BUNDLE.report_schema)
    return not list(cls(BUNDLE.report_schema, registry=registry).iter_errors(report))


def test_duplicate_comparison_axis_passes_schema_and_fails_checker():
    report = _report(observed_name="CA-observed-matching")
    report["comparison"].append(dict(report["comparison"][0]))
    assert _schema_accepts(report), "schema is expected to accept a duplicated axis"
    result = check_report(report, bundle=BUNDLE)
    assert not result.conformant
    assert any("C2PA_AXIS_DUPLICATE" in f for f in result.findings)


def test_missing_comparison_axis_passes_schema_and_fails_checker():
    report = _report(observed_name="CA-observed-matching")
    report["comparison"] = [item for item in report["comparison"] if item["axis"] != "timestamp"]
    assert _schema_accepts(report)
    result = check_report(report, bundle=BUNDLE)
    assert not result.conformant
    assert any("C2PA_AXIS_COVERAGE" in f for f in result.findings)


def test_illegal_reason_for_state_passes_schema_and_fails_checker():
    report = _report(observed_name="CA-observed-matching")
    _comparison(report, "claim_signature")["comparison_reason"] = "trust_basis_delta"
    assert _schema_accepts(report)
    result = check_report(report, bundle=BUNDLE)
    assert not result.conformant
    assert any("C2PA_REASON_ILLEGAL_FOR_STATE" in f for f in result.findings)


def test_illegal_posture_for_reason_passes_schema_and_fails_checker():
    report = _report(observed_name="CA-observed-matching")
    _comparison(report, "claim_signature")["integrity_posture"] = "possible_substantive_divergence"
    assert _schema_accepts(report)
    result = check_report(report, bundle=BUNDLE)
    assert not result.conformant
    assert any("C2PA_POSTURE_ILLEGAL_FOR_REASON" in f for f in result.findings)


def test_declared_status_not_grounded_in_the_side_is_rejected():
    report = _report(observed_name="CA-observed-matching")
    _comparison(report, "claim_signature")["observed_status"] = "failed"
    assert _schema_accepts(report)
    result = check_report(report, bundle=BUNDLE)
    assert not result.conformant
    assert any("C2PA_STATUS_NOT_GROUNDED" in f for f in result.findings)


def test_comparability_must_be_recomputed_not_asserted():
    report = _report(observed_name="CA-observed-trust-basis-delta")
    report["comparability"]["trust_basis_match"] = True
    assert _schema_accepts(report)
    result = check_report(report, bundle=BUNDLE)
    assert not result.conformant
    assert any("C2PA_COMPARABILITY_NOT_RECOMPUTED" in f for f in result.findings)


def test_integrity_accusation_without_a_comparable_basis_is_rejected():
    report = _report(observed_name="CA-observed-trust-basis-delta")
    entry = _comparison(report, "signer_trust")
    entry["state"] = "mismatch"
    entry["comparison_reason"] = "same_inputs_same_semantics"
    entry["integrity_posture"] = "possible_substantive_divergence"
    result = check_report(report, bundle=BUNDLE)
    assert not result.conformant
    assert any("C2PA_INTEGRITY_" in f for f in result.findings)


@pytest.mark.parametrize("name", sorted(FORBIDDEN_AGGREGATE_KEYS))
def test_forbidden_aggregate_key_anywhere_is_rejected(name):
    report = _report()
    report["recomputed"]["axes"][0][name] = True
    result = check_report(report, bundle=BUNDLE)
    assert not result.conformant
    assert any("C2PA_AGGREGATE_FORBIDDEN" in f for f in result.findings)


def test_non_hermetic_settings_are_rejected():
    report = _report()
    report["recomputed"]["settings"]["remote_manifest_fetch"] = True
    report["recomputed"]["settings"]["hermeticity"]["network_access_permitted"] = True
    result = check_report(report, bundle=BUNDLE)
    assert not result.conformant
    assert any("C2PA_HERMETICITY" in f for f in result.findings)


def test_a_pinnable_validation_clock_is_rejected():
    """No settings path makes the validation instant caller-pinnable."""
    report = _report()
    report["recomputed"]["validation_clock"]["caller_pinnable"] = True
    result = check_report(report, bundle=BUNDLE)
    assert not result.conformant
    assert any("C2PA_CLOCK" in f for f in result.findings)


def test_mislabelled_sides_are_rejected():
    report = _report(observed_name="CA-observed-matching")
    report["observed"]["side"] = "recomputed"
    result = check_report(report, bundle=BUNDLE)
    assert not result.conformant
    assert any("C2PA_SIDE_LABEL" in f for f in result.findings)


def test_match_without_equality_is_rejected():
    report = _report(observed_name="CA-observed-trust-basis-delta")
    entry = _comparison(report, "signer_trust")
    entry["state"] = "match"
    entry["comparison_reason"] = "same_inputs_same_semantics"
    entry["integrity_posture"] = "no_integrity_inference"
    result = check_report(report, bundle=BUNDLE)
    assert not result.conformant
    assert any("C2PA_MATCH_WITHOUT_EQUALITY" in f for f in result.findings)


def test_every_report_carries_limitations_and_non_claims():
    report = _report()
    assert report["limitations"] and report["non_claims"]
    joined = " ".join(report["non_claims"])
    assert "unrevoked" in joined
    assert "official public C2PA trust list" in joined
