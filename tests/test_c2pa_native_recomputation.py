"""ARCSV-C2PA0 acceptance suite: hermetic native C2PA recomputation and comparison.

Hermetic execution model
------------------------
Every test here runs with no network, no credentials, and no mutable external
resource. The `recomputed` side of each report is genuine output of the pinned
native validator over the real specimen bytes, in one of two evidence classes:

* ``live_native_invocation`` — the pinned validator is present on this machine
  and is invoked now. Gated on ``ARCS_VERIFY_C2PATOOL`` naming a build whose
  version matches the contract pin.
* ``replayed_frozen_native_report`` — a recorded output of that same pinned
  validator, committed under ``fixtures/c2pa-native/frozen-native-reports/`` by
  ``tools/generate_c2pa_native_fixtures.py``.

A replayed frozen report is never presented as a fresh independent
recomputation; the evidence class travels with it into the report.
"""

from __future__ import annotations

import copy
import json
import os
import subprocess
import tempfile
from pathlib import Path

import pytest

from arcs_verify.c2pa_native import (
    AXIS_ORDER,
    HERMETIC_SETTINGS_TOML,
    PINNED_VALIDATOR,
    VALIDATOR_ENV,
    _classify_invocation,
    build_report,
    canonical_finding_from_native_report,
    canonical_finding_unavailable,
    check_report,
    digest_text,
    load_bundle,
    native_validation_state,
    native_validator_version,
    parse_native_report,
    recompute,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "c2pa-native"
SPECIMENS = FIXTURES / "specimens"
FROZEN = FIXTURES / "frozen-native-reports"
OBSERVED = FIXTURES / "observed"
TRUST = FIXTURES / "trust"

BUNDLE = load_bundle()

DEFAULT_TRUST = {
    "mode": "default",
    "material_digest": None,
    "material_source": None,
    "material_source_pin": None,
    "on_official_c2pa_trust_list": "not_established",
}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def frozen(case: str) -> dict:
    return json.loads((FROZEN / f"{case}.json").read_text(encoding="utf-8"))


def observed_fixture(name: str) -> dict:
    payload = json.loads((OBSERVED / f"{name}.json").read_text(encoding="utf-8"))
    assert payload["x_fixture_provenance"] == "constructed"
    return payload["finding"]


def replay(case: str, *, trust: dict | None = None, instant: str = "2026-08-15T12:00:00Z") -> dict:
    """Build a recomputed-side canonical finding from a frozen native report."""
    record = frozen(case)
    if record["evaluation_status"] != "evaluated":
        return canonical_finding_unavailable(
            side="recomputed",
            evidence_class="replayed_frozen_native_report",
            asset_digest=record["asset_digest"],
            manifest_acquisition_mode=record["manifest_acquisition_mode"],
            settings_digest=record["settings_digest"],
            trust_basis=trust or DEFAULT_TRUST,
            detail=record["evaluation_status_detail"],
            unresolved_inputs=[
                {
                    "input": "manifest_store",
                    "reason": "required manifest store not available locally under hermetic settings",
                    "uri": None,
                }
            ],
            bundle=BUNDLE,
            validation_instant=instant,
        )
    return canonical_finding_from_native_report(
        record["native_report"],
        side="recomputed",
        evidence_class="replayed_frozen_native_report",
        asset_digest=record["asset_digest"],
        manifest_acquisition_mode=record["manifest_acquisition_mode"],
        settings_digest=record["settings_digest"],
        trust_basis=trust or DEFAULT_TRUST,
        bundle=BUNDLE,
        manifest_store_digest=record["external_manifest_digest"],
        native_report_digest=None,
        validation_instant=instant,
    )


def axis(finding: dict, name: str) -> dict:
    return next(item for item in finding["axes"] if item["axis"] == name)


def comparison_for(report: dict, name: str) -> dict:
    return next(item for item in report["comparison"] if item["axis"] == name)


def report_for(case: str, *, observed: dict | None = None, trust: dict | None = None) -> dict:
    record = frozen(case)
    return build_report(
        subject={"asset_digest": record["asset_digest"], "asset_label": record["asset"]},
        recomputed=replay(case, trust=trust),
        observed=observed,
        bundle=BUNDLE,
    )


def live_validator() -> str | None:
    path = os.environ.get(VALIDATOR_ENV)
    if not path or not Path(path).exists():
        return None
    if native_validator_version(path) != PINNED_VALIDATOR["version"]:
        return None
    return path


requires_live = pytest.mark.skipif(
    live_validator() is None,
    reason=(
        f"pinned native validator not available; set {VALIDATOR_ENV} to a "
        f"{PINNED_VALIDATOR['implementation']} {PINNED_VALIDATOR['version']} build. "
        "The hermetic suite runs without it by replaying frozen native reports."
    ),
)


# ---------------------------------------------------------------------------
# HARNESS RULE — the obvious implementation is wrong
# ---------------------------------------------------------------------------


def test_harness_never_derives_semantics_from_exit_status():
    """Exit status separates 'could not evaluate' from 'evaluated', not valid from invalid.

    The pinned validator exits 0 for ``validation_state: Valid`` AND for
    ``validation_state: Invalid``, and exits non-zero only when a required input
    is unavailable. A harness that gated on ``exit_status == 0`` would classify a
    tampered asset as a success. This is the single most load-bearing regression
    in the suite because the wrong implementation is the natural one.
    """
    valid = frozen("CA-default-trust")
    invalid = frozen("XCA-asset-binding-mismatch")
    unavailable = frozen("cloud-manifest-not-captured")

    # The recorded exit statuses are themselves the evidence.
    assert valid["process_exit_status"] == 0
    assert invalid["process_exit_status"] == 0
    assert unavailable["process_exit_status"] == 1

    # Identical exit status, opposite native verdicts.
    assert valid["native_report"]["validation_state"] == "Valid"
    assert invalid["native_report"]["validation_state"] == "Invalid"

    # And the classifier agrees with the report, not with the exit status.
    assert valid["evaluation_status"] == "evaluated"
    assert invalid["evaluation_status"] == "evaluated"
    assert unavailable["evaluation_status"] == "input_unavailable"


def test_classifier_ignores_exit_status_when_a_report_is_present():
    """A non-zero exit alongside a parseable report is still an evaluation."""
    payload = json.dumps(frozen("XCA-asset-binding-mismatch")["native_report"])
    for exit_status in (0, 1, 2, 255):
        outcome = _classify_invocation(payload, "", exit_status)
        assert outcome.evaluation_status == "evaluated"
        assert outcome.exit_status == exit_status


def test_classifier_reports_unavailable_not_failure_when_no_report():
    outcome = _classify_invocation(
        "", "Error: must fetch remote manifests from url https://example.invalid/m", 1
    )
    assert outcome.evaluation_status == "input_unavailable"
    assert outcome.report is None


def test_zero_exit_without_a_report_is_not_a_pass():
    outcome = _classify_invocation("", "", 0)
    assert outcome.evaluation_status == "invocation_error"


# ---------------------------------------------------------------------------
# Parser rule — scoped validation_results, never the legacy flattened array
# ---------------------------------------------------------------------------


def test_parser_reads_scoped_results_and_ignores_legacy_flattened_array():
    """The legacy top-level array duplicates entries with no scope marker.

    On the expired-certificate specimen the legacy ``validation_status`` array
    lists each code twice, because active-manifest and ingredient findings
    collapse together. The scoped parser must not inherit those duplicates.
    """
    report = frozen("expired-signing-certificate")["native_report"]
    legacy = [item["code"] for item in report.get("validation_status") or []]
    assert len(legacy) > len(set(legacy)), "fixture no longer exhibits the legacy duplication"

    entries = parse_native_report(report)
    active = [e for e in entries if e.scope == "activeManifest"]
    assert len(active) == len(set((e.code, e.url) for e in active))
    assert all(e.scope in {"activeManifest", "ingredientDeltas"} for e in entries)


def test_parser_handles_ingredient_deltas_as_a_list():
    """``ingredientDeltas`` is a list of scoped delta objects, not a severity map."""
    report = frozen("CA-default-trust")["native_report"]
    raw = report["validation_results"]["ingredientDeltas"]
    assert isinstance(raw, list)
    entries = [e for e in parse_native_report(report) if e.scope == "ingredientDeltas"]
    assert entries, "fixture carries no ingredient deltas"
    assert all(e.ingredient_assertion_uri for e in entries)


def test_parser_ignores_a_legacy_only_report():
    """A report carrying only the legacy array yields no findings at all."""
    assert parse_native_report({"validation_status": [{"code": "assertion.dataHash.match"}]}) == []


# ---------------------------------------------------------------------------
# ACCEPTANCE CASE 1 — validity and trust remain distinct
# ---------------------------------------------------------------------------


def test_acceptance_1_valid_with_untrusted_signer_keeps_axes_distinct():
    record = frozen("CA-default-trust")
    assert record["native_report"]["validation_state"] == "Valid"

    finding = replay("CA-default-trust")
    assert finding["native_validation_state"] == "Valid"
    assert axis(finding, "claim_signature")["status"] == "satisfied"
    assert axis(finding, "asset_binding")["status"] == "satisfied"
    # Valid co-occurs with an untrusted signer. Collapsing these would publish
    # untrusted content as valid.
    assert axis(finding, "signer_trust")["status"] == "failed"

    report = report_for("CA-default-trust")
    assert check_report(report, bundle=BUNDLE).conformant


def test_acceptance_1_native_state_is_never_promoted_to_a_verdict():
    report = report_for("CA-default-trust")
    flat = json.dumps(report)
    assert "native_validation_state" in flat
    for forbidden in ("c2pa_verified", "provenance_valid", "native_observation_matches_recomputation"):
        assert forbidden not in flat
    # No top-level pass/fail exists to be mistaken for one.
    assert "passed" not in report and "verdict" not in report


# ---------------------------------------------------------------------------
# ACCEPTANCE CASE 2 — native Invalid with process exit 0
# ---------------------------------------------------------------------------


def test_acceptance_2_native_invalid_with_zero_exit_is_reported_invalid():
    record = frozen("XCA-asset-binding-mismatch")
    assert record["process_exit_status"] == 0
    assert record["native_report"]["validation_state"] == "Invalid"

    finding = replay("XCA-asset-binding-mismatch")
    assert finding["evaluation_status"] == "evaluated"
    assert finding["native_validation_state"] == "Invalid"
    assert axis(finding, "asset_binding")["status"] == "failed"
    assert check_report(report_for("XCA-asset-binding-mismatch"), bundle=BUNDLE).conformant


# ---------------------------------------------------------------------------
# ACCEPTANCE CASE 3 — sealed replay of a frozen remote manifest
# ---------------------------------------------------------------------------


def test_acceptance_3_frozen_remote_manifest_replays_sealed():
    record = frozen("cloud-sealed-replay")
    assert record["manifest_acquisition_mode"] == "remote_reference"
    assert record["external_manifest_digest"] is not None
    assert record["evaluation_status"] == "evaluated"

    finding = replay("cloud-sealed-replay")
    assert finding["inputs"]["manifest_store_digest"] == record["external_manifest_digest"]
    assert axis(finding, "asset_binding")["status"] == "satisfied"
    assert axis(finding, "claim_signature")["status"] == "satisfied"
    assert finding["settings"]["hermeticity"]["remote_resource_fetch_attempted"] is False
    assert check_report(report_for("cloud-sealed-replay"), bundle=BUNDLE).conformant


@requires_live
def test_acceptance_3_sealed_replay_live():
    """The same subject, recomputed live from frozen local inputs alone."""
    with tempfile.TemporaryDirectory() as tmp:
        settings = Path(tmp) / "hermetic.toml"
        settings.write_text(HERMETIC_SETTINGS_TOML, encoding="utf-8")
        report = recompute(
            SPECIMENS / "cloud.jpg",
            executable=live_validator(),
            settings_path=settings,
            external_manifest=SPECIMENS / "cloud_remote_manifest.c2pa",
            manifest_acquisition_mode="remote_reference",
            bundle=BUNDLE,
        )
    assert report["recomputed"]["evaluation_status"] == "evaluated"
    assert axis(report["recomputed"], "asset_binding")["status"] == "satisfied"
    assert check_report(report, bundle=BUNDLE).conformant


# ---------------------------------------------------------------------------
# ACCEPTANCE CASE 4 — remote manifest not captured
# ---------------------------------------------------------------------------


def test_acceptance_4_uncaptured_remote_manifest_is_unavailable_not_failed():
    record = frozen("cloud-manifest-not-captured")
    assert record["evaluation_status"] == "input_unavailable"
    assert record["native_report"] is None

    finding = replay("cloud-manifest-not-captured")
    assert finding["evaluation_status"] == "input_unavailable"
    assert finding["native_validation_state"] is None
    # An unavailable input is NOT a validation failure. No axis may say failed.
    assert {item["status"] for item in finding["axes"]} == {"not_evaluated"}
    assert finding["inputs"]["unresolved_inputs"]
    assert finding["settings"]["hermeticity"]["network_access_permitted"] is False
    assert check_report(report_for("cloud-manifest-not-captured"), bundle=BUNDLE).conformant


def test_acceptance_4_unavailable_reported_as_failure_is_rejected():
    """The checker refuses a report that launders unavailability into a failure."""
    report = report_for("cloud-manifest-not-captured")
    axis(report["recomputed"], "asset_binding")["status"] = "failed"
    result = check_report(report, bundle=BUNDLE)
    assert not result.conformant
    assert any("C2PA_UNAVAILABLE_AS_FAILURE" in f for f in result.findings)


@requires_live
def test_acceptance_4_no_network_is_attempted_live():
    with tempfile.TemporaryDirectory() as tmp:
        settings = Path(tmp) / "hermetic.toml"
        settings.write_text(HERMETIC_SETTINGS_TOML, encoding="utf-8")
        report = recompute(
            SPECIMENS / "cloud.jpg",
            executable=live_validator(),
            settings_path=settings,
            manifest_acquisition_mode="remote_reference",
            bundle=BUNDLE,
        )
    assert report["recomputed"]["evaluation_status"] == "input_unavailable"
    assert {item["status"] for item in report["recomputed"]["axes"]} == {"not_evaluated"}


# ---------------------------------------------------------------------------
# ACCEPTANCE CASE 5 — trust-basis delta on identical bytes
# ---------------------------------------------------------------------------


def test_acceptance_5_trust_basis_delta_is_not_comparable():
    """Same asset bytes, different trust material: no divergence claim is available.

    The recomputation ran under default trust and found the signer untrusted.
    The observation ran under a supplied allowed list and found it trusted. Not
    one byte of the asset differs. Trust is an input to the finding, so the
    honest comparison state is ``not_comparable``.
    """
    observed = observed_fixture("CA-observed-trust-basis-delta")
    report = report_for("CA-default-trust", observed=observed)

    assert report["comparability"]["asset_digest_match"] is True
    assert report["comparability"]["trust_basis_match"] is False

    trust = comparison_for(report, "signer_trust")
    assert trust["state"] == "not_comparable"
    assert trust["comparison_reason"] == "trust_basis_delta"
    assert trust["integrity_posture"] == "no_integrity_inference"
    assert trust["observed_status"] == "satisfied"
    assert trust["recomputed_status"] == "failed"
    assert check_report(report, bundle=BUNDLE).conformant


def test_acceptance_5_trust_delta_never_yields_an_integrity_accusation():
    report = report_for("CA-default-trust", observed=observed_fixture("CA-observed-trust-basis-delta"))
    postures = {item["integrity_posture"] for item in report["comparison"]}
    assert "possible_substantive_divergence" not in postures


@requires_live
def test_acceptance_5_trust_material_changes_the_finding_live():
    """The same bytes yield a different trust finding under different material."""
    pem = (TRUST / "ca-signer-ee.pem").read_text(encoding="utf-8").strip()
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp) / "hermetic.toml"
        base.write_text(HERMETIC_SETTINGS_TOML, encoding="utf-8")
        allowed = Path(tmp) / "allowed.toml"
        allowed.write_text(
            HERMETIC_SETTINGS_TOML + f'[trust]\nallowed_list = """{pem}"""\n', encoding="utf-8"
        )
        default_report = recompute(
            SPECIMENS / "CA.jpg", executable=live_validator(), settings_path=base, bundle=BUNDLE
        )
        trusted_report = recompute(
            SPECIMENS / "CA.jpg", executable=live_validator(), settings_path=allowed, bundle=BUNDLE
        )
    assert axis(default_report["recomputed"], "signer_trust")["status"] == "failed"
    assert axis(trusted_report["recomputed"], "signer_trust")["status"] == "satisfied"
    assert default_report["subject"]["asset_digest"] == trusted_report["subject"]["asset_digest"]


# ---------------------------------------------------------------------------
# ACCEPTANCE CASE 6 — wall-clock-sensitive certificate state
# ---------------------------------------------------------------------------


def test_acceptance_6_wall_clock_divergence_makes_no_integrity_accusation():
    """A certificate that aged out is not a failed hermetic replay.

    The producer observed this subject while the signing certificate was inside
    its validity window. The recomputation runs after the window closed. The
    bytes are identical and the validator is identical; the only thing that
    changed is the wall clock, and the native validator exposes no
    validation-clock control anywhere in its settings hierarchy. This must not
    become an integrity accusation.
    """
    observed = observed_fixture("expired-observed-before-expiry")
    report = report_for("expired-signing-certificate", observed=observed)

    assert report["comparability"]["asset_digest_match"] is True
    assert report["comparability"]["validator_version_match"] is True

    validity = comparison_for(report, "signer_validity")
    assert validity["reproducibility_class"] == "time_dependent"
    assert validity["observed_status"] == "satisfied"
    assert validity["recomputed_status"] == "failed"
    assert validity["state"] == "not_comparable"
    assert validity["comparison_reason"] == "validation_clock_delta"
    assert validity["integrity_posture"] == "no_integrity_inference"
    assert check_report(report, bundle=BUNDLE).conformant


def test_acceptance_6_hermetic_does_not_mean_timeless():
    """Hermeticity facts are provable; the validation clock still is not pinnable."""
    finding = replay("expired-signing-certificate")
    hermeticity = finding["settings"]["hermeticity"]
    assert hermeticity["network_access_permitted"] is False
    assert hermeticity["remote_resource_fetch_attempted"] is False
    assert hermeticity["trust_list_uri_dereferenced"] is False
    assert hermeticity["ocsp_fetch_permitted"] is False
    # And yet:
    assert finding["validation_clock"]["source"] == "wall_clock"
    assert finding["validation_clock"]["caller_pinnable"] is False


def test_acceptance_6_integrity_accusation_on_a_time_dependent_axis_is_rejected():
    """Even a hand-edited report cannot smuggle an accusation onto a clock-dependent axis."""
    report = report_for("expired-signing-certificate", observed=observed_fixture("expired-observed-before-expiry"))
    entry = comparison_for(report, "signer_validity")
    entry["state"] = "mismatch"
    entry["comparison_reason"] = "same_inputs_same_semantics"
    entry["integrity_posture"] = "possible_substantive_divergence"
    result = check_report(report, bundle=BUNDLE)
    assert not result.conformant
    assert any("C2PA_INTEGRITY_ON_NONDETERMINISTIC_AXIS" in f for f in result.findings)


# ---------------------------------------------------------------------------
# ACCEPTANCE CASE 7 — trusted timestamp represented independently
# ---------------------------------------------------------------------------


def test_acceptance_7_trusted_timestamp_is_its_own_axis():
    finding = replay("CA-default-trust")
    timestamp = axis(finding, "timestamp")
    assert timestamp["status"] == "satisfied"
    codes = {item["code"] for item in timestamp["native_findings"]}
    assert {"timeStamp.validated", "timeStamp.trusted"} <= codes
    # Independent of trust and of validity: the signer is untrusted on this very
    # specimen while the timestamp is both validated and trusted.
    assert axis(finding, "signer_trust")["status"] == "failed"
    assert finding["validation_clock"]["anchored_by_trusted_timestamp"] is True


def test_acceptance_7_untrusted_timestamp_is_indeterminate_not_failed():
    """An informational-only timestamp finding is not a failure and not a pass."""
    finding = replay("CACA-default-trust")
    timestamp = axis(finding, "timestamp")
    codes = {item["code"] for item in timestamp["native_findings"]}
    assert "timeStamp.untrusted" in codes
    assert timestamp["status"] == "indeterminate"


def test_acceptance_7_timestamp_absence_is_not_evaluated():
    """The expired-certificate specimen carries no timestamp code at all."""
    finding = replay("expired-signing-certificate")
    timestamp = axis(finding, "timestamp")
    assert timestamp["native_findings"] == []
    assert timestamp["status"] == "not_evaluated"
    assert finding["validation_clock"]["anchored_by_trusted_timestamp"] is False


# ---------------------------------------------------------------------------
# ACCEPTANCE CASE 8 — asset mutation
# ---------------------------------------------------------------------------


def test_acceptance_8_asset_binding_failure_leaves_other_axes_separate():
    finding = replay("XCA-asset-binding-mismatch")
    assert axis(finding, "asset_binding")["status"] == "failed"
    # The claim signature, the manifest structure, and the timestamp are all
    # unaffected by the asset mutation and must not be dragged down with it.
    assert axis(finding, "claim_signature")["status"] == "satisfied"
    assert axis(finding, "manifest_structure")["status"] == "satisfied"
    assert axis(finding, "timestamp")["status"] == "satisfied"
    assert axis(finding, "signer_trust")["status"] == "failed"  # independently, for trust reasons


def test_acceptance_8_claim_signature_failure_leaves_asset_binding_intact():
    """The converse specimen: signature broken, binding intact. The axes are orthogonal."""
    finding = replay("E-sig-CA-claim-signature-mismatch")
    assert axis(finding, "claim_signature")["status"] == "failed"
    assert axis(finding, "asset_binding")["status"] == "satisfied"
    assert axis(finding, "manifest_structure")["status"] == "satisfied"


@requires_live
def test_acceptance_8_locally_mutated_asset_breaks_only_the_binding():
    """Mutate the asset bytes ourselves and confirm which axis moves."""
    source = (SPECIMENS / "CA.jpg").read_bytes()
    mutated = bytearray(source)
    mutated[len(mutated) - 64] ^= 0xFF  # flip a bit in image data, well past the manifest
    with tempfile.TemporaryDirectory() as tmp:
        settings = Path(tmp) / "hermetic.toml"
        settings.write_text(HERMETIC_SETTINGS_TOML, encoding="utf-8")
        target = Path(tmp) / "CA-mutated.jpg"
        target.write_bytes(bytes(mutated))
        clean = recompute(SPECIMENS / "CA.jpg", executable=live_validator(), settings_path=settings, bundle=BUNDLE)
        dirty = recompute(target, executable=live_validator(), settings_path=settings, bundle=BUNDLE)
    assert axis(clean["recomputed"], "asset_binding")["status"] == "satisfied"
    assert axis(dirty["recomputed"], "asset_binding")["status"] == "failed"
    assert axis(dirty["recomputed"], "claim_signature")["status"] == "satisfied"
    assert clean["subject"]["asset_digest"] != dirty["subject"]["asset_digest"]


# ---------------------------------------------------------------------------
# ACCEPTANCE CASE 9 — SRS signature mutation leaves C2PA untouched
# ---------------------------------------------------------------------------

SRS_VECTORS = ROOT / "vendor/arcs-srs/vectors/signed-receipt-v0.1"
SRS_SCHEMA = ROOT / "vendor/arcs-srs/schemas/srs-envelope/v0.2.0/srs-envelope.schema.json"


def test_acceptance_9_srs_signature_mutation_does_not_touch_c2pa_validity():
    """A valid C2PA manifest may coexist with an invalid SRS signature.

    These are different signatures over different bytes established by different
    authorities. Breaking the SRS receipt signature must move the SRS signature
    axis and nothing on the C2PA side; the C2PA recomputation does not even read
    the receipt.
    """
    from arcs_verify.verifier import verify_receipt

    keyring = json.loads((SRS_VECTORS / "trust/issuer-keys.json").read_text(encoding="utf-8"))
    receipt = json.loads((SRS_VECTORS / "valid/admission-admitted.json").read_text(encoding="utf-8"))

    intact = verify_receipt(receipt, keyring, schema_path=SRS_SCHEMA, selected_profile="srs.mcp.sdk_enforcement.v0.1")
    assert intact.signature_valid

    tampered = copy.deepcopy(receipt)
    signature = tampered["receipt_signature"]["signature"]
    flipped = "A" if signature[0] != "A" else "B"
    tampered["receipt_signature"]["signature"] = flipped + signature[1:]
    broken = verify_receipt(tampered, keyring, schema_path=SRS_SCHEMA, selected_profile="srs.mcp.sdk_enforcement.v0.1")
    assert not broken.signature_valid

    # The C2PA recomputation is byte-identical across both, because the SRS
    # receipt is not one of its inputs.
    before = replay("CA-default-trust")
    after = replay("CA-default-trust")
    assert before == after
    assert axis(after, "claim_signature")["status"] == "satisfied"
    assert axis(after, "asset_binding")["status"] == "satisfied"


def test_acceptance_9_c2pa_report_declares_it_is_not_srs_verification():
    report = report_for("CA-default-trust")
    joined = " ".join(report["limitations"])
    assert "not an SRS receipt verification" in joined
    assert "SRS signatures" in joined


# ---------------------------------------------------------------------------
# ACCEPTANCE CASE 10 — observed absent
# ---------------------------------------------------------------------------


def test_acceptance_10_observed_absent_still_emits_a_recomputation():
    report = report_for("CA-default-trust")
    assert "recomputed" in report
    assert report["recomputed"]["axes"]
    assert "observed" not in report
    # Absent, not an array of synthetic not_evaluated comparisons.
    assert "comparison" not in report
    assert "comparability" not in report
    assert check_report(report, bundle=BUNDLE).conformant


def test_acceptance_10_synthetic_comparison_without_observed_is_rejected():
    report = report_for("CA-default-trust")
    report["comparison"] = [
        {
            "axis": name,
            "state": "not_evaluated",
            "comparison_reason": "insufficient_evidence",
            "integrity_posture": "not_assessable",
            "reproducibility_class": "byte_deterministic",
        }
        for name in AXIS_ORDER
    ]
    result = check_report(report, bundle=BUNDLE)
    assert not result.conformant
    assert any("C2PA_COMPARISON_UNGROUNDED" in f for f in result.findings)


def test_acceptance_10_observed_without_comparison_is_rejected():
    report = report_for("CA-default-trust", observed=observed_fixture("CA-observed-matching"))
    del report["comparison"]
    result = check_report(report, bundle=BUNDLE)
    assert not result.conformant
    assert any("C2PA_COMPARISON_MISSING" in f for f in result.findings)


def test_acceptance_10_recomputation_is_required():
    report = report_for("CA-default-trust")
    del report["recomputed"]
    result = check_report(report, bundle=BUNDLE)
    assert not result.conformant
    assert any("C2PA_RECOMPUTATION_REQUIRED" in f for f in result.findings)


# ---------------------------------------------------------------------------
# ACCEPTANCE CASE 11 — substantive divergence on a comparable basis
# ---------------------------------------------------------------------------


def test_acceptance_11_same_validator_same_inputs_axis_mismatch():
    """The one shape that reaches possible_substantive_divergence.

    Identical asset bytes, identical manifest store, identical validator
    identity and version, identical policy basis, and a byte-deterministic axis:
    the observation says the asset binding holds, the recomputation says it
    failed. Nothing but a substantive disagreement explains that. It is still a
    prompt to investigate, not a finding of tampering.
    """
    observed = observed_fixture("XCA-observed-claims-binding-satisfied")
    report = report_for("XCA-asset-binding-mismatch", observed=observed)

    assert all(report["comparability"].values()), report["comparability"]

    binding = comparison_for(report, "asset_binding")
    assert binding["state"] == "mismatch"
    assert binding["comparison_reason"] == "same_inputs_same_semantics"
    assert binding["integrity_posture"] == "possible_substantive_divergence"
    assert binding["reproducibility_class"] == "byte_deterministic"
    assert binding["observed_status"] == "satisfied"
    assert binding["recomputed_status"] == "failed"
    assert check_report(report, bundle=BUNDLE).conformant


def test_acceptance_11_unaffected_axes_stay_matched():
    """A substantive divergence on one axis does not contaminate the others."""
    report = report_for(
        "XCA-asset-binding-mismatch", observed=observed_fixture("XCA-observed-claims-binding-satisfied")
    )
    for name in ("manifest_structure", "claim_signature", "signer_trust", "timestamp"):
        entry = comparison_for(report, name)
        assert entry["state"] == "match", name
        assert entry["integrity_posture"] == "no_integrity_inference", name


def test_acceptance_11_full_agreement_produces_no_divergence():
    report = report_for("CA-default-trust", observed=observed_fixture("CA-observed-matching"))
    states = {item["axis"]: item["state"] for item in report["comparison"]}
    assert states["revocation"] == "not_comparable"
    for name in AXIS_ORDER:
        if name == "revocation":
            continue
        assert states[name] == "match", (name, states[name])
    assert check_report(report, bundle=BUNDLE).conformant


# ---------------------------------------------------------------------------
# Revocation discipline
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "case",
    ["CA-default-trust", "CA-allowed-list-trust", "XCA-asset-binding-mismatch", "cloud-sealed-replay"],
)
def test_revocation_is_always_not_evaluated(case):
    """Silence about revocation is never represented as non-revocation."""
    finding = replay(case)
    revocation = axis(finding, "revocation")
    assert revocation["status"] == "not_evaluated"
    assert "not evidence of non-revocation" in (revocation["status_reason"] or "")


def test_revocation_claimed_satisfied_is_rejected():
    report = report_for("CA-default-trust")
    axis(report["recomputed"], "revocation")["status"] = "satisfied"
    result = check_report(report, bundle=BUNDLE)
    assert not result.conformant
    assert any("C2PA_REVOCATION_IMPLIED" in f for f in result.findings)


def test_revocation_comparison_is_never_substantive():
    report = report_for("CA-default-trust", observed=observed_fixture("CA-observed-matching"))
    entry = comparison_for(report, "revocation")
    assert entry["state"] == "not_comparable"
    assert entry["comparison_reason"] == "revocation_basis_delta"
    assert entry["integrity_posture"] == "no_integrity_inference"


# ---------------------------------------------------------------------------
# Hermeticity of the suite itself
# ---------------------------------------------------------------------------


def test_settings_are_hermetic_by_construction():
    assert "remote_manifest_fetch = false" in HERMETIC_SETTINGS_TOML
    assert "ocsp_fetch = false" in HERMETIC_SETTINGS_TOML
    assert "allowed_network_hosts = []" in HERMETIC_SETTINGS_TOML
    assert digest_text(HERMETIC_SETTINGS_TOML).startswith("sha256:")


def test_frozen_reports_were_produced_under_the_pinned_validator():
    manifest = json.loads((FROZEN / "FROZEN_MANIFEST.json").read_text(encoding="utf-8"))
    assert manifest["validator"]["version"] == PINNED_VALIDATOR["version"]
    assert manifest["validator"]["implementation"] == PINNED_VALIDATOR["implementation"]
    assert manifest["hermetic_settings_digest"] == digest_text(HERMETIC_SETTINGS_TOML)


def test_frozen_reports_match_their_recorded_digests():
    import hashlib

    manifest = json.loads((FROZEN / "FROZEN_MANIFEST.json").read_text(encoding="utf-8"))
    for name, entry in manifest["cases"].items():
        path = FROZEN / entry["file"]
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        assert actual == entry["sha256"], f"{name} drifted from its recorded digest"


def test_specimens_match_their_recorded_digests():
    import hashlib

    acquisition = json.loads((SPECIMENS / "ACQUISITION.json").read_text(encoding="utf-8"))
    for name, entry in acquisition["specimens"].items():
        actual = "sha256:" + hashlib.sha256((SPECIMENS / name).read_bytes()).hexdigest()
        assert actual == entry["sha256"], f"{name} drifted from its recorded digest"


def test_c2pa_rs_specimens_are_commit_pinned():
    """Reconnaissance left these digest-recorded but not commit-recorded."""
    acquisition = json.loads((SPECIMENS / "ACQUISITION.json").read_text(encoding="utf-8"))
    source = acquisition["sources"]["c2pa-rs-fixtures"]
    assert source["commit_pinned"] is True
    assert len(source["commit"]) == 40


def test_replayed_evidence_class_is_never_presented_as_live():
    finding = replay("CA-default-trust")
    assert finding["evidence_class"] == "replayed_frozen_native_report"


def test_no_specimen_claims_official_trust_list_membership():
    """A supplied allowed list proves plumbing, not membership. Different claims."""
    pins = json.loads((TRUST / "TRUST_PINS.json").read_text(encoding="utf-8"))
    assert "NOT ESTABLISHED" in pins["official_c2pa_trust_list"]["membership_status"]
    finding = replay("CA-allowed-list-trust")
    assert finding["trust_basis"]["on_official_c2pa_trust_list"] == "not_established"


@requires_live
def test_live_recomputation_is_deterministic():
    """Two consecutive runs over identical frozen inputs agree on every axis."""
    with tempfile.TemporaryDirectory() as tmp:
        settings = Path(tmp) / "hermetic.toml"
        settings.write_text(HERMETIC_SETTINGS_TOML, encoding="utf-8")
        first = recompute(SPECIMENS / "CA.jpg", executable=live_validator(), settings_path=settings, bundle=BUNDLE)
        second = recompute(SPECIMENS / "CA.jpg", executable=live_validator(), settings_path=settings, bundle=BUNDLE)
    assert first["recomputed"]["axes"] == second["recomputed"]["axes"]
    assert first["recomputed"]["native_report_digest"] == second["recomputed"]["native_report_digest"]


@requires_live
def test_live_recomputation_matches_the_frozen_replay_on_deterministic_axes():
    """The frozen reports are genuine outputs, not stale approximations.

    Only byte-deterministic axes are compared: a time-dependent axis may
    legitimately have moved since the reports were frozen, and treating that as
    drift is exactly the mistake this contract exists to prevent.
    """
    with tempfile.TemporaryDirectory() as tmp:
        settings = Path(tmp) / "hermetic.toml"
        settings.write_text(HERMETIC_SETTINGS_TOML, encoding="utf-8")
        live = recompute(SPECIMENS / "CA.jpg", executable=live_validator(), settings_path=settings, bundle=BUNDLE)
    replayed = replay("CA-default-trust")
    for name in ("manifest_structure", "asset_binding", "claim_signature"):
        assert axis(live["recomputed"], name)["status"] == axis(replayed, name)["status"], name


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_check_accepts_a_conformant_report(tmp_path):
    from arcs_verify.c2pa_native import main

    path = tmp_path / "report.json"
    path.write_text(json.dumps(report_for("CA-default-trust")), encoding="utf-8")
    assert main(["--check", str(path)]) == 0


def test_cli_check_rejects_a_nonconformant_report(tmp_path):
    from arcs_verify.c2pa_native import main

    report = report_for("CA-default-trust")
    report["native_observation_matches_recomputation"] = True
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    assert main(["--check", str(path)]) == 1


def test_cli_requires_a_pinned_validator_rather_than_guessing(monkeypatch, capsys):
    from arcs_verify.c2pa_native import main

    monkeypatch.delenv(VALIDATOR_ENV, raising=False)
    assert main([str(SPECIMENS / "CA.jpg")]) == 2
    assert PINNED_VALIDATOR["install_command"] in capsys.readouterr().err


def test_cli_subcommand_is_registered():
    from arcs_verify import cli

    source = Path(cli.__file__).read_text(encoding="utf-8")
    assert "c2pa-native" in source


def test_no_producer_import():
    """Verifier independence: this module imports no producer or DAGR code."""
    source = (ROOT / "arcs_verify" / "c2pa_native.py").read_text(encoding="utf-8")
    for forbidden in ("import dagr", "from dagr", "import garp", "from garp"):
        assert forbidden not in source
