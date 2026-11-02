"""The adapter's profile gate agrees with the pinned arcs-srs profile on its own vectors.

The vectors are byte-exact arcs-srs fixtures (constructed there; none is a produced
observation). A gate that accepted something the pinned profile rejects, or the reverse,
would be a second dialect."""
import hashlib
import json
from pathlib import Path

import pytest

from arcs_verify import c2pa_srs_observed as adapter

ROOT = Path(__file__).resolve().parent / "pinned_vectors"
PIN = json.loads((ROOT / "PIN.json").read_text())

# What the pinned arcs-srs checker (tools/validate_srs_profile.py at SOURCE_COMMIT) reports as
# the rule-level code for each invalid vector. Recorded from running that checker; the adapter
# may report additional codes (schema, adapter policy) but must include this one.
EXPECTED_RULE_CODE = {
    "c2pa-aggregate-validity-field.json": "AGGREGATE_FIELD_PRESENT",
    "c2pa-comparison-posture-overstated.json": "COMPARISON_POSTURE_OVERSTATED",
    "c2pa-custom-basis-claims-official-trust-list.json": "TRUST_BASIS_MISREPRESENTED",
    "c2pa-exit-code-as-verdict.json": "EXIT_CODE_AS_VERDICT",
    "c2pa-input-unavailable-rendered-as-validation-failure.json": "INPUT_UNAVAILABLE_RENDERED_AS_VALIDATION_FAILURE",
    "c2pa-manifest-digest-without-bytes.json": "MANIFEST_DIGEST_WITHOUT_BYTES",
    "c2pa-missing-conditional-limitation.json": "MISSING_CONDITIONAL_MACHINE_LIMITATION",
    "c2pa-prior-report-comparison-conflict.json": "PRIOR_REPORT_COMPARISON_CONFLICT",
    "c2pa-remote-manifest-uri-missing.json": "REMOTE_MANIFEST_URI_MISSING",
    "c2pa-signer-provenance-unordered.json": "SIGNER_PROVENANCE_NOT_ORDERED",
    "c2pa-spec-version-claim-weakens-applied.json": "SPEC_VERSION_CLAIM_WEAKENS_APPLIED",
    "c2pa-subject-binding-mismatch.json": "SUBJECT_BINDING_MISMATCH",
    "c2pa-trust-observation-without-basis.json": "TRUST_OBSERVATION_WITHOUT_BASIS",
    "c2pa-trust-pointer-dereferenced.json": "TRUST_POINTER_DEREFERENCED",
    "c2pa-wrong-profile-id.json": "PROFILE_ID_MISMATCH",
}


def load(kind, name):
    raw = json.loads((ROOT / kind / name).read_text())
    return {k: v for k, v in raw.items() if not k.startswith("_")}  # fixture annotations


def names(kind):
    return sorted(p.name for p in (ROOT / kind).glob("*.json"))


def test_vectors_are_the_pinned_bytes():
    assert PIN["source_commit"] == adapter.SOURCE_COMMIT
    on_disk = {f"{k}/{n}" for k in ("valid", "invalid") for n in names(k)}
    assert on_disk == set(PIN["files"]) and len(on_disk) == 27
    for rel, entry in PIN["files"].items():
        assert "sha256:" + hashlib.sha256((ROOT / rel).read_bytes()).hexdigest() == entry["sha256"], rel


def test_vector_split_matches_the_pinned_profile_census():
    assert len(names("valid")) == 12 and len(names("invalid")) == 15
    assert set(names("invalid")) == set(EXPECTED_RULE_CODE)


@pytest.mark.parametrize("name", names("valid"))
def test_every_valid_vector_passes_the_profile_gate(name):
    _, outcome = adapter._stage_conformance(load("valid", name))
    assert outcome.status == "completed", [r.to_dict() for r in outcome.refusals]


@pytest.mark.parametrize("name", names("invalid"))
def test_every_invalid_vector_is_refused_with_the_pinned_rule_code(name):
    _, outcome = adapter._stage_conformance(load("invalid", name))
    assert outcome.status == "refused"
    assert EXPECTED_RULE_CODE[name] in {r.code for r in outcome.refusals}


@pytest.mark.parametrize(
    "name",
    [
        "c2pa-missing-conditional-limitation.json",
        "c2pa-signer-provenance-unordered.json",
        "c2pa-subject-binding-mismatch.json",
    ],
)
def test_vectors_the_field_schema_accepts_are_caught_by_rules_not_by_schema(name):
    """Three invalid vectors carry `_expected_field_schema: accept`; only the profile's
    conformance rules reject them. The adapter must reach them through the rules."""
    _, outcome = adapter._stage_conformance(load("invalid", name))
    assert {r.code for r in outcome.refusals} == {EXPECTED_RULE_CODE[name]}


def test_fixture_annotation_keys_are_not_silently_tolerated_by_the_adapter():
    raw = json.loads((ROOT / "valid" / names("valid")[0]).read_text())
    assert any(k.startswith("_") for k in raw)
    _, outcome = adapter._stage_conformance(raw)
    assert "ADAPTER_UNKNOWN_FIELD" in {r.code for r in outcome.refusals}
