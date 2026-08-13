"""SRS-RECON0-VR0 — self-identifying VerificationReport regressions.

Fixtures are the two metadata-only receipts from the RECON0-C1 run (the decisive
regression: re-run them and require signature-negative results whose reports now
differ intrinsically because each binds its own receipt/profile subject).

Constitutional invariant asserted here: self-identification is not
self-authorization. The new fields identify the receipt, selected profile,
schema, and profile posture; they never participate in `passed` and never
establish trust, admission, standing, authenticity, or authority.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import rfc8785

from arcs_verify import cli
from arcs_verify.verifier import (
    EDITORIAL_SOURCE_CAPTURE_PROFILE_V02,
    EDITORIAL_SOURCE_INGEST_PROFILE,
    PROFILE_IDENTITIES,
    PROFILE_REGISTRY,
    PROVISIONAL_PROFILE_DETAILS,
    REPORT_CONTRACT_V0_1,
    SUPPORTED_PROFILE_DESCRIPTIONS,
    VerificationReport,
    verify_receipt,
)

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "arcs_verify" / "data" / "srs-envelope-v0.2.1.schema.json"
FX = Path(__file__).resolve().parent / "fixtures" / "vr0"
KEYRING: dict = {"issuers": []}
SCHEMA_V021_SHA = "sha256:2afa1ec9f093fd7c06c4f5db7bfd37cc63e64e3dcbe47c963f4df586a1c18ca1"


def _load(name: str) -> dict:
    return json.loads((FX / name).read_text())


def _verify(name: str, profile: str) -> dict:
    return verify_receipt(_load(name), KEYRING, schema_path=SCHEMA, selected_profile=profile).to_dict()


# 1. Existing axes retain exactly their old semantics.
def test_existing_axes_unchanged() -> None:
    d = _verify("source_capture_receipt.json", EDITORIAL_SOURCE_CAPTURE_PROFILE_V02)
    for k in ("schema_digest", "envelope", "profile", "raw_content_exclusion",
              "signature_valid", "issuer_key_resolved", "issuer_key_trusted",
              "attestation_limits_present"):
        assert isinstance(d[k], bool)
    assert d["chain_status"] == "not_applicable"
    assert isinstance(d["failure_codes"], list) and isinstance(d["details"], list)
    assert d["failure_codes"] == ["signature_object_invalid"]
    assert d["passed"] is False


# 2. C1 source_capture receipt self-identifies fully.
def test_capture_report_self_identifies() -> None:
    rcpt = _load("source_capture_receipt.json")
    d = _verify("source_capture_receipt.json", EDITORIAL_SOURCE_CAPTURE_PROFILE_V02)
    assert d["report_contract"] == REPORT_CONTRACT_V0_1
    assert d["selected_profile"] == EDITORIAL_SOURCE_CAPTURE_PROFILE_V02
    assert d["verified_receipt_id"] == rcpt["receipt_id"]
    assert d["verified_receipt_version"] == rcpt["receipt_version"]
    assert d["verified_receipt_profile_id"] == "srs.editorial.source_capture"
    assert d["verified_receipt_profile_version"] == "v0.2"
    expected = "sha256:" + hashlib.sha256(rfc8785.dumps(rcpt)).hexdigest()
    assert d["verified_receipt_canonical_json_sha256"] == expected
    assert d["envelope_schema_identity"] == {"published_version": "v0.2.1", "sha256": SCHEMA_V021_SHA}
    assert d["selected_profile_release_stage"] == "provisional"
    assert d["passed"] is False


# 3. C1 source_ingest receipt self-identifies with its own identity.
def test_ingest_report_self_identifies() -> None:
    rcpt = _load("source_ingest_receipt.json")
    d = _verify("source_ingest_receipt.json", EDITORIAL_SOURCE_INGEST_PROFILE)
    assert d["selected_profile"] == EDITORIAL_SOURCE_INGEST_PROFILE
    assert d["verified_receipt_id"] == rcpt["receipt_id"]
    assert d["verified_receipt_profile_id"] == "srs.editorial.source_ingest"
    assert d["selected_profile_release_stage"] == "provisional"
    assert d["failure_codes"] == ["signature_object_invalid"]
    assert d["passed"] is False


# 4. The two C1 reports MUST now serialize differently.
def test_two_c1_reports_serialize_differently() -> None:
    a = _verify("source_capture_receipt.json", EDITORIAL_SOURCE_CAPTURE_PROFILE_V02)
    b = _verify("source_ingest_receipt.json", EDITORIAL_SOURCE_INGEST_PROFILE)
    assert json.dumps(a, sort_keys=True) != json.dumps(b, sort_keys=True)


# 5. Same receipt + profile + schema => deterministic identical report bytes.
def test_same_inputs_deterministic() -> None:
    a = _verify("source_capture_receipt.json", EDITORIAL_SOURCE_CAPTURE_PROFILE_V02)
    b = _verify("source_capture_receipt.json", EDITORIAL_SOURCE_CAPTURE_PROFILE_V02)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


# 6. Profile mismatch is intrinsically intelligible.
def test_profile_mismatch_is_self_describing() -> None:
    d = _verify("source_capture_receipt.json", EDITORIAL_SOURCE_INGEST_PROFILE)
    assert d["selected_profile"] == EDITORIAL_SOURCE_INGEST_PROFILE       # asked to evaluate X
    assert d["verified_receipt_profile_id"] == "srs.editorial.source_capture"  # receipt declared Y
    assert d["verified_receipt_profile_version"] == "v0.2"
    assert d["profile"] is False


# 7. Unpinned schema: actual SHA recorded, published_version null (never inferred).
def test_unpinned_schema_records_actual_sha_null_version(tmp_path: Path) -> None:
    bad = tmp_path / "unpinned.schema.json"
    bad.write_text('{"type": "object"}', encoding="utf-8")
    d = verify_receipt(_load("source_capture_receipt.json"), KEYRING, schema_path=bad,
                       selected_profile=EDITORIAL_SOURCE_CAPTURE_PROFILE_V02).to_dict()
    assert d["schema_digest"] is False
    assert d["envelope_schema_identity"]["published_version"] is None
    assert d["envelope_schema_identity"]["sha256"].startswith("sha256:")
    assert len(d["envelope_schema_identity"]["sha256"]) == len("sha256:") + 64


# 8. CLI profile listing is generated from the canonical registry (no drift).
def test_cli_list_projected_from_registry() -> None:
    assert cli.SUPPORTED_PROFILES == {s: m.description for s, m in PROFILE_REGISTRY.items()}
    assert EDITORIAL_SOURCE_CAPTURE_PROFILE_V02 in cli.SUPPORTED_PROFILES
    assert EDITORIAL_SOURCE_INGEST_PROFILE in cli.SUPPORTED_PROFILES


def test_registry_projections_cannot_drift() -> None:
    assert set(PROFILE_IDENTITIES) == set(PROFILE_REGISTRY)
    assert set(SUPPORTED_PROFILE_DESCRIPTIONS) == set(PROFILE_REGISTRY)
    assert set(PROVISIONAL_PROFILE_DETAILS) <= set(PROFILE_REGISTRY)
    for slug, meta in PROFILE_REGISTRY.items():
        assert PROFILE_IDENTITIES[slug] == (meta.profile_id, meta.profile_version)
        if meta.release_stage == "provisional":
            assert slug in PROVISIONAL_PROFILE_DETAILS


# 9. No new identity/posture field participates in `passed`.
def test_identity_metadata_never_flips_passed() -> None:
    base = dict(schema_digest=True, envelope=True, profile=True, raw_content_exclusion=True,
                signature_valid=True, issuer_key_resolved=True, issuer_key_trusted=True,
                attestation_limits_present=True)
    assert VerificationReport(**base).passed is True
    # setting identity/posture metadata does not change passed either way
    assert VerificationReport(**base, selected_profile_release_stage="provisional",
                              verified_receipt_id="x", report_contract="anything").passed is True
