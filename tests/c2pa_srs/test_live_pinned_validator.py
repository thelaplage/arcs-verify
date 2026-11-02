"""The adapter against the REAL pinned native validator.

NOT_EXERCISED unless ARCS_VERIFY_C2PATOOL names the pinned build (c2patool 0.27.15). The
observations are still SYNTHETIC: where a real specimen is used, the "producer" side is this
test running the same validator through the verifier's own harness, so these tests check the
real report shape, exit-status semantics and the missing-manifest path, not independence of
two implementations. The specimens are read from ARCS_VERIFY_C2PA_SPECIMEN_DIR (not vendored
here) and are used only if their sha256 equals the pinned value below."""
import base64
import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

from arcs_verify import c2pa_native
from arcs_verify import c2pa_srs_observed as adapter

from . import material as m

LIVE = os.environ.get("ARCS_VERIFY_C2PATOOL")
SPECIMEN_DIR = os.environ.get("ARCS_VERIFY_C2PA_SPECIMEN_DIR")

pytestmark = pytest.mark.skipif(
    not LIVE, reason="NOT_EXERCISED: set ARCS_VERIFY_C2PATOOL to the pinned c2patool 0.27.15"
)

# Public c2pa-rs test specimens (Apache-2.0 OR MIT), digests as recorded by the dev fixture bundle.
SPECIMEN_SHA256 = {
    "C.jpg": "a2d14755db55de67a47c04090340d8266e892367be4104a45626d7a6fa6e9ffd",
    "E-sig-CA.jpg": "20dc072a4c843d3b7d7cb4f4002fbb4d8f20d7ee859ca726f2458c1e0358a98c",
}

# An 8x8 JPEG with no C2PA manifest, generated for this test (SYNTHETIC).
SYNTHETIC_NO_MANIFEST_JPEG = base64.b64decode(
    "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDABALDA4MChAODQ4SERATGCgaGBYWGDEjJR0oOjM9PDkzODdASFxOQERXRTc4UG1RV19iZ2hnPk1xeXBkeFxlZ2P/2wBDARESEhgVGC8aGi9jQjhCY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2P/wAARCAAIAAgDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwDIooor6A7T/9k="
)


def test_the_executable_is_the_pinned_build():
    out = subprocess.run([LIVE, "--version"], capture_output=True, text=True, timeout=60, check=False).stdout
    assert out.split()[-1] == c2pa_native.PINNED_VALIDATOR["version"], out


def live_evidence(asset, name, report_bytes):
    return m.RetainedEvidence(asset=asset, asset_name=name, native_report=report_bytes)


def specimen(name):
    if not SPECIMEN_DIR:
        pytest.skip("NOT_EXERCISED: set ARCS_VERIFY_C2PA_SPECIMEN_DIR to a directory holding the pinned c2pa-rs specimens")
    path = Path(SPECIMEN_DIR) / name
    data = path.read_bytes()
    assert hashlib.sha256(data).hexdigest() == SPECIMEN_SHA256[name], f"{name} is not the pinned specimen"
    return data


def run_validator_once(asset, name, tmp_path):
    asset_path = tmp_path / name
    asset_path.write_bytes(asset)
    settings = tmp_path / "hermetic.toml"
    settings.write_text(c2pa_native.HERMETIC_SETTINGS_TOML)
    outcome = c2pa_native.run_native_validator(LIVE, asset_path, settings_path=settings)
    return outcome


def synthetic_producer_observation(asset, name, tmp_path):
    """Build a SYNTHETIC observation around the real validator's report for this asset."""
    outcome = run_validator_once(asset, name, tmp_path)
    assert outcome.evaluated
    report = outcome.report
    raw = json.dumps(report, sort_keys=True).encode()
    obs = m.synthetic_observation(
        m.native_report(report["validation_state"]),  # shape donor only; replaced below
        asset=asset,
        exit_code=outcome.exit_status,
    )
    results = report["validation_results"]
    findings = []
    for severity in ("success", "informational", "failure"):
        for item in results["activeManifest"].get(severity, []):
            findings.append({"scope": "activeManifest", "severity": severity, "code": item["code"], "uri": item["url"]})
    for delta in results.get("ingredientDeltas", []):
        for severity in ("success", "informational", "failure"):
            for item in delta["validationDeltas"].get(severity, []):
                findings.append({"scope": "ingredientDeltas", "severity": severity, "code": item["code"], "uri": item["url"]})
    obs["native_findings"] = findings
    obs["native_report"].update(report_digest=m.sha(raw), native_validation_state=report["validation_state"], process_exit_code=outcome.exit_status)
    obs["signer_trust"]["trust_observation"] = "untrusted" if any(f["code"] == "signingCredential.untrusted" for f in findings) else "not_evaluated"
    obs["signer_validity"]["observation"] = "not_evaluated"
    obs["native_validator"]["version"] = c2pa_native.PINNED_VALIDATOR["version"]
    return obs, raw, outcome


def test_real_validator_finds_no_manifest_store_and_the_comparison_is_not_evaluated(tmp_path):
    synthetic_report = m.REPORT_VALID_UNTRUSTED
    obs = m.synthetic_observation(synthetic_report, asset=SYNTHETIC_NO_MANIFEST_JPEG)
    ev = live_evidence(SYNTHETIC_NO_MANIFEST_JPEG, "synthetic-no-manifest.jpg", m.report_bytes(synthetic_report))
    result = adapter.consume_observation(m.encode(obs), ev, executable=LIVE)
    assert result.stages["native_recomputation"].status == "completed"
    recomputed = result.report["native_recomputation"]["recomputed"]
    assert recomputed["evaluation_status"] == "input_unavailable"
    assert result.stages["comparison"].status == "not_evaluated"
    assert result.stopped_at == "comparison"
    assert recomputed["validator"]["version"] == c2pa_native.PINNED_VALIDATOR["version"]


def test_real_report_shape_flows_through_all_stages_for_a_signed_specimen(tmp_path):
    asset = specimen("C.jpg")
    obs, raw, outcome = synthetic_producer_observation(asset, "C.jpg", tmp_path)
    assert outcome.exit_status == 0 and obs["native_report"]["native_validation_state"] == "Valid"
    assert "validation_status" in outcome.report  # the legacy flattened array exists in the real report and is not read
    result = adapter.consume_observation(m.encode(obs), live_evidence(asset, "C.jpg", raw), executable=LIVE)
    assert result.stopped_at is None, [(n, [r.code for r in s.refusals]) for n, s in result.stages.items() if s.refusals]
    axes = {a["axis"]: a for a in result.report["axes"]["independent_comparison"]["per_axis"]}
    assert axes["claim_signature"]["state"] == "match" and axes["asset_binding"]["state"] == "match"
    assert result.report["native_recomputation"]["recomputed"]["evidence_class"] == "live_native_invocation"
    assert result.report["axes"]["srs_receipt_authentication"]["issuance_authentication"] == "not_evaluated"
    states = result.report["axes"]["native_validation_state"]
    assert states["recomputed_verbatim"] == "Valid"
    assert result.report["axes"]["signer_trust"]["recomputed_axis_status"] == "failed"  # Valid with an untrusted signer


def test_real_native_invalid_with_exit_zero_is_failed_not_satisfied(tmp_path):
    asset = specimen("E-sig-CA.jpg")
    obs, raw, outcome = synthetic_producer_observation(asset, "E-sig-CA.jpg", tmp_path)
    assert outcome.exit_status == 0 and obs["native_report"]["native_validation_state"] == "Invalid"
    result = adapter.consume_observation(m.encode(obs), live_evidence(asset, "E-sig-CA.jpg", raw), executable=LIVE)
    assert result.stopped_at is None
    axes = {a["axis"]: a for a in result.report["axes"]["independent_comparison"]["per_axis"]}
    assert axes["claim_signature"]["recomputed_status"] == "failed"
    assert "claimSignature.mismatch" in result.report["axes"]["native_failure_codes"]["recomputed"]
    assert result.report["producer_asserted"]["process_exit_code"] == 0


def test_real_report_of_a_different_asset_is_a_mismatch_not_a_match(tmp_path):
    """Both assets and both reports are real. The observation names asset C.jpg but carries the
    real Invalid report of E-sig-CA.jpg; every digest matches the bytes retained, so correspondence
    passes, and only the verifier's own run over C.jpg exposes the pairing."""
    named = specimen("C.jpg")
    other = specimen("E-sig-CA.jpg")
    obs, raw_other, _ = synthetic_producer_observation(other, "E-sig-CA.jpg", tmp_path)
    obs["asset_digest"] = obs["subject_ref"] = m.sha(named)
    result = adapter.consume_observation(m.encode(obs), live_evidence(named, "C.jpg", raw_other), executable=LIVE)
    assert result.stages["input_correspondence"].status == "completed"
    assert result.stopped_at is None
    claim = {a["axis"]: a for a in result.report["axes"]["independent_comparison"]["per_axis"]}["claim_signature"]
    assert claim["state"] == "mismatch" and (claim["observed_status"], claim["recomputed_status"]) == ("failed", "satisfied")
