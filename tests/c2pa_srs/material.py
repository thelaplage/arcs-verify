"""SYNTHETIC test material for the SRS C2PA observed-side adapter.

Everything in this module is constructed by the test suite. NOTHING here is a produced
observation, a real C2PA asset, a real native report or a real validator run:

* the observations are hand-built profile-shaped dictionaries (receipt ids, issuer and
  runtime names carry the word SYNTHETIC / NON-OPERATIONAL);
* the "assets" are opaque filler bytes, not media;
* the "native reports" are small c2patool-shaped documents written here;
* the "validator" is a test double that prints a canned report for a given asset digest.

They exist to exercise the adapter's ordering, refusals and typed outcomes. They prove
nothing about end-to-end producer -> verifier interoperability; that is owed to a replay
over bytes a real producer emitted.
"""
from __future__ import annotations

import copy
import hashlib
import json
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from arcs_verify import c2pa_native
from arcs_verify.c2pa_srs_observed import RetainedEvidence

ASSET_NAME = "synthetic-asset-0001.jpg"
SYNTHETIC_ASSET = b"SYNTHETIC-ASSET-0001 opaque filler, not media\n" * 8
SYNTHETIC_OTHER_ASSET = b"SYNTHETIC-ASSET-0002 opaque filler, not media\n" * 8
SYNTHETIC_MANIFEST_STORE = b"SYNTHETIC-MANIFEST-STORE-0001 opaque filler\n" * 8
SYNTHETIC_OTHER_MANIFEST_STORE = b"SYNTHETIC-MANIFEST-STORE-0002 opaque filler\n" * 8
HERMETIC_CONFIG = c2pa_native.HERMETIC_SETTINGS_TOML.encode("utf-8")
PINNED_VERSION = c2pa_native.PINNED_VALIDATOR["version"]
ALLOWED_LIST_DIGEST = "sha256:" + "ab" * 32
ANCHORS_DIGEST = "sha256:" + "cd" * 32

LIMITATION_BASE = (
    "The receipt records an observation of a native C2PA validation performed by a named external validator "
    "over pinned inputs. It does not establish content truth, depicted-event truth, physical liveness, "
    "universal signer trust, independent ARCS recomputation, DAGR admission, or public standing."
)


def sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _item(code: str, url: str | None = None) -> dict[str, Any]:
    return {"code": code, "explanation": "synthetic", "url": url or f"self#jumbf=/c2pa/synthetic/{code}"}


def native_report(
    state: str,
    *,
    success: tuple[str, ...] = (),
    informational: tuple[str, ...] = (),
    failure: tuple[str, ...] = (),
    ingredient_failure: tuple[str, ...] = (),
) -> dict[str, Any]:
    """A c2patool-shaped synthetic report. The legacy flattened ``validation_status`` array
    is included on purpose (and made misleading) because the verifier must never read it."""
    results: dict[str, Any] = {
        "activeManifest": {
            "success": [_item(c) for c in success],
            "informational": [_item(c) for c in informational],
            "failure": [_item(c) for c in failure],
        }
    }
    if ingredient_failure:
        results["ingredientDeltas"] = [
            {
                "ingredientAssertionURI": "self#jumbf=/c2pa/synthetic/c2pa.assertions/c2pa.ingredient",
                "validationDeltas": {
                    "success": [],
                    "informational": [],
                    "failure": [_item(c) for c in ingredient_failure],
                },
            }
        ]
    return {
        "active_manifest": "synthetic:urn:uuid:00000000-0000-0000-0000-000000000001",
        "manifests": {"synthetic:urn:uuid:00000000-0000-0000-0000-000000000001": {"title": "SYNTHETIC"}},
        "validation_results": results,
        "validation_state": state,
        "validation_status": [_item("misleading.legacy.flattened.code")],
    }


REPORT_VALID_UNTRUSTED = native_report(
    "Valid",
    success=("claimSignature.validated", "assertion.dataHash.match"),
    failure=("signingCredential.untrusted",),
)
REPORT_INVALID_CLAIM = native_report(
    "Invalid",
    success=("assertion.dataHash.match",),
    failure=("claimSignature.mismatch", "signingCredential.untrusted"),
)
REPORT_TRUSTED_ALLOWED = native_report(
    "Trusted",
    success=("claimSignature.validated", "assertion.dataHash.match", "signingCredential.trusted"),
)
REPORT_EXPIRED = native_report(
    "Invalid",
    success=("assertion.dataHash.match",),
    failure=("signingCredential.expired", "signingCredential.untrusted"),
)
REPORT_ANCHORED = native_report(
    "Valid",
    success=("claimSignature.validated", "assertion.dataHash.match", "timeStamp.validated", "timeStamp.trusted"),
    failure=("signingCredential.untrusted",),
)


def report_bytes(report: dict[str, Any]) -> bytes:
    return json.dumps(report, indent=2, sort_keys=True).encode("utf-8")


def findings_of(report: dict[str, Any]) -> list[dict[str, str]]:
    """The observation's native_findings, derived independently of the verifier's parser."""
    out: list[dict[str, str]] = []
    results = report["validation_results"]
    for severity in ("success", "informational", "failure"):
        for item in results["activeManifest"][severity]:
            out.append({"scope": "activeManifest", "severity": severity, "code": item["code"], "uri": item["url"]})
    for delta in results.get("ingredientDeltas", []):
        for severity in ("success", "informational", "failure"):
            for item in delta["validationDeltas"][severity]:
                out.append({"scope": "ingredientDeltas", "severity": severity, "code": item["code"], "uri": item["url"]})
    return out


def synthetic_observation(
    report: dict[str, Any] = REPORT_VALID_UNTRUSTED,
    *,
    asset: bytes = SYNTHETIC_ASSET,
    manifest_store: bytes | None = None,
    mode: str = "embedded",
    version: str = PINNED_VERSION,
    config: bytes = HERMETIC_CONFIG,
    exit_code: int = 0,
) -> dict[str, Any]:
    """A profile-conformant, SYNTHETIC observation whose digests match the supplied bytes."""
    asset_digest = sha(asset)
    store: dict[str, Any] = {"state": "present", "digest": sha(manifest_store or SYNTHETIC_MANIFEST_STORE), "byte_length": len(manifest_store or SYNTHETIC_MANIFEST_STORE)}
    acquisition: dict[str, Any] = {
        "mode": mode,
        "remote_resolution_performed": False,
        "remote_resolution_phase": "not_performed",
    }
    if mode == "remote_reference":
        acquisition["remote_manifest_uri"] = "https://synthetic.invalid/manifests/0001"
    state = report["validation_state"]
    expired = any(i["code"] == "signingCredential.expired" for i in report["validation_results"]["activeManifest"]["failure"])
    trusted = any(i["code"] == "signingCredential.trusted" for i in report["validation_results"]["activeManifest"]["success"])
    return {
        "receipt_version": "srs.core.v5.1",
        "profile_id": "srs.c2pa.validation_observation",
        "profile_version": "v0.1",
        "receipt_id": "synthetic-c2pa-observation-0001",
        "receipt_type": "provenance",
        "receipt_kind": "c2pa_validation_observation",
        "boundary_type": "c2pa_validation_observation_boundary",
        "protocol_binding": "c2pa/2.4+native-validator-observation-v0-1",
        "external_binding_relation_mode": "validation_observation",
        "subject_ref": asset_digest,
        "issuer_id": "issuer.synthetic-test/NON-OPERATIONAL",
        "runtime_instance_id": "synthetic-runtime-0001",
        "boundary_id": "synthetic-boundary-0001",
        "issued_at": "2026-10-31T00:00:00Z",
        "asset_digest": asset_digest,
        "manifest_store": store,
        "manifest_acquisition": acquisition,
        "hermetic_replay": {
            "performed": True,
            "remote_manifest_fetch_applied": False,
            "ocsp_fetch_applied": False,
            "allowed_network_hosts": [],
        },
        "native_validator": {
            "implementation": "c2patool",
            "version": version,
            "build_digest": sha(b"synthetic-validator-build"),
            "configuration_posture": "configuration_supplied",
            "configuration_digest": sha(config),
            "specification_version_applied": "2.4",
            "specification_version_applied_source": "native_validator_applied",
        },
        "native_report": {
            "report_digest": sha(report_bytes(report)),
            "report_format": "c2patool.json",
            "verdict_source": "native_machine_report",
            "process_exit_code": exit_code,
            "native_validation_state": state,
        },
        "native_findings": findings_of(report),
        "signer_provenance": [{"order": 0, "subject": "SYNTHETIC Signer", "issuer": "SYNTHETIC CA", "role": "end_entity"}],
        "signer_trust": {
            "trust_basis": "default_no_trust_material",
            "trust_observation": "trusted" if trusted else "untrusted",
            "trust_pointer_dereferenced": False,
        },
        "signer_validity": {"observation": "expired" if expired else "inside_validity", "determinism_class": "time_dependent"},
        "trusted_timestamp": {"present": False, "observation": "not_present"},
        "validation_time": {
            "validation_timestamp_observed": "2026-10-31T00:00:00Z",
            "validation_time_control": "unsupported",
            "trusted_timestamp_relevant": False,
        },
        "revocation": {"observation": "not_evaluated", "mechanism": "not_available"},
        "assertion_attribution": {"support": "not_applicable"},
        "ingredient_refs": [],
        "prior_producer_report": {"present": False, "comparison_posture": "not_evaluated"},
        "later_comparison_posture": "comparable",
        "evaluation_posture": "native_validation_performed",
        "unavailable_inputs": [
            {"input": "certificate_revocation_evidence", "reason": "no mechanism exists to supply captured revocation responses"}
        ],
        "artifact_classes_covered": [
            "asset_digest",
            "manifest_store_state",
            "manifest_acquisition_mode",
            "native_validator_identity",
            "native_report_digest",
            "trust_material_digests",
            "validation_observation",
            "trusted_timestamp_observation",
        ],
        "artifact_classes_excluded": [
            "raw_asset_bytes",
            "raw_manifest_store_bytes",
            "raw_native_report_bytes",
            "raw_certificate_private_material",
        ],
        "attestation_limits": [LIMITATION_BASE],
        "machine_limitations": [
            {"code": code}
            for code in (
                "CONTENT_TRUTH_NOT_EVALUATED",
                "ADMISSION_NOT_EVALUATED",
                "C2PA_SIGNER_TRUST_NOT_UNIVERSAL",
                "C2PA_NATIVE_VALIDATION_NOT_RECOMPUTED",
                "C2PA_DEPICTED_CONTENT_NOT_ESTABLISHED",
                "PUBLIC_STANDING_NOT_EVALUATED",
                "C2PA_REVOCATION_NOT_EVALUATED",
                "C2PA_VALIDATION_TIME_NOT_CONTROLLED",
            )
        ],
        "extensions": {},
    }


def evidence_for(
    report: dict[str, Any] = REPORT_VALID_UNTRUSTED,
    *,
    asset: bytes = SYNTHETIC_ASSET,
    manifest_store: bytes | None = None,
    configuration: bytes | None = None,
    include_report: bool = True,
) -> RetainedEvidence:
    return RetainedEvidence(
        asset=asset,
        asset_name=ASSET_NAME,
        native_report=report_bytes(report) if include_report else None,
        manifest_store=manifest_store,
        configuration=configuration,
    )


def encode(obs: dict[str, Any]) -> bytes:
    return json.dumps(obs, sort_keys=True).encode("utf-8")


def mutated(obs: dict[str, Any], dotted: str, value: Any) -> dict[str, Any]:
    """A deep copy with one dotted path set (the last hop is created if absent)."""
    out = copy.deepcopy(obs)
    node = out
    parts = dotted.split(".")
    for part in parts[:-1]:
        node = node[part]
    node[parts[-1]] = value
    return out


def without(obs: dict[str, Any], dotted: str) -> dict[str, Any]:
    out = copy.deepcopy(obs)
    node = out
    parts = dotted.split(".")
    for part in parts[:-1]:
        node = node[part]
    del node[parts[-1]]
    return out


# ---------------------------------------------------------------------------
# Test-double validator (NOT the pinned native validator)
# ---------------------------------------------------------------------------

_FAKE_SCRIPT = r'''
import hashlib, json, sys
SCENARIOS = {scenarios!r}
LOG = {log!r}
VERSION = {version!r}

def main(argv):
    if argv == ["--version"]:
        print("c2patool " + VERSION)
        return 0
    settings = None
    external = None
    rest = list(argv)
    asset = None
    while rest:
        item = rest.pop(0)
        if item == "--settings":
            settings = rest.pop(0)
        elif item == "--external-manifest":
            external = rest.pop(0)
        else:
            asset = item
    asset_digest = hashlib.sha256(open(asset, "rb").read()).hexdigest()
    entry = {{
        "argv": argv,
        "asset_sha256": asset_digest,
        "external_sha256": hashlib.sha256(open(external, "rb").read()).hexdigest() if external else None,
        "settings_text": open(settings).read() if settings else None,
    }}
    with open(LOG, "a") as handle:
        handle.write(json.dumps(entry) + "\n")
    scenario = json.load(open(SCENARIOS)).get(asset_digest)
    if scenario is None:
        sys.stderr.write("Error: No claim found\n")
        return 1
    sys.stdout.write(scenario["stdout"])
    sys.stderr.write(scenario.get("stderr", ""))
    return scenario["exit"]

sys.exit(main(sys.argv[1:]))
'''


@dataclass
class FakeValidator:
    path: str
    log: Path

    def calls(self) -> list[dict[str, Any]]:
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text().splitlines() if line]


def install_fake_validator(
    tmp_path: Path,
    scenarios: dict[bytes, tuple[dict[str, Any] | None, int]],
    *,
    version: str = PINNED_VERSION,
) -> FakeValidator:
    """``scenarios`` maps asset bytes -> (report or None, native process exit code). An asset
    with no scenario behaves like a file with no manifest store: no report, exit 1."""
    table = {
        hashlib.sha256(asset).hexdigest(): {"stdout": json.dumps(report) if report is not None else "", "exit": exit_code}
        for asset, (report, exit_code) in scenarios.items()
    }
    root = tmp_path / "fake-validator"
    root.mkdir()
    scenarios_path = root / "scenarios.json"
    scenarios_path.write_text(json.dumps(table))
    log = root / "calls.jsonl"
    script = root / "fake_validator.py"
    script.write_text(_FAKE_SCRIPT.format(scenarios=str(scenarios_path), log=str(log), version=version))
    wrapper = root / "c2patool-synthetic-test-double"
    wrapper.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{script}" "$@"\n')
    wrapper.chmod(wrapper.stat().st_mode | stat.S_IXUSR)
    return FakeValidator(path=str(wrapper), log=log)
