"""Hermetic native C2PA recomputation and comparison (ARCSV-C2PA0 v0.1).

arcs-verify does not reimplement C2PA validation. It invokes a pinned build of
the official native implementation over frozen inputs under hermetic settings,
parses the machine report, normalizes it into per-axis canonical findings, and
— only when a producer observation is also supplied — compares the two sides
axis by axis.

Three things this module refuses to do, each because getting them wrong is the
obvious implementation:

1. It never derives semantic status from the native process exit status. The
   pinned validator exits 0 for both ``Valid`` and ``Invalid`` and exits
   non-zero only when a required input is unavailable.
2. It never reads the legacy flattened top-level ``validation_status`` array,
   which collapses active-manifest and ingredient findings together with no
   scope marker and emits duplicates. It reads the scoped
   ``validation_results`` object only.
3. It never emits an aggregate match Boolean, and it never emits a synthetic
   array of ``not_evaluated`` comparisons when there is no observation to
   compare against. Absent means absent.

Hermetic is not timeless. This module can establish that no network was
permitted, no remote resource was dereferenced, and no trust-list URI was
fetched, while still recording that the validation clock is wall-clock and not
caller-pinnable. A certificate state that changed because time passed is not a
failed hermetic replay and never produces an integrity accusation.

This module reports NATIVE C2PA validation. It is not an SRS receipt verifier
and establishes nothing about SRS envelope structure, SRS signatures, or SRS
issuer trust. It imports no producer implementation code.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence

import rfc8785

__all__ = [
    "PINNED_VALIDATOR",
    "HERMETIC_SETTINGS_TOML",
    "AXIS_ORDER",
    "NativeInvocationResult",
    "run_native_validator",
    "parse_native_report",
    "canonical_finding_from_native_report",
    "canonical_finding_unavailable",
    "build_report",
    "compare_sides",
    "check_report",
    "ContractBundle",
    "load_bundle",
    "contract_semantic_projection",
    "contract_semantic_digest",
    "SEMANTIC_PROJECTION_ID",
    "SEMANTIC_PROJECTION_INCLUDED_FIELDS",
    "SEMANTIC_PROJECTION_EXCLUDED_FIELDS",
    "main",
]

CONTRACT_ID = "arcs.c2pa_native_finding.report.v0.1"
CONTRACT_VERSION = "0.1"
BUNDLE_DIR = Path(__file__).resolve().parent / "contracts" / "c2pa-native-finding" / "v0.1"

# ---------------------------------------------------------------------------
# Pins
# ---------------------------------------------------------------------------

PINNED_VALIDATOR: dict[str, str] = {
    "implementation": "c2patool",
    "version": "0.27.15",
    "source": "crates.io",
    "install_command": "cargo install c2patool --version 0.27.15 --locked",
    "c2pa_specification_version": "2.4",
}
"""The exact native implementation this contract recomputes against.

The version is pinned explicitly rather than resolved from whatever happens to
be on PATH. This crate published five patch versions inside forty-eight hours
during reconnaissance, and a validator version change is a verdict input: the
same bytes have been observed to validate differently across versions. A
recomputation performed by a different version is reported as
``validator_version_delta``, never as a substantive divergence.
"""

# Environment variable naming an executable to use as the native validator.
# Unset in hermetic test execution; tests then replay frozen native reports.
VALIDATOR_ENV = "ARCS_VERIFY_C2PATOOL"

HERMETIC_SETTINGS_TOML = """\
version = 1
[verify]
remote_manifest_fetch = false
ocsp_fetch = false
verify_trust = true
verify_timestamp_trust = true
[core]
allowed_network_hosts = []
"""
"""Mandatory hermetic posture.

``remote_manifest_fetch`` defaults to true in the native implementation, so the
default posture is networked and must be explicitly disabled. ``ocsp_fetch``
defaults to false, which is why revocation is reported ``not_evaluated`` rather
than satisfied: silence about revocation is not evidence of non-revocation, and
the pinned validator offers no way to inject captured revocation responses for
offline replay.
"""

HERMETIC_SETTINGS_APPLIED: dict[str, Any] = {
    "remote_manifest_fetch": False,
    "ocsp_fetch": False,
    "verify_trust": True,
    "verify_timestamp_trust": True,
    "allowed_network_hosts": [],
}

# ---------------------------------------------------------------------------
# Taxonomy (loaded from the pinned bundle, never hard-coded twice)
# ---------------------------------------------------------------------------

AXIS_ORDER: tuple[str, ...] = (
    "manifest_structure",
    "asset_binding",
    "claim_signature",
    "signer_trust",
    "signer_validity",
    "timestamp",
    "revocation",
    "ingredient",
)

FORBIDDEN_AGGREGATE_KEYS = frozenset(
    {
        "native_observation_matches_recomputation",
        "observation_matches_recomputation",
        "provenance_valid",
        "c2pa_verified",
        "verified",
    }
)

_SEVERITIES = ("success", "informational", "failure")


# ---------------------------------------------------------------------------
# The downstream pin: a canonical projection, not a file digest
# ---------------------------------------------------------------------------

SEMANTIC_PROJECTION_ID = "arcs.c2pa_native_finding.semantic_projection.v0.1"

SEMANTIC_PROJECTION_INCLUDED_FIELDS: tuple[str, ...] = (
    "contract_id",
    "contract_version",
    "status",
    "digest_algorithm",
    "files",
    "native_semantic_pins.c2pa_specification_version",
    "native_semantic_pins.native_validator_pin.implementation",
    "native_semantic_pins.native_validator_pin.version",
    "native_semantic_pins.native_validator_pin.source",
    "native_semantic_pins.native_validator_pin.install_command",
)
"""Exactly the manifest fields the downstream semantic pin identifies.

This is an allowlist, not a denylist. A field added to ``contract.manifest.json``
later is outside the pin until it is named here deliberately.
"""

SEMANTIC_PROJECTION_EXCLUDED_FIELDS: tuple[str, ...] = (
    "authority",
    "scope_note",
    "excluded_from_pin",
    "semantic_pin",
    "file_count",
    "native_validator_pin.pin_rationale",
)
"""Manifest fields the projection deliberately drops.

``authority``, ``scope_note`` and ``pin_rationale`` are prose: they explain the
pin, they are not the pin. ``excluded_from_pin`` and ``semantic_pin`` are
descriptions of the pinning arrangement rather than pinned semantics; the
authoritative definition of the projection is this module plus its tests.
``file_count`` is derived from ``files`` and carries no information ``files``
does not already carry.
"""


def contract_semantic_projection(manifest: dict[str, Any]) -> dict[str, Any]:
    """Project ``contract.manifest.json`` onto its canonical machine fields.

    The manifest file cannot exempt its own bytes from a digest a consumer
    computes over the file — a self-declaration in ``excluded_from_pin`` is not
    enforceable against ``sha256(contract.manifest.json)``. Since the manifest
    carries prose (``authority``, ``scope_note``, ``pin_rationale``), a digest
    over the raw file moves when the prose is clarified, which is precisely the
    behaviour that trains consumers to ignore pin movement.

    So the downstream pin is not the file digest. It is the digest of this
    projection: the contract identity, the digests of the three pinned machine
    members, and the native semantic pins. Editing prose does not move it.
    Editing any pinned machine member does.
    """
    validator = manifest["native_validator_pin"]
    return {
        "projection_id": SEMANTIC_PROJECTION_ID,
        "contract_id": manifest["contract_id"],
        "contract_version": manifest["contract_version"],
        "status": manifest["status"],
        "digest_algorithm": manifest["digest_algorithm"],
        "files": {name: str(digest) for name, digest in sorted(manifest["files"].items())},
        "native_semantic_pins": {
            "c2pa_specification_version": manifest["c2pa_specification_version"],
            "native_validator_pin": {
                "implementation": validator["implementation"],
                "version": validator["version"],
                "source": validator["source"],
                "install_command": validator["install_command"],
            },
        },
    }


def contract_semantic_digest(manifest: dict[str, Any]) -> str:
    """``sha256`` over the RFC 8785 canonical form of the semantic projection."""
    canonical = rfc8785.dumps(contract_semantic_projection(manifest))
    return "sha256:" + _digest_bytes(canonical)


@dataclass(frozen=True)
class ContractBundle:
    """The pinned machine semantics of the c2pa-native-finding contract."""

    directory: Path
    taxonomy: dict[str, Any]
    report_schema: dict[str, Any]
    finding_schema: dict[str, Any]
    manifest: dict[str, Any]

    @property
    def semantic_projection(self) -> dict[str, Any]:
        return contract_semantic_projection(self.manifest)

    @property
    def semantic_digest(self) -> str:
        """The value downstream consumers pin. Prose-stable by construction."""
        return contract_semantic_digest(self.manifest)

    @property
    def manifest_file_digest(self) -> str:
        """Digest of the manifest bytes as they sit on disk.

        Recorded for provenance only. It is NOT the downstream pin: it moves
        when manifest prose moves. Nothing in a report carries it.
        """
        return "sha256:" + _digest_bytes((self.directory / "contract.manifest.json").read_bytes())

    def axis_for_code(self, code: str) -> tuple[str, str] | None:
        for axis, spec in self.taxonomy["axes"].items():
            mapped = spec.get("native_codes") or {}
            if code in mapped:
                return axis, mapped[code]
        return None

    def axis_class(self, axis: str) -> str:
        return str(self.taxonomy["axes"][axis]["reproducibility_class"])

    def axis_contributing_classes(self, axis: str) -> list[str]:
        return list(self.taxonomy["axes"][axis].get("contributing_reproducibility_classes") or [])


def load_bundle(directory: Path | None = None) -> ContractBundle:
    root = Path(directory) if directory is not None else BUNDLE_DIR
    return ContractBundle(
        directory=root,
        taxonomy=_read_json(root / "comparison-taxonomy.json"),
        report_schema=_read_json(root / "native-finding-report.schema.json"),
        finding_schema=_read_json(root / "canonical-native-finding.schema.json"),
        manifest=_read_json(root / "contract.manifest.json"),
    )


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_file(path: Path) -> str:
    return "sha256:" + _digest_bytes(Path(path).read_bytes())


def digest_text(text: str) -> str:
    return "sha256:" + _digest_bytes(text.encode("utf-8"))


# ---------------------------------------------------------------------------
# Native invocation harness
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NativeInvocationResult:
    """Outcome of one native validator invocation.

    ``evaluation_status`` is derived from whether a machine report was produced
    and parsed. ``exit_status`` is recorded for forensics only and is never
    consulted to decide valid versus invalid; see
    :func:`_classify_invocation`.
    """

    evaluation_status: str
    report: dict[str, Any] | None
    exit_status: int
    stderr: str
    detail: str | None = None

    @property
    def evaluated(self) -> bool:
        return self.evaluation_status == "evaluated"


_REMOTE_UNAVAILABLE_MARKERS = (
    "must fetch remote manifests",
    "remote manifest",
)


def _classify_invocation(stdout: str, stderr: str, exit_status: int) -> NativeInvocationResult:
    """Determine semantic status from the machine report, never from exit status.

    The pinned validator exits 0 for ``validation_state: Valid`` and 0 for
    ``validation_state: Invalid``. It exits 1 when a required input — a remote
    manifest store that hermetic settings forbid fetching — is unavailable, and
    in that case emits no report at all. So:

    * a parseable report with a ``validation_results`` object  -> ``evaluated``,
      whatever the exit status and whatever the verdict inside it;
    * no parseable report                                      -> not evaluated.

    A harness that branched on ``exit_status == 0`` would classify a tampered
    asset as a success. That is the whole point of this function.
    """
    payload: dict[str, Any] | None = None
    text = stdout.strip()
    if text:
        try:
            candidate = json.loads(text)
        except json.JSONDecodeError:
            candidate = None
        if isinstance(candidate, dict) and "validation_results" in candidate:
            payload = candidate

    if payload is not None:
        return NativeInvocationResult("evaluated", payload, exit_status, stderr)

    lowered = stderr.lower()
    if any(marker in lowered for marker in _REMOTE_UNAVAILABLE_MARKERS):
        return NativeInvocationResult(
            "input_unavailable",
            None,
            exit_status,
            stderr,
            "required manifest store was not available locally and hermetic "
            "settings forbid dereferencing it",
        )
    return NativeInvocationResult(
        "invocation_error",
        None,
        exit_status,
        stderr,
        "native validator produced no machine report",
    )


def resolve_validator(explicit: str | None = None) -> str | None:
    """Locate the native validator executable, or return None.

    Never falls back to an unpinned executable silently: the caller must supply
    a path explicitly or set the environment variable. Version agreement with
    :data:`PINNED_VALIDATOR` is checked at invocation time and a disagreement is
    recorded in the report rather than hidden.
    """
    if explicit:
        return explicit
    return os.environ.get(VALIDATOR_ENV) or None


def native_validator_version(executable: str) -> str | None:
    try:
        proc = subprocess.run(
            [executable, "--version"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    parts = (proc.stdout or "").strip().split()
    return parts[-1] if parts else None


def run_native_validator(
    executable: str,
    asset: Path,
    *,
    settings_path: Path,
    external_manifest: Path | None = None,
    timeout: int = 300,
) -> NativeInvocationResult:
    """Invoke the native validator hermetically and classify the outcome.

    No URL is ever passed on the command line and no network-enabling option is
    ever added; the settings file supplied is the only policy input.
    """
    argv: list[str] = [executable, "--settings", str(settings_path)]
    if external_manifest is not None:
        argv += ["--external-manifest", str(external_manifest)]
    argv.append(str(asset))
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return NativeInvocationResult("invocation_error", None, -1, str(exc), "native validator could not be executed")
    return _classify_invocation(proc.stdout, proc.stderr, proc.returncode)


# ---------------------------------------------------------------------------
# Native report parsing
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NativeEntry:
    code: str
    severity: str
    scope: str
    url: str | None = None
    ingredient_assertion_uri: str | None = None


def parse_native_report(report: dict[str, Any]) -> list[NativeEntry]:
    """Flatten the scoped ``validation_results`` object into labelled entries.

    Reads ``validation_results`` only. The legacy top-level
    ``validation_status`` array is a flattened view in which active-manifest and
    ingredient findings collapse together with no scope marker — it has been
    observed emitting each code twice — and is never consulted here.

    ``validation_results.activeManifest`` is an object of severity arrays;
    ``validation_results.ingredientDeltas`` is a *list* of
    ``{ingredientAssertionURI, validationDeltas}`` objects. Both shapes are
    handled; a shape that is neither is skipped rather than coerced.
    """
    results = report.get("validation_results")
    if not isinstance(results, dict):
        return []

    entries: list[NativeEntry] = []

    active = results.get("activeManifest")
    if isinstance(active, dict):
        entries.extend(_entries_from_severity_map(active, "activeManifest", None))

    deltas = results.get("ingredientDeltas")
    if isinstance(deltas, list):
        for delta in deltas:
            if not isinstance(delta, dict):
                continue
            uri = delta.get("ingredientAssertionURI")
            inner = delta.get("validationDeltas")
            if isinstance(inner, dict):
                entries.extend(
                    _entries_from_severity_map(
                        inner, "ingredientDeltas", uri if isinstance(uri, str) else None
                    )
                )
    return entries


def _entries_from_severity_map(
    payload: dict[str, Any], scope: str, ingredient_uri: str | None
) -> Iterator[NativeEntry]:
    for severity in _SEVERITIES:
        bucket = payload.get(severity)
        if not isinstance(bucket, list):
            continue
        for item in bucket:
            if not isinstance(item, dict):
                continue
            code = item.get("code")
            if not isinstance(code, str):
                continue
            url = item.get("url")
            yield NativeEntry(
                code=code,
                severity=severity,
                scope=scope,
                url=url if isinstance(url, str) else None,
                ingredient_assertion_uri=ingredient_uri,
            )


def native_validation_state(report: dict[str, Any]) -> str | None:
    """Return ``validation_state`` verbatim, as a native field only.

    This value is never promoted to an arcs-verify verdict. The pinned
    validator emits ``Valid`` simultaneously with a ``signingCredential.untrusted``
    failure, so a projection that read this field alone would publish untrusted
    content as valid.
    """
    state = report.get("validation_state")
    return state if isinstance(state, str) else None


# ---------------------------------------------------------------------------
# Canonicalization
# ---------------------------------------------------------------------------


def _axis_status(entries: Sequence[NativeEntry], bundle: ContractBundle, axis: str) -> tuple[str, str | None]:
    if not entries:
        return "not_evaluated", "no native finding was produced for this axis"

    mapped = bundle.taxonomy["axes"][axis].get("native_codes") or {}
    if any(entry.severity == "failure" for entry in entries):
        return "failed", None
    declared = {mapped.get(entry.code) for entry in entries}
    if any(entry.severity == "success" for entry in entries):
        if "indeterminate" in declared:
            return "indeterminate", (
                "the native validator produced both success and informational "
                "findings for this axis and did not resolve it"
            )
        return "satisfied", None
    if "indeterminate" in declared or all(entry.severity == "informational" for entry in entries):
        return "indeterminate", "the native validator produced only informational findings for this axis"
    return "not_evaluated", None


def _axis_class(
    bundle: ContractBundle, axis: str, entries: Sequence[NativeEntry]
) -> tuple[str, list[str]]:
    spec = bundle.taxonomy["axes"][axis]
    primary = str(spec["reproducibility_class"])
    contributing = list(spec.get("contributing_reproducibility_classes") or [primary])
    if spec.get("inherits_class_from_codes") and entries:
        inherited: set[str] = set()
        for entry in entries:
            hit = bundle.axis_for_code(entry.code)
            if hit and hit[0] != axis:
                inherited.add(bundle.axis_class(hit[0]))
        if inherited:
            contributing = sorted(set(contributing) | inherited)
            primary = _weakest_class(contributing)
    return primary, contributing


_CLASS_STRENGTH = {
    "byte_deterministic": 0,
    "policy_dependent": 1,
    "validator_version_dependent": 2,
    "time_dependent": 3,
    "resource_dependent": 4,
}


def _weakest_class(classes: Iterable[str]) -> str:
    return max(classes, key=lambda name: _CLASS_STRENGTH.get(name, 0))


def canonical_finding_from_native_report(
    report: dict[str, Any],
    *,
    side: str,
    evidence_class: str,
    asset_digest: str,
    manifest_acquisition_mode: str,
    settings_digest: str,
    trust_basis: dict[str, Any],
    validator: dict[str, Any] | None = None,
    bundle: ContractBundle | None = None,
    manifest_store_digest: str | None = None,
    remote_manifest_uri: str | None = None,
    asset_bytes: int | None = None,
    native_report_digest: str | None = None,
    validation_instant: str | None = None,
) -> dict[str, Any]:
    """Normalize one native report into a canonical per-axis finding object."""
    bundle = bundle or load_bundle()
    entries = parse_native_report(report)

    by_axis: dict[str, list[NativeEntry]] = {axis: [] for axis in AXIS_ORDER}
    unmapped: list[dict[str, Any]] = []
    for entry in entries:
        # Ingredient-scoped findings belong to the ingredient axis regardless of
        # which code they carry; the code's own axis still feeds the inherited
        # reproducibility class.
        if entry.scope == "ingredientDeltas":
            by_axis["ingredient"].append(entry)
            continue
        hit = bundle.axis_for_code(entry.code)
        if hit is None:
            unmapped.append(
                {
                    "code": entry.code,
                    "severity": entry.severity,
                    "scope": entry.scope,
                    "url": entry.url,
                }
            )
            continue
        by_axis[hit[0]].append(entry)

    anchored = any(
        entry.code == "timeStamp.trusted" and entry.severity == "success" for entry in entries
    )

    axes: list[dict[str, Any]] = []
    for axis in AXIS_ORDER:
        axis_entries = by_axis[axis]
        if axis == "revocation":
            # Forced: revocation is reachable only via network OCSP, which
            # hermetic settings disable, and captured OCSP responses cannot be
            # injected for offline replay. Silence is not non-revocation.
            axes.append(
                {
                    "axis": axis,
                    "status": "not_evaluated",
                    "status_reason": (
                        "revocation is reachable only via network OCSP, which hermetic "
                        "settings disable; this is not evidence of non-revocation"
                    ),
                    "reproducibility_class": bundle.axis_class(axis),
                    "contributing_reproducibility_classes": bundle.axis_contributing_classes(axis),
                    "native_findings": [_entry_dict(entry) for entry in axis_entries],
                }
            )
            continue
        status, reason = _axis_status(axis_entries, bundle, axis)
        primary, contributing = _axis_class(bundle, axis, axis_entries)
        axes.append(
            {
                "axis": axis,
                "status": status,
                "status_reason": reason,
                "reproducibility_class": primary,
                "contributing_reproducibility_classes": contributing,
                "native_findings": [_entry_dict(entry) for entry in axis_entries],
            }
        )

    finding: dict[str, Any] = {
        "side": side,
        "evidence_class": evidence_class,
        "validator": dict(validator or PINNED_VALIDATOR),
        "inputs": {
            "asset_digest": asset_digest,
            "manifest_store_digest": manifest_store_digest,
            "manifest_acquisition_mode": manifest_acquisition_mode,
            "remote_manifest_uri": remote_manifest_uri,
            "unresolved_inputs": [],
        },
        "settings": {
            "settings_digest": settings_digest,
            **{key: value for key, value in HERMETIC_SETTINGS_APPLIED.items()},
            "hermeticity": {
                "network_access_permitted": False,
                "remote_resource_fetch_attempted": False,
                "trust_list_uri_dereferenced": False,
                "ocsp_fetch_permitted": False,
            },
        },
        "trust_basis": dict(trust_basis),
        "validation_clock": {
            "source": "wall_clock",
            "caller_pinnable": False,
            "instant": validation_instant,
            "anchored_by_trusted_timestamp": anchored,
        },
        "evaluation_status": "evaluated",
        "evaluation_status_detail": None,
        "native_validation_state": native_validation_state(report),
        "native_report_digest": native_report_digest,
        "axes": axes,
        "unmapped_native_codes": unmapped,
    }
    if asset_bytes is not None:
        finding["inputs"]["asset_bytes"] = asset_bytes
    return finding


def _entry_dict(entry: NativeEntry) -> dict[str, Any]:
    return {
        "code": entry.code,
        "severity": entry.severity,
        "scope": entry.scope,
        "url": entry.url,
        "ingredient_assertion_uri": entry.ingredient_assertion_uri,
    }


def canonical_finding_unavailable(
    *,
    side: str,
    evidence_class: str,
    asset_digest: str,
    manifest_acquisition_mode: str,
    settings_digest: str,
    trust_basis: dict[str, Any],
    detail: str,
    unresolved_inputs: list[dict[str, Any]],
    remote_manifest_uri: str | None = None,
    bundle: ContractBundle | None = None,
    validation_instant: str | None = None,
) -> dict[str, Any]:
    """A canonical finding for a subject whose required input was unavailable.

    Every axis is ``not_evaluated``. An unavailable input is not a validation
    failure and must never be reported as one: the native validator declines to
    produce a report at all rather than emitting a failure code, and hermetic
    settings forbid going to the network to resolve it.
    """
    bundle = bundle or load_bundle()
    axes = [
        {
            "axis": axis,
            "status": "not_evaluated",
            "status_reason": "a required native input was unavailable; no evaluation occurred",
            "reproducibility_class": bundle.axis_class(axis),
            "contributing_reproducibility_classes": bundle.axis_contributing_classes(axis),
            "native_findings": [],
        }
        for axis in AXIS_ORDER
    ]
    return {
        "side": side,
        "evidence_class": evidence_class,
        "validator": dict(PINNED_VALIDATOR),
        "inputs": {
            "asset_digest": asset_digest,
            "manifest_store_digest": None,
            "manifest_acquisition_mode": manifest_acquisition_mode,
            "remote_manifest_uri": remote_manifest_uri,
            "unresolved_inputs": unresolved_inputs,
        },
        "settings": {
            "settings_digest": settings_digest,
            **{key: value for key, value in HERMETIC_SETTINGS_APPLIED.items()},
            "hermeticity": {
                "network_access_permitted": False,
                "remote_resource_fetch_attempted": False,
                "trust_list_uri_dereferenced": False,
                "ocsp_fetch_permitted": False,
                "remote_resource_required_but_unavailable": True,
            },
        },
        "trust_basis": dict(trust_basis),
        "validation_clock": {
            "source": "wall_clock",
            "caller_pinnable": False,
            "instant": validation_instant,
            "anchored_by_trusted_timestamp": False,
        },
        "evaluation_status": "input_unavailable",
        "evaluation_status_detail": detail,
        "native_validation_state": None,
        "native_report_digest": None,
        "axes": axes,
        "unmapped_native_codes": [],
    }


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------


def _comparability(observed: dict[str, Any], recomputed: dict[str, Any]) -> dict[str, bool]:
    obs_v, rec_v = observed["validator"], recomputed["validator"]
    obs_i, rec_i = observed["inputs"], recomputed["inputs"]
    obs_t, rec_t = observed["trust_basis"], recomputed["trust_basis"]
    return {
        "validator_identity_match": obs_v.get("implementation") == rec_v.get("implementation"),
        "validator_version_match": (
            obs_v.get("implementation") == rec_v.get("implementation")
            and obs_v.get("version") == rec_v.get("version")
        ),
        "asset_digest_match": obs_i.get("asset_digest") == rec_i.get("asset_digest"),
        "manifest_store_digest_match": obs_i.get("manifest_store_digest")
        == rec_i.get("manifest_store_digest"),
        "trust_basis_match": (
            obs_t.get("mode") == rec_t.get("mode")
            and obs_t.get("material_digest") == rec_t.get("material_digest")
        ),
        "settings_match": observed["settings"].get("settings_digest")
        == recomputed["settings"].get("settings_digest"),
    }


_AXIS_BASIS_REASON = {
    "signer_trust": "trust_basis_delta",
    "timestamp": "timestamp_basis_delta",
    "revocation": "revocation_basis_delta",
}


def compare_sides(
    observed: dict[str, Any],
    recomputed: dict[str, Any],
    *,
    bundle: ContractBundle | None = None,
) -> tuple[list[dict[str, Any]], dict[str, bool]]:
    """Compare two canonical findings axis by axis.

    The causal question (``comparison_reason``) is answered before, and
    separately from, the inferential question (``integrity_posture``). Only one
    combination ever licenses ``possible_substantive_divergence``: both sides
    resolved the axis, on identical inputs, with identical validator identity
    and version, on an identical policy basis, on an axis whose reproducibility
    class permits substantive comparison. Every other divergence is explained by
    a named basis delta and carries ``no_integrity_inference``.
    """
    bundle = bundle or load_bundle()
    comparability = _comparability(observed, recomputed)

    obs_axes = {item["axis"]: item for item in observed["axes"]}
    rec_axes = {item["axis"]: item for item in recomputed["axes"]}

    obs_anchored = bool(observed["validation_clock"].get("anchored_by_trusted_timestamp"))
    rec_anchored = bool(recomputed["validation_clock"].get("anchored_by_trusted_timestamp"))
    clock_anchored = obs_anchored and rec_anchored

    comparisons: list[dict[str, Any]] = []
    for axis in AXIS_ORDER:
        obs = obs_axes.get(axis)
        rec = rec_axes.get(axis)
        rec_status = rec["status"] if rec else None
        obs_status = obs["status"] if obs else None
        klass = (rec or obs or {}).get("reproducibility_class") or bundle.axis_class(axis)

        state, reason, note = _compare_axis(
            axis=axis,
            obs_status=obs_status,
            rec_status=rec_status,
            klass=klass,
            comparability=comparability,
            clock_anchored=clock_anchored,
        )
        posture = bundle.taxonomy["reason_posture_matrix"][state][reason]
        comparisons.append(
            {
                "axis": axis,
                "state": state,
                "comparison_reason": reason,
                "integrity_posture": posture,
                "reproducibility_class": klass,
                "observed_status": obs_status,
                "recomputed_status": rec_status,
                "note": note,
            }
        )
    return comparisons, comparability


def _compare_axis(
    *,
    axis: str,
    obs_status: str | None,
    rec_status: str | None,
    klass: str,
    comparability: dict[str, bool],
    clock_anchored: bool,
) -> tuple[str, str, str | None]:
    if obs_status is None or rec_status is None:
        return (
            "not_evaluated",
            "insufficient_evidence",
            "one side carries no finding for this axis",
        )

    # Revocation can never be substantively compared under hermetic settings:
    # neither side can have evaluated it, and a captured revocation response
    # cannot be injected for replay.
    if axis == "revocation":
        return (
            "not_comparable",
            "revocation_basis_delta",
            "revocation is not evaluable under hermetic settings on either side",
        )

    if not comparability["asset_digest_match"] or not comparability["manifest_store_digest_match"]:
        return (
            "not_comparable",
            "input_delta",
            "the two sides were evaluated over different bytes",
        )

    if not comparability["validator_identity_match"]:
        return (
            "not_comparable",
            "validator_implementation_delta",
            "the two sides were produced by different native implementations",
        )

    if not comparability["validator_version_match"]:
        return (
            "not_comparable",
            "validator_version_delta",
            "the two sides were produced by different versions of the native implementation; "
            "a version change is a verdict input",
        )

    # Policy-dependent axes are functions of caller-supplied material. A
    # difference in that material is a difference of inputs, not of findings.
    if not comparability["trust_basis_match"] and axis in _AXIS_BASIS_REASON:
        return (
            "not_comparable",
            _AXIS_BASIS_REASON[axis],
            "this axis is a function of caller-supplied trust material, which differs "
            "between the two sides; no divergence claim is available",
        )

    if not comparability["settings_match"]:
        return (
            "not_comparable",
            "policy_delta",
            "the two sides applied different validator settings",
        )

    if obs_status == rec_status:
        return ("match", "same_inputs_same_semantics", None)

    # Divergent, on comparable inputs. Now the reproducibility class decides
    # whether the divergence is even attributable to a substantive disagreement.
    if klass == "time_dependent" and not clock_anchored:
        return (
            "not_comparable",
            "validation_clock_delta",
            "this axis depends on the validation instant, the native validator exposes no "
            "validation-clock control, and no trusted timestamp anchors it; a difference "
            "here is consistent with wall-clock passage alone and is not an integrity finding",
        )

    if klass == "policy_dependent":
        return (
            "not_comparable",
            "policy_delta",
            "this axis is policy-dependent and the two sides cannot be shown to share a policy basis",
        )

    if klass == "resource_dependent":
        return (
            "not_comparable",
            "unsupported_native_feature",
            "this axis depends on an external resource that cannot be frozen and replayed",
        )

    return (
        "mismatch",
        "same_inputs_same_semantics",
        "identical frozen inputs, identical validator identity and version, identical policy "
        "basis, byte-deterministic axis. A substantive disagreement is possible; this is a "
        "prompt to investigate, not a finding of tampering or bad faith",
    )


# ---------------------------------------------------------------------------
# Report assembly
# ---------------------------------------------------------------------------

BASE_LIMITATIONS = (
    "This report describes native C2PA validation only. It is not an SRS receipt "
    "verification and establishes nothing about SRS envelope structure, SRS signatures, "
    "or SRS issuer trust.",
    "Revocation was not evaluated. Revocation is reachable only via network OCSP, which "
    "hermetic settings disable, and captured revocation responses cannot be injected for "
    "offline replay. Absence of a revocation failure is not evidence of non-revocation.",
    "The native validation clock is wall clock and is not caller-pinnable. Hermetic "
    "execution bounds network and resource access; it does not freeze time.",
    "The native validator version is a verdict input. The same bytes have been observed to "
    "validate differently across validator versions.",
    "Signer trust is a function of caller-supplied trust material, not a property of the "
    "asset. A trust finding is only as meaningful as the digest-pinned material behind it.",
)

BASE_NON_CLAIMS = (
    "This report does not establish that the depicted content is authentic, accurate, or "
    "truthfully described.",
    "This report does not establish that the signer is trustworthy in general, nor that the "
    "signing credential appears on the official public C2PA trust list.",
    "This report does not establish that the signing credential is unrevoked.",
    "A native validation_state of Valid is recorded as a native field only. It is not an "
    "arcs-verify verdict; the pinned validator emits Valid simultaneously with a "
    "signingCredential.untrusted failure.",
    "A comparison state of mismatch is not an accusation. It records that two evaluations "
    "differed on a comparable basis and nothing further.",
)


def build_report(
    *,
    subject: dict[str, Any],
    recomputed: dict[str, Any],
    observed: dict[str, Any] | None = None,
    bundle: ContractBundle | None = None,
    extra_limitations: Sequence[str] = (),
    extra_non_claims: Sequence[str] = (),
) -> dict[str, Any]:
    """Assemble a native finding report.

    ``comparison`` and ``comparability`` are emitted if and only if ``observed``
    is supplied. When there is no observation there is no comparison — not an
    array of ``not_evaluated`` comparisons, which would manufacture the shape of
    an evaluation that was never in scope.
    """
    bundle = bundle or load_bundle()
    report: dict[str, Any] = {
        "report_contract_id": CONTRACT_ID,
        "report_contract_version": CONTRACT_VERSION,
        "contract_semantic_digest": bundle.semantic_digest,
        "subject": dict(subject),
        "recomputed": recomputed,
        "limitations": list(BASE_LIMITATIONS) + list(extra_limitations),
        "non_claims": list(BASE_NON_CLAIMS) + list(extra_non_claims),
        "unexercised_paths": list(bundle.taxonomy["unexercised_paths"]["codes"])
        + list(bundle.taxonomy["unexercised_paths"]["features"]),
    }
    if observed is not None:
        comparisons, comparability = compare_sides(observed, recomputed, bundle=bundle)
        report["observed"] = observed
        report["comparability"] = comparability
        report["comparison"] = comparisons
    return report


# ---------------------------------------------------------------------------
# Bundle conformance checker
# ---------------------------------------------------------------------------


@dataclass
class ConformanceResult:
    findings: list[str] = field(default_factory=list)

    @property
    def conformant(self) -> bool:
        return not self.findings

    def fail(self, code: str, message: str) -> None:
        self.findings.append(f"{code}: {message}")


def _walk_keys(value: Any) -> Iterator[str]:
    if isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            yield from _walk_keys(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_keys(item)


def check_report(report: dict[str, Any], *, bundle: ContractBundle | None = None) -> ConformanceResult:
    """Enforce the cross-object invariants JSON Schema cannot express.

    JSON Schema can say a comparison entry has an ``axis`` and a ``state``. It
    cannot say that the set of axes is exactly the canonical set with no
    repeats, that a mismatch attributed to a trust-basis delta must not carry an
    integrity accusation, or that a comparison must not exist at all when there
    is nothing to compare against. Those are this function's job, and the schema
    is not a substitute for it.
    """
    bundle = bundle or load_bundle()
    result = ConformanceResult()

    # -- Structural schema validation first ---------------------------------
    try:  # pragma: no cover - exercised whenever jsonschema is installed
        import jsonschema
        from jsonschema import validators
        from referencing import Registry, Resource

        registry = Registry().with_resources(
            [
                (bundle.finding_schema["$id"], Resource.from_contents(bundle.finding_schema)),
                (bundle.report_schema["$id"], Resource.from_contents(bundle.report_schema)),
            ]
        )
        validator_cls = validators.validator_for(bundle.report_schema)
        validator = validator_cls(bundle.report_schema, registry=registry)
        for error in sorted(validator.iter_errors(report), key=lambda e: list(e.path)):
            path = "/".join(str(part) for part in error.path) or "<root>"
            result.fail("C2PA_SCHEMA", f"{path}: {error.message}")
    except ImportError:  # pragma: no cover
        result.fail("C2PA_SCHEMA", "jsonschema is not available; structural validation not performed")

    # -- Forbidden aggregate constructs -------------------------------------
    for key in _walk_keys(report):
        if key in FORBIDDEN_AGGREGATE_KEYS:
            result.fail(
                "C2PA_AGGREGATE_FORBIDDEN",
                f"report carries prohibited aggregate key '{key}'; the contract reports "
                "separate axes and no aggregate match Boolean",
            )

    if "recomputed" not in report:
        result.fail("C2PA_RECOMPUTATION_REQUIRED", "'recomputed' is required and is absent")
        return result

    has_observed = "observed" in report
    has_comparison = "comparison" in report
    has_comparability = "comparability" in report

    # -- Presence coupling ---------------------------------------------------
    if has_observed and not has_comparison:
        result.fail(
            "C2PA_COMPARISON_MISSING",
            "'observed' is present but 'comparison' is absent",
        )
    if has_comparison and not has_observed:
        result.fail(
            "C2PA_COMPARISON_UNGROUNDED",
            "'comparison' is present without 'observed'; a comparison with nothing to "
            "compare against must be absent, not synthesized as not_evaluated entries",
        )
    if has_comparability != has_observed:
        result.fail(
            "C2PA_COMPARABILITY_COUPLING",
            "'comparability' must be present exactly when 'observed' is present",
        )

    # -- Side labelling ------------------------------------------------------
    if report["recomputed"].get("side") != "recomputed":
        result.fail("C2PA_SIDE_LABEL", "'recomputed' is not labelled side=recomputed")
    if has_observed and report["observed"].get("side") != "observed":
        result.fail("C2PA_SIDE_LABEL", "'observed' is not labelled side=observed")

    # -- Per-side axis coverage and uniqueness -------------------------------
    for side_name in ("recomputed", "observed"):
        side = report.get(side_name)
        if not isinstance(side, dict):
            continue
        axes = [item.get("axis") for item in side.get("axes", [])]
        _check_axis_set(result, f"{side_name}.axes", axes)
        _check_hermeticity(result, side_name, side)
        _check_revocation(result, side_name, side)
        _check_clock(result, side_name, side)
        _check_unavailable(result, side_name, side)

    if not has_comparison or not has_observed:
        # A comparison with no observation behind it has already been reported as
        # ungrounded; there is nothing to check it against, and pretending
        # otherwise would be the same collapse the rule exists to prevent.
        return result

    # -- Comparison axis uniqueness and coverage -----------------------------
    comparison = report["comparison"]
    _check_axis_set(result, "comparison", [item.get("axis") for item in comparison])

    matrix = bundle.taxonomy["reason_posture_matrix"]
    obs_axes = {item["axis"]: item for item in report["observed"].get("axes", [])}
    rec_axes = {item["axis"]: item for item in report["recomputed"].get("axes", [])}
    recomputed_comparability = _comparability(report["observed"], report["recomputed"])

    if report.get("comparability") != recomputed_comparability:
        result.fail(
            "C2PA_COMPARABILITY_NOT_RECOMPUTED",
            "the declared comparability predicates do not match the values recomputed from "
            "the two sides' own recorded inputs; comparability is a recomputed fact, not an "
            "assertion",
        )

    for entry in comparison:
        axis = entry.get("axis")
        state = entry.get("state")
        reason = entry.get("comparison_reason")
        posture = entry.get("integrity_posture")

        legal = matrix.get(state)
        if legal is None:
            result.fail("C2PA_COMPARISON_STATE", f"{axis}: unknown comparison state '{state}'")
            continue
        if reason not in legal:
            result.fail(
                "C2PA_REASON_ILLEGAL_FOR_STATE",
                f"{axis}: comparison_reason '{reason}' is not legal for state '{state}'",
            )
            continue
        if posture != legal[reason]:
            result.fail(
                "C2PA_POSTURE_ILLEGAL_FOR_REASON",
                f"{axis}: state '{state}' with reason '{reason}' requires integrity_posture "
                f"'{legal[reason]}', found '{posture}'",
            )

        # An integrity accusation is only ever available on a byte-deterministic
        # axis compared on identical inputs by an identical validator.
        if posture == "possible_substantive_divergence":
            if entry.get("reproducibility_class") != "byte_deterministic":
                result.fail(
                    "C2PA_INTEGRITY_ON_NONDETERMINISTIC_AXIS",
                    f"{axis}: possible_substantive_divergence claimed on a "
                    f"{entry.get('reproducibility_class')} axis; a divergence explainable by "
                    "clock, policy, or resource variation is not an integrity inference",
                )
            for predicate, value in recomputed_comparability.items():
                if not value:
                    result.fail(
                        "C2PA_INTEGRITY_WITHOUT_COMPARABLE_BASIS",
                        f"{axis}: possible_substantive_divergence claimed while "
                        f"comparability predicate '{predicate}' is false",
                    )

        # Reported statuses must be the statuses actually recorded on each side.
        declared_obs = entry.get("observed_status")
        declared_rec = entry.get("recomputed_status")
        actual_obs = obs_axes.get(axis, {}).get("status")
        actual_rec = rec_axes.get(axis, {}).get("status")
        if declared_obs != actual_obs:
            result.fail(
                "C2PA_STATUS_NOT_GROUNDED",
                f"{axis}: comparison observed_status '{declared_obs}' does not match the "
                f"observed side's recorded status '{actual_obs}'",
            )
        if declared_rec != actual_rec:
            result.fail(
                "C2PA_STATUS_NOT_GROUNDED",
                f"{axis}: comparison recomputed_status '{declared_rec}' does not match the "
                f"recomputed side's recorded status '{actual_rec}'",
            )
        if state == "match" and actual_obs != actual_rec:
            result.fail(
                "C2PA_MATCH_WITHOUT_EQUALITY",
                f"{axis}: state 'match' declared while the two sides recorded different statuses",
            )
        if state == "mismatch" and actual_obs == actual_rec:
            result.fail(
                "C2PA_MISMATCH_WITHOUT_DIFFERENCE",
                f"{axis}: state 'mismatch' declared while the two sides recorded the same status",
            )

    return result


def _check_axis_set(result: ConformanceResult, label: str, axes: Sequence[Any]) -> None:
    seen: set[Any] = set()
    for axis in axes:
        if axis in seen:
            result.fail("C2PA_AXIS_DUPLICATE", f"{label}: axis '{axis}' appears more than once")
        seen.add(axis)
    missing = set(AXIS_ORDER) - seen
    if missing:
        result.fail(
            "C2PA_AXIS_COVERAGE",
            f"{label}: missing axis/axes {sorted(missing)}; every canonical axis must be "
            "represented explicitly rather than omitted",
        )
    extra = seen - set(AXIS_ORDER)
    if extra:
        result.fail("C2PA_AXIS_UNKNOWN", f"{label}: unknown axis/axes {sorted(extra)}")


def _check_hermeticity(result: ConformanceResult, side_name: str, side: dict[str, Any]) -> None:
    hermeticity = side.get("settings", {}).get("hermeticity", {})
    for flag in (
        "network_access_permitted",
        "remote_resource_fetch_attempted",
        "trust_list_uri_dereferenced",
        "ocsp_fetch_permitted",
    ):
        if hermeticity.get(flag) is not False:
            result.fail(
                "C2PA_HERMETICITY",
                f"{side_name}: hermetic invocation requires {flag}=false, found "
                f"{hermeticity.get(flag)!r}",
            )
    settings = side.get("settings", {})
    if settings.get("remote_manifest_fetch") is not False:
        result.fail("C2PA_HERMETICITY", f"{side_name}: remote_manifest_fetch must be false")
    if settings.get("ocsp_fetch") is not False:
        result.fail("C2PA_HERMETICITY", f"{side_name}: ocsp_fetch must be false")
    if settings.get("allowed_network_hosts") != []:
        result.fail("C2PA_HERMETICITY", f"{side_name}: allowed_network_hosts must be empty")


def _check_revocation(result: ConformanceResult, side_name: str, side: dict[str, Any]) -> None:
    for item in side.get("axes", []):
        if item.get("axis") != "revocation":
            continue
        if item.get("status") != "not_evaluated":
            result.fail(
                "C2PA_REVOCATION_IMPLIED",
                f"{side_name}: revocation status is '{item.get('status')}'; under hermetic "
                "settings revocation must be not_evaluated, never a value that implies "
                "non-revocation",
            )


def _check_clock(result: ConformanceResult, side_name: str, side: dict[str, Any]) -> None:
    clock = side.get("validation_clock", {})
    if clock.get("source") != "wall_clock":
        result.fail(
            "C2PA_CLOCK_SOURCE",
            f"{side_name}: validation_clock.source must be wall_clock; the pinned validator "
            "exposes no validation-clock control",
        )
    if clock.get("caller_pinnable") is not False:
        result.fail(
            "C2PA_CLOCK_PINNABLE",
            f"{side_name}: validation_clock.caller_pinnable must be false; hermetic execution "
            "does not make the validation instant pinnable",
        )


def _check_unavailable(result: ConformanceResult, side_name: str, side: dict[str, Any]) -> None:
    if side.get("evaluation_status") == "evaluated":
        return
    for item in side.get("axes", []):
        if item.get("status") not in {"not_evaluated", "not_applicable"}:
            result.fail(
                "C2PA_UNAVAILABLE_AS_FAILURE",
                f"{side_name}: evaluation_status is "
                f"'{side.get('evaluation_status')}' but axis '{item.get('axis')}' reports "
                f"'{item.get('status')}'; an unavailable input is not a validation failure",
            )
    if side.get("native_validation_state") is not None:
        result.fail(
            "C2PA_UNAVAILABLE_WITH_STATE",
            f"{side_name}: a native validation_state is recorded although no evaluation occurred",
        )


# ---------------------------------------------------------------------------
# End-to-end recomputation
# ---------------------------------------------------------------------------


def recompute(
    asset: Path,
    *,
    executable: str,
    settings_path: Path,
    external_manifest: Path | None = None,
    trust_basis: dict[str, Any] | None = None,
    bundle: ContractBundle | None = None,
    manifest_acquisition_mode: str | None = None,
    remote_manifest_uri: str | None = None,
    subject_extra: dict[str, Any] | None = None,
    observed: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run the pinned validator over frozen inputs and assemble a report."""
    bundle = bundle or load_bundle()
    asset = Path(asset)
    asset_digest = digest_file(asset)
    settings_digest = digest_file(settings_path)
    trust_basis = trust_basis or {
        "mode": "default",
        "material_digest": None,
        "material_source": None,
        "material_source_pin": None,
        "on_official_c2pa_trust_list": "not_established",
    }
    mode = manifest_acquisition_mode or ("external_supplied" if external_manifest else "embedded")
    instant = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    detected_version = native_validator_version(executable)
    validator = dict(PINNED_VALIDATOR)
    if detected_version:
        validator["version"] = detected_version

    outcome = run_native_validator(
        executable,
        asset,
        settings_path=settings_path,
        external_manifest=external_manifest,
    )

    if outcome.evaluated and outcome.report is not None:
        native_bytes = json.dumps(outcome.report, sort_keys=True, separators=(",", ":")).encode("utf-8")
        recomputed = canonical_finding_from_native_report(
            outcome.report,
            side="recomputed",
            evidence_class="live_native_invocation",
            asset_digest=asset_digest,
            manifest_acquisition_mode=mode,
            settings_digest=settings_digest,
            trust_basis=trust_basis,
            validator=validator,
            bundle=bundle,
            manifest_store_digest=digest_file(external_manifest) if external_manifest else None,
            remote_manifest_uri=remote_manifest_uri,
            asset_bytes=asset.stat().st_size,
            native_report_digest="sha256:" + _digest_bytes(native_bytes),
            validation_instant=instant,
        )
    else:
        recomputed = canonical_finding_unavailable(
            side="recomputed",
            evidence_class="live_native_invocation",
            asset_digest=asset_digest,
            manifest_acquisition_mode=mode,
            settings_digest=settings_digest,
            trust_basis=trust_basis,
            detail=outcome.detail or "no machine report was produced",
            unresolved_inputs=[
                {
                    "input": "manifest_store",
                    "reason": "required manifest store not available locally under hermetic settings",
                    "uri": remote_manifest_uri,
                }
            ],
            remote_manifest_uri=remote_manifest_uri,
            bundle=bundle,
            validation_instant=instant,
        )

    subject = {"asset_digest": asset_digest, "asset_label": asset.name}
    subject.update(subject_extra or {})
    return build_report(subject=subject, recomputed=recomputed, observed=observed, bundle=bundle)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="arcs-verify c2pa-native",
        description=(
            "Independently recompute a native C2PA validation over frozen inputs under "
            "hermetic settings and, when an observation is supplied, compare the two "
            "axis by axis. This reports NATIVE C2PA validation; it is not SRS receipt "
            "verification."
        ),
    )
    parser.add_argument("asset", type=Path, nargs="?", help="path to the asset bytes")
    parser.add_argument(
        "--external-manifest",
        type=Path,
        default=None,
        help="path to captured manifest-store bytes (the sealed replay path for a remote manifest)",
    )
    parser.add_argument(
        "--c2patool",
        default=None,
        help=(
            f"path to the pinned native validator ({PINNED_VALIDATOR['implementation']} "
            f"{PINNED_VALIDATOR['version']}); may also be set via {VALIDATOR_ENV}"
        ),
    )
    parser.add_argument("--observed", type=Path, default=None, help="path to a canonical observed finding JSON")
    parser.add_argument("--check", type=Path, default=None, help="check an existing report for contract conformance and exit")
    parser.add_argument("--json", action="store_true", dest="as_json")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    bundle = load_bundle()

    if args.check is not None:
        report = json.loads(Path(args.check).read_text(encoding="utf-8"))
        result = check_report(report, bundle=bundle)
        for finding in result.findings:
            print(finding)
        print(f"{'PASS' if result.conformant else 'FAIL'}: {len(result.findings)} finding(s)")
        return 0 if result.conformant else 1

    if args.asset is None:
        parser.error("an asset path is required unless --check is used")

    executable = resolve_validator(args.c2patool)
    if executable is None:
        print(
            "usage error: no native validator supplied. Install the pinned build with\n"
            f"  {PINNED_VALIDATOR['install_command']}\n"
            f"then pass --c2patool PATH or set {VALIDATOR_ENV}.",
            file=sys.stderr,
        )
        return 2

    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        settings_path = Path(tmp) / "hermetic.toml"
        settings_path.write_text(HERMETIC_SETTINGS_TOML, encoding="utf-8")
        observed = (
            json.loads(Path(args.observed).read_text(encoding="utf-8"))
            if args.observed is not None
            else None
        )
        report = recompute(
            args.asset,
            executable=executable,
            settings_path=settings_path,
            external_manifest=args.external_manifest,
            bundle=bundle,
            observed=observed,
        )

    result = check_report(report, bundle=bundle)
    if args.as_json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        rec = report["recomputed"]
        print(f"evaluation_status: {rec['evaluation_status']}")
        print(f"native_validation_state (native field only): {rec['native_validation_state']}")
        for item in rec["axes"]:
            print(f"  {item['axis']}: {item['status']}  [{item['reproducibility_class']}]")
        for item in report.get("comparison", []):
            print(
                f"  comparison {item['axis']}: {item['state']} "
                f"({item['comparison_reason']} / {item['integrity_posture']})"
            )
        for finding in result.findings:
            print(f"contract_finding: {finding}")
    return 0 if result.conformant else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
