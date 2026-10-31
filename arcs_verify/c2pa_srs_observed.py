"""Untrusted adapter: an SRS C2PA validation observation -> the canonical observed
finding that ``arcs_verify.c2pa_native`` compares against its own recomputation.

EXPERIMENTAL / PROVISIONAL. Owner acceptance outstanding. AUTHORITY_MOVEMENT = 0.

Inputs are serialized bytes only: the observation (``srs.c2pa.validation_observation.v0.1``)
and the native-report evidence the producer retained. No producer code is imported,
nothing is fetched, and no key material is read.

The pipeline runs in a fixed order and stops at the first stage that does not complete:

1. ``input_correspondence``  every digest the observation names is checked against the
                             retained bytes (or listed as unchecked), and the observation's
                             claims about the native report are checked against that report.
2. ``profile_conformance``   the observation is checked against the pinned arcs-srs profile
                             (field schema, manifest, conformance rules, limitation registry,
                             envelope v0.2.1), vendored byte-exact and re-hashed on load.
3. ``observed_finding_construction``  only now is the untrusted observed-side canonical
                             finding built; a value that has no canonical representation is
                             refused, never defaulted.

Then the verifier recomputes from the frozen inputs with its OWN pinned native validator
path (``c2pa_native.recompute``) and compares the two sides axis by axis with the existing
comparison. The producer's own validator output is never the independent result.

What this module does NOT do, by construction:

* It is not an SRS receipt verifier. The SRS signature, key resolution and key trust axes
  are always ``not_evaluated``: the profile is unsigned (``requires_signing: false``) and no
  key material is accepted. An unsigned or unverified observation is never reported as
  authenticated issuance.
* A trust value the producer asserted is reported as ``producer_asserted``. It is never an
  independent finding and it never feeds a canonical axis.
* There is no aggregate verdict anywhere in the report.
* The native validation state, the producer's process exit code and the observation's
  conformance are different facts and are reported separately.

``# GUARD:<ID>`` comments mark single-line guard sites. They are the enumerable mutation
surface used by the lane's mutation battery; they have no runtime meaning.
"""

from __future__ import annotations

import argparse
import functools
import hashlib
import json
import re
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence

from jsonschema import Draft202012Validator

from . import c2pa_native
from .schema import ENVELOPE_SCHEMA_PINS

__all__ = [
    "ADAPTER_ID",
    "PROFILE_SLUG",
    "SOURCE_REPOSITORY",
    "SOURCE_COMMIT",
    "PINNED_CONTRACT_FILES",
    "STAGES",
    "ContractPinError",
    "OrderingViolation",
    "Refusal",
    "StageOutcome",
    "RetainedEvidence",
    "ConsumptionResult",
    "consume_observation",
    "construct_observed_side",
    "source_digest_refusals",
    "main",
]

ADAPTER_ID = "arcs-verify.c2pa-srs-observed/experimental-1"
PROFILE_SLUG = "srs.c2pa.validation_observation.v0.1"
SOURCE_REPOSITORY = "thelaplage/arcs-srs"
SOURCE_COMMIT = "3219ff83eb47f46582eefbd53dc46a9d78ef5d4b"
BINDING_SEMANTIC_DIGEST = "sha256:23506ae1d4b50c1742019363d43799d62844ad5a066398eb4bff04a58949d2f5"
PROFILE_MANIFEST_PROJECTION_SHA256 = "ca2e1c22253a75ffe25c3a7067919cd00206646a9236a5ca3315fc1fd2e1e7b2"

_PACKAGE_ROOT = Path(__file__).resolve().parent
CONTRACT_DIR = _PACKAGE_ROOT / "contracts" / "c2pa-srs-observation" / "v0.1"
ENVELOPE_SCHEMA_PATH = _PACKAGE_ROOT / "data" / "srs-envelope-v0.2.1.schema.json"

# The pin lives in code, not only in a data file that could be edited together with the
# bytes it pins: (sha256 of the file, git blob id). Values are the arcs-srs bytes at
# SOURCE_COMMIT.
PINNED_CONTRACT_FILES: dict[str, tuple[str, str]] = {
    "field.schema.json": (
        "6549230ebed4b28c9def301576ccf7dfead7a25e1bd8fb870fc751d466dce6df",
        "0a539efa1a13da517802b1f5b7279439c65895ed",
    ),
    "profile.manifest.json": (
        "824b40cb50b2b30281c03f31e9fa46ad6c2da70176eaf575848f141aa809cfbd",
        "1746deff40f5eb94d9fbbc2f1a662a5ba40091a7",
    ),
    "conformance-rules.json": (
        "eaa8c20ed2992badcdefa63d9cb63293bcdd174087fa1e828b929034271c3b48",
        "c0488a2ef08d561e7acefaef392a6da7eb25783f",
    ),
    "limitation-codes.json": (
        "40caf8e622b5de9b9f8b08365d7d2dcc6fb89a9d4781e3dd35f84163fd3d1186",
        "6530e1c62b37f16a82307d920a2d172d4ddb5f67",
    ),
}

STAGES: tuple[str, ...] = (
    "input_parse",
    "input_correspondence",
    "profile_conformance",
    "observed_finding_construction",
    "native_recomputation",
    "comparison",
)

SUPPORTED_REPORT_FORMAT = "c2patool.json"
MAX_OBSERVATION_BYTES = 16 * 1024 * 1024
MAX_NATIVE_REPORT_BYTES = 64 * 1024 * 1024
MAX_JSON_DEPTH = 64
_ASSET_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_DIGEST_STRICT_RE = re.compile(r"sha256:[0-9a-f]{64}")

# Canonical-contract vocabularies (arcs_verify/contracts/c2pa-native-finding/v0.1).
_CANONICAL_ACQUISITION_MODES = frozenset(
    {"embedded", "remote_reference", "external_supplied", "sidecar", "durable_recovery"}
)
_CANONICAL_NATIVE_STATES = frozenset({"Trusted", "Valid", "Invalid"})
_TRUST_MODE = {
    "default_no_trust_material": "default",
    "explicit_anchors": "anchors_supplied",
    "custom_allowed_list": "allowed_list_supplied",
    "trust_verification_disabled": "trust_disabled",
}
_MATERIAL_BASES = frozenset({"explicit_anchors", "custom_allowed_list"})
_INVALID_VALIDITY_CODES = frozenset(
    {"signingCredential.expired", "signingCredential.notValidYet", "signingCredential.invalid"}
)


class ContractPinError(ValueError):
    """A vendored contract file does not match the code-held pin (installation integrity)."""


class OrderingViolation(RuntimeError):
    """The observed-side finding was requested before steps 1 and 2 completed."""


# ---------------------------------------------------------------------------
# Typed results
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Refusal:
    code: str
    field: str | None
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code, "field": self.field, "detail": self.detail}


@dataclass(frozen=True)
class StageOutcome:
    """One stage's own result. ``completed`` means the stage ran to the end with no
    refusal; it is not a statement that the observation is valid, true or trusted."""

    stage: str
    status: str  # completed | refused | not_evaluated | not_run
    refusals: tuple[Refusal, ...] = ()
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "stage": self.stage,
            "status": self.status,
            "refusals": [item.to_dict() for item in self.refusals],
            "detail": self.detail,
        }


@dataclass(frozen=True)
class RetainedEvidence:
    """Bytes the producer retained. ``asset_name`` is an untrusted label used only for the
    extension the native validator uses to detect the format."""

    asset: bytes
    asset_name: str = "asset.bin"
    native_report: bytes | None = None
    manifest_store: bytes | None = None
    configuration: bytes | None = None


@dataclass(frozen=True)
class ConsumptionResult:
    stages: Mapping[str, StageOutcome]
    stopped_at: str | None
    report: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return self.report


def _clip(value: Any, limit: int = 240) -> str:
    text = value if isinstance(value, str) else repr(value)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def _dict(value: Any, *path: str) -> Any:
    """Descend through dict hops; None as soon as a hop is not a dict or is missing."""
    node = value
    for key in path:
        if not isinstance(node, dict):
            return None
        node = node.get(key)
    return node


# ---------------------------------------------------------------------------
# Pinned contract loading
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Contract:
    directory: Path
    field_schema: dict[str, Any]
    manifest: dict[str, Any]
    rules: dict[str, Any]
    registry: dict[str, Any]
    envelope_schema: dict[str, Any]
    field_validator: Draft202012Validator
    envelope_validator: Draft202012Validator


_RULES_SECTIONS = (
    "required_object_fields",
    "subject_binding",
    "manifest_store",
    "manifest_acquisition",
    "hermetic_replay",
    "native_validator",
    "evaluation_posture",
    "signer_trust",
    "signer_provenance",
    "later_comparison_posture",
    "prior_producer_report",
    "conditional_machine_limitation_codes",
)


@functools.lru_cache(maxsize=4)
def _load_contract_cached(directory: str) -> _Contract:
    root = Path(directory)
    raw: dict[str, bytes] = {}
    for name, (sha, blob) in PINNED_CONTRACT_FILES.items():
        data = (root / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != sha:  # GUARD:PF-PIN-SHA256
            raise ContractPinError(f"vendored contract file {name} does not match its pinned sha256")
        if _git_blob_sha1(data) != blob:  # GUARD:PF-PIN-BLOB
            raise ContractPinError(f"vendored contract file {name} does not match its pinned git blob")
        raw[name] = data

    provenance = json.loads((root / "source-pin.json").read_bytes())
    if provenance.get("source_commit") != SOURCE_COMMIT:  # GUARD:PF-PIN-PROVENANCE
        raise ContractPinError("source-pin.json source_commit does not match the code-held pin")
    for name, (sha, blob) in PINNED_CONTRACT_FILES.items():
        recorded = provenance.get("files", {}).get(name, {})
        if recorded.get("sha256") != sha or recorded.get("git_blob") != blob:  # GUARD:PF-PIN-PROVENANCE-FILES
            raise ContractPinError(f"source-pin.json disagrees with the code-held pin for {name}")

    envelope_bytes = ENVELOPE_SCHEMA_PATH.read_bytes()
    if hashlib.sha256(envelope_bytes).hexdigest() != ENVELOPE_SCHEMA_PINS["v0.2.1"]:  # GUARD:PF-PIN-ENVELOPE
        raise ContractPinError("vendored SRS envelope v0.2.1 schema does not match its pinned sha256")

    field_schema = json.loads(raw["field.schema.json"])
    manifest = json.loads(raw["profile.manifest.json"])
    rules = json.loads(raw["conformance-rules.json"])
    registry = json.loads(raw["limitation-codes.json"])
    envelope_schema = json.loads(envelope_bytes)

    if manifest.get("profile_slug") != PROFILE_SLUG or rules.get("profile_slug") != PROFILE_SLUG:
        raise ContractPinError("vendored profile files do not name the expected profile slug")
    if rules.get("schema") != "arcs-srs.profile-conformance-rules.v0.1":
        raise ContractPinError("vendored conformance rules declare an unexpected schema")
    missing = [section for section in _RULES_SECTIONS if section not in rules]
    if missing:
        raise ContractPinError(f"vendored conformance rules lack sections {missing}")
    if registry.get("version") != manifest.get("limitation_codes_registry_version"):
        raise ContractPinError("limitation-code registry version does not match the profile manifest")

    Draft202012Validator.check_schema(field_schema)
    Draft202012Validator.check_schema(envelope_schema)
    return _Contract(
        directory=root,
        field_schema=field_schema,
        manifest=manifest,
        rules=rules,
        registry=registry,
        envelope_schema=envelope_schema,
        field_validator=Draft202012Validator(field_schema),
        envelope_validator=Draft202012Validator(envelope_schema),
    )


def _load_contract() -> _Contract:
    return _load_contract_cached(str(CONTRACT_DIR))


# ---------------------------------------------------------------------------
# Stage 0: strict parse of the untrusted observation
# ---------------------------------------------------------------------------


class _DuplicateKey(ValueError):
    pass


def _strict_loads(data: bytes) -> Any:
    text = data.decode("utf-8")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in items:
            if key in out:
                raise _DuplicateKey(key)
            out[key] = value
        return out

    def constant(name: str) -> Any:
        raise ValueError(f"non-finite JSON constant {name}")

    def number(text_value: str) -> float:
        value = float(text_value)
        if value in (float("inf"), float("-inf")) or value != value:
            raise ValueError("non-finite JSON number")
        return value

    return json.loads(text, object_pairs_hook=pairs, parse_constant=constant, parse_float=number)


def _json_depth(value: Any) -> int:
    deepest = 0
    stack = [(value, 1)]
    while stack:
        node, depth = stack.pop()
        deepest = max(deepest, depth)
        children: Sequence[Any] = ()
        if isinstance(node, dict):
            children = list(node.values())
        elif isinstance(node, list):
            children = node
        for child in children:
            if isinstance(child, (dict, list)):
                stack.append((child, depth + 1))
    return deepest


def _stage_parse(data: bytes) -> tuple[dict[str, Any] | None, StageOutcome]:
    stage = "input_parse"

    def refuse(code: str, detail: str) -> tuple[None, StageOutcome]:
        return None, StageOutcome(stage, "refused", (Refusal(code, None, detail),))

    if len(data) > MAX_OBSERVATION_BYTES:  # GUARD:PARSE-SIZE
        return refuse("OBS_TOO_LARGE", f"observation exceeds {MAX_OBSERVATION_BYTES} bytes")
    try:
        value = _strict_loads(data)
    except UnicodeDecodeError:
        return refuse("OBS_NOT_UTF8", "observation is not valid UTF-8")
    except _DuplicateKey as exc:
        return refuse("OBS_DUPLICATE_KEY", f"duplicate object key {_clip(str(exc))}")
    except RecursionError:
        return refuse("OBS_TOO_DEEP", "observation nesting exceeds the parser limit")
    except ValueError as exc:
        return refuse("OBS_NOT_JSON", _clip(str(exc)))
    if not isinstance(value, dict):  # GUARD:PARSE-OBJECT
        return refuse("OBS_NOT_OBJECT", "observation must be a JSON object")
    if _json_depth(value) > MAX_JSON_DEPTH:  # GUARD:PARSE-DEPTH
        return refuse("OBS_TOO_DEEP", f"observation nesting exceeds {MAX_JSON_DEPTH}")
    return value, StageOutcome(
        stage,
        "completed",
        detail={"observation_sha256": _sha256(data), "observation_bytes": len(data)},
    )


# ---------------------------------------------------------------------------
# Step 1: exact input correspondence
# ---------------------------------------------------------------------------


def _iter_named_digests(value: Any, path: str = "") -> Iterator[tuple[str, str]]:
    """Every string leaf that names a digest, wherever it sits."""
    if isinstance(value, dict):
        for key, item in value.items():
            yield from _iter_named_digests(item, f"{path}.{key}" if path else str(key))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _iter_named_digests(item, f"{path}[{index}]")
    elif isinstance(value, str) and value.startswith("sha256:"):
        yield path, value


def _parse_report_bytes(data: bytes) -> dict[str, Any] | None:
    if len(data) > MAX_NATIVE_REPORT_BYTES:
        return None
    try:
        value = _strict_loads(data)
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None
    if not isinstance(value, dict) or not isinstance(value.get("validation_results"), dict):
        return None
    return value


def _findings_mismatch(claimed: Any, report: dict[str, Any]) -> str | None:
    """Return a description when the observation's native_findings do not correspond to the
    retained native report, else None. Uses the verifier's own report parser and, like it,
    never reads the legacy flattened ``validation_status`` array."""
    entries = c2pa_native.parse_native_report(report)
    actual = sorted((e.scope, e.severity, e.code) for e in entries)
    claimed_list = claimed if isinstance(claimed, list) else []
    claimed_keys: list[tuple[str, str, str]] = []
    for item in claimed_list:
        if not isinstance(item, dict):
            return "a native_findings entry is not an object"
        claimed_keys.append((str(item.get("scope")), str(item.get("severity")), str(item.get("code"))))
    if sorted(claimed_keys) != actual:
        return "native_findings (scope, severity, code) do not equal the retained report's findings"
    urls: dict[tuple[str, str, str], list[str | None]] = {}
    for entry in entries:
        urls.setdefault((entry.scope, entry.severity, entry.code), []).append(entry.url)
    for item in claimed_list:
        uri = item.get("uri")
        if uri is None:
            continue
        pool = urls.get((str(item.get("scope")), str(item.get("severity")), str(item.get("code"))), [])
        if uri not in pool:
            return "a native_findings uri is not a url the retained report carries for that finding"
        pool.remove(uri)
    return None


def _stage_correspondence(obs: dict[str, Any], evidence: RetainedEvidence) -> tuple[None, StageOutcome]:
    stage = "input_correspondence"
    refusals: list[Refusal] = []
    checks: list[dict[str, Any]] = []
    unchecked: list[dict[str, str]] = []

    def refuse(code: str, field_name: str, detail: str) -> None:
        refusals.append(Refusal(code, field_name, detail))

    def record(field_name: str, status: str, **extra: Any) -> None:
        checks.append({"field": field_name, "status": status, **extra})

    census = list(_iter_named_digests(obs))
    for path, value in census:
        if not _DIGEST_STRICT_RE.fullmatch(value):  # GUARD:CORR-DIGEST-FORMAT
            refuse("CORR_DIGEST_MALFORMED", path, "a named digest is not sha256: plus 64 lowercase hex characters")

    asset_actual = _sha256(evidence.asset)

    named = obs.get("asset_digest")
    if not isinstance(named, str):  # GUARD:CORR-ASSET-NOT-NAMED
        refuse("CORR_ASSET_DIGEST_NOT_NAMED", "asset_digest", "the observation does not name the asset digest")
    elif named != asset_actual:  # GUARD:CORR-ASSET-DIGEST
        refuse("CORR_ASSET_DIGEST_MISMATCH", "asset_digest", "named asset digest differs from the retained asset bytes")
        record("asset_digest", "mismatch", named=named, retained_bytes_digest=asset_actual)
    else:
        record("asset_digest", "match", named=named, retained_bytes_digest=asset_actual)

    subject_ref = obs.get("subject_ref")
    if isinstance(subject_ref, str) and subject_ref != asset_actual:  # GUARD:CORR-SUBJECT-REF
        refuse("CORR_SUBJECT_REF_MISMATCH", "subject_ref", "subject_ref differs from the retained asset bytes")
        record("subject_ref", "mismatch", named=subject_ref, retained_bytes_digest=asset_actual)
    elif isinstance(subject_ref, str):
        record("subject_ref", "match", named=subject_ref, retained_bytes_digest=asset_actual)

    manifest_named = _dict(obs, "manifest_store", "digest")
    if evidence.manifest_store is not None:
        manifest_actual = _sha256(evidence.manifest_store)
        if not isinstance(manifest_named, str):  # GUARD:CORR-MANIFEST-UNNAMED
            refuse("CORR_EVIDENCE_NOT_NAMED", "manifest_store.digest", "manifest-store bytes were supplied but the observation names no manifest-store digest")
        elif manifest_named != manifest_actual:  # GUARD:CORR-MANIFEST-DIGEST
            refuse("CORR_MANIFEST_STORE_DIGEST_MISMATCH", "manifest_store.digest", "named manifest-store digest differs from the retained bytes")
            record("manifest_store.digest", "mismatch", named=manifest_named, retained_bytes_digest=manifest_actual)
        else:
            record("manifest_store.digest", "match", named=manifest_named, retained_bytes_digest=manifest_actual)
    elif isinstance(manifest_named, str):
        unchecked.append({"field": "manifest_store.digest", "reason": "retained_bytes_not_supplied"})

    report_obj = obs.get("native_report")
    report_dict = report_obj if isinstance(report_obj, dict) else None
    if evidence.native_report is not None:
        report_actual = _sha256(evidence.native_report)
        if report_dict is None:  # GUARD:CORR-REPORT-UNNAMED
            refuse("CORR_EVIDENCE_NOT_NAMED", "native_report", "native-report bytes were supplied but the observation names no native report")
        elif report_dict.get("report_digest") != report_actual:  # GUARD:CORR-REPORT-DIGEST
            refuse("CORR_NATIVE_REPORT_DIGEST_MISMATCH", "native_report.report_digest", "named native-report digest differs from the retained report bytes")
            record("native_report.report_digest", "mismatch", named=report_dict.get("report_digest"), retained_bytes_digest=report_actual)
        else:
            record("native_report.report_digest", "match", named=report_dict.get("report_digest"), retained_bytes_digest=report_actual)
            if report_dict.get("report_format") != SUPPORTED_REPORT_FORMAT:  # GUARD:CORR-REPORT-FORMAT
                refuse("CORR_NATIVE_REPORT_FORMAT_UNSUPPORTED", "native_report.report_format", f"only {SUPPORTED_REPORT_FORMAT} reports can be parsed")
            else:
                parsed = _parse_report_bytes(evidence.native_report)
                if parsed is None:  # GUARD:CORR-REPORT-PARSE
                    refuse("CORR_NATIVE_REPORT_UNPARSEABLE", "native_report", "retained report is not a JSON object with a validation_results object")
                else:
                    if report_dict.get("native_validation_state") != parsed.get("validation_state"):  # GUARD:CORR-STATE
                        refuse("CORR_VALIDATION_STATE_MISMATCH", "native_report.native_validation_state", "claimed native validation state differs from the retained report")
                    problem = _findings_mismatch(obs.get("native_findings"), parsed)
                    if problem is not None:  # GUARD:CORR-FINDINGS
                        refuse("CORR_NATIVE_FINDINGS_MISMATCH", "native_findings", problem)
                    record("native_report.claims", "checked_against_retained_report")
    elif report_dict is not None:  # GUARD:CORR-REPORT-MISSING
        refuse("CORR_NATIVE_REPORT_BYTES_MISSING", "native_report", "the observation names a native report but no report bytes were retained")

    config_named = _dict(obs, "native_validator", "configuration_digest")
    if evidence.configuration is not None:
        config_actual = _sha256(evidence.configuration)
        if not isinstance(config_named, str):  # GUARD:CORR-CONFIG-UNNAMED
            refuse("CORR_EVIDENCE_NOT_NAMED", "native_validator.configuration_digest", "configuration bytes were supplied but the observation names no configuration digest")
        elif config_named != config_actual:  # GUARD:CORR-CONFIG-DIGEST
            refuse("CORR_CONFIGURATION_DIGEST_MISMATCH", "native_validator.configuration_digest", "named configuration digest differs from the retained bytes")
            record("native_validator.configuration_digest", "mismatch", named=config_named, retained_bytes_digest=config_actual)
        else:
            record("native_validator.configuration_digest", "match", named=config_named, retained_bytes_digest=config_actual)
    elif isinstance(config_named, str):
        unchecked.append({"field": "native_validator.configuration_digest", "reason": "retained_bytes_not_supplied"})

    # Every other digest the observation names has no retained-bytes slot in this adapter.
    slot_paths = {
        "asset_digest",
        "subject_ref",
        "manifest_store.digest",
        "native_report.report_digest",
        "native_validator.configuration_digest",
    }
    for path, _value in census:
        if path not in slot_paths:
            unchecked.append({"field": path, "reason": "no_retained_bytes_slot"})

    detail = {
        "named_digest_count": len(census),
        "checks": checks,
        "unchecked": unchecked,
        "unchecked_note": "An unchecked digest is NOT corroborated by this run. not_evaluated is not a match.",
    }
    status = "refused" if refusals else "completed"
    return None, StageOutcome(stage, status, tuple(refusals), detail)


# ---------------------------------------------------------------------------
# Step 2: conformance to the pinned profile
# ---------------------------------------------------------------------------


def _is_digest(value: Any) -> bool:
    return isinstance(value, str) and _DIGEST_STRICT_RE.fullmatch(value) is not None


def _resolve_path(obs: dict[str, Any], dotted: str) -> Any:
    node: Any = obs
    for part in dotted.split("."):
        if not isinstance(node, dict):
            return None
        node = node.get(part)
    return node


def _schema_path(error: Any) -> str:
    return ".".join(str(part) for part in error.absolute_path) or "$"


def _profile_findings(obs: dict[str, Any], c: _Contract) -> list[Refusal]:
    out: list[Refusal] = []
    manifest, rules = c.manifest, c.rules

    def add(code: str, field_name: str | None, detail: str) -> None:
        out.append(Refusal(code, field_name, _clip(detail)))

    # -- Envelope v0.2.1 and the profile field schema ---------------------------------
    for error in sorted(c.envelope_validator.iter_errors(obs), key=lambda e: ([str(p) for p in e.absolute_path], e.validator)):  # GUARD:PF-ENVELOPE-SCHEMA
        add("ENVELOPE_SCHEMA", _schema_path(error), error.message)
    for error in sorted(c.field_validator.iter_errors(obs), key=lambda e: ([str(p) for p in e.absolute_path], e.validator)):  # GUARD:PF-FIELD-SCHEMA
        add("FIELD_SCHEMA", _schema_path(error), error.message)

    # -- Adapter policy: only what can be mapped is consumed --------------------------
    allowed = set(c.field_schema.get("properties", {}))
    for key in sorted(set(obs) - allowed):  # GUARD:PF-UNKNOWN-FIELD
        add("ADAPTER_UNKNOWN_FIELD", key, "the profile schema permits extra top-level fields; this adapter refuses what it cannot map")
    extensions = obs.get("extensions")
    if isinstance(extensions, dict) and extensions:  # GUARD:PF-EXTENSIONS
        add("ADAPTER_EXTENSIONS_NOT_SUPPORTED", "extensions", "non-empty extensions cannot be interpreted and are refused")

    # -- Identity, required fields, classes -------------------------------------------
    if obs.get("profile_id") != manifest["profile_id"]:  # GUARD:PF-PROFILE-ID
        add("PROFILE_ID_MISMATCH", "profile_id", f"must equal {manifest['profile_id']!r}")
    if obs.get("profile_version") != manifest["profile_version"]:  # GUARD:PF-PROFILE-VERSION
        add("PROFILE_VERSION_MISMATCH", "profile_version", f"must equal {manifest['profile_version']!r}")
    for name, required in manifest["fixed_values"].items():
        if obs.get(name) != required:  # GUARD:PF-FIXED-VALUES
            add("FIXED_VALUE_MISMATCH", name, f"must equal {required!r}")
    for name in manifest["required_fields"]:
        if name not in obs:  # GUARD:PF-REQUIRED-FIELDS
            add("MISSING_PROFILE_FIELD", name, "required field is missing")
    for list_name, required_key, code in (
        ("artifact_classes_covered", "artifact_classes_covered_required", "MISSING_REQUIRED_COVERAGE"),
        ("artifact_classes_excluded", "artifact_classes_excluded_required", "MISSING_REQUIRED_EXCLUSION"),
    ):
        actual = obs.get(list_name)
        if isinstance(actual, list):
            for member in manifest[required_key]:
                if member not in actual:  # GUARD:PF-CLASSES
                    add(code, list_name, f"must include {member!r}")
    if obs.get("receipt_kind") not in manifest["receipt_kinds"]:  # GUARD:PF-RECEIPT-KIND
        add("INVALID_RECEIPT_KIND", "receipt_kind", f"expected one of {manifest['receipt_kinds']}")
    for key in sorted(set(manifest["forbidden_aggregate_fields"]) & set(obs)):  # GUARD:PF-AGGREGATE-FIELDS
        add("AGGREGATE_FIELD_PRESENT", key, "no aggregate roll-up of the independent native axes may appear")

    # -- Asset binding -----------------------------------------------------------------
    binding = rules["subject_binding"]["subject_ref_must_equal_field"]
    if not _is_digest(obs.get(binding)):  # GUARD:PF-ASSET-DIGEST-FORMAT
        add("INVALID_DIGEST_FORMAT", binding, "must be sha256: followed by 64 lowercase hex characters")
    if obs.get("subject_ref") != obs.get(binding):  # GUARD:PF-SUBJECT-BINDING
        add("SUBJECT_BINDING_MISMATCH", "subject_ref", f"must equal {binding}")

    # -- Manifest store ----------------------------------------------------------------
    store = obs.get("manifest_store")
    store_state = None
    if isinstance(store, dict):
        store_state = store.get("state")
        if store_state not in manifest["manifest_store_states"]:  # GUARD:PF-STORE-STATE
            add("INVALID_MANIFEST_STORE_STATE", "manifest_store.state", f"expected one of {manifest['manifest_store_states']}")
        digest = store.get("digest")
        digest_state = rules["manifest_store"]["state_requiring_digest"]
        if store_state == digest_state:
            if digest is None:  # GUARD:PF-STORE-DIGEST-REQUIRED
                add("MISSING_MANIFEST_DIGEST", "manifest_store.digest", "present Manifest Store bytes must be digest-bound")
            elif not _is_digest(digest):
                add("INVALID_DIGEST_FORMAT", "manifest_store.digest", "must be sha256: followed by 64 lowercase hex characters")
        elif digest is not None and rules["manifest_store"]["digest_forbidden_unless_state_requires_it"]:  # GUARD:PF-STORE-DIGEST-FORBIDDEN
            add("MANIFEST_DIGEST_WITHOUT_BYTES", "manifest_store.digest", "a digest must not be fabricated for an absent or unobtainable store")

    # -- Acquisition -------------------------------------------------------------------
    acquisition = obs.get("manifest_acquisition")
    if isinstance(acquisition, dict):
        mode = acquisition.get("mode")
        if mode not in manifest["manifest_acquisition_modes"]:  # GUARD:PF-ACQUISITION-MODE
            add("INVALID_ACQUISITION_MODE", "manifest_acquisition.mode", f"expected one of {manifest['manifest_acquisition_modes']}")
        acq_rules = rules["manifest_acquisition"]
        if (
            mode == acq_rules["mode_requiring_remote_manifest_uri"]
            and store_state == acq_rules["remote_manifest_uri_required_only_when_store_state"]
            and not acquisition.get("remote_manifest_uri")
        ):  # GUARD:PF-REMOTE-URI
            add("REMOTE_MANIFEST_URI_MISSING", "manifest_acquisition.remote_manifest_uri", "captured remote store must record its source")

    # -- Hermetic replay ---------------------------------------------------------------
    replay = obs.get("hermetic_replay")
    if isinstance(replay, dict) and replay.get("performed") is True:
        if replay.get("remote_manifest_fetch_applied") is not rules["hermetic_replay"]["remote_manifest_fetch_applied_must_be"]:  # GUARD:PF-HERMETIC
            add("NON_HERMETIC_REPLAY", "hermetic_replay.remote_manifest_fetch_applied", "a hermetic replay consumes frozen local bytes only")
        if replay.get("replay_report_digest") is not None and not _is_digest(replay.get("replay_report_digest")):
            add("INVALID_DIGEST_FORMAT", "hermetic_replay.replay_report_digest", "must be sha256: followed by 64 lowercase hex characters")

    # -- Native validator identity -----------------------------------------------------
    validator = obs.get("native_validator")
    nv_rules = rules["native_validator"]
    if isinstance(validator, dict):
        for key in nv_rules["required_identity_fields"]:
            value = validator.get(key)
            if not isinstance(value, str) or not value:  # GUARD:PF-VALIDATOR-IDENTITY
                add("MISSING_NATIVE_VALIDATOR_IDENTITY", f"native_validator.{key}", "validator version is a verdict input")
        posture = validator.get("configuration_posture")
        config_digest = validator.get("configuration_digest")
        if posture == nv_rules["posture_requiring_configuration_digest"]:
            if not _is_digest(config_digest):  # GUARD:PF-CONFIG-DIGEST-REQUIRED
                add("MISSING_VALIDATOR_CONFIGURATION_DIGEST", "native_validator.configuration_digest", "required when a configuration was supplied")
        elif posture == nv_rules["posture_forbidding_configuration_digest"] and config_digest is not None:  # GUARD:PF-CONFIG-DIGEST-FORBIDDEN
            add("VALIDATOR_CONFIGURATION_DIGEST_WITHOUT_CONFIGURATION", "native_validator.configuration_digest", "must be null under validator defaults")
        if validator.get("specification_version_applied_source") != nv_rules["specification_version_applied_source_required"]:  # GUARD:PF-SPEC-SOURCE
            add("SPEC_VERSION_CLAIM_WEAKENS_APPLIED", "native_validator.specification_version_applied_source", "a manifest-claimed version is a claim only")

    # -- Evaluation posture ------------------------------------------------------------
    ep = rules["evaluation_posture"]
    posture_value = obs.get("evaluation_posture")
    native_report = obs.get("native_report")
    if posture_value == ep["input_unavailable_value"]:
        if isinstance(native_report, dict) and native_report.get("native_validation_state"):  # GUARD:PF-UNAVAILABLE-STATE
            add("INPUT_UNAVAILABLE_RENDERED_AS_VALIDATION_FAILURE", "native_report", "an unobtainable input is not a validation result")
        unavailable = obs.get("unavailable_inputs")
        if not isinstance(unavailable, list) or not unavailable:  # GUARD:PF-UNAVAILABLE-LIST
            add("MISSING_UNAVAILABLE_INPUTS", "unavailable_inputs", "must record which input could not be obtained and why")
    elif posture_value == ep["native_validation_performed_value"]:
        if not isinstance(native_report, dict):  # GUARD:PF-PERFORMED-REPORT
            add("MISSING_PROFILE_FIELD", "native_report", "a performed validation must record the native machine report")
        else:
            if native_report.get("verdict_source") != ep["verdict_source_required"]:  # GUARD:PF-VERDICT-SOURCE
                add("EXIT_CODE_AS_VERDICT", "native_report.verdict_source", f"must equal {ep['verdict_source_required']!r}")
            if not _is_digest(native_report.get("report_digest")):
                add("INVALID_DIGEST_FORMAT", "native_report.report_digest", "must be sha256: followed by 64 lowercase hex characters")
            if not native_report.get("native_validation_state"):
                add("MISSING_PROFILE_FIELD", "native_report.native_validation_state", "must record the verbatim native value")
        if not isinstance(obs.get("native_findings"), list):  # GUARD:PF-FINDINGS-REQUIRED
            add("NATIVE_FINDINGS_MISSING", "native_findings", "required when a native validation was performed")

    # -- Signer trust ------------------------------------------------------------------
    st_rules = rules["signer_trust"]
    signer_trust = obs.get("signer_trust")
    if isinstance(signer_trust, dict):
        basis = signer_trust.get("trust_basis")
        if basis not in manifest["trust_basis_values"]:  # GUARD:PF-TRUST-BASIS
            add("INVALID_TRUST_BASIS", "signer_trust.trust_basis", f"expected one of {manifest['trust_basis_values']}")
        if (
            signer_trust.get("trust_observation") == st_rules["forbidden_trust_observation_under_non_supplying_basis"]
            and basis in st_rules["non_supplying_trust_bases"]
        ):  # GUARD:PF-TRUST-WITHOUT-BASIS
            add("TRUST_OBSERVATION_WITHOUT_BASIS", "signer_trust.trust_observation", "trust is a function of caller-supplied trust material")
        refs = signer_trust.get("trust_material_refs")
        if basis in st_rules["material_requiring_trust_bases"]:
            if not isinstance(refs, list) or not refs:  # GUARD:PF-TRUST-MATERIAL-REQUIRED
                add("MISSING_TRUST_MATERIAL_DIGEST", "signer_trust.trust_material_refs", "digest-bound trust material is required for this basis")
        if isinstance(refs, list):
            for index, ref in enumerate(refs):
                if not isinstance(ref, dict):
                    add("INVALID_TRUST_MATERIAL_REF", f"signer_trust.trust_material_refs[{index}]", "must be an object")
                    continue
                if not _is_digest(ref.get("digest")):
                    add("INVALID_DIGEST_FORMAT", f"signer_trust.trust_material_refs[{index}].digest", "must be sha256: followed by 64 lowercase hex characters")
                for key in st_rules["trust_material_ref_required_keys"]:
                    if not ref.get(key):  # GUARD:PF-TRUST-REF-KEYS
                        add("MISSING_TRUST_MATERIAL_DIGEST", f"signer_trust.trust_material_refs[{index}].{key}", "an immutable source pin is required")
        if (
            signer_trust.get("official_trust_list_membership") is not None
            and basis != st_rules["official_trust_list_membership_requires_basis"]
        ):  # GUARD:PF-OFFICIAL-MEMBERSHIP
            add("TRUST_BASIS_MISREPRESENTED", "signer_trust.official_trust_list_membership", "permitted only under the official trust-list basis")
        if signer_trust.get("trust_pointer_dereferenced") is not st_rules["trust_pointer_dereferenced_must_be"]:  # GUARD:PF-TRUST-POINTER
            add("TRUST_POINTER_DEREFERENCED", "signer_trust.trust_pointer_dereferenced", "remote trust pointers must not be dereferenced")

    # -- Ordered signer provenance -----------------------------------------------------
    provenance = obs.get("signer_provenance")
    if provenance is not None and rules["signer_provenance"]["order_must_equal_zero_based_index"]:
        if not isinstance(provenance, list):
            add("SIGNER_PROVENANCE_NOT_ORDERED", "signer_provenance", "must be an ordered array")
        else:
            orders = [item.get("order") for item in provenance if isinstance(item, dict)]
            if orders != list(range(len(provenance))):  # GUARD:PF-SIGNER-ORDER
                add("SIGNER_PROVENANCE_NOT_ORDERED", "signer_provenance", "order must be the zero-based index")

    # -- Comparison postures -----------------------------------------------------------
    lcp = rules["later_comparison_posture"]
    if (
        isinstance(signer_trust, dict)
        and signer_trust.get("trust_basis") == lcp["trust_basis_forcing_not_comparable"]
        and obs.get("later_comparison_posture") != lcp["required_value"]
    ):  # GUARD:PF-COMPARISON-POSTURE
        add("COMPARISON_POSTURE_OVERSTATED", "later_comparison_posture", f"must be {lcp['required_value']!r}")
    prior = obs.get("prior_producer_report")
    if isinstance(prior, dict):
        absent = rules["prior_producer_report"]["absent_requires_comparison_posture"]
        if prior.get("present") is False and prior.get("comparison_posture") != absent:  # GUARD:PF-PRIOR-REPORT
            add("PRIOR_REPORT_COMPARISON_CONFLICT", "prior_producer_report.comparison_posture", f"must be {absent!r} when no prior report exists")
        if prior.get("report_digest") is not None and not _is_digest(prior.get("report_digest")):
            add("INVALID_DIGEST_FORMAT", "prior_producer_report.report_digest", "must be sha256: followed by 64 lowercase hex characters")

    # -- Attestation limits and machine limitations ------------------------------------
    base_limit = manifest["required_attestation_limits"].get("base")
    limits = obs.get("attestation_limits")
    if base_limit and (not isinstance(limits, list) or base_limit not in limits):  # GUARD:PF-ATTESTATION-LIMIT
        add("MISSING_REQUIRED_ATTESTATION_LIMIT", "attestation_limits", "the required base limit must appear verbatim")

    codes_index = {entry["id"]: entry for entry in c.registry.get("codes", [])}
    declared: set[str] = set()
    items = obs.get("machine_limitations")
    for index, item in enumerate(items if isinstance(items, list) else []):
        code = item.get("code") if isinstance(item, dict) else None
        if not isinstance(code, str) or not code:  # GUARD:PF-LIMITATION-ITEM
            add("INVALID_MACHINE_LIMITATION_ITEM", f"machine_limitations[{index}]", "must be an object with a non-empty string code")
            continue
        if code not in codes_index:  # GUARD:PF-LIMITATION-REGISTERED
            add("UNKNOWN_LIMITATION_CODE", f"machine_limitations[{index}].code", f"{code!r} is not in the registry")
            continue
        declared.add(code)
    for code in sorted(declared):
        for claim in codes_index[code].get("contradicts_claims", []):
            if claim in obs and obs[claim]:  # GUARD:PF-LIMITATION-CONTRADICTION
                add("CONTRADICTION_DETECTED", "machine_limitations", f"{code!r} contradicts the affirmed claim {claim!r}")
    for required in manifest["required_machine_limitation_codes"]:
        if required not in declared:  # GUARD:PF-LIMITATION-REQUIRED
            add("MISSING_REQUIRED_MACHINE_LIMITATION", "machine_limitations", f"{required!r} is required")
    for entry in rules["conditional_machine_limitation_codes"]:
        actual = _resolve_path(obs, entry["field_path"])
        if entry["operator"] == "equals":
            triggered = actual == entry["value"]
        else:
            triggered = actual is not None and actual != entry["value"]
        if triggered and entry["code"] not in declared:  # GUARD:PF-LIMITATION-CONDITIONAL
            add("MISSING_CONDITIONAL_MACHINE_LIMITATION", "machine_limitations", f"{entry['reason']}, so {entry['code']!r} must be declared")
    return out


def _stage_conformance(obs: dict[str, Any]) -> tuple[None, StageOutcome]:
    stage = "profile_conformance"
    contract = _load_contract()
    try:
        findings = _profile_findings(obs, contract)
    except Exception as exc:  # fail closed: an internal error is a refusal, never a pass
        findings = [Refusal("PROFILE_GATE_INTERNAL_ERROR", None, _clip(f"{type(exc).__name__}: {exc}"))]
    detail = {
        "profile": PROFILE_SLUG,
        "source_repository": SOURCE_REPOSITORY,
        "source_commit": SOURCE_COMMIT,
        "scope": "observation structure only; conformance is not a native C2PA finding and not content truth",
    }
    return None, StageOutcome(stage, "refused" if findings else "completed", tuple(findings), detail)


# ---------------------------------------------------------------------------
# Step 3: the untrusted observed-side canonical finding
# ---------------------------------------------------------------------------


def _require_completed(outcome: Any, stage: str) -> None:
    if not isinstance(outcome, StageOutcome) or outcome.stage != stage or outcome.status != "completed":  # GUARD:ORDER-CONSTRUCT-PRECONDITION
        raise OrderingViolation(f"the {stage} stage has not completed; the observed-side finding cannot be constructed")


def _native_report_from_findings(obs: dict[str, Any]) -> dict[str, Any]:
    """Shape the observation's own native_findings like a native report so the verifier's
    single normalizer produces the observed-side axes (no second dialect)."""
    active: dict[str, list[dict[str, Any]]] = {"success": [], "informational": [], "failure": []}
    ingredient: dict[str, list[dict[str, Any]]] = {"success": [], "informational": [], "failure": []}
    for item in obs.get("native_findings") or []:
        entry: dict[str, Any] = {"code": item["code"]}
        if "uri" in item:
            entry["url"] = item["uri"]
        target = active if item["scope"] == "activeManifest" else ingredient
        target[item["severity"]].append(entry)
    results: dict[str, Any] = {"activeManifest": active}
    if any(ingredient.values()):
        results["ingredientDeltas"] = [{"validationDeltas": ingredient}]
    state = _dict(obs, "native_report", "native_validation_state")
    return {"validation_state": state, "validation_results": results}


def _finding_keys(obs: dict[str, Any]) -> set[tuple[str, str]]:
    return {(item["severity"], item["code"]) for item in obs.get("native_findings") or [] if isinstance(item, dict)}


def _map_trust_basis(obs: dict[str, Any], refuse: Any) -> dict[str, Any] | None:
    trust = obs["signer_trust"]
    basis = trust["trust_basis"]
    refs = trust.get("trust_material_refs") or []
    mode = _TRUST_MODE.get(basis)
    if mode is None:  # GUARD:MAP-TRUST-BASIS-UNMAPPED
        refuse("MAP_TRUST_BASIS_UNMAPPED", "signer_trust.trust_basis", f"{basis!r} has no mode in the canonical finding; it is refused, not approximated")
        return None
    material = source = pin = None
    if basis in _MATERIAL_BASES:
        if len(refs) != 1:  # GUARD:MAP-TRUST-MATERIAL-COUNT
            refuse("MAP_TRUST_MATERIAL_COUNT_UNMAPPED", "signer_trust.trust_material_refs", "the canonical finding carries exactly one trust-material digest")
            return None
        material, source, pin = refs[0]["digest"], refs[0]["source_identity"], refs[0]["source_pin"]
    elif refs:  # GUARD:MAP-TRUST-MATERIAL-UNEXPECTED
        refuse("MAP_TRUST_MATERIAL_UNEXPECTED", "signer_trust.trust_material_refs", f"{basis!r} supplies no trust material but refs are present")
        return None
    return {
        "mode": mode,
        "material_digest": material,
        "material_source": source,
        "material_source_pin": pin,
        "on_official_c2pa_trust_list": "not_established",
    }


def _producer_asserted(obs: dict[str, Any]) -> dict[str, Any]:
    """What the producer asserted, labelled as such. Nothing here is an independent finding
    and none of it feeds a canonical axis."""
    keys = _finding_keys(obs)
    trust = obs.get("signer_trust") if isinstance(obs.get("signer_trust"), dict) else {}
    observation = trust.get("trust_observation")
    if observation == "trusted":
        trust_consistency = "consistent" if ("success", "signingCredential.trusted") in keys else "uncorroborated"
    elif observation == "untrusted":
        trust_consistency = "consistent" if ("failure", "signingCredential.untrusted") in keys else "uncorroborated"
    else:
        trust_consistency = "uncorroborated"
    return {
        "provenance": "producer_asserted",
        "independent_finding": "not_evaluated",
        "issuer_id": obs.get("issuer_id"),
        "signer_trust": {
            "trust_basis": trust.get("trust_basis"),
            "trust_observation": observation,
            "official_trust_list_membership": trust.get("official_trust_list_membership"),
            "trust_pointer_uri": trust.get("trust_pointer_uri"),
            "consistency_with_native_findings": trust_consistency,
        },
        "signer_validity": obs.get("signer_validity"),
        "trusted_timestamp": obs.get("trusted_timestamp"),
        "validation_time": obs.get("validation_time"),
        "revocation": obs.get("revocation"),
        "native_validation_state": _dict(obs, "native_report", "native_validation_state"),
        "process_exit_code": _dict(obs, "native_report", "process_exit_code"),
        "process_exit_code_semantics": "observation_only_never_a_verdict",
    }


def construct_observed_side(
    obs: dict[str, Any],
    correspondence: StageOutcome,
    conformance: StageOutcome,
    *,
    bundle: c2pa_native.ContractBundle | None = None,
) -> tuple[dict[str, Any] | None, StageOutcome]:
    """Build the untrusted observed-side canonical finding.

    Requires completed ``input_correspondence`` and ``profile_conformance`` outcomes
    (``OrderingViolation`` otherwise). Every value without a canonical representation is a
    typed refusal; nothing is defaulted.
    """
    _require_completed(correspondence, "input_correspondence")
    _require_completed(conformance, "profile_conformance")
    stage = "observed_finding_construction"
    bundle = bundle or c2pa_native.load_bundle()
    refusals: list[Refusal] = []

    def refuse(code: str, field_name: str | None, detail: str) -> None:
        refusals.append(Refusal(code, field_name, _clip(detail)))

    posture = obs["evaluation_posture"]
    if posture not in ("native_validation_performed", "input_unavailable"):  # GUARD:MAP-POSTURE
        refuse("MAP_EVALUATION_POSTURE_UNMAPPED", "evaluation_posture", f"{posture!r} records no native evaluation to compare")

    mode = obs["manifest_acquisition"]["mode"]
    if mode not in _CANONICAL_ACQUISITION_MODES:  # GUARD:MAP-ACQUISITION-MODE
        refuse("MAP_ACQUISITION_MODE_UNMAPPED", "manifest_acquisition.mode", f"{mode!r} has no canonical acquisition mode")

    validator = obs["native_validator"]
    config_digest = validator.get("configuration_digest")
    if not _is_digest(config_digest):  # GUARD:MAP-SETTINGS-DIGEST
        refuse("MAP_SETTINGS_DIGEST_UNAVAILABLE", "native_validator.configuration_digest", "the canonical finding requires the digest of the settings the validator ran under")

    replay = obs.get("hermetic_replay")
    hermetic = (
        isinstance(replay, dict)
        and replay.get("performed") is True
        and replay.get("remote_manifest_fetch_applied") is False
        and replay.get("ocsp_fetch_applied") is False
        and replay.get("allowed_network_hosts") == []
    )
    if not hermetic:  # GUARD:MAP-HERMETICITY
        refuse("MAP_HERMETICITY_NOT_ESTABLISHED", "hermetic_replay", "the canonical finding requires a stated hermetic replay with no fetch, no OCSP and no allowed hosts")

    if obs["validation_time"]["validation_time_control"] == "supported_and_pinned":  # GUARD:MAP-VALIDATION-TIME
        refuse("MAP_VALIDATION_TIME_PINNED_UNSUPPORTED", "validation_time.validation_time_control", "the canonical finding fixes caller_pinnable=false")

    native_state = _dict(obs, "native_report", "native_validation_state")
    if posture == "native_validation_performed" and native_state not in _CANONICAL_NATIVE_STATES:  # GUARD:MAP-NATIVE-STATE
        refuse("MAP_NATIVE_VALIDATION_STATE_UNMAPPED", "native_report.native_validation_state", f"{native_state!r} is not a canonical native state")

    trust_basis = _map_trust_basis(obs, refuse)

    keys = _finding_keys(obs)
    trust_observation = obs["signer_trust"]["trust_observation"]
    if trust_observation == "trusted" and ("failure", "signingCredential.untrusted") in keys:  # GUARD:MAP-TRUST-CONTRADICTS-TRUSTED
        refuse("MAP_TRUST_OBSERVATION_CONTRADICTS_FINDINGS", "signer_trust.trust_observation", "asserted trusted while the native findings carry signingCredential.untrusted")
    if trust_observation == "untrusted" and ("success", "signingCredential.trusted") in keys:  # GUARD:MAP-TRUST-CONTRADICTS-UNTRUSTED
        refuse("MAP_TRUST_OBSERVATION_CONTRADICTS_FINDINGS", "signer_trust.trust_observation", "asserted untrusted while the native findings carry signingCredential.trusted")
    if obs["signer_validity"]["observation"] == "inside_validity" and any(
        severity == "failure" and code in _INVALID_VALIDITY_CODES for severity, code in keys
    ):  # GUARD:MAP-VALIDITY-CONTRADICTS
        refuse("MAP_SIGNER_VALIDITY_CONTRADICTS_FINDINGS", "signer_validity.observation", "asserted inside_validity while the native findings carry a signing-credential validity failure")

    if refusals:
        return None, StageOutcome(stage, "refused", tuple(refusals))

    assert trust_basis is not None
    store = obs["manifest_store"]
    # Embedded stores are not separate bytes (canonical contract: null); every other mode
    # carries the captured store's digest.
    manifest_store_digest = store.get("digest") if (mode != "embedded" and store.get("state") == "present") else None
    remote_uri = obs["manifest_acquisition"].get("remote_manifest_uri")
    validator_identity: dict[str, Any] = {
        "implementation": validator["implementation"],
        "version": validator["version"],
    }
    if validator.get("specification_version_applied"):
        validator_identity["c2pa_specification_version"] = validator["specification_version_applied"]
    instant = obs["validation_time"].get("validation_timestamp_observed")

    if posture == "native_validation_performed":
        finding = c2pa_native.canonical_finding_from_native_report(
            _native_report_from_findings(obs),
            side="observed",
            evidence_class="supplied_producer_assertion",
            asset_digest=obs["asset_digest"],
            manifest_acquisition_mode=mode,
            settings_digest=config_digest,
            trust_basis=trust_basis,
            validator=validator_identity,
            bundle=bundle,
            manifest_store_digest=manifest_store_digest,
            remote_manifest_uri=remote_uri,
            native_report_digest=obs["native_report"]["report_digest"],
            validation_instant=instant,
        )
    else:
        finding = c2pa_native.canonical_finding_unavailable(
            side="observed",
            evidence_class="supplied_producer_assertion",
            asset_digest=obs["asset_digest"],
            manifest_acquisition_mode=mode,
            settings_digest=config_digest,
            trust_basis=trust_basis,
            detail="the observation records evaluation_posture=input_unavailable",
            unresolved_inputs=[
                {"input": item["input"], "reason": item["reason"], "uri": remote_uri}
                for item in obs["unavailable_inputs"]
            ],
            remote_manifest_uri=remote_uri,
            bundle=bundle,
            validation_instant=instant,
        )
        finding["validator"] = validator_identity
        finding["inputs"]["manifest_store_digest"] = manifest_store_digest

    # Settings are derived from what the observation states about its own run, never copied
    # from this verifier's constants. MAP-HERMETICITY above has already refused anything but a
    # stated hermetic replay; check_report re-checks the same flags on the assembled report.
    # Optional keys the observation does not state (verify_trust, ...) are omitted.
    replay = obs["hermetic_replay"]
    finding["settings"] = {
        "settings_digest": config_digest,
        "remote_manifest_fetch": replay["remote_manifest_fetch_applied"],
        "ocsp_fetch": replay["ocsp_fetch_applied"],
        "allowed_network_hosts": list(replay["allowed_network_hosts"]),
        "hermeticity": {
            "network_access_permitted": bool(replay["allowed_network_hosts"]),
            "remote_resource_fetch_attempted": replay["remote_manifest_fetch_applied"],
            "trust_list_uri_dereferenced": obs["signer_trust"]["trust_pointer_dereferenced"],
            "ocsp_fetch_permitted": replay["ocsp_fetch_applied"],
            **(
                {"remote_resource_required_but_unavailable": True}
                if posture == "input_unavailable"
                else {}
            ),
        },
    }
    return finding, StageOutcome(
        stage,
        "completed",
        detail={
            "evidence_class": "supplied_producer_assertion",
            "trust_basis_mode": trust_basis["mode"],
            "manifest_store_digest_mapping": (
                "embedded store is not separate bytes: canonical value null"
                if manifest_store_digest is None
                else "captured store digest carried"
            ),
            "unmapped_native_codes": finding.get("unmapped_native_codes", []),
        },
    )


def _stage_construct(
    obs: dict[str, Any],
    correspondence: StageOutcome,
    conformance: StageOutcome,
    bundle: c2pa_native.ContractBundle,
) -> tuple[dict[str, Any] | None, StageOutcome]:
    try:
        return construct_observed_side(obs, correspondence, conformance, bundle=bundle)
    except OrderingViolation:
        raise
    except Exception as exc:  # fail closed
        return None, StageOutcome(
            "observed_finding_construction",
            "refused",
            (Refusal("OBSERVED_FINDING_INTERNAL_ERROR", None, _clip(f"{type(exc).__name__}: {exc}")),),
        )


# ---------------------------------------------------------------------------
# Recomputation with the verifier's own pinned native validator path
# ---------------------------------------------------------------------------


def _stage_recompute(
    obs: dict[str, Any],
    evidence: RetainedEvidence,
    executable: str | None,
    bundle: c2pa_native.ContractBundle,
) -> tuple[dict[str, Any] | None, StageOutcome]:
    stage = "native_recomputation"
    exe = c2pa_native.resolve_validator(executable)
    if exe is None:  # GUARD:REC-VALIDATOR-REQUIRED
        return None, StageOutcome(
            stage,
            "not_evaluated",
            (Refusal("RECOMPUTE_VALIDATOR_NOT_SUPPLIED", None, "no native validator path was supplied; the verifier never falls back to an unpinned executable on PATH"),),
        )
    name = evidence.asset_name
    if _ASSET_NAME_RE.fullmatch(name) is None:  # GUARD:REC-ASSET-NAME
        return None, StageOutcome(
            stage,
            "refused",
            (Refusal("RECOMPUTE_ASSET_NAME_INVALID", None, "asset_name must be a bare filename (letters, digits, dot, dash, underscore)"),),
        )
    needs_store = obs["manifest_acquisition"]["mode"] != "embedded" and obs["manifest_store"]["state"] == "present"
    if needs_store and evidence.manifest_store is None:  # GUARD:REC-MANIFEST-BYTES-REQUIRED
        return None, StageOutcome(
            stage,
            "not_evaluated",
            (Refusal("RECOMPUTE_MANIFEST_STORE_BYTES_NOT_RETAINED", "manifest_store", "the acquisition mode needs the captured store bytes and none were retained"),),
        )
    with tempfile.TemporaryDirectory(prefix="arcs-verify-c2pa-srs-") as tmp:
        root = Path(tmp)
        asset_path = root / name
        asset_path.write_bytes(evidence.asset)
        settings_path = root / "hermetic.toml"
        settings_path.write_text(c2pa_native.HERMETIC_SETTINGS_TOML, encoding="utf-8")
        external: Path | None = None
        if needs_store:
            external = root / "manifest-store.c2pa"
            external.write_bytes(evidence.manifest_store or b"")
        try:
            report = c2pa_native.recompute(
                asset_path,
                executable=exe,
                settings_path=settings_path,
                external_manifest=external,
                bundle=bundle,
                subject_extra={"asset_label": name},
            )
        except Exception as exc:  # fail closed: no report means no recomputation, never a pass
            return None, StageOutcome(
                stage,
                "refused",
                (Refusal("RECOMPUTE_INTERNAL_ERROR", None, _clip(f"{type(exc).__name__}: {exc}")),),
            )
    recomputed = report["recomputed"]
    pinned = c2pa_native.PINNED_VALIDATOR
    detail = {
        "evidence_class": recomputed["evidence_class"],
        "evaluation_status": recomputed["evaluation_status"],
        "validator": recomputed["validator"],
        "validator_pin": {
            "implementation": pinned["implementation"],
            "version": pinned["version"],
            "detected_version": recomputed["validator"].get("version"),
            "detected_version_equals_pin": recomputed["validator"].get("version") == pinned["version"],
        },
        "settings": "arcs_verify.c2pa_native.HERMETIC_SETTINGS_TOML (verifier-owned; the producer's configuration is never used)",
    }
    return report, StageOutcome(stage, "completed", detail=detail)


# ---------------------------------------------------------------------------
# Comparison (existing axis-by-axis comparison; independent axes only)
# ---------------------------------------------------------------------------


def source_digest_refusals(observed: dict[str, Any], recomputed: dict[str, Any]) -> list[Refusal]:
    """The comparison's own source-digest gate: both sides must have been evaluated over the
    same asset bytes and the same manifest-store bytes before any axis is compared."""
    out: list[Refusal] = []
    if observed["inputs"].get("asset_digest") != recomputed["inputs"].get("asset_digest"):  # GUARD:CMP-ASSET-DIGEST
        out.append(Refusal("COMPARISON_ASSET_DIGEST_MISMATCH", "inputs.asset_digest", "the two sides were evaluated over different asset bytes"))
    if observed["inputs"].get("manifest_store_digest") != recomputed["inputs"].get("manifest_store_digest"):  # GUARD:CMP-MANIFEST-DIGEST
        out.append(Refusal("COMPARISON_MANIFEST_STORE_DIGEST_MISMATCH", "inputs.manifest_store_digest", "the two sides were evaluated over different manifest-store bytes"))
    return out


def _stage_compare(
    observed: dict[str, Any],
    recompute_report: dict[str, Any],
    bundle: c2pa_native.ContractBundle,
) -> tuple[dict[str, Any] | None, StageOutcome]:
    stage = "comparison"
    recomputed = recompute_report["recomputed"]
    sides = {"observed": observed["evaluation_status"], "recomputed": recomputed["evaluation_status"]}
    if any(status != "evaluated" for status in sides.values()):  # GUARD:CMP-BOTH-EVALUATED
        return None, StageOutcome(
            stage,
            "not_evaluated",
            (Refusal("COMPARISON_SIDE_NOT_EVALUATED", None, "a side has no native evaluation; two non-evaluations are not a match and one is not a mismatch"),),
            {"evaluation_status": sides},
        )
    gate = source_digest_refusals(observed, recomputed)
    if gate:  # GUARD:CMP-GATE-REFUSES
        return None, StageOutcome(stage, "refused", tuple(gate), {"evaluation_status": sides})
    try:
        report = c2pa_native.build_report(
            subject=recompute_report["subject"], recomputed=recomputed, observed=observed, bundle=bundle
        )
        conformance = c2pa_native.check_report(report, bundle=bundle)
    except Exception as exc:  # fail closed
        return None, StageOutcome(
            stage,
            "refused",
            (Refusal("COMPARISON_INTERNAL_ERROR", None, _clip(f"{type(exc).__name__}: {exc}")),),
            {"evaluation_status": sides},
        )
    detail = {
        "report_contract_check": {
            "contract": c2pa_native.CONTRACT_ID,
            "findings": list(conformance.findings),
        }
    }
    if conformance.findings:  # GUARD:CMP-REPORT-CONFORMANT
        return report, StageOutcome(
            stage,
            "refused",
            (Refusal("COMPARISON_REPORT_NONCONFORMANT", None, "the assembled native comparison report does not conform to its contract; do not rely on it"),),
            detail,
        )
    return report, StageOutcome(stage, "completed", detail=detail)


# ---------------------------------------------------------------------------
# Report assembly
# ---------------------------------------------------------------------------

_AXIS_NAMES = c2pa_native.AXIS_ORDER

_BASE_LIMITATIONS = (
    "This is an untrusted adapter over a provisional profile. It is not an SRS receipt verifier.",
    "The SRS signature, key-resolution and key-trust axes are not_evaluated: the profile is unsigned and no key material is accepted. An unsigned or unverified observation is not authenticated issuance.",
    "Trust values the producer asserted are producer_asserted. They are not independent findings and feed no canonical axis.",
    "The producer's native validator output is never the independent result; the recomputation uses this verifier's own pinned native validator path under its own hermetic settings.",
    "Digests with no retained-bytes slot are listed as unchecked; unchecked is not a match.",
    "Revocation is not_evaluated on both sides; silence is not evidence of non-revocation.",
    "The validation clock is wall clock on both sides and is not caller-pinnable.",
    "Nothing here establishes content truth, depicted-event truth, signer trust in general, trust-list membership, issuer standing or operational issuance readiness.",
)


def _failure_codes(finding: dict[str, Any] | None) -> list[str] | None:
    if finding is None or finding.get("evaluation_status") != "evaluated":
        return None
    codes = {
        entry["code"]
        for axis in finding["axes"]
        for entry in axis["native_findings"]
        if entry["severity"] == "failure"
    }
    codes |= {entry["code"] for entry in finding.get("unmapped_native_codes", []) if entry["severity"] == "failure"}
    return sorted(codes)


def _failure_code_axis(observed: dict[str, Any] | None, recomputed: dict[str, Any] | None) -> dict[str, Any]:
    seen = _failure_codes(observed)
    rebuilt = _failure_codes(recomputed)
    both = seen is not None and rebuilt is not None
    return {
        "observed": seen,
        "recomputed": rebuilt,
        "only_in_observed": sorted(set(seen) - set(rebuilt)) if both else None,
        "only_in_recomputed": sorted(set(rebuilt) - set(seen)) if both else None,
    }


def _axis_status(finding: dict[str, Any] | None, axis: str) -> str | None:
    if finding is None:
        return None
    for item in finding["axes"]:
        if item["axis"] == axis:
            return item["status"]
    return None


def _assemble(
    *,
    obs: dict[str, Any] | None,
    observation_digest: str | None,
    stages: dict[str, StageOutcome],
    stopped_at: str | None,
    observed: dict[str, Any] | None,
    recompute_report: dict[str, Any] | None,
    comparison_report: dict[str, Any] | None,
) -> dict[str, Any]:
    recomputed = recompute_report["recomputed"] if recompute_report else None
    comparisons = {item["axis"]: item for item in (comparison_report or {}).get("comparison", [])}
    conformance_ran = stages["profile_conformance"].status in ("completed", "refused")

    def comparison_for(axis: str) -> dict[str, Any] | None:
        item = comparisons.get(axis)
        if item is None:
            return None
        view = {k: item[k] for k in ("state", "comparison_reason", "integrity_posture", "reproducibility_class", "observed_status", "recomputed_status", "note")}
        if item["state"] == "match":
            # The existing comparison reports `match` when both sides carry the same status,
            # including when neither side evaluated the axis. Say which, so an absence of
            # evidence on both sides is not read as agreement.
            view["agreement_basis"] = (
                "both_sides_not_evaluated" if item["observed_status"] == "not_evaluated" else "same_status"
            )
        return view

    corr_detail = stages["input_correspondence"].detail
    checks = {c["field"]: c for c in corr_detail.get("checks", [])}
    producer = _producer_asserted(obs) if (obs is not None and stages["profile_conformance"].status == "completed") else None

    observed_state = _dict(obs, "native_report", "native_validation_state") if obs else None
    srs_signature_present = bool(obs is not None and "receipt_signature" in obs)

    report: dict[str, Any] = {
        "adapter": ADAPTER_ID,
        "status": "PROVISIONAL_EXPERIMENTAL_UNTRUSTED_ADAPTER",
        "authority_movement": 0,
        "profile_pin": {
            "profile": PROFILE_SLUG,
            "source_repository": SOURCE_REPOSITORY,
            "source_commit": SOURCE_COMMIT,
            "contract_files_sha256": {name: sha for name, (sha, _blob) in PINNED_CONTRACT_FILES.items()},
            "binding_semantic_digest_recorded": BINDING_SEMANTIC_DIGEST,
            "envelope": "srs-envelope@0.2.1+sha256:" + ENVELOPE_SCHEMA_PINS["v0.2.1"],
            "pin_scope": "exact bytes re-hashed on every load; profile status is provisional and not ratified",
        },
        "input": {"observation_sha256": observation_digest},
        "pipeline": {
            "order": list(STAGES),
            "stopped_at": stopped_at,
            "stages": {name: stages[name].to_dict() for name in STAGES},
        },
        "axes": {
            "observation_conformance": {
                "status": stages["profile_conformance"].status,
                "profile": PROFILE_SLUG,
                "refusal_codes": sorted({r.code for r in stages["profile_conformance"].refusals}),
                "scope": "structure of the observation only; not a native C2PA finding",
            },
            "asset_manifest_binding": {
                "status": stages["input_correspondence"].status,
                "asset_digest": checks.get("asset_digest"),
                "manifest_store_digest": checks.get("manifest_store.digest"),
                "unchecked": corr_detail.get("unchecked", []),
            },
            "native_validation_state": {
                "observed_verbatim": observed_state,
                "observed_provenance": "producer_asserted",
                "recomputed_verbatim": recomputed.get("native_validation_state") if recomputed else None,
                "semantics": "native_field_only_never_a_verdict_never_signer_trust",
            },
            "native_failure_codes": _failure_code_axis(observed, recomputed),
            "signer_trust": {
                "producer_asserted": producer["signer_trust"] if producer else None,
                "observed_axis_status": _axis_status(observed, "signer_trust"),
                "recomputed_axis_status": _axis_status(recomputed, "signer_trust"),
                "independent_comparison": comparison_for("signer_trust"),
            },
            "signer_validity": {
                "producer_asserted": producer["signer_validity"] if producer else None,
                "independent_comparison": comparison_for("signer_validity"),
            },
            "timestamp": {
                "producer_asserted": {
                    "trusted_timestamp": producer["trusted_timestamp"] if producer else None,
                    "validation_time": producer["validation_time"] if producer else None,
                },
                "independent_comparison": comparison_for("timestamp"),
            },
            "revocation": {
                "observed_status": _axis_status(observed, "revocation"),
                "recomputed_status": _axis_status(recomputed, "revocation"),
                "producer_asserted": producer["revocation"] if producer else None,
                "limitation": "not_evaluated on both sides; silence is not evidence of non-revocation",
                "independent_comparison": comparison_for("revocation"),
            },
            "independent_comparison": {
                "status": stages["comparison"].status,
                "per_axis": [{"axis": axis, **comparison_for(axis)} for axis in _AXIS_NAMES if comparison_for(axis)],
                "comparability": (comparison_report or {}).get("comparability"),
                "scope": "axes the verifier recomputed itself; no aggregate match value exists",
            },
            "srs_receipt_authentication": {
                "receipt_signature_present": srs_signature_present,
                "signature_shape": "not_evaluated",
                "signature_valid": "not_evaluated",
                "key_resolved": "not_evaluated",
                "key_trusted": "not_evaluated",
                "issuance_authentication": "not_evaluated",
                "reason": (
                    "the profile is unsigned (requires_signing: false) and this adapter accepts no key material; "
                    + ("a receipt_signature is present but was not verified" if srs_signature_present else "no receipt_signature is present")
                ),
            },
            "source_digest_pin": {
                "profile_pin_source_commit": SOURCE_COMMIT,
                "native_validator_pin": dict(c2pa_native.PINNED_VALIDATOR),
                "recomputation_validator": recomputed.get("validator") if recomputed else None,
                "contract_semantic_digest": (comparison_report or recompute_report or {}).get("contract_semantic_digest"),
            },
        },
        "producer_asserted": producer,
        "observed_finding": observed,
        "native_recomputation": recompute_report,
        "native_comparison_report": comparison_report,
        "missing_paths": _missing_paths(stages, corr_detail, observed, recomputed, conformance_ran),
        "limitations": list(_BASE_LIMITATIONS),
        "unexercised_paths": (
            list(recompute_report["unexercised_paths"]) if recompute_report else []
        ),
    }
    return report


def _missing_paths(
    stages: dict[str, StageOutcome],
    corr_detail: dict[str, Any],
    observed: dict[str, Any] | None,
    recomputed: dict[str, Any] | None,
    conformance_ran: bool,
) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for name in STAGES:
        outcome = stages[name]
        if outcome.status in ("refused", "not_evaluated", "not_run"):
            out.append({"path": name, "status": outcome.status, "codes": ",".join(sorted({r.code for r in outcome.refusals})) or "-"})
    for item in corr_detail.get("unchecked", []):
        out.append({"path": f"digest:{item['field']}", "status": "unchecked", "codes": item["reason"]})
    if observed is not None:
        for entry in observed.get("unmapped_native_codes", []):
            out.append({"path": f"observed_unmapped_native_code:{entry['code']}", "status": "unmapped", "codes": "-"})
    if recomputed is not None:
        for entry in recomputed.get("unmapped_native_codes", []):
            out.append({"path": f"recomputed_unmapped_native_code:{entry['code']}", "status": "unmapped", "codes": "-"})
    return out


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


def consume_observation(
    observation: bytes,
    evidence: RetainedEvidence,
    *,
    executable: str | None = None,
    bundle: c2pa_native.ContractBundle | None = None,
) -> ConsumptionResult:
    """Run the fixed-order pipeline. Never raises for bad *input*; raises ``TypeError`` for
    misuse, ``ContractPinError`` for a corrupted installation and ``OrderingViolation`` for
    an internal ordering bug."""
    if not isinstance(observation, (bytes, bytearray)):
        raise TypeError("observation must be bytes")
    if not isinstance(evidence, RetainedEvidence) or not isinstance(evidence.asset, bytes):
        raise TypeError("evidence must be RetainedEvidence carrying asset bytes")
    _load_contract()
    bundle = bundle or c2pa_native.load_bundle()

    stages: dict[str, StageOutcome] = {
        name: StageOutcome(name, "not_run") for name in STAGES
    }
    state: dict[str, Any] = {"obs": None, "observed": None, "recompute": None, "comparison": None, "digest": None}

    def done(stopped: str | None) -> ConsumptionResult:
        report = _assemble(
            obs=state["obs"],
            observation_digest=state["digest"],
            stages=stages,
            stopped_at=stopped,
            observed=state["observed"],
            recompute_report=state["recompute"],
            comparison_report=state["comparison"],
        )
        return ConsumptionResult(stages=dict(stages), stopped_at=stopped, report=report)

    obs, outcome = _stage_parse(bytes(observation))
    stages["input_parse"] = outcome
    state["digest"] = outcome.detail.get("observation_sha256")
    if outcome.status != "completed":  # GUARD:ORDER-STOP-PARSE
        return done("input_parse")
    state["obs"] = obs

    _, outcome = _stage_correspondence(obs, evidence)
    stages["input_correspondence"] = outcome
    if outcome.status != "completed":  # GUARD:ORDER-STOP-CORRESPONDENCE
        return done("input_correspondence")

    _, outcome = _stage_conformance(obs)
    stages["profile_conformance"] = outcome
    if outcome.status != "completed":  # GUARD:ORDER-STOP-CONFORMANCE
        return done("profile_conformance")

    observed, outcome = _stage_construct(
        obs, stages["input_correspondence"], stages["profile_conformance"], bundle
    )
    stages["observed_finding_construction"] = outcome
    if outcome.status != "completed":  # GUARD:ORDER-STOP-CONSTRUCTION
        return done("observed_finding_construction")
    state["observed"] = observed

    recompute_report, outcome = _stage_recompute(obs, evidence, executable, bundle)
    stages["native_recomputation"] = outcome
    state["recompute"] = recompute_report
    if outcome.status != "completed":  # GUARD:ORDER-STOP-RECOMPUTATION
        return done("native_recomputation")

    comparison_report, outcome = _stage_compare(observed, recompute_report, bundle)
    stages["comparison"] = outcome
    state["comparison"] = comparison_report
    if outcome.status != "completed":
        return done("comparison")
    return done(None)


# ---------------------------------------------------------------------------
# CLI: python -m arcs_verify.c2pa_srs_observed
# ---------------------------------------------------------------------------

_MAX_CLI_FILE_BYTES = 1024 * 1024 * 1024


def _read_file(path: Path | None) -> bytes | None:
    if path is None:
        return None
    if path.stat().st_size > _MAX_CLI_FILE_BYTES:
        raise ValueError(f"{path.name} exceeds {_MAX_CLI_FILE_BYTES} bytes")
    return path.read_bytes()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m arcs_verify.c2pa_srs_observed",
        description=(
            "Consume an untrusted SRS C2PA validation observation and its retained evidence, "
            "recompute with the pinned native validator, and compare axis by axis. Experimental; "
            "not an SRS receipt verifier."
        ),
    )
    parser.add_argument("--observation", type=Path, required=True, help="serialized observation JSON")
    parser.add_argument("--asset", type=Path, required=True, help="retained asset bytes")
    parser.add_argument(
        "--asset-name",
        default=None,
        help="label whose extension the native validator uses to detect the format (default: the asset file name)",
    )
    parser.add_argument("--native-report", type=Path, default=None, help="retained native machine report bytes")
    parser.add_argument("--manifest-store", type=Path, default=None, help="retained manifest-store bytes")
    parser.add_argument("--configuration", type=Path, default=None, help="retained validator configuration bytes")
    parser.add_argument(
        "--c2patool",
        default=None,
        help=f"path to the pinned native validator; may also be set via {c2pa_native.VALIDATOR_ENV}",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Exit 0: every stage completed (a comparison was produced; that says nothing about
    whether the sides match). Exit 1: a stage refused or was not evaluated. Exit 2: usage or
    source-integrity error."""
    args = build_parser().parse_args(argv)
    try:
        evidence = RetainedEvidence(
            asset=_read_file(args.asset) or b"",
            asset_name=args.asset_name or args.asset.name,
            native_report=_read_file(args.native_report),
            manifest_store=_read_file(args.manifest_store),
            configuration=_read_file(args.configuration),
        )
        observation = _read_file(args.observation) or b""
        result = consume_observation(observation, evidence, executable=args.c2patool)
    except (OSError, ValueError) as exc:
        print(f"usage or source-integrity error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    return 0 if result.stopped_at is None else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
