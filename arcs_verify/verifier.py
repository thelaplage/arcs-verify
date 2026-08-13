from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator

FROZEN_SCHEMA_SHA256 = (
    "d03aad1d5517e2acb65d5c866905aed7219bcbbfadd1a4a97eac546dd23f0333"
)

# SRS envelope schema pins, keyed by the artifact version each digest names.
# v0.2.0 is retained verbatim: it is the pin that verifies every historical
# v0.2.0-era receipt and it keeps FROZEN_SCHEMA_SHA256 as its own value. v0.2.1
# is the additive successor vendored from arcs-srs merge ccc4e4bb; it differs
# from v0.2.0 only in $id, title, and the optional subject_ref_origin property.
#
# Accepting a second pin is purely additive: an input that verified under the
# v0.2.0 pin before this change verifies identically after it, and an input
# offered with any unpinned schema still fails schema_digest. No pre-existing
# disposition moves.
ENVELOPE_SCHEMA_PINS = {
    "v0.2.0": FROZEN_SCHEMA_SHA256,
    "v0.2.1": (
        "2afa1ec9f093fd7c06c4f5db7bfd37cc63e64e3dcbe47c963f4df586a1c18ca1"
    ),
}

ACCEPTED_SCHEMA_SHA256 = frozenset(ENVELOPE_SCHEMA_PINS.values())

MCP_PROFILE = "srs.mcp.sdk_enforcement.v0.1"
CONNECTION_PROFILE = "srs.connection.lifecycle.v0.1"
BROADCAST_CONTROL_PROFILE = "srs.broadcast_control.v0.1"
DEFERRED_OPERATION_PROFILE = "srs.deferred_operation.v0.1"
EDITORIAL_PUBLICATION_INGEST_PROFILE = "srs.editorial.publication_ingest.v0.1"
EDITORIAL_SOURCE_CAPTURE_PROFILE = "srs.editorial.source_capture.v0.1"
# Provisional successor. v0.1.1 is a distinct receipt model (top-level
# outcome / declared_url / captured_bytes_ref, editorial_corpus_boundary,
# capture_attempt kind) and coexists with the byte-frozen v0.1 verifier under
# its own (profile_id, profile_version) identity.
EDITORIAL_SOURCE_CAPTURE_PROFILE_V011 = "srs.editorial.source_capture.v0.1.1"
# Provisional declaration-scoped successor (arcs-srs 1f8768d). v0.2 is a
# DISTINCT profile identity for a broader subject domain; it supersedes v0.1 for
# declaration-scoped capture but does not amend, deprecate, or coerce v0.1/v0.1.1.
# A v0.2 receipt is verified as v0.2 or fails — there is no silent fallback.
EDITORIAL_SOURCE_CAPTURE_PROFILE_V02 = "srs.editorial.source_capture.v0.2"
# Provisional source-ingest stage (arcs-srs 1f8768d). Deterministic ingest/
# derivation of exact captured source bytes under a pinned parser; references a
# capture observation and never re-attests it.
EDITORIAL_SOURCE_INGEST_PROFILE = "srs.editorial.source_ingest.v0.1"
ACTIVITY_GOVERNED_READ_PROFILE = "srs.activity.governed_read.v0.1"
# Provisional citation-pack assembly profile (arcs-srs 4d90b9c, profile document
# a78df524..., release_stage PROVISIONAL / not ratified). A single pack_assembly
# provenance receipt for one editorial publication artifact. This is a
# SINGLE-RECEIPT STRUCTURAL verifier: it validates fixed identity, digest-
# reference FORM, subject binding, required covered/excluded classes, required
# machine-limitation codes, and the base attestation limit. It does NOT
# recompute the referenced objects (publication_artifact_id, pack_integrity_ref,
# declaration_manifest_ref) from bytes — the receipt is metadata-only and
# supplies no referenced bytes or byte-count contract — and it does not attempt
# the profile's NON-ENFORCED cross-receipt consistency rules.
EDITORIAL_CITATION_PACK_PROFILE = "srs.editorial.citation_pack.v0.1"

# Provisional profiles emit an advisory into report.details: a structural PASS
# attests conformance to a provisional (unratified) contract only, never to a
# stable/ratified profile, and never admission/trust/truth.
# The first formally versioned VerificationReport contract. A report that lacks
# this field is a legacy/unversioned predecessor; never retroactively label it.
REPORT_CONTRACT_V0_1 = "arcs.verify.srs_receipt_verification_report.v0.1"

# The additive self-identifying fields introduced by the v0.1 report contract.
# They are emitted together, and only when report_contract is set (i.e. by
# verify_receipt). A legacy/bare report omits the stamp AND all of these, so the
# serialized shape is a clean binary boundary with no ambiguous null-stamp state.
_VR0_ADDITIVE_FIELDS = (
    "report_contract",
    "selected_profile",
    "selected_profile_release_stage",
    "verified_receipt_id",
    "verified_receipt_version",
    "verified_receipt_profile_id",
    "verified_receipt_profile_version",
    "verified_receipt_canonical_json_sha256",
    "envelope_schema_identity",
)


@dataclass(frozen=True)
class ProfileMetadata:
    """Canonical per-profile metadata. Single source projected into profile
    identities, the CLI supported-profile listing, the report release-stage
    field, and the provisional advisory — so none of those can drift from what
    the verifier actually routes."""

    profile_id: str
    profile_version: str
    # "provisional" | <other explicitly known stage> | None. None means the
    # stage is NOT established by the verifier's pinned metadata. NEVER infer
    # "stable" from absence.
    release_stage: str | None
    description: str
    advisory: str | None = None  # provisional advisory surfaced into report.details


_PROVISIONAL_ADVISORY = (
    "provisional_profile: {slug} is PROVISIONAL (arcs-srs, not ratified). A "
    "structural PASS attests conformance to the provisional verification "
    "contract only — not admission, trust, truth, source authenticity, or "
    "conformance to any stable/ratified profile."
)

# THE canonical profile registry. Every profile the verifier routes appears here
# exactly once; identities, the CLI listing, release stage, and provisional
# advisories are all projected from it below. Release stage is populated only
# where pinned upstream evidence establishes it; otherwise None.
PROFILE_REGISTRY: dict[str, ProfileMetadata] = {
    MCP_PROFILE: ProfileMetadata(
        "srs.mcp.sdk_enforcement", "v0.1", None,
        "MCP tool-call admission receipts emitted at an SDK enforcement boundary (default)."),
    CONNECTION_PROFILE: ProfileMetadata(
        "srs.connection.lifecycle", "v0.1", None,
        "MCP connection lifecycle receipts (connect, scope grant, revoke, disconnect)."),
    BROADCAST_CONTROL_PROFILE: ProfileMetadata(
        "srs.broadcast_control", "v0.1", None,
        "Broadcast-control receipts for governed one-to-many distribution events."),
    DEFERRED_OPERATION_PROFILE: ProfileMetadata(
        "srs.deferred_operation", "v0.1", None,
        "Deferred-operation receipts (deferral, review linkage, outcome, disclosed gaps)."),
    EDITORIAL_PUBLICATION_INGEST_PROFILE: ProfileMetadata(
        "srs.editorial.publication_ingest", "v0.1", None,
        "Editorial corpus publication-ingest receipts (provenance of a parsed publication artifact)."),
    EDITORIAL_SOURCE_CAPTURE_PROFILE: ProfileMetadata(
        "srs.editorial.source_capture", "v0.1", None,
        "Editorial source-capture receipts (digest of the bytes a referenced URL or record returned at capture time)."),
    EDITORIAL_SOURCE_CAPTURE_PROFILE_V011: ProfileMetadata(
        "srs.editorial.source_capture", "v0.1.1", "provisional",
        "Editorial source-capture receipts, provisional v0.1.1 dialect (top-level outcome / declared_url / captured_bytes_ref with enforced cross-field null rules).",
        advisory=_PROVISIONAL_ADVISORY.format(slug=EDITORIAL_SOURCE_CAPTURE_PROFILE_V011)),
    EDITORIAL_SOURCE_CAPTURE_PROFILE_V02: ProfileMetadata(
        "srs.editorial.source_capture", "v0.2", "provisional",
        "Editorial source-capture receipts, provisional v0.2 (declaration-scoped capture; digest of exact captured bytes; no silent v0.1/v0.1.1 fallback).",
        advisory=_PROVISIONAL_ADVISORY.format(slug=EDITORIAL_SOURCE_CAPTURE_PROFILE_V02)),
    EDITORIAL_SOURCE_INGEST_PROFILE: ProfileMetadata(
        "srs.editorial.source_ingest", "v0.1", "provisional",
        "Editorial source-ingest receipts, provisional (deterministic ingest/derivation of exact captured bytes under a pinned parser; references a capture observation, never re-attests it).",
        advisory=_PROVISIONAL_ADVISORY.format(slug=EDITORIAL_SOURCE_INGEST_PROFILE)),
    ACTIVITY_GOVERNED_READ_PROFILE: ProfileMetadata(
        "srs.activity.governed_read", "v0.1", None,
        "Activity governed-read receipts (one governed read against a pinned basis; admitted result or typed refusal, mandatory C8 visibility)."),
    EDITORIAL_CITATION_PACK_PROFILE: ProfileMetadata(
        "srs.editorial.citation_pack", "v0.1", "provisional",
        "Editorial citation-pack assembly receipts, PROVISIONAL (arcs-srs, not ratified). Single-receipt structural verification of one pack_assembly provenance receipt: digest-reference form, subject binding, required classes/limits. A PASS attests structural conformance to the provisional contract only — not admission, trust, or correctness.",
        advisory=(
            "provisional_profile: srs.editorial.citation_pack.v0.1 is PROVISIONAL "
            "(arcs-srs, not ratified). A structural PASS attests conformance to the "
            "provisional verification contract only — not admission, trust, truth, "
            "evidence completeness, source authenticity, correct citation mappings, "
            "or conformance to any stable/ratified profile."
        )),
}

# Projections — derived from the registry so they cannot drift from routing.
PROFILE_IDENTITIES = {
    slug: (m.profile_id, m.profile_version) for slug, m in PROFILE_REGISTRY.items()
}
PROVISIONAL_PROFILE_DETAILS = {
    slug: m.advisory for slug, m in PROFILE_REGISTRY.items() if m.advisory is not None
}
SUPPORTED_PROFILE_DESCRIPTIONS = {
    slug: m.description for slug, m in PROFILE_REGISTRY.items()
}

RECEIPT_VERSION = "srs.core.v5.1"

SIGNATURE_FAILURE_CODES = {
    "preimage_canonicalization_failed",
    "signature_invalid",
    "key_id_unresolved",
    "key_untrusted",
    "version_binding_mismatch",
    "signature_object_invalid",
    "signature_encoding_invalid",
    "public_key_encoding_invalid",
    "legacy_unverified",
}

RAW_KEY_RE = re.compile(
    r"(?:^|_)("
    r"api_?key|apikey|password|secret(?:_?value)?|"
    r"credential(?:_?material)?|private_?key|privatekey|"
    r"access_?token|accesstoken|refresh_?token|refreshtoken|"
    r"provider_?token|session_?cookie|authorization(?:_?header)?|"
    r"prompt_?text|transcript|raw_?(?:payload|content|prompt|output)|"
    r"tool_?arguments?|arguments|tool_?result|result_?body|result|"
    r"request_?body|response_?body|content_?payloads?|"
    r"document_?body|message_?body|file_?body|"
    r"raw_?scope_?grant|scope_?document|user_?content|tenant_?content|"
    r"headers?"
    r")(?:$|_)",
    re.IGNORECASE,
)

def _normalize_key(value: str) -> str:
    snake = re.sub(r"(?<!^)(?=[A-Z])", "_", value)
    return snake.replace("-", "_").lower()


PRIVATE_MARKERS = (
    "/" + "Users" + "/",
    "/" + "home" + "/",
    "/" + "private" + "/" + "var",
    "C:" + "\\" + "\\",
    "~" + "/" + "garp-",
    "~" + "/" + "arcs-anchor",
)

PROHIBITED_VALUE_RE = re.compile(
    r"(?:"
    r"Bearer\s+[A-Za-z0-9._~-]+|"
    r"\bsk-(?:ant-)?[A-Za-z0-9_-]{8,}|"
    r"\bgh[pousr]_[A-Za-z0-9]{20,}|"
    r"\bxox[baprs]-[A-Za-z0-9-]{10,}|"
    r"\bAIza[0-9A-Za-z_-]{20,}"
    r")"
)

BASE_REQUIRED = {
    "receipt_version",
    "profile_id",
    "profile_version",
    "receipt_id",
    "receipt_type",
    "receipt_kind",
    "boundary_type",
    "protocol_binding",
    "subject_ref",
    "issuer_id",
    "runtime_instance_id",
    "boundary_id",
    "issued_at",
    "artifact_classes_covered",
    "artifact_classes_excluded",
    "attestation_limits",
    "extensions",
    "receipt_signature",
}

MCP_REQUIRED = BASE_REQUIRED | {"logical_call_id"}

# Registered binding-owned governance fields for the DAGR MCP receipt/profile.
# The DAGR emitter records these top-level delivery-state facts as strict JSON
# Booleans (see dagr_mcp CANCELLATION_FIELD_NAMES). They are deliberately named
# without a result-shaped token so they do not collide with raw-content
# exclusion, which means ARCS must independently type-check them: a re-signed
# receipt can otherwise smuggle raw tool-result material through one of these
# names. ARCS cannot trust issuer-side validation, so it enforces the Boolean
# contract itself. Absent is permitted; present requires a JSON Boolean.
MCP_BOOLEAN_GOVERNANCE_FIELDS = (
    "delivery_incomplete",
    "request_cancelled",
    "execution_state_unknown",
)

CONNECTION_REQUIRED = BASE_REQUIRED | {
    "tenant_id",
    "actor_ref",
    "source_record_refs",
}

SIGNATURE_MEMBERS = {
    "algorithm",
    "canonicalization",
    "key_id",
    "signature",
}

RESULT_LIMIT = (
    "The receipt establishes the request, admission disposition, and semantic "
    "result returned at the configured boundary. It does not independently "
    "establish that the underlying tool body executed for this invocation, "
    "because middleware such as caches may satisfy a call without handler "
    "execution."
)

TASK_LIMIT = (
    "The receipt establishes admission and submission to the configured task "
    "backend. It does not establish execution or completion."
)

CONNECTION_GENERAL_LIMIT = (
    "The receipt establishes the governance conditions enforced at the named "
    "connection boundary for the declared lifecycle event. It does not "
    "establish provider-side behavior."
)

CONNECTION_EVENT_LIMITS = {
    "connect": (
        "The receipt does not establish that the provider accepted, activated, "
        "maintained, or continued the connection."
    ),
    "scope_grant": (
        "The receipt does not establish that the provider enforced or honored "
        "the referenced scope set."
    ),
    "retention_selection": (
        "The receipt does not establish provider-side retention, deletion, "
        "legal-hold, or preservation behavior."
    ),
    "revoke": (
        "The receipt does not establish that provider credentials were "
        "invalidated or that provider-side access ceased."
    ),
    "delete": (
        "The receipt does not establish provider-side deletion, erasure, or "
        "destruction of provider-held data."
    ),
}

OPAQUE_REF_RE = re.compile(
    r"^[A-Za-z][A-Za-z0-9+.-]*:[A-Za-z0-9._~:@/-]+$"
)
SHA256_REF_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
STABLE_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9._:-]+$")


@dataclass(slots=True)
class VerificationReport:
    schema_digest: bool = False
    envelope: bool = False
    profile: bool = False
    raw_content_exclusion: bool = False
    signature_valid: bool = False
    issuer_key_resolved: bool = False
    issuer_key_trusted: bool = False
    attestation_limits_present: bool = False
    chain_status: str = "not_applicable"
    failure_codes: list[str] = field(default_factory=list)
    details: list[str] = field(default_factory=list)

    # --- Self-identifying contract (VR0, additive) ---------------------------
    # These identify WHAT was verified; they never participate in `passed`.
    # Self-identification is not self-authorization: naming the receipt, selected
    # profile, schema, and profile posture involved in a verification event does
    # NOT establish source truth, issuer trust, producer authority, admission,
    # standing, or publication eligibility.
    #
    # report_contract defaults to None: the stamp is set only in verify_receipt,
    # where the identity fields are actually populated, so the version can never
    # exist without the guarantee it signals. A bare VerificationReport() is the
    # legacy verdict-only shape.
    report_contract: str | None = None
    selected_profile: str | None = None
    selected_profile_release_stage: str | None = None
    verified_receipt_id: str | None = None
    verified_receipt_version: str | None = None
    verified_receipt_profile_id: str | None = None
    verified_receipt_profile_version: str | None = None
    verified_receipt_canonical_json_sha256: str | None = None
    envelope_schema_identity: dict[str, str | None] | None = None

    @property
    def passed(self) -> bool:
        return all(
            (
                self.schema_digest,
                self.envelope,
                self.profile,
                self.raw_content_exclusion,
                self.signature_valid,
                self.issuer_key_resolved,
                self.issuer_key_trusted,
                self.attestation_limits_present,
            )
        ) and self.chain_status == "not_applicable"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["passed"] = self.passed
        # Binary feature-detection boundary: a report with no contract stamp
        # serializes as the legacy verdict-only shape (stamp and all VR0 identity
        # fields omitted); a stamped report emits the complete enriched set.
        if self.report_contract is None:
            for key in _VR0_ADDITIVE_FIELDS:
                data.pop(key, None)
        return data


def _b64url_decode(value: str, *, code: str) -> bytes:
    if not isinstance(value, str) or not value or "=" in value:
        raise ValueError(code)
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:
        raise ValueError(code) from exc
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value:
        raise ValueError(code)
    return decoded


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _walk(value: Any) -> Iterable[tuple[str | None, Any]]:
    if isinstance(value, dict):
        for key, item in value.items():
            yield str(key), item
            yield from _walk(item)
    elif isinstance(value, list):
        for item in value:
            yield None, item
            yield from _walk(item)


def _missing_required(
    receipt: dict[str, Any],
    required: set[str],
) -> list[str]:
    missing = sorted(required - receipt.keys())
    if not missing:
        return []
    return ["profile.missing_required:" + ",".join(missing)]


def _is_opaque_reference(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    if value.startswith(("http:", "https:", "file:")):
        return False
    if any(marker in value for marker in PRIVATE_MARKERS):
        return False
    if any(marker in value for marker in ("?", "#", "%")):
        return False
    return OPAQUE_REF_RE.fullmatch(value) is not None


def _is_reference_or_digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and (
            SHA256_REF_RE.fullmatch(value) is not None
            or _is_opaque_reference(value)
        )
    )


def _is_stable_identifier(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and STABLE_IDENTIFIER_RE.fullmatch(value) is not None
    )


def _raw_content_failure(
    key: str,
    value: Any,
) -> str | None:
    normalized = _normalize_key(key)

    if RAW_KEY_RE.search(normalized) is None:
        return None

    if normalized.endswith(("_digest", "_hash")):
        if (
            isinstance(value, str)
            and SHA256_REF_RE.fullmatch(value) is not None
        ):
            return None
        return f"raw_content.invalid_digest_evidence:{key}"

    if normalized.endswith("_ref"):
        if _is_reference_or_digest(value):
            return None
        return f"raw_content.invalid_reference_evidence:{key}"

    if normalized.endswith("_refs"):
        if (
            isinstance(value, list)
            and bool(value)
            and all(_is_reference_or_digest(item) for item in value)
        ):
            return None
        return f"raw_content.invalid_reference_evidence:{key}"

    if normalized.endswith("_id"):
        if _is_stable_identifier(value) or _is_opaque_reference(value):
            return None
        return f"raw_content.invalid_identifier_evidence:{key}"

    if normalized.endswith("_ids"):
        if (
            isinstance(value, list)
            and bool(value)
            and all(
                _is_stable_identifier(item)
                or _is_opaque_reference(item)
                for item in value
            )
        ):
            return None
        return f"raw_content.invalid_identifier_evidence:{key}"

    return f"raw_content.forbidden_key:{key}"


def _contains_prohibited_value(value: str) -> bool:
    return (
        any(marker in value for marker in PRIVATE_MARKERS)
        or PROHIBITED_VALUE_RE.search(value) is not None
    )


def _mcp_profile_errors(receipt: dict[str, Any]) -> list[str]:
    errors = _missing_required(receipt, MCP_REQUIRED)

    expected = {
        "receipt_version": RECEIPT_VERSION,
        "profile_id": "srs.mcp.sdk_enforcement",
        "profile_version": "v0.1",
        "receipt_type": "sdk_enforcement",
        "boundary_type": "mcp_tool_call",
        "protocol_binding": "mcp",
    }

    for key, value in expected.items():
        if receipt.get(key) != value:
            errors.append(f"profile.invalid_{key}")

    kind = receipt.get("receipt_kind")

    if kind == "admission":
        for key in (
            "requested_tool_name",
            "tool_resolution_status",
            "argument_digest",
            "policy_pack_id",
            "policy_pack_version",
            "disposition",
        ):
            if key not in receipt:
                errors.append(f"profile.admission_missing_{key}")

        disposition = receipt.get("disposition")

        if disposition not in {
            "admitted",
            "refused",
            "deferred_for_review",
        }:
            errors.append("profile.invalid_disposition")

        if disposition == "deferred_for_review":
            if not receipt.get("review_object_ref"):
                errors.append(
                    "profile.deferred_missing_review_object_ref"
                )
            if receipt.get("retry_contract") != "retry_after_approval":
                errors.append(
                    "profile.deferred_invalid_retry_contract"
                )

    elif kind == "outcome":
        if not receipt.get("admission_receipt_ref"):
            errors.append(
                "profile.outcome_missing_admission_receipt_ref"
            )

        outcome = receipt.get("outcome")

        if outcome not in {
            "result_returned",
            "error_returned",
            "exception",
            "task_submitted",
            "indeterminate",
        }:
            errors.append("profile.invalid_outcome")

        if outcome in {"result_returned", "error_returned"}:
            if not receipt.get("result_digest"):
                errors.append("profile.result_missing_digest")
            if RESULT_LIMIT not in receipt.get("attestation_limits", []):
                errors.append(
                    "profile.result_missing_attestation_limit"
                )

        if (
            outcome == "task_submitted"
            and TASK_LIMIT not in receipt.get("attestation_limits", [])
        ):
            errors.append("profile.task_missing_attestation_limit")

    else:
        errors.append("profile.invalid_receipt_kind")

    if (
        receipt.get("tool_resolution_status") == "not_observed"
        and "resolved_tool_ref" in receipt
    ):
        errors.append("profile.resolution_ref_for_not_observed")

    for governance_field in MCP_BOOLEAN_GOVERNANCE_FIELDS:
        if (
            governance_field in receipt
            and not isinstance(receipt[governance_field], bool)
        ):
            errors.append(
                f"profile.non_boolean_governance_field:{governance_field}"
            )

    excluded = set(receipt.get("artifact_classes_excluded") or [])

    if not {
        "raw_prompt",
        "raw_output",
        "raw_tool_arguments",
        "raw_tool_result",
    }.issubset(excluded):
        errors.append("profile.raw_artifact_exclusions_missing")

    return errors


def _connection_profile_errors(
    receipt: dict[str, Any],
) -> list[str]:
    errors = _missing_required(receipt, CONNECTION_REQUIRED)

    expected = {
        "receipt_version": RECEIPT_VERSION,
        "profile_id": "srs.connection.lifecycle",
        "profile_version": "v0.1",
        "receipt_type": "connection",
        "boundary_type": "connection_boundary",
    }

    for key, value in expected.items():
        if receipt.get(key) != value:
            errors.append(f"profile.invalid_{key}")

    binding = receipt.get("protocol_binding")

    if not isinstance(binding, str) or not binding:
        errors.append("profile.invalid_protocol_binding")

    extensions = receipt.get("extensions")

    if not isinstance(extensions, dict):
        errors.append("profile.extensions_not_object")
    elif (
        "forum_projection" in extensions
        and binding != "arcs-forum"
    ):
        errors.append("profile.forum_projection_binding_mismatch")

    source_refs = receipt.get("source_record_refs")

    if (
        not isinstance(source_refs, list)
        or not source_refs
        or not all(_is_reference_or_digest(item) for item in source_refs)
    ):
        errors.append("profile.invalid_source_record_refs")

    covered = set(receipt.get("artifact_classes_covered") or [])

    if "connection_governance_event" not in covered:
        errors.append(
            "profile.connection_governance_event_not_covered"
        )

    excluded = set(receipt.get("artifact_classes_excluded") or [])

    if not {
        "credential_material",
        "provider_tokens",
        "content_payloads",
    }.issubset(excluded):
        errors.append("profile.raw_artifact_exclusions_missing")

    limits = receipt.get("attestation_limits")
    limit_values = set(limits) if isinstance(limits, list) else set()

    if CONNECTION_GENERAL_LIMIT not in limit_values:
        errors.append(
            "profile.connection_general_attestation_limit_missing"
        )

    kind = receipt.get("receipt_kind")

    if kind not in CONNECTION_EVENT_LIMITS:
        errors.append("profile.invalid_receipt_kind")
        return errors

    if CONNECTION_EVENT_LIMITS[kind] not in limit_values:
        errors.append(
            f"profile.{kind}_attestation_limit_missing"
        )

    if kind == "connect":
        if not _is_opaque_reference(receipt.get("provider_ref")):
            errors.append("profile.connect_missing_provider_ref")

    elif kind == "scope_grant":
        scope_refs = receipt.get("scope_refs")
        if (
            not isinstance(scope_refs, list)
            or not scope_refs
            or not all(
                _is_reference_or_digest(item)
                for item in scope_refs
            )
        ):
            errors.append("profile.scope_grant_invalid_scope_refs")

    elif kind == "retention_selection":
        if not _is_stable_identifier(
            receipt.get("retention_class")
        ):
            errors.append(
                "profile.retention_selection_invalid_retention_class"
            )

    elif kind == "revoke":
        if (
            "reason_code" in receipt
            and not _is_stable_identifier(
                receipt.get("reason_code")
            )
        ):
            errors.append("profile.revoke_invalid_reason_code")

        for forbidden in (
            "reason",
            "reason_text",
            "reason_message",
        ):
            if forbidden in receipt:
                errors.append(
                    f"profile.revoke_free_form_reason_forbidden:{forbidden}"
                )

    if (
        "retention_class" in receipt
        and not _is_stable_identifier(
            receipt.get("retention_class")
        )
    ):
        errors.append("profile.invalid_retention_class")

    return errors


BROADCAST_CONTROL_BASE_LIMIT = (
    "The receipt declares a governed broadcast control operation under the "
    "srs.broadcast_control profile. It does not independently establish that "
    "the broadcast product received, executed, or entered the declared target "
    "state. MCP call success does not establish delivery; delivery requires a "
    "correlated native product state event."
)

BROADCAST_CONTROL_RECEIPT_KINDS = frozenset(
    ["request", "acceptance", "execution", "observed_consequence", "delivery"]
)

BROADCAST_CONTROL_TARGET_STATE_KINDS = frozenset(
    ["execution", "observed_consequence", "delivery"]
)

BROADCAST_CONTROL_CAPTURE_POSTURES = frozenset(
    ["observed", "native_emission", "dagr_governed", "lifecycle_assembled"]
)

BROADCAST_CONTROL_REQUIRED_EXCLUSIONS = frozenset(
    ["raw_arguments", "raw_product_state", "raw_event_payload"]
)


def _broadcast_control_profile_errors(receipt: dict[str, Any]) -> list[str]:
    errors: list[str] = []

    if receipt.get("receipt_type") != "provenance":
        errors.append("broadcast_control.invalid_receipt_type")

    if receipt.get("boundary_type") != "broadcast_control_boundary":
        errors.append("broadcast_control.invalid_boundary_type")

    if receipt.get("profile_id") != "srs.broadcast_control":
        errors.append("broadcast_control.invalid_profile_id")

    if receipt.get("profile_version") != "v0.1":
        errors.append("broadcast_control.invalid_profile_version")

    kind = receipt.get("receipt_kind")

    if kind not in BROADCAST_CONTROL_RECEIPT_KINDS:
        errors.append("broadcast_control.invalid_receipt_kind")
    elif kind in BROADCAST_CONTROL_TARGET_STATE_KINDS:
        target_state = receipt.get("target_state")
        if (
            not isinstance(target_state, str)
            or SHA256_REF_RE.fullmatch(target_state) is None
        ):
            errors.append("broadcast_control.missing_target_state")

    excluded = set(receipt.get("artifact_classes_excluded") or [])

    if not BROADCAST_CONTROL_REQUIRED_EXCLUSIONS.issubset(excluded):
        errors.append("broadcast_control.missing_required_exclusions")

    capture_posture = receipt.get("capture_posture")

    if capture_posture is not None and capture_posture not in BROADCAST_CONTROL_CAPTURE_POSTURES:
        errors.append("broadcast_control.invalid_capture_posture")

    extensions = receipt.get("extensions")

    if isinstance(extensions, dict):
        for ext_value in extensions.values():
            if isinstance(ext_value, dict):
                if ext_value.get("mcp_success_proves_delivery") is True:
                    errors.append(
                        "broadcast_control.invalid_assurance_claim"
                    )
                if ext_value.get("operation_type") == "toggle":
                    errors.append(
                        "broadcast_control.forbidden_operation_type"
                    )

    limits = receipt.get("attestation_limits")
    limit_values = set(limits) if isinstance(limits, list) else set()

    if BROADCAST_CONTROL_BASE_LIMIT not in limit_values:
        errors.append(
            "broadcast_control.missing_base_attestation_limit"
        )

    return errors


DEFERRED_OPERATION_BASE_LIMIT = (
    "The receipt establishes the declared event role and associated metadata "
    "at the time of issuance. It does not independently establish that the "
    "governed operation executed, that conditions were actually met, or that "
    "the sequence is complete. Receipt presence is not equivalent to "
    "operational compliance."
)

DEFERRED_OPERATION_RECEIPT_KINDS = frozenset([
    "defer_request",
    "condition_response",
    "reevaluation",
    "terminal_admission",
    "execution_outcome",
    "receipt_gap",
])

DEFERRED_OPERATION_OUTCOME_VALUES = frozenset([
    "result_returned",
    "error_returned",
    "exception",
    "task_submitted",
    "indeterminate",
])

DEFERRED_OPERATION_REQUIRED_EXCLUSIONS = frozenset([
    "raw_prompt",
    "raw_output",
    "raw_tool_arguments",
    "raw_tool_result",
])


def _deferred_operation_profile_errors(receipt: dict[str, Any]) -> list[str]:
    """Independent structural findings for a single srs.deferred_operation.v0.1 receipt.

    Authority boundaries (per profile manifest §7 / spec §7):
    - Sequence linkage (sequence_id continuity, operation_digest chain,
      predecessor_receipt_ref chain) CANNOT be verified from a single receipt.
      Cross-receipt findings belong to the sequence verifier.
    - condition_response.response_status == approved does NOT make the
      operation admissible. This verifier does not assert admissibility.
    - key_resolved and key_trusted are evaluated by the signature path, not here.
    - NOT_EVALUATED is not PASS.
    """
    errors: list[str] = []

    if receipt.get("profile_id") != "srs.deferred_operation":
        errors.append("deferred_operation.invalid_profile_id")

    if receipt.get("profile_version") != "v0.1":
        errors.append("deferred_operation.invalid_profile_version")

    if receipt.get("receipt_type") != "provenance":
        errors.append("deferred_operation.invalid_receipt_type")

    kind = receipt.get("receipt_kind")

    if kind not in DEFERRED_OPERATION_RECEIPT_KINDS:
        errors.append("deferred_operation.invalid_receipt_kind")
        return errors

    # sequence_id required on all kinds
    seq_id = receipt.get("sequence_id")
    if not isinstance(seq_id, str) or not seq_id:
        errors.append("deferred_operation.missing_sequence_id")

    # base attestation limit required on all kinds
    limits = receipt.get("attestation_limits")
    limit_values = set(limits) if isinstance(limits, list) else set()
    if DEFERRED_OPERATION_BASE_LIMIT not in limit_values:
        errors.append("deferred_operation.missing_base_attestation_limit")

    # raw content exclusions required on all kinds
    excluded = set(receipt.get("artifact_classes_excluded") or [])
    if not DEFERRED_OPERATION_REQUIRED_EXCLUSIONS.issubset(excluded):
        errors.append("deferred_operation.missing_required_exclusions")

    # --- kind-specific checks ---

    if kind == "defer_request":
        for field_name in (
            "argument_digest",
            "policy_pack_id",
            "policy_pack_version",
            "review_condition",
            "operation_digest",
        ):
            if not receipt.get(field_name):
                errors.append(
                    f"deferred_operation.defer_request_missing_{field_name}"
                )

        if receipt.get("disposition") != "deferred_for_review":
            errors.append("deferred_operation.defer_request_invalid_disposition")

        if receipt.get("retry_contract") != "retry_after_condition":
            errors.append("deferred_operation.defer_request_invalid_retry_contract")

        op_digest = receipt.get("operation_digest")
        if op_digest and not SHA256_REF_RE.fullmatch(op_digest):
            errors.append("deferred_operation.defer_request_invalid_operation_digest")

        arg_digest = receipt.get("argument_digest")
        if arg_digest and not SHA256_REF_RE.fullmatch(arg_digest):
            errors.append("deferred_operation.defer_request_invalid_argument_digest")

    elif kind == "condition_response":
        for field_name in (
            "predecessor_receipt_ref",
            "condition_digest",
            "responder_ref",
            "response_status",
        ):
            if not receipt.get(field_name):
                errors.append(
                    f"deferred_operation.condition_response_missing_{field_name}"
                )

        resp_status = receipt.get("response_status")
        if resp_status not in {"approved", "rejected", "expired"}:
            errors.append(
                "deferred_operation.condition_response_invalid_response_status"
            )

        cond_digest = receipt.get("condition_digest")
        if cond_digest and not SHA256_REF_RE.fullmatch(cond_digest):
            errors.append(
                "deferred_operation.condition_response_invalid_condition_digest"
            )

    elif kind == "reevaluation":
        for field_name in (
            "predecessor_receipt_ref",
            "condition_receipt_ref",
            "operation_digest",
            "policy_pack_id",
            "policy_pack_version",
        ):
            if not receipt.get(field_name):
                errors.append(
                    f"deferred_operation.reevaluation_missing_{field_name}"
                )

        op_digest = receipt.get("operation_digest")
        if op_digest and not SHA256_REF_RE.fullmatch(op_digest):
            errors.append("deferred_operation.reevaluation_invalid_operation_digest")

    elif kind == "terminal_admission":
        for field_name in (
            "predecessor_receipt_ref",
            "condition_receipt_ref",
            "defer_receipt_ref",
            "operation_digest",
            "disposition",
            "policy_pack_id",
            "policy_pack_version",
        ):
            if not receipt.get(field_name):
                errors.append(
                    f"deferred_operation.terminal_admission_missing_{field_name}"
                )

        disposition = receipt.get("disposition")
        if disposition not in {"admitted", "refused"}:
            errors.append(
                "deferred_operation.terminal_admission_invalid_disposition"
            )

        op_digest = receipt.get("operation_digest")
        if op_digest and not SHA256_REF_RE.fullmatch(op_digest):
            errors.append(
                "deferred_operation.terminal_admission_invalid_operation_digest"
            )

    elif kind == "execution_outcome":
        for field_name in (
            "predecessor_receipt_ref",
            "defer_receipt_ref",
            "terminal_admission_ref",
            "operation_digest",
            "outcome",
        ):
            if not receipt.get(field_name):
                errors.append(
                    f"deferred_operation.execution_outcome_missing_{field_name}"
                )

        outcome = receipt.get("outcome")
        if outcome not in DEFERRED_OPERATION_OUTCOME_VALUES:
            errors.append("deferred_operation.execution_outcome_invalid_outcome")

        op_digest = receipt.get("operation_digest")
        if op_digest and not SHA256_REF_RE.fullmatch(op_digest):
            errors.append(
                "deferred_operation.execution_outcome_invalid_operation_digest"
            )

    elif kind == "receipt_gap":
        gap_reason = receipt.get("gap_reason")
        if not isinstance(gap_reason, str) or not gap_reason.strip():
            errors.append("deferred_operation.receipt_gap_missing_gap_reason")

    return errors


EDITORIAL_INGEST_REQUIRED = frozenset([
    "publication_artifact_id",
    "corpus_scope",
    "root_id",
    "relative_path",
    "occurrence_posture",
    "corpus_manifest_ref",
    "parser_identity",
    "declaration_manifest_ref",
])

EDITORIAL_INGEST_OCCURRENCE_POSTURES = frozenset([
    "unique_artifact",
    "duplicate_location",
])

EDITORIAL_INGEST_REQUIRED_COVERED = frozenset([
    "publication_artifact_digest",
    "declared_reference_manifest_digest",
])

EDITORIAL_INGEST_REQUIRED_EXCLUDED = frozenset([
    "raw_publication_bytes",
    "raw_frontmatter_yaml",
    "raw_body_text",
])

EDITORIAL_INGEST_REQUIRED_LIMITATION_CODES = frozenset([
    "ARTICLE_TRUTH_NOT_EVALUATED",
    "EVIDENCE_COMPLETENESS_NOT_EVALUATED",
])

EDITORIAL_INGEST_BASE_LIMIT = (
    "The receipt declares that an editorial publication artifact was ingested "
    "and parsed by the stated parser. It does not establish article truth, "
    "evidence completeness, or source verification. Declared references are "
    "not independently captured."
)

EDITORIAL_INGEST_KIND_LIMIT = (
    "The receipt does not establish that any declared source was captured, "
    "verified, or independently confirmed."
)


def _editorial_publication_ingest_profile_errors(
    receipt: dict[str, Any],
) -> list[str]:
    errors: list[str] = []

    if receipt.get("profile_id") != "srs.editorial.publication_ingest":
        errors.append("editorial_ingest.invalid_profile_id")

    if receipt.get("profile_version") != "v0.1":
        errors.append("editorial_ingest.invalid_profile_version")

    if receipt.get("receipt_type") != "provenance":
        errors.append("editorial_ingest.invalid_receipt_type")

    if receipt.get("boundary_type") != "editorial_corpus_boundary":
        errors.append("editorial_ingest.invalid_boundary_type")

    if receipt.get("receipt_kind") != "ingest":
        errors.append("editorial_ingest.invalid_receipt_kind")

    for field in EDITORIAL_INGEST_REQUIRED:
        if field not in receipt:
            errors.append(f"editorial_ingest.missing_required:{field}")

    pub_art_id = receipt.get("publication_artifact_id")
    subject_ref = receipt.get("subject_ref")
    if (
        pub_art_id is not None
        and subject_ref is not None
        and pub_art_id != subject_ref
    ):
        errors.append("editorial_ingest.subject_binding_mismatch")

    if (
        pub_art_id is not None
        and not isinstance(pub_art_id, str)
        or (
            isinstance(pub_art_id, str)
            and not pub_art_id.startswith("sha256:")
        )
    ):
        errors.append("editorial_ingest.invalid_publication_artifact_id")

    posture = receipt.get("occurrence_posture")
    if posture is not None and posture not in EDITORIAL_INGEST_OCCURRENCE_POSTURES:
        errors.append("editorial_ingest.invalid_occurrence_posture")

    covered = set(receipt.get("artifact_classes_covered") or [])
    if not EDITORIAL_INGEST_REQUIRED_COVERED.issubset(covered):
        errors.append("editorial_ingest.missing_required_covered_classes")

    excluded = set(receipt.get("artifact_classes_excluded") or [])
    if not EDITORIAL_INGEST_REQUIRED_EXCLUDED.issubset(excluded):
        errors.append("editorial_ingest.missing_required_excluded_classes")

    limitations = receipt.get("machine_limitations")
    if isinstance(limitations, list):
        present_codes = {
            item.get("code")
            for item in limitations
            if isinstance(item, dict)
        }
        missing = EDITORIAL_INGEST_REQUIRED_LIMITATION_CODES - present_codes
        for code in sorted(missing):
            errors.append(
                f"editorial_ingest.missing_required_limitation_code:{code}"
            )
    else:
        for code in sorted(EDITORIAL_INGEST_REQUIRED_LIMITATION_CODES):
            errors.append(
                f"editorial_ingest.missing_required_limitation_code:{code}"
            )

    limits = receipt.get("attestation_limits")
    limit_values = set(limits) if isinstance(limits, list) else set()
    if EDITORIAL_INGEST_BASE_LIMIT not in limit_values:
        errors.append("editorial_ingest.missing_base_attestation_limit")
    if EDITORIAL_INGEST_KIND_LIMIT not in limit_values:
        errors.append("editorial_ingest.missing_ingest_attestation_limit")

    return errors


SOURCE_CAPTURE_REQUIRED_COVERED = frozenset([
    "captured_response_digest",
    "capture_transaction_metadata",
])

SOURCE_CAPTURE_REQUIRED_EXCLUDED = frozenset([
    "raw_network_response_body",
    "raw_source_bytes",
    "article_truth",
])

SOURCE_CAPTURE_REQUIRED_LIMITATION_CODES = frozenset([
    "ARTICLE_TRUTH_NOT_EVALUATED",
    "CLAIM_SUPPORT_NOT_EVALUATED",
    "SOURCE_IDENTITY_NOT_EVALUATED",
])


def _editorial_source_capture_profile_errors(
    receipt: dict[str, Any],
) -> list[str]:
    """Profile checks for editorial source-capture receipts.

    A capture receipt attests to the digest of the bytes a referenced EXTERNAL
    URL returned at a network capture at capture time. It binds a declared
    reference to a captured-body digest, and — like ingest — never asserts
    article truth, claim support, or source identity.

    This profile is external/network capture only. An internal governed-record
    reference is a distinct semantic class (declaration resolution / pin
    verification) governed by the proposed srs.editorial.reference_resolution
    profile; it MUST NOT receive a source_capture receipt. The external-URL
    requirement below is what keeps the two classes from being conflated at the
    verifier (see the internal_source_capture_masquerade defect).
    """
    errors: list[str] = []

    if receipt.get("profile_id") != "srs.editorial.source_capture":
        errors.append("source_capture.invalid_profile_id")
    if receipt.get("profile_version") != "v0.1":
        errors.append("source_capture.invalid_profile_version")
    if receipt.get("receipt_type") != "provenance":
        errors.append("source_capture.invalid_receipt_type")
    if receipt.get("boundary_type") != "editorial_source_capture_boundary":
        errors.append("source_capture.invalid_boundary_type")
    if receipt.get("receipt_kind") != "source_capture":
        errors.append("source_capture.invalid_receipt_kind")

    capture = receipt.get("capture")
    if not isinstance(capture, dict):
        errors.append("source_capture.missing_capture_block")
        capture = {}

    digest = capture.get("captured_body_sha256")
    if not isinstance(digest, str) or not digest.startswith("sha256:"):
        errors.append("source_capture.invalid_captured_body_digest")

    # External/network capture only: the captured URL must be an http(s) URL.
    # An internal governed-record reference (e.g. counterpedia://record/<id>) is
    # a distinct semantic class and MUST NOT ride this profile. Requiring an
    # external URL here is the verifier-side guard against the
    # internal_source_capture_masquerade defect.
    requested_url = capture.get("requested_url")
    if not isinstance(requested_url, str) or not (
        requested_url.startswith("http://") or requested_url.startswith("https://")
    ):
        errors.append("source_capture.capture_url_not_external")

    # subject_ref must bind the receipt to the declared reference it captured.
    reference = receipt.get("reference")
    if not isinstance(reference, dict) or not reference.get("ref_id"):
        errors.append("source_capture.missing_reference_binding")
    elif receipt.get("subject_ref") != reference.get("ref_id"):
        errors.append("source_capture.subject_binding_mismatch")

    covered = set(receipt.get("artifact_classes_covered") or [])
    if not SOURCE_CAPTURE_REQUIRED_COVERED.issubset(covered):
        errors.append("source_capture.missing_required_covered_classes")

    excluded = set(receipt.get("artifact_classes_excluded") or [])
    if not SOURCE_CAPTURE_REQUIRED_EXCLUDED.issubset(excluded):
        errors.append("source_capture.missing_required_excluded_classes")

    limitations = receipt.get("machine_limitations")
    present_codes = (
        {item.get("code") for item in limitations if isinstance(item, dict)}
        if isinstance(limitations, list)
        else set()
    )
    for code in sorted(SOURCE_CAPTURE_REQUIRED_LIMITATION_CODES - present_codes):
        errors.append(f"source_capture.missing_required_limitation_code:{code}")

    if receipt.get("retention_class_applied") != "hash_only":
        errors.append("source_capture.invalid_retention_class")

    return errors


SOURCE_CAPTURE_V011_OUTCOME_VALUES = frozenset([
    "success",
    "blocked",
    "dns_error",
    "http_error",
    "connection_error",
    "redirect_error",
    "timeout",
    "no_url_declared",
])

SOURCE_CAPTURE_V011_REQUIRED_COVERED = frozenset([
    "declared_reference_identity",
    "capture_attempt_record",
])

SOURCE_CAPTURE_V011_REQUIRED_EXCLUDED = frozenset([
    "raw_captured_bytes",
])

SOURCE_CAPTURE_V011_REQUIRED_LIMITATION_CODES = frozenset([
    "CONTENT_NOT_VERIFIED",
])


def _editorial_source_capture_v011_profile_errors(
    receipt: dict[str, Any],
) -> list[str]:
    """Profile errors for srs.editorial.source_capture.v0.1.1 (provisional).

    Distinct receipt model from v0.1: the capture disposition is a top-level
    ``outcome`` enum, and ``declared_url`` / ``captured_bytes_ref`` are
    top-level fields bound to that outcome by two structurally enforced
    cross-field rules. The frozen v0.1 ``capture``-block verifier is not
    touched or widened.
    """
    errors: list[str] = []

    if receipt.get("profile_id") != "srs.editorial.source_capture":
        errors.append("source_capture.invalid_profile_id")
    if receipt.get("profile_version") != "v0.1.1":
        errors.append("source_capture.invalid_profile_version")
    if receipt.get("receipt_type") != "provenance":
        errors.append("source_capture.invalid_receipt_type")
    if receipt.get("boundary_type") != "editorial_corpus_boundary":
        errors.append("source_capture.invalid_boundary_type")
    if receipt.get("receipt_kind") != "capture_attempt":
        errors.append("source_capture.invalid_receipt_kind")

    outcome = receipt.get("outcome")
    outcome_known = outcome in SOURCE_CAPTURE_V011_OUTCOME_VALUES
    if not outcome_known:
        errors.append("source_capture.invalid_outcome")

    # captured_bytes_ref: a sha256:<hex> digest exactly when outcome is
    # 'success', JSON null for every other outcome (including
    # no_url_declared). Both directions enforced. The cross-field rule is
    # only evaluated for a known outcome so an invalid outcome yields one code.
    cbr = receipt.get("captured_bytes_ref")
    if outcome == "success":
        if not (isinstance(cbr, str) and cbr.startswith("sha256:")):
            errors.append("source_capture.missing_captured_bytes_on_success")
    elif outcome_known and cbr is not None:
        errors.append("source_capture.captured_bytes_on_nonsuccess")

    # declared_url: JSON null exactly when outcome is 'no_url_declared', a
    # non-empty string for every other outcome. Both directions enforced.
    declared_url = receipt.get("declared_url")
    if outcome == "no_url_declared":
        if declared_url is not None:
            errors.append("source_capture.declared_url_on_no_url_declared")
    elif outcome_known and not (isinstance(declared_url, str) and declared_url):
        errors.append("source_capture.missing_declared_url")

    # subject_ref binds the receipt to the declared reference it targeted.
    reference_artifact_id = receipt.get("reference_artifact_id")
    if not (isinstance(reference_artifact_id, str) and reference_artifact_id):
        errors.append("source_capture.missing_reference_binding")
    elif receipt.get("subject_ref") != reference_artifact_id:
        errors.append("source_capture.subject_binding_mismatch")

    covered = set(receipt.get("artifact_classes_covered") or [])
    if not SOURCE_CAPTURE_V011_REQUIRED_COVERED.issubset(covered):
        errors.append("source_capture.missing_required_covered_classes")

    excluded = set(receipt.get("artifact_classes_excluded") or [])
    if not SOURCE_CAPTURE_V011_REQUIRED_EXCLUDED.issubset(excluded):
        errors.append("source_capture.missing_required_excluded_classes")

    limitations = receipt.get("machine_limitations")
    present_codes = (
        {item.get("code") for item in limitations if isinstance(item, dict)}
        if isinstance(limitations, list)
        else set()
    )
    for code in sorted(
        SOURCE_CAPTURE_V011_REQUIRED_LIMITATION_CODES - present_codes
    ):
        errors.append(f"source_capture.missing_required_limitation_code:{code}")

    return errors


# --- srs.editorial.source_capture.v0.2 ---------------------------------------
#
# Provisional declaration-scoped capture successor (arcs-srs 1f8768d). The
# expectation values below are transcribed from the vendored, byte-pinned
# profile manifest at vendor/arcs-srs/vectors/editorial-source-capture-v0.2/
# profile.manifest.json (document_sha256
# d621fa989350c010221ed91bd78017458ed73fc419f7d0c9fbecd5471167bc86); the pin
# test asserts these constants against those bytes so the verifier never drifts
# into a fresh local dialect. This is a DISTINCT profile identity from v0.1 /
# v0.1.1 — the frozen predecessors above are not touched or widened, and a v0.2
# receipt is never coerced down to them.

SOURCE_CAPTURE_V02_FIXED_VALUES = {
    "receipt_version": "srs.core.v5.1",
    "profile_id": "srs.editorial.source_capture",
    "receipt_type": "provenance",
    "boundary_type": "editorial_corpus_boundary",
}

SOURCE_CAPTURE_V02_REQUIRED_FIELDS = (
    "receipt_version",
    "profile_id",
    "profile_version",
    "receipt_id",
    "receipt_type",
    "receipt_kind",
    "boundary_type",
    "protocol_binding",
    "subject_ref",
    "issuer_id",
    "runtime_instance_id",
    "boundary_id",
    "issued_at",
    "source_reference_id",
    "declaring_artifact_ref",
    "source_inventory_key",
    "declared_url",
    "capturer_identity",
    "outcome",
    "captured_bytes_ref",
    "artifact_classes_covered",
    "artifact_classes_excluded",
    "attestation_limits",
    "extensions",
)

SOURCE_CAPTURE_V02_OUTCOME_VALUES = frozenset([
    "success",
    "blocked",
    "dns_error",
    "http_error",
    "connection_error",
    "redirect_error",
    "timeout",
    "no_url_declared",
])

SOURCE_CAPTURE_V02_REQUIRED_COVERED = frozenset([
    "declared_reference_identity",
    "capture_attempt_record",
])

SOURCE_CAPTURE_V02_REQUIRED_EXCLUDED = frozenset([
    "raw_captured_bytes",
])

SOURCE_CAPTURE_V02_REQUIRED_LIMITATION_CODES = frozenset([
    "CONTENT_NOT_VERIFIED",
])

SOURCE_CAPTURE_V02_BASE_ATTESTATION_LIMIT = (
    "The receipt declares a source capture attempt for a governed declared "
    "source reference. It does not establish that the captured bytes are "
    "authentic, that the source is the one the declaration intended, or that "
    "the content supports any claim the declaration is used to support."
)


def _editorial_source_capture_v02_profile_errors(
    receipt: dict[str, Any],
) -> list[str]:
    """Profile errors for srs.editorial.source_capture.v0.2 (provisional).

    A capture_attempt receipt over a DECLARED SOURCE REFERENCE in a governed
    declaration. The subject is declaration identity, never a locator:
    ``source_reference_id`` derives only from ``declaring_artifact_ref`` and
    ``source_inventory_key`` (profile s4), and ``declared_url`` / capturer
    identity are explicitly excluded from it so identical-reference captures by
    different pipelines converge on one reference identity. The verifier
    recomputes receipt structure only: captured bytes do not establish source
    identity, and nothing here asserts article truth, claim support, or source
    identity.

    This is the v0.2 identity; ``profile_version`` is not coerced to v0.1/v0.1.1.
    """
    errors: list[str] = []

    # Fixed values (manifest fixed_values). profile_version is version identity,
    # not a fixed_value, and gets its own named finding so a mislabelled version
    # never silently falls back to another source_capture profile.
    for field, expected in SOURCE_CAPTURE_V02_FIXED_VALUES.items():
        if receipt.get(field) != expected:
            errors.append("FIXED_VALUE_MISMATCH")
    if receipt.get("profile_version") != "v0.2":
        errors.append("PROFILE_VERSION_MISMATCH")
    if receipt.get("receipt_kind") != "capture_attempt":
        errors.append("INVALID_RECEIPT_KIND")

    for field in SOURCE_CAPTURE_V02_REQUIRED_FIELDS:
        if field not in receipt:
            errors.append("MISSING_PROFILE_FIELD")

    # Subject binding: subject_ref MUST equal source_reference_id (s2).
    source_reference_id = receipt.get("source_reference_id")
    if (
        isinstance(source_reference_id, str)
        and receipt.get("subject_ref") != source_reference_id
    ):
        errors.append("SUBJECT_BINDING_MISMATCH")

    # Declaration identity (s4): source_reference_id is derived ONLY from
    # declaring_artifact_ref (sha256 of the governed declaration) and
    # source_inventory_key. Structurally recomputable from bytes: the declaring
    # artifact hex and the inventory key MUST both appear in the reference id,
    # and the locator / capturer identity MUST NOT — folding either in is a
    # declaration-identity tamper that fails closed.
    declaring_artifact_ref = receipt.get("declaring_artifact_ref")
    source_inventory_key = receipt.get("source_inventory_key")
    if isinstance(declaring_artifact_ref, str):
        if not SHA256_REF_RE.fullmatch(declaring_artifact_ref):
            errors.append("INVALID_DECLARING_ARTIFACT_REF")
        if isinstance(source_reference_id, str):
            declaring_hex = declaring_artifact_ref.split("sha256:", 1)[-1]
            if (
                declaring_hex not in source_reference_id
                or not isinstance(source_inventory_key, str)
                or source_inventory_key not in source_reference_id
            ):
                errors.append("SOURCE_REFERENCE_ID_NOT_DECLARATION_DERIVED")
    if isinstance(source_reference_id, str):
        declared_url = receipt.get("declared_url")
        if isinstance(declared_url, str) and declared_url and (
            declared_url in source_reference_id
        ):
            errors.append("SOURCE_REFERENCE_ID_INCORPORATES_LOCATOR")
        capturer_identity = receipt.get("capturer_identity")
        if isinstance(capturer_identity, str) and capturer_identity and (
            capturer_identity in source_reference_id
        ):
            errors.append("SOURCE_REFERENCE_ID_INCORPORATES_CAPTURER")

    # Capture semantics.
    outcome = receipt.get("outcome")
    outcome_known = outcome in SOURCE_CAPTURE_V02_OUTCOME_VALUES
    if not outcome_known:
        errors.append("INVALID_OUTCOME")

    # captured_bytes_ref: a sha256:<hex> digest exactly when outcome is success,
    # JSON null for every other outcome. Both directions enforced (manifest s8).
    cbr = receipt.get("captured_bytes_ref")
    if outcome == "success":
        if not (isinstance(cbr, str) and SHA256_REF_RE.fullmatch(cbr)):
            errors.append("CAPTURED_BYTES_REF_OUTCOME_MISMATCH")
    elif outcome_known and cbr is not None:
        errors.append("CAPTURED_BYTES_REF_OUTCOME_MISMATCH")

    # declared_url: JSON null exactly when outcome is no_url_declared, a
    # non-empty string otherwise. Both directions enforced (manifest s5).
    declared_url = receipt.get("declared_url")
    if outcome == "no_url_declared":
        if declared_url is not None:
            errors.append("DECLARED_URL_OUTCOME_MISMATCH")
    elif outcome_known and not (
        isinstance(declared_url, str) and declared_url
    ):
        errors.append("DECLARED_URL_OUTCOME_MISMATCH")

    covered = set(receipt.get("artifact_classes_covered") or [])
    if not SOURCE_CAPTURE_V02_REQUIRED_COVERED.issubset(covered):
        errors.append("MISSING_REQUIRED_ARTIFACT_CLASS")
    excluded = set(receipt.get("artifact_classes_excluded") or [])
    if not SOURCE_CAPTURE_V02_REQUIRED_EXCLUDED.issubset(excluded):
        errors.append("MISSING_REQUIRED_ARTIFACT_CLASS")

    limitations = receipt.get("machine_limitations")
    present_codes = (
        {item.get("code") for item in limitations if isinstance(item, dict)}
        if isinstance(limitations, list)
        else set()
    )
    for code in sorted(
        SOURCE_CAPTURE_V02_REQUIRED_LIMITATION_CODES - present_codes
    ):
        errors.append(f"MISSING_LIMITATION_CODE:{code}")

    limits = receipt.get("attestation_limits")
    limit_values = set(limits) if isinstance(limits, list) else set()
    if SOURCE_CAPTURE_V02_BASE_ATTESTATION_LIMIT not in limit_values:
        errors.append("MISSING_ATTESTATION_LIMIT")

    return list(dict.fromkeys(errors))


# --- srs.editorial.source_ingest.v0.1 ----------------------------------------
#
# Provisional source-ingest stage (arcs-srs 1f8768d). Expectation values are
# transcribed from the vendored, byte-pinned profile manifest at
# vendor/arcs-srs/vectors/editorial-source-ingest-v0.1/profile.manifest.json
# (document_sha256
# 0454e96ea67c5f415c57ea9b7ca624165366ea0b80914bdb6be77448bdf56b98); the pin
# test asserts these constants against those bytes. The receipt attests a
# deterministic derivation of exact captured source bytes under a pinned parser;
# it references a capture observation (never re-attesting capture), asserts no
# source truth / claim support / admission, and carries no raw content.

SOURCE_INGEST_V01_FIXED_VALUES = {
    "receipt_version": "srs.core.v5.1",
    "profile_id": "srs.editorial.source_ingest",
    "receipt_type": "provenance",
    "boundary_type": "editorial_corpus_boundary",
}

SOURCE_INGEST_V01_REQUIRED_FIELDS = (
    "receipt_version",
    "profile_id",
    "profile_version",
    "receipt_id",
    "receipt_type",
    "receipt_kind",
    "boundary_type",
    "protocol_binding",
    "subject_ref",
    "issuer_id",
    "runtime_instance_id",
    "boundary_id",
    "issued_at",
    "source_artifact_id",
    "capture_observation_ref",
    "parser_identity",
    "pdo_module_identity",
    "derivation",
    "pdo_ref",
    "extraction_ref",
    "artifact_classes_covered",
    "artifact_classes_excluded",
    "attestation_limits",
    "extensions",
)

SOURCE_INGEST_V01_REQUIRED_COVERED = frozenset([
    "source_artifact_digest",
    "parser_identity",
    "derivation_chain",
])

SOURCE_INGEST_V01_REQUIRED_EXCLUDED = frozenset([
    "raw_source_content",
    "raw_extracted_text",
])

SOURCE_INGEST_V01_REQUIRED_LIMITATION_CODES = frozenset([
    "SOURCE_TRUTH_NOT_EVALUATED",
    "EVIDENCE_COMPLETENESS_NOT_EVALUATED",
    "CLAIM_SUPPORT_NOT_EVALUATED",
    "CONTENT_NOT_VERIFIED",
])

SOURCE_INGEST_V01_BASE_ATTESTATION_LIMIT = (
    "The receipt declares a deterministic ingest/derivation of exact captured "
    "source bytes under the named parser. It does not establish that the "
    "source content is authentic, that the source is the one a declaration "
    "intended, that the source supports any claim, or that any article or "
    "publication is true. It evaluates neither evidence completeness nor claim "
    "support, and confers no admission or standing."
)

# Capture-only fields: their presence at top level would re-attest capture,
# which s4 forbids — an ingest receipt references a capture observation and
# never restates its outcome or locator.
SOURCE_INGEST_V01_CAPTURE_ONLY_FIELDS = (
    "outcome",
    "declared_url",
    "captured_bytes_ref",
    "capturer_identity",
    "source_reference_id",
)


def _editorial_source_ingest_v01_profile_errors(
    receipt: dict[str, Any],
) -> list[str]:
    """Profile errors for srs.editorial.source_ingest.v0.1 (provisional).

    Binds a deterministic derivation to the exact captured source bytes:
    ``subject_ref == source_artifact_id``, ``derivation.input_hash ==
    source_artifact_id``, ``extraction_ref == derivation.output_hash``, and
    ``derivation.parser_id == parser_identity`` (manifest s3/s7). The historical
    ``pdo_module_identity`` is carried verbatim from the PDO bytes and is NOT
    reconciled to the executing distribution; the optional
    ``ingest_implementation`` is validated only for shape when present and MAY be
    omitted. The receipt references a capture observation and never re-attests
    it. The verifier recomputes structure and the declared digests' internal
    consistency only; it does not re-run the parser or establish source truth.
    """
    errors: list[str] = []

    for field, expected in SOURCE_INGEST_V01_FIXED_VALUES.items():
        if receipt.get(field) != expected:
            errors.append("FIXED_VALUE_MISMATCH")
    if receipt.get("profile_version") != "v0.1":
        errors.append("PROFILE_VERSION_MISMATCH")
    if receipt.get("receipt_kind") != "source_ingest":
        errors.append("INVALID_RECEIPT_KIND")

    for field in SOURCE_INGEST_V01_REQUIRED_FIELDS:
        if field not in receipt:
            errors.append("MISSING_PROFILE_FIELD")

    # Subject identity: subject_ref MUST equal source_artifact_id, the sha256 of
    # the exact captured source bytes (s3). A staging filename is never identity.
    source_artifact_id = receipt.get("source_artifact_id")
    if isinstance(source_artifact_id, str):
        if not SHA256_REF_RE.fullmatch(source_artifact_id):
            errors.append("INVALID_SOURCE_ARTIFACT_ID")
        if receipt.get("subject_ref") != source_artifact_id:
            errors.append("SUBJECT_BINDING_MISMATCH")

    # Parser identity binding (s5/s7): parser_identity is the stamped parser and
    # derivation.parser_id MUST equal it.
    parser_identity = receipt.get("parser_identity")
    if not (isinstance(parser_identity, str) and parser_identity):
        errors.append("PARSER_IDENTITY_INVALID")

    # Derivation: bind the deterministic derivation by digest (s7).
    derivation = receipt.get("derivation")
    if not isinstance(derivation, dict):
        errors.append("DERIVATION_INVALID")
        derivation = {}

    input_hash = derivation.get("input_hash")
    if (
        isinstance(source_artifact_id, str)
        and input_hash != source_artifact_id
    ):
        errors.append("DERIVATION_INPUT_MISMATCH")

    derivation_parser_id = derivation.get("parser_id")
    if (
        isinstance(parser_identity, str)
        and derivation_parser_id != parser_identity
    ):
        errors.append("PARSER_IDENTITY_MISMATCH")

    output_hash = derivation.get("output_hash")
    extraction_ref = receipt.get("extraction_ref")
    if extraction_ref != output_hash:
        errors.append("EXTRACTION_REF_MISMATCH")

    # pdo_ref MUST be the sha256:<hex> of the exact emitted PDO artifact (s7).
    pdo_ref = receipt.get("pdo_ref")
    if pdo_ref is not None and not (
        isinstance(pdo_ref, str) and SHA256_REF_RE.fullmatch(pdo_ref)
    ):
        errors.append("PDO_REF_DIGEST_INVALID")

    # Historical module identity (s5): {module_id, module_version} carried
    # verbatim from the PDO bytes. Validated for shape only; NEVER reconciled to
    # the executing distribution.
    pdo_module_identity = receipt.get("pdo_module_identity")
    if pdo_module_identity is not None and not (
        isinstance(pdo_module_identity, dict)
        and isinstance(pdo_module_identity.get("module_id"), str)
        and pdo_module_identity.get("module_id")
        and isinstance(pdo_module_identity.get("module_version"), str)
        and pdo_module_identity.get("module_version")
    ):
        errors.append("PDO_MODULE_IDENTITY_INVALID")

    # Optional ingest_implementation (s6): substantiated-or-omitted. When
    # present it MUST be {distribution, version, revision}; it is never derived
    # from pdo_module_identity and a valid receipt MAY omit it entirely.
    if "ingest_implementation" in receipt:
        impl = receipt.get("ingest_implementation")
        if not (
            isinstance(impl, dict)
            and all(
                isinstance(impl.get(k), str) and impl.get(k)
                for k in ("distribution", "version", "revision")
            )
        ):
            errors.append("INGEST_IMPLEMENTATION_INVALID")

    # Capture linkage (s4): reference the capture observation, never re-attest
    # it. capture_observation_ref MUST be a non-empty reference, and capture-only
    # fields (outcome / locator / captured bytes / capturer) MUST NOT be restated.
    capture_observation_ref = receipt.get("capture_observation_ref")
    if not (
        isinstance(capture_observation_ref, str) and capture_observation_ref
    ):
        errors.append("CAPTURE_OBSERVATION_REF_INVALID")
    if any(
        field in receipt for field in SOURCE_INGEST_V01_CAPTURE_ONLY_FIELDS
    ):
        errors.append("CAPTURE_OBSERVATION_RESTATED")

    covered = set(receipt.get("artifact_classes_covered") or [])
    if not SOURCE_INGEST_V01_REQUIRED_COVERED.issubset(covered):
        errors.append("MISSING_REQUIRED_ARTIFACT_CLASS")
    excluded = set(receipt.get("artifact_classes_excluded") or [])
    if not SOURCE_INGEST_V01_REQUIRED_EXCLUDED.issubset(excluded):
        errors.append("MISSING_REQUIRED_ARTIFACT_CLASS")

    limitations = receipt.get("machine_limitations")
    present_codes = (
        {item.get("code") for item in limitations if isinstance(item, dict)}
        if isinstance(limitations, list)
        else set()
    )
    for code in sorted(
        SOURCE_INGEST_V01_REQUIRED_LIMITATION_CODES - present_codes
    ):
        errors.append(f"MISSING_LIMITATION_CODE:{code}")

    limits = receipt.get("attestation_limits")
    limit_values = set(limits) if isinstance(limits, list) else set()
    if SOURCE_INGEST_V01_BASE_ATTESTATION_LIMIT not in limit_values:
        errors.append("MISSING_ATTESTATION_LIMIT")

    return list(dict.fromkeys(errors))


# --- srs.activity.governed_read.v0.1 -----------------------------------------
#
# Field-level profile for one governed read against a pinned basis. The
# authoritative field contract is the arcs-srs field schema, sourced here the
# same way the SRS envelope schema is: a byte-identical runtime copy under
# arcs_verify/data/ (shipped as package data), with a provenance copy under
# vendor/arcs-srs/ and the sha256 pinned below. The verifier loads that schema,
# re-derives structural conformance from it against serialized receipt bytes,
# and maps schema violations onto this profile's named failure codes. It trusts
# no issuer claim: the disposition of a receipt is recomputed from the schema
# and the closed-set rules, never read from an emitter assertion.
#
# The schema encodes almost every closed-set rule structurally (fixed values,
# the C8 visibility enum, the sha256 digest format, the C6 no-aggregate
# denylist, required fields, and the admitted/refused disposition coherence).
# The one rule the schema states only as a $comment — subject_ref MUST equal
# basis_version_ref — is re-derived here as an explicit check so the binding is
# actually enforced rather than merely documented.
_ACTIVITY_GOVERNED_READ_SCHEMA_PATH = (
    Path(__file__).resolve().parent
    / "data"
    / "srs.activity.governed_read.v0.1.schema.json"
)

# sha256 of the arcs-srs field schema bytes (arcs-srs PR #34 head 47c95f8).
# The runtime copy is verified against this pin on load, so a drifted or
# substituted schema is a hard error rather than a silent re-interpretation.
ACTIVITY_GOVERNED_READ_SCHEMA_SHA256 = (
    "7b89ebe13cd87b3ac456077fa80f40914e6129a3d78a9e6dd87d6963fda29f19"
)

# Mandatory C8 closed-set visibility posture (ACT0 s3).
GOVERNED_READ_C8_VISIBILITY = frozenset(
    {"LOCAL", "PRIVATE_ORG", "SHARED", "PUBLIC_CANDIDATE", "PUBLIC"}
)

# Typed refusal classes (recorded, not adjudicated).
GOVERNED_READ_REFUSAL_CLASSES = frozenset(
    {
        "POLICY_REFUSED",
        "PRINCIPAL_NOT_PERMITTED",
        "SCOPE_EXCEEDED",
        "BASIS_UNAVAILABLE",
        "DEFERRED_FOR_REVIEW",
    }
)

_GOVERNED_READ_SCHEMA_CACHE: dict[str, Any] | None = None


def _load_governed_read_schema() -> dict[str, Any]:
    """Load and pin the arcs-srs governed_read field schema.

    Raises ValueError if the vendored runtime copy does not match the pinned
    digest, so the verifier never validates against a schema it cannot vouch
    for. Cached after first successful load.
    """

    global _GOVERNED_READ_SCHEMA_CACHE

    if _GOVERNED_READ_SCHEMA_CACHE is None:
        schema_bytes = _ACTIVITY_GOVERNED_READ_SCHEMA_PATH.read_bytes()
        digest = hashlib.sha256(schema_bytes).hexdigest()

        if digest != ACTIVITY_GOVERNED_READ_SCHEMA_SHA256:
            raise ValueError(
                "governed_read field schema digest mismatch: "
                f"{digest} != {ACTIVITY_GOVERNED_READ_SCHEMA_SHA256}"
            )

        _GOVERNED_READ_SCHEMA_CACHE = json.loads(schema_bytes)

    return _GOVERNED_READ_SCHEMA_CACHE


def _map_governed_read_schema_error(error: Any) -> str:
    """Map one jsonschema validation error to a named profile failure code.

    Keyed on the failing keyword and its position in the schema so that the two
    root-level ``not`` schemas (C6 no-aggregate vs. the disposition-coherence
    ``then.not``) resolve to distinct codes rather than collide.
    """

    keyword = error.validator
    instance_path = list(error.path)
    schema_path = list(error.schema_path)
    field = instance_path[-1] if instance_path else None

    if keyword == "required":
        return "MISSING_PROFILE_FIELD"

    if keyword == "enum":
        if field == "visibility":
            return "INVALID_VISIBILITY"
        if field == "refusal_class":
            return "governed_read.invalid_refusal_class"
        if field == "read_disposition":
            return "governed_read.invalid_read_disposition"
        return "governed_read.invalid_enum_value"

    if keyword == "pattern":
        # Every ``pattern`` in the field schema is the sha256_ref format.
        return "INVALID_DIGEST_FORMAT"

    if keyword == "const":
        return "governed_read.invalid_fixed_value"

    if keyword == "not":
        # The single root-level ``not`` is the C6 no-aggregate denylist; a
        # ``not`` nested under allOf/then is the disposition-coherence guard.
        if schema_path == ["not"]:
            return "AGGREGATE_FIELD_PRESENT"
        return "governed_read.disposition_field_conflict"

    if keyword == "contains":
        return "governed_read.missing_required_artifact_class"

    return "governed_read.field_schema_invalid"


def _activity_governed_read_profile_errors(
    receipt: dict[str, Any],
) -> list[str]:
    """Profile checks for srs.activity.governed_read.v0.1 receipts.

    Records one governed read against a pinned basis: a declared acting
    principal, a mandatory C8 visibility posture, an identity-bound basis
    version, and an admitted-or-refused disposition. Content is never carried;
    every digest is a ``sha256:`` reference and no aggregate/trust/reputation/
    standing field may appear (C6 no-aggregate).

    Conformance is re-derived from the pinned arcs-srs field schema plus the
    subject-binding rule the schema states only as a comment. No emitter claim
    is trusted.
    """

    errors: list[str] = []

    schema = _load_governed_read_schema()
    validator = Draft202012Validator(schema)

    for error in sorted(
        validator.iter_errors(receipt),
        key=lambda err: list(err.path),
    ):
        errors.append(_map_governed_read_schema_error(error))

    # subject_ref MUST equal basis_version_ref (subject binding). The field
    # schema requires both to be present but expresses their equality only as a
    # $comment, so it is enforced here explicitly. Checked only when both are
    # present strings; absence is already a MISSING_PROFILE_FIELD above.
    subject_ref = receipt.get("subject_ref")
    basis_version_ref = receipt.get("basis_version_ref")

    if (
        isinstance(subject_ref, str)
        and isinstance(basis_version_ref, str)
        and subject_ref != basis_version_ref
    ):
        errors.append("governed_read.subject_binding_mismatch")

    return list(dict.fromkeys(errors))


CITATION_PACK_REQUIRED_COVERED = frozenset([
    "publication_artifact_identity",
    "declaration_manifest_digest",
    "pack_integrity_digest",
])

CITATION_PACK_REQUIRED_EXCLUDED = frozenset([
    "raw_publication_bytes",
    "raw_captured_bytes",
])

CITATION_PACK_REQUIRED_LIMITATION_CODES = frozenset([
    "ARTICLE_TRUTH_NOT_EVALUATED",
    "EVIDENCE_COMPLETENESS_NOT_EVALUATED",
    "CITATION_MAPPING_MACHINE_PROPOSED",
])

CITATION_PACK_BASE_ATTESTATION_LIMIT = (
    "The receipt declares that a citation pack was assembled for the named "
    "editorial publication artifact. It does not establish article truth, "
    "evidence completeness, source authenticity, or that any citation mapping "
    "is correct. Machine-proposed mappings require operator admission before "
    "use."
)


def _editorial_citation_pack_profile_errors(
    receipt: dict[str, Any],
) -> list[str]:
    """Profile checks for provisional srs.editorial.citation_pack.v0.1 receipts.

    A citation pack is a single ``pack_assembly`` provenance receipt for one
    editorial publication artifact. This is a SINGLE-RECEIPT STRUCTURAL verifier:
    it validates the fixed identity fields, the FORM of the digest references the
    receipt carries, the subject binding, the required covered/excluded artifact
    classes, the required machine-limitation codes, and the base attestation
    limit.

    It deliberately does NOT recompute publication_artifact_id, pack_integrity_ref,
    or declaration_manifest_ref from referenced bytes: the receipt is
    metadata-only (raw bytes are an excluded class) and supplies no referenced
    object bytes or byte-count contract to recompute against. Cross-receipt
    consistency (declaration_manifest_ref against an ingest receipt), the
    repository-snapshot mixing rule, and the protocol_binding "MUST NOT embed
    file system paths or deployment credentials" rule are NON-ENFORCED (no
    lexical rule / deterministic detector); only non-empty/non-whitespace
    protocol_binding is checked. The profile is PROVISIONAL: a PASS attests
    structural conformance to the provisional contract only (see
    PROVISIONAL_PROFILE_DETAILS).

    Fail-closed: the checker never raises on a malformed field type — malformed
    container/member values yield deterministic failure codes, not exceptions.
    """
    errors: list[str] = []

    if receipt.get("profile_id") != "srs.editorial.citation_pack":
        errors.append("citation_pack.invalid_profile_id")
    if receipt.get("profile_version") != "v0.1":
        errors.append("citation_pack.invalid_profile_version")
    if receipt.get("receipt_type") != "provenance":
        errors.append("citation_pack.invalid_receipt_type")
    if receipt.get("receipt_kind") != "pack_assembly":
        errors.append("citation_pack.invalid_receipt_kind")
    if receipt.get("boundary_type") != "editorial_corpus_boundary":
        errors.append("citation_pack.invalid_boundary_type")

    # protocol_binding MUST identify the assembly pipeline and MUST NOT be empty
    # (profile §2). Only the non-empty/non-whitespace rule is deterministically
    # enforceable here; the profile's "MUST NOT embed file system paths or
    # deployment credentials" rule has no lexical definition in arcs-srs and no
    # repo-wide deterministic detector exists, so that portion is NON-ENFORCED
    # (see the profile section in docs/FAILURE_CODES.md).
    protocol_binding = receipt.get("protocol_binding")
    if not (isinstance(protocol_binding, str) and protocol_binding.strip()):
        errors.append("citation_pack.invalid_protocol_binding")

    # Digest-reference FORM only (sha256:<64 hex>). No referenced bytes are
    # supplied, so the referenced objects themselves are never recomputed here.
    pub_id = receipt.get("publication_artifact_id")
    if not (isinstance(pub_id, str) and SHA256_REF_RE.fullmatch(pub_id)):
        errors.append("citation_pack.invalid_publication_artifact_id_digest")
    pack_integrity_ref = receipt.get("pack_integrity_ref")
    if not (
        isinstance(pack_integrity_ref, str)
        and SHA256_REF_RE.fullmatch(pack_integrity_ref)
    ):
        errors.append("citation_pack.invalid_pack_integrity_digest")
    declaration_manifest_ref = receipt.get("declaration_manifest_ref")
    if not (
        isinstance(declaration_manifest_ref, str)
        and SHA256_REF_RE.fullmatch(declaration_manifest_ref)
    ):
        errors.append("citation_pack.invalid_declaration_manifest_digest")

    # capture_manifest_ref is optional (SHOULD-level presence; NOT required). If
    # present and non-null it MUST be a sha256:<64 hex> digest (profile §5).
    capture_manifest_ref = receipt.get("capture_manifest_ref")
    if capture_manifest_ref is not None and not (
        isinstance(capture_manifest_ref, str)
        and SHA256_REF_RE.fullmatch(capture_manifest_ref)
    ):
        errors.append("citation_pack.invalid_capture_manifest_digest")

    # subject_ref MUST equal publication_artifact_id (profile §2 binding).
    if receipt.get("subject_ref") != pub_id:
        errors.append("citation_pack.subject_binding_mismatch")

    # Fail-closed: verify_receipt runs profile checks even after envelope
    # validation fails, so a malformed member (e.g. a dict inside a list) must
    # produce a deterministic failure code, never a TypeError. Only str members
    # are considered; malformed values collapse to the empty set and fail the
    # required-membership checks below.
    covered_value = receipt.get("artifact_classes_covered")
    covered = (
        {c for c in covered_value if isinstance(c, str)}
        if isinstance(covered_value, list)
        else set()
    )
    if not CITATION_PACK_REQUIRED_COVERED.issubset(covered):
        errors.append("citation_pack.missing_required_covered_classes")

    excluded_value = receipt.get("artifact_classes_excluded")
    excluded = (
        {c for c in excluded_value if isinstance(c, str)}
        if isinstance(excluded_value, list)
        else set()
    )
    if not CITATION_PACK_REQUIRED_EXCLUDED.issubset(excluded):
        errors.append("citation_pack.missing_required_excluded_classes")

    limitations = receipt.get("machine_limitations")
    present_codes = (
        {item.get("code") for item in limitations if isinstance(item, dict)}
        if isinstance(limitations, list)
        else set()
    )
    for code in sorted(CITATION_PACK_REQUIRED_LIMITATION_CODES - present_codes):
        errors.append(f"citation_pack.missing_required_limitation_code:{code}")

    limits = receipt.get("attestation_limits")
    limit_values = (
        {x for x in limits if isinstance(x, str)}
        if isinstance(limits, list)
        else set()
    )
    if CITATION_PACK_BASE_ATTESTATION_LIMIT not in limit_values:
        errors.append("citation_pack.missing_base_attestation_limit")

    return errors


def _profile_errors(
    receipt: dict[str, Any],
    selected_profile: str,
) -> list[str]:
    if selected_profile == MCP_PROFILE:
        return _mcp_profile_errors(receipt)

    if selected_profile == CONNECTION_PROFILE:
        return _connection_profile_errors(receipt)

    if selected_profile == BROADCAST_CONTROL_PROFILE:
        return _broadcast_control_profile_errors(receipt)

    if selected_profile == DEFERRED_OPERATION_PROFILE:
        return _deferred_operation_profile_errors(receipt)

    if selected_profile == EDITORIAL_PUBLICATION_INGEST_PROFILE:
        return _editorial_publication_ingest_profile_errors(receipt)

    if selected_profile == EDITORIAL_SOURCE_CAPTURE_PROFILE:
        return _editorial_source_capture_profile_errors(receipt)

    if selected_profile == EDITORIAL_SOURCE_CAPTURE_PROFILE_V011:
        return _editorial_source_capture_v011_profile_errors(receipt)

    if selected_profile == EDITORIAL_SOURCE_CAPTURE_PROFILE_V02:
        return _editorial_source_capture_v02_profile_errors(receipt)

    if selected_profile == EDITORIAL_SOURCE_INGEST_PROFILE:
        return _editorial_source_ingest_v01_profile_errors(receipt)

    if selected_profile == ACTIVITY_GOVERNED_READ_PROFILE:
        return _activity_governed_read_profile_errors(receipt)

    if selected_profile == EDITORIAL_CITATION_PACK_PROFILE:
        return _editorial_citation_pack_profile_errors(receipt)

    return ["profile.unsupported_selection"]


def verify_receipt(
    receipt: dict[str, Any],
    keyring: dict[str, Any],
    *,
    schema_path: Path,
    selected_profile: str | None = None,
) -> VerificationReport:
    report = VerificationReport()
    selected = selected_profile or MCP_PROFILE

    schema_bytes = schema_path.read_bytes()
    report.schema_digest = (
        hashlib.sha256(schema_bytes).hexdigest()
        in ACCEPTED_SCHEMA_SHA256
    )

    if not report.schema_digest:
        report.failure_codes.append("schema.digest_mismatch")

    # --- Self-identifying contract (VR0) -- descriptive, never a verdict axis.
    report.report_contract = REPORT_CONTRACT_V0_1
    report.selected_profile = selected
    _selected_meta = PROFILE_REGISTRY.get(selected)
    report.selected_profile_release_stage = (
        _selected_meta.release_stage if _selected_meta is not None else None
    )
    _rid = receipt.get("receipt_id")
    report.verified_receipt_id = _rid if isinstance(_rid, str) else None
    _rver = receipt.get("receipt_version")
    report.verified_receipt_version = _rver if isinstance(_rver, str) else None
    _rpid = receipt.get("profile_id")
    report.verified_receipt_profile_id = _rpid if isinstance(_rpid, str) else None
    _rpver = receipt.get("profile_version")
    report.verified_receipt_profile_version = _rpver if isinstance(_rpver, str) else None
    try:
        _canonical = rfc8785.dumps(receipt)
        report.verified_receipt_canonical_json_sha256 = (
            "sha256:" + hashlib.sha256(_canonical).hexdigest()
        )
    except Exception:
        # Canonical JSON is best-effort identity metadata; its absence never
        # changes any verdict axis.
        report.verified_receipt_canonical_json_sha256 = None
    _schema_sha = hashlib.sha256(schema_bytes).hexdigest()
    _published = next(
        (version for version, digest in ENVELOPE_SCHEMA_PINS.items() if digest == _schema_sha),
        None,
    )
    report.envelope_schema_identity = {
        "published_version": _published,  # None if the digest maps to no pinned version
        "sha256": "sha256:" + _schema_sha,
    }

    schema = json.loads(schema_bytes)
    schema_errors = sorted(
        Draft202012Validator(schema).iter_errors(receipt),
        key=lambda error: list(error.path),
    )

    report.envelope = not schema_errors

    for error in schema_errors:
        report.failure_codes.append("envelope.schema_invalid")
        report.details.append(error.message)

    profile_errors = _profile_errors(receipt, selected)
    report.profile = not profile_errors
    report.failure_codes.extend(profile_errors)

    provisional_detail = PROVISIONAL_PROFILE_DETAILS.get(selected)
    if provisional_detail is not None:
        report.details.append(provisional_detail)

    raw_errors: list[str] = []

    for key, value in _walk(receipt):
        if key is not None:
            failure = _raw_content_failure(key, value)
            if failure is not None:
                raw_errors.append(failure)

        if (
            isinstance(value, str)
            and _contains_prohibited_value(value)
        ):
            raw_errors.append("raw_content.prohibited_value")

    report.raw_content_exclusion = not raw_errors
    report.failure_codes.extend(raw_errors)

    limits = receipt.get("attestation_limits")
    report.attestation_limits_present = (
        isinstance(limits, list)
        and bool(limits)
        and all(
            isinstance(item, str) and item.strip()
            for item in limits
        )
    )

    if not report.attestation_limits_present:
        report.failure_codes.append(
            "attestation.missing_or_empty"
        )

    signature = receipt.get("receipt_signature")

    if isinstance(signature, str):
        report.failure_codes.append("legacy_unverified")
        return _dedupe(report)

    if (
        not isinstance(signature, dict)
        or set(signature) != SIGNATURE_MEMBERS
        or signature.get("algorithm") != "Ed25519"
        or signature.get("canonicalization") != "RFC8785-JCS"
    ):
        report.failure_codes.append("signature_object_invalid")
        return _dedupe(report)

    key_id = signature.get("key_id")
    entries = (
        keyring.get("issuers", [])
        if isinstance(keyring, dict)
        else []
    )
    entry = next(
        (
            item
            for item in entries
            if isinstance(item, dict)
            and item.get("key_id") == key_id
        ),
        None,
    )

    report.issuer_key_resolved = entry is not None

    if entry is None:
        report.failure_codes.append("key_id_unresolved")
        return _dedupe(report)

    try:
        public_key_bytes = _b64url_decode(
            entry.get("public_key"),
            code="public_key_encoding_invalid",
        )
        signature_bytes = _b64url_decode(
            signature.get("signature"),
            code="signature_encoding_invalid",
        )

        if len(public_key_bytes) != 32:
            raise ValueError("public_key_encoding_invalid")

        if len(signature_bytes) != 64:
            raise ValueError("signature_encoding_invalid")

    except ValueError as exc:
        report.failure_codes.append(str(exc))
        return _dedupe(report)

    preimage = copy.deepcopy(receipt)
    del preimage["receipt_signature"]["signature"]

    try:
        canonical = rfc8785.dumps(preimage)
    except Exception:
        report.failure_codes.append(
            "preimage_canonicalization_failed"
        )
        return _dedupe(report)

    try:
        Ed25519PublicKey.from_public_bytes(
            public_key_bytes
        ).verify(
            signature_bytes,
            canonical,
        )
        report.signature_valid = True
    except InvalidSignature:
        report.failure_codes.append("signature_invalid")

    identity = PROFILE_IDENTITIES.get(selected)

    if (
        identity is None
        or receipt.get("receipt_version") != RECEIPT_VERSION
        or receipt.get("profile_id") != identity[0]
        or receipt.get("profile_version") != identity[1]
    ):
        report.failure_codes.append("version_binding_mismatch")
        report.signature_valid = False

    try:
        issued_at = _parse_time(receipt["issued_at"])
        trusted = (
            entry.get("trusted") is True
            and entry.get("issuer_id")
            == receipt.get("issuer_id")
        )
        trusted = (
            trusted
            and _parse_time(entry["not_before"])
            <= issued_at
            <= _parse_time(entry["not_after"])
        )
    except Exception:
        trusted = False

    report.issuer_key_trusted = bool(trusted)

    if not report.issuer_key_trusted:
        report.failure_codes.append("key_untrusted")

    return _dedupe(report)


def _dedupe(
    report: VerificationReport,
) -> VerificationReport:
    report.failure_codes = list(
        dict.fromkeys(report.failure_codes)
    )
    report.details = list(dict.fromkeys(report.details))
    return report
