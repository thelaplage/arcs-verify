"""Independent verifier for the EXIT-O semantic-issuer origin-authentication proof.

Consumes a serialized ``srs.activity.semantic_issuer_origin_authentication.v0.1``
receipt (the producer-side proof artifact landed in arcs-srs #68) plus the
evidence bytes it references, and recomputes findings from those bytes and the
pinned profile authority alone. It imports no producer code (issuer/verifier
separation is inviolate) and trusts no producer posture.

Design rules (from PUBLIC-REFUSAL-EXIT-O-BINDING0 / owner authorization
5282467938):

  * This verifier gets its OWN report contract. It does not touch, extend, or
    reuse ``arcs_verify.verifier.VerificationReport`` or its ``chain_status``
    field — ``chain_status`` already means ``not_applicable`` for the
    standalone-SRS path and participates in that path's pass semantics.

  * The four EXIT-O evidence layers are reported independently. A producer
    posture is NEVER accepted as a verifier finding.

  * ``artifact bytes present != digest matches != semantic layer verified``.
    Byte presence and digest form/equality are structural facts this verifier
    can recompute. Substantive semantic verification of a layer requires a
    governed verifier contract for that upstream evidence type; where none
    exists yet, the finding is ``not_evaluated`` (or ``unavailable`` when the
    evidence itself was not supplied) — it is NEVER upgraded to ``pass`` on the
    strength of byte integrity or a producer posture.

  * Any overall EXIT-O result succeeds only when every REQUIRED substantive
    finding is ``pass``. ``fail`` / ``not_evaluated`` / ``unavailable`` fail
    closed. In the current world (no governed upstream evidence verifiers, no
    provisioned key) a well-formed, correctly-bound proof therefore yields
    ``exit_o_chain_satisfied = False`` — the verifier refuses correctly before a
    real producer or signing key exists.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from datetime import datetime
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_public_key,
)

# Substantive finding domain. Reuse the single-sourced verdict tokens where they
# already exist; add the EXIT-O-specific "unavailable".
from arcs_verify.verdict_discipline import (
    VERDICT_NOT_EVALUATED,
    VERDICT_PASS,
)

VERDICT_FAIL: str = "fail"
VERDICT_UNAVAILABLE: str = "unavailable"
"""The referenced evidence bytes for a layer were not supplied to the verifier.
Distinct from not_evaluated (evidence present but no governed verifier for it)
and never a pass."""

SUBSTANTIVE_DOMAIN = frozenset(
    {VERDICT_PASS, VERDICT_FAIL, VERDICT_NOT_EVALUATED, VERDICT_UNAVAILABLE}
)

REPORT_CONTRACT = "arcs.verify.exit-o-origin-authentication-report/v0.1"

# --- Pinned upstream proof-contract authority ------------------------------
PROFILE = "srs.activity.semantic_issuer_origin_authentication.v0.1"
PROFILE_ID = "srs.activity.semantic_issuer_origin_authentication"
PROFILE_VERSION = "v0.1"
# arcs-srs commit that landed the profile (#68).
PROFILE_SOURCE_HEAD = "11db54bbb3143c13b0db148efece68b5a2f3766b"
PROFILE_SOURCE_PATH = (
    "schemas/activity-profiles/v0.1/"
    "srs.activity.semantic_issuer_origin_authentication.v0.1.schema.json"
)
# git blob sha1 and raw sha256 of the vendored schema; the two must agree with
# the pinned source or the verifier refuses to run against a drifted schema.
PROFILE_SCHEMA_BLOB_SHA1 = "236643eb4cc229d38266c6e7a5bcfa8291b0aec7"
PROFILE_SCHEMA_SHA256 = (
    "c03733f92e5bb05f4087c8fcc944528f013bf3043940478f6ea7a087da0c5531"
)
# Normative profile document sha256 (manifest-pinned; owner authorization).
PROFILE_DOCUMENT_SHA256 = (
    "85dd6a9b3ae0fb084a6a932f880adb5bbbce3c5924a78954548281e597ad82ea"
)

_VENDORED_SCHEMA_PATH = (
    Path(__file__).resolve().parent
    / "data"
    / "srs.activity.semantic_issuer_origin_authentication.v0.1.schema.json"
)

_SHA256_REF = "sha256:"
_LAYER_KEYS = (
    "key_authentication",
    "act_principal",
    "semantic_authority",
    "semantic_act",
)


def _is_sha256_ref(value: object) -> bool:
    if not isinstance(value, str) or not value.startswith(_SHA256_REF):
        return False
    hexpart = value[len(_SHA256_REF) :]
    return len(hexpart) == 64 and all(c in "0123456789abcdef" for c in hexpart)


def _git_blob_sha1(data: bytes) -> str:
    h = hashlib.sha1()
    h.update(b"blob %d\0" % len(data))
    h.update(data)
    return h.hexdigest()


def _parse_offset_aware_iso8601(value: object) -> datetime | None:
    """Parse an offset-aware ISO-8601 timestamp, accepting terminal Z."""
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed


# --- trust-bundle signature + key-authentication seam -----------------------
#
# Mirrors the Ed25519/RFC8785-JCS receipt-signature verification pattern
# already landed in arcs_verify.verifier (~lines 2310-2379): resolve
# receipt_signature.key_id, delete the signature member from a deep-copied
# preimage, canonicalize with RFC8785-JCS, and verify Ed25519 over the
# canonical bytes. Reimplemented locally (not imported) so this module keeps
# its own report contract and failure-code namespace; the cryptographic
# recipe is identical.
#
# The trust-bundle shape consumed here is the arcs-srs trust-bundle v0.2
# schema (schemas/trust-bundles/v0.2/trust-bundle.schema.json): a
# verifier-selected `{"keys": [...]}` mapping of key entries, each carrying
# `public_key_pem`, `allowed_profiles`, `not_before`/`not_after`, and a
# `revocation` block. This verifier never mints or ships a trust bundle; it
# only recomputes findings from one the caller supplies.

SIGNATURE_MEMBERS = {"algorithm", "canonicalization", "key_id", "signature"}

# Fixed relation constants for the #74 institutional key<->principal binding
# relation (dagr_sdk.institutional_key_binding.AUTHORITY_DOMAIN /
# RELATION_PURPOSE). Mirrored as literal constants, NOT imported: this module
# imports no producer/runtime code (issuer/verifier independence is
# inviolate). If the upstream relation constants are ever renumbered this
# mirror must be updated deliberately, not silently re-derived.
_KEY_BINDING_AUTHORITY_DOMAIN = "institutional_admission"
_KEY_BINDING_RELATION_PURPOSE = "semantic-origin-authentication"

# Domain-separated fingerprint tag, wire spec: "keyfp:sha256:" +
# sha256(domain_tag + raw_public_key_bytes).hexdigest(). Cited from the WIRE0
# spec (dagr_sdk.institutional_key_binding.compute_key_fingerprint); recomputed
# INLINE here over raw Ed25519 public-key bytes derived from the trust-bundle
# entry's PEM via `cryptography` (SPKI -> Encoding.Raw), never imported.
_KEY_BINDING_FINGERPRINT_DOMAIN_TAG = b"dagr.institutional_key_binding.fingerprint.v0.1:"


def _b64url_decode(value: object) -> bytes | None:
    """Strict b64url decode: rejects padding chars and any non-canonical
    re-encoding, mirroring arcs_verify.verifier._b64url_decode."""
    if not isinstance(value, str) or not value or "=" in value:
        return None
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception:
        return None
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value:
        return None
    return decoded


def _load_ed25519_public_key(pem: object) -> Ed25519PublicKey | None:
    if not isinstance(pem, str) or not pem:
        return None
    try:
        key = load_pem_public_key(pem.encode("utf-8"))
    except Exception:
        return None
    if not isinstance(key, Ed25519PublicKey):
        return None
    return key


def _raw_ed25519_public_key_bytes(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def _recompute_key_fingerprint(pem: object) -> str | None:
    """Independently recompute the WIRE0 key fingerprint from a trust-bundle
    entry's PEM public key. Returns None if the PEM does not decode to an
    Ed25519 public key."""
    key = _load_ed25519_public_key(pem)
    if key is None:
        return None
    raw = _raw_ed25519_public_key_bytes(key)
    digest = hashlib.sha256(_KEY_BINDING_FINGERPRINT_DOMAIN_TAG + raw).hexdigest()
    fingerprint = "keyfp:sha256:" + digest
    return fingerprint


def _resolve_trust_bundle_entry(
    trust_bundle: Mapping[str, Any], key_id: object
) -> Mapping[str, Any] | None:
    keys = trust_bundle.get("keys")
    if not isinstance(keys, list):
        return None
    for entry in keys:
        if isinstance(entry, Mapping) and entry.get("key_id") == key_id:
            return entry
    return None


def _key_entry_usability_failure(
    entry: Mapping[str, Any], *, issued_at_dt: datetime | None, profile: str
) -> str | None:
    """Return a failure code if the entry is not usable to authenticate this
    receipt, else None. Fails closed on any malformed/ambiguous entry shape."""
    revocation = entry.get("revocation")
    if not isinstance(revocation, Mapping):
        return "exit_o.trust_bundle_entry_malformed"
    if revocation.get("revoked") is True:
        return "exit_o.signature_key_revoked"
    if revocation.get("compromise") is True:
        return "exit_o.signature_key_compromised"

    if issued_at_dt is None:
        return "exit_o.signature_issued_at_invalid"

    not_before_raw = entry.get("not_before")
    not_after_raw = entry.get("not_after")
    not_before_dt = (
        _parse_offset_aware_iso8601(not_before_raw)
        if not_before_raw is not None
        else None
    )
    if not_before_raw is not None and not_before_dt is None:
        return "exit_o.trust_bundle_entry_malformed"
    not_after_dt = (
        _parse_offset_aware_iso8601(not_after_raw)
        if not_after_raw is not None
        else None
    )
    if not_after_raw is not None and not_after_dt is None:
        return "exit_o.trust_bundle_entry_malformed"

    if not_before_dt is not None and not (not_before_dt <= issued_at_dt):
        return "exit_o.signature_key_outside_validity_window"
    if not_after_dt is not None and not (issued_at_dt < not_after_dt):
        return "exit_o.signature_key_outside_validity_window"

    allowed_profiles = entry.get("allowed_profiles")
    if not isinstance(allowed_profiles, list) or profile not in allowed_profiles:
        return "exit_o.signature_key_profile_not_allowed"

    return None


@dataclass
class ExitOOriginAuthenticationVerificationReport:
    """Independent EXIT-O origin-authentication findings. Its own contract; does
    not reuse or mutate VerificationReport / chain_status."""

    report_contract: str = REPORT_CONTRACT
    profile: str = PROFILE
    profile_source_head: str = PROFILE_SOURCE_HEAD

    # Structural findings the verifier recomputes from bytes + pinned schema.
    profile_schema_pinned: bool = False  # vendored schema matches the pin
    proof_receipt_conformance: bool = False  # validates against pinned schema
    exact_semantic_disposition_binding: bool = False  # semantic_act ref+digest == disposition

    # Substantive findings (SUBSTANTIVE_DOMAIN). Default not_evaluated: a check
    # not run is never a pass.
    proof_receipt_signature: str = VERDICT_NOT_EVALUATED
    key_authentication_finding: str = VERDICT_NOT_EVALUATED
    act_principal_finding: str = VERDICT_NOT_EVALUATED
    semantic_authority_finding: str = VERDICT_NOT_EVALUATED
    semantic_act_finding: str = VERDICT_NOT_EVALUATED
    historical_scope_authorization_finding: str = VERDICT_NOT_EVALUATED
    temporal_consistency_finding: str = VERDICT_NOT_EVALUATED

    # Overall. True only if every required substantive finding is pass.
    exit_o_chain_satisfied: bool = False

    failure_codes: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["profile_schema_sha256"] = PROFILE_SCHEMA_SHA256
        data["profile_document_sha256"] = PROFILE_DOCUMENT_SHA256
        return data


# Required substantive findings for an overall EXIT-O pass. All four layers plus
# the signature, the historical-scope authorization, and temporal consistency.
_REQUIRED_SUBSTANTIVE = (
    "proof_receipt_signature",
    "key_authentication_finding",
    "act_principal_finding",
    "semantic_authority_finding",
    "semantic_act_finding",
    "historical_scope_authorization_finding",
    "temporal_consistency_finding",
)


def _compute_exit_o_chain_satisfied(
    report: ExitOOriginAuthenticationVerificationReport,
) -> bool:
    """Fail closed across BOTH structural and substantive prerequisites."""
    structural_ok = (
        report.profile_schema_pinned
        and report.proof_receipt_conformance
        and report.exact_semantic_disposition_binding
    )
    substantive_ok = all(
        getattr(report, name) == VERDICT_PASS for name in _REQUIRED_SUBSTANTIVE
    )
    return structural_ok and substantive_ok


def _load_pinned_schema(report: ExitOOriginAuthenticationVerificationReport) -> dict[str, Any] | None:
    try:
        raw = _VENDORED_SCHEMA_PATH.read_bytes()
    except OSError:
        report.failure_codes.append("exit_o.profile_schema_unreadable")
        return None
    if (
        _git_blob_sha1(raw) != PROFILE_SCHEMA_BLOB_SHA1
        or hashlib.sha256(raw).hexdigest() != PROFILE_SCHEMA_SHA256
    ):
        report.failure_codes.append("exit_o.profile_schema_pin_mismatch")
        return None
    report.profile_schema_pinned = True
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        report.failure_codes.append("exit_o.profile_schema_invalid")
        return None


def verify_exit_o_origin_authentication_receipt(
    receipt: Mapping[str, Any],
    *,
    supplied_evidence_bytes: Mapping[str, bytes] | None = None,
    trust_bundle: Mapping[str, Any] | None = None,
    key_principal_binding: Mapping[str, Any] | None = None,
    genesis_evidence: Mapping[str, Any] | None = None,
) -> ExitOOriginAuthenticationVerificationReport:
    """Recompute EXIT-O origin-authentication findings from receipt bytes.

    ``supplied_evidence_bytes`` maps a layer key to the literal evidence bytes
    handed to the verifier for that layer. The verifier recomputes sha256 itself;
    it never accepts a caller-asserted evidence digest as proof of integrity.
    Absence of a layer's entry makes that layer's substantive finding
    ``unavailable`` (evidence not supplied), never a pass. Even when evidence
    IS supplied and its independently recomputed digest matches, the substantive
    finding stays ``not_evaluated`` until a governed verifier contract for that
    upstream evidence type exists — digest match is integrity, not semantic
    authentication.

    ``trust_bundle`` is a verifier-selected arcs-srs trust-bundle v0.2 mapping
    (``{"keys": [...]}"``). When supplied, ``proof_receipt_signature`` is
    recomputed: the receipt's ``receipt_signature.key_id`` is resolved to a
    trust-bundle entry, the entry must be usable (not revoked/compromised,
    ``issued_at`` inside ``[not_before, not_after)``, profile in
    ``allowed_profiles``), and the Ed25519 signature is verified over the
    RFC8785-JCS canonical preimage. Without a trust bundle the finding stays
    ``not_evaluated`` (unchanged, never a pass).

    ``key_principal_binding`` is an optional #74 key<->principal binding wire
    dict (``dagr.institutional_key_principal_binding.v0.1`` shape — NOT
    imported from ``dagr_sdk``; only its wire fields are read). When supplied
    AND ``proof_receipt_signature`` passes, ``key_authentication_finding`` is
    recomputed by independently recomputing the trust-bundle entry's key
    fingerprint (inline, from the WIRE0 spec) and requiring it equal the
    binding's asserted ``key_fingerprint``, plus binding scope consistency
    (``key_id``, the fixed ``authority_domain``/``relation_purpose``
    constants, and — if ``genesis_evidence`` is also supplied — the bound
    actor/profile/genesis reference). Without binding evidence,
    ``key_authentication_finding`` stays ``not_evaluated`` even if the
    signature passes: this verifier never authenticates a key from a valid
    signature alone.

    Independence note: this module imports no producer/runtime code
    (``dagr_sdk``, ``dagr_runtime``, or any other producer package). The
    fingerprint recipe and the fixed relation constants are mirrored inline
    from the published wire spec, not consumed via import.
    """
    report = ExitOOriginAuthenticationVerificationReport()
    supplied = dict(supplied_evidence_bytes or {})

    schema = _load_pinned_schema(report)
    if not isinstance(receipt, Mapping):
        report.failure_codes.append("exit_o.receipt_not_object")
        return report

    # --- proof_receipt_conformance: validate against the pinned schema -------
    if schema is not None:
        # Refuse a receipt that is not this profile/version at all.
        if (
            receipt.get("profile_id") != PROFILE_ID
            or receipt.get("profile_version") != PROFILE_VERSION
        ):
            report.failure_codes.append("exit_o.wrong_profile_or_version")
        else:
            try:
                import jsonschema

                jsonschema.Draft202012Validator(
                    schema, format_checker=jsonschema.FormatChecker()
                ).validate(dict(receipt))
                report.proof_receipt_conformance = True
            except jsonschema.ValidationError as exc:  # type: ignore[attr-defined]
                report.failure_codes.append(
                    "exit_o.conformance_failed:" + (exc.json_path or "$")
                )
            except Exception:  # pragma: no cover - defensive
                report.failure_codes.append("exit_o.conformance_error")

    # --- exact_semantic_disposition_binding (structural recompute) -----------
    disp_ref = receipt.get("semantic_disposition_ref")
    disp_digest = receipt.get("semantic_disposition_digest")
    sem_act = receipt.get("semantic_act")
    if isinstance(sem_act, Mapping):
        bref = sem_act.get("binding_ref")
        bdig = sem_act.get("binding_digest")
        if (
            disp_ref is not None
            and bref == disp_ref
            and _is_sha256_ref(bdig)
            and bdig == disp_digest
        ):
            report.exact_semantic_disposition_binding = True
        else:
            report.failure_codes.append("exit_o.exact_act_binding_mismatch")
    else:
        report.failure_codes.append("exit_o.semantic_act_absent")

    # --- temporal_consistency_finding (structural recompute) -----------------
    # O5: historical_act_time < present_attestation_time == issued_at.
    # The equality to issued_at is literal per the producer contract; ordering
    # is by parsed instants, not lexicographic string order.
    hist = receipt.get("historical_act_time")
    pres = receipt.get("present_attestation_time")
    issued = receipt.get("issued_at")
    hist_dt = _parse_offset_aware_iso8601(hist)
    pres_dt = _parse_offset_aware_iso8601(pres)
    issued_dt = _parse_offset_aware_iso8601(issued)
    if hist_dt is None or pres_dt is None or issued_dt is None:
        report.temporal_consistency_finding = VERDICT_FAIL
        report.failure_codes.append("exit_o.temporal_fields_invalid")
    elif pres != issued:
        report.temporal_consistency_finding = VERDICT_FAIL
        report.failure_codes.append("exit_o.attestation_time_mismatch")
    elif not (hist_dt < pres_dt):
        report.temporal_consistency_finding = VERDICT_FAIL
        report.failure_codes.append("exit_o.historical_not_before_present")
    else:
        report.temporal_consistency_finding = VERDICT_PASS

    # --- historical_scope_authorization_finding ------------------------------
    # Structural: the copied scope must equal the top-level proof scope, and the
    # authorization's effective interval must cover the attestation instant.
    # Substantive activation still requires a governed authority verifier that
    # does not exist yet -> not_evaluated (never pass on structure).
    hsa = receipt.get("historical_scope_authorization")
    if not isinstance(hsa, Mapping):
        report.historical_scope_authorization_finding = VERDICT_FAIL
        report.failure_codes.append("exit_o.historical_scope_authorization_absent")
    else:
        scope_pairs = (
            ("present_attester_ref", receipt.get("present_attester_ref")),
            ("historical_actor_ref", receipt.get("historical_actor_ref")),
            ("semantic_issuer_ref", receipt.get("semantic_issuer_ref")),
            (
                "semantic_authority_profile_ref",
                receipt.get("semantic_authority_profile_ref"),
            ),
            ("authority_domain", receipt.get("authority_domain")),
        )
        scope_mismatch = any(hsa.get(name) != top for name, top in scope_pairs)

        interval = hsa.get("effective_interval")
        covers = False
        if isinstance(interval, Mapping) and pres_dt is not None:
            nb_dt = _parse_offset_aware_iso8601(interval.get("effective_not_before"))
            na_raw = interval.get("effective_not_after")
            na_dt = (
                _parse_offset_aware_iso8601(na_raw)
                if na_raw is not None
                else None
            )
            if nb_dt is not None and (na_raw is None or na_dt is not None):
                covers = nb_dt <= pres_dt and (na_dt is None or pres_dt <= na_dt)

        # same-string identity is not continuity: an authorization object cannot
        # be substituted by merely echoing the historical actor reference.
        echoes_actor = hsa.get("binding_ref") == receipt.get("historical_actor_ref")

        if scope_mismatch:
            report.historical_scope_authorization_finding = VERDICT_FAIL
            report.failure_codes.append("exit_o.historical_scope_mismatch")
        elif not covers:
            report.historical_scope_authorization_finding = VERDICT_FAIL
            report.failure_codes.append(
                "exit_o.historical_scope_interval_excludes_attestation"
            )
        elif echoes_actor:
            report.historical_scope_authorization_finding = VERDICT_FAIL
            report.failure_codes.append(
                "exit_o.historical_scope_same_string_as_actor"
            )
        else:
            report.historical_scope_authorization_finding = VERDICT_NOT_EVALUATED
            report.notes.append(
                "historical_scope_authorization is structurally scoped to this "
                "proof and effective at the attestation time, but no governed "
                "authority verifier exists to confirm it is active; not upgraded "
                "to pass."
            )

    # Independently recompute the semantic-authority scope copy. JSON Schema
    # requires the fields but cannot express equality to the top-level issuer /
    # profile / domain.
    sem_auth = receipt.get("semantic_authority")
    if isinstance(sem_auth, Mapping):
        if any(
            sem_auth.get(name) != receipt.get(name)
            for name in (
                "semantic_issuer_ref",
                "semantic_authority_profile_ref",
                "authority_domain",
            )
        ):
            report.semantic_authority_finding = VERDICT_FAIL
            report.failure_codes.append("exit_o.semantic_authority_scope_mismatch")

    # --- proof_receipt_signature ---------------------------------------------
    sig = receipt.get("receipt_signature")
    resolved_entry: Mapping[str, Any] | None = None
    if not isinstance(sig, Mapping):
        report.proof_receipt_signature = VERDICT_FAIL
        report.failure_codes.append("exit_o.signature_absent")
    elif trust_bundle is None:
        # shape may be well-formed, but no verifier-selected trust bundle -> the
        # substantive signature check was not run.
        report.proof_receipt_signature = VERDICT_NOT_EVALUATED
        report.notes.append(
            "no verifier-selected trust bundle supplied; signature not "
            "cryptographically verified (not a pass)."
        )
    elif (
        set(sig) != SIGNATURE_MEMBERS
        or sig.get("algorithm") != "Ed25519"
        or sig.get("canonicalization") != "RFC8785-JCS"
    ):
        report.proof_receipt_signature = VERDICT_FAIL
        report.failure_codes.append("exit_o.signature_object_invalid")
    elif not isinstance(trust_bundle, Mapping):
        report.proof_receipt_signature = VERDICT_FAIL
        report.failure_codes.append("exit_o.trust_bundle_malformed")
    else:
        key_id = sig.get("key_id")
        entry = _resolve_trust_bundle_entry(trust_bundle, key_id)
        if entry is None:
            report.proof_receipt_signature = VERDICT_FAIL
            report.failure_codes.append("exit_o.signature_key_id_unresolved")
        else:
            usability_failure = _key_entry_usability_failure(
                entry, issued_at_dt=issued_dt, profile=PROFILE
            )
            if usability_failure is not None:
                report.proof_receipt_signature = VERDICT_FAIL
                report.failure_codes.append(usability_failure)
            else:
                signature_bytes = _b64url_decode(sig.get("signature"))
                public_key = _load_ed25519_public_key(entry.get("public_key_pem"))
                if signature_bytes is None:
                    report.proof_receipt_signature = VERDICT_FAIL
                    report.failure_codes.append("exit_o.signature_encoding_invalid")
                elif public_key is None:
                    report.proof_receipt_signature = VERDICT_FAIL
                    report.failure_codes.append(
                        "exit_o.trust_bundle_public_key_invalid"
                    )
                else:
                    preimage = copy.deepcopy(dict(receipt))
                    del preimage["receipt_signature"]["signature"]
                    try:
                        canonical = rfc8785.dumps(preimage)
                    except Exception:
                        report.proof_receipt_signature = VERDICT_FAIL
                        report.failure_codes.append(
                            "exit_o.preimage_canonicalization_failed"
                        )
                        canonical = None
                    if canonical is not None:
                        try:
                            public_key.verify(signature_bytes, canonical)
                            report.proof_receipt_signature = VERDICT_PASS
                            resolved_entry = entry
                        except InvalidSignature:
                            report.proof_receipt_signature = VERDICT_FAIL
                            report.failure_codes.append("exit_o.signature_invalid")

    # --- four semantic layer findings ----------------------------------------
    # Producer postures are NEVER accepted as verifier findings. Digest match is
    # integrity, not semantic authentication.
    for key in _LAYER_KEYS:
        finding_attr = {
            "key_authentication": "key_authentication_finding",
            "act_principal": "act_principal_finding",
            "semantic_authority": "semantic_authority_finding",
            "semantic_act": "semantic_act_finding",
        }[key]
        layer = receipt.get(key)
        if not isinstance(layer, Mapping):
            setattr(report, finding_attr, VERDICT_FAIL)
            report.failure_codes.append(f"exit_o.layer_absent:{key}")
            continue
        bdig = layer.get("binding_digest")
        if not _is_sha256_ref(bdig):
            setattr(report, finding_attr, VERDICT_FAIL)
            report.failure_codes.append(f"exit_o.layer_digest_malformed:{key}")
            continue

        # A cross-field structural failure found earlier is terminal for this
        # layer. Missing bytes must not downgrade fail to unavailable.
        if getattr(report, finding_attr) == VERDICT_FAIL:
            continue

        evidence = supplied.get(key)
        if evidence is None:
            setattr(report, finding_attr, VERDICT_UNAVAILABLE)
            report.notes.append(
                f"{key}: referenced evidence bytes not supplied; unavailable."
            )
            continue
        if not isinstance(evidence, (bytes, bytearray, memoryview)):
            setattr(report, finding_attr, VERDICT_FAIL)
            report.failure_codes.append(f"exit_o.layer_evidence_bytes_invalid:{key}")
            continue
        supplied_digest = "sha256:" + hashlib.sha256(bytes(evidence)).hexdigest()
        if supplied_digest != bdig:
            setattr(report, finding_attr, VERDICT_FAIL)
            report.failure_codes.append(f"exit_o.layer_evidence_digest_mismatch:{key}")
            continue
        # bytes present AND independently recomputed digest matches -> integrity
        # holds, but semantic authentication of this layer needs a governed
        # verifier that does not exist yet. NOT a pass. Preserve any earlier
        # structural scope failure on semantic_authority.
        if getattr(report, finding_attr) != VERDICT_FAIL:
            setattr(report, finding_attr, VERDICT_NOT_EVALUATED)
        report.notes.append(
            f"{key}: evidence digest matches (integrity), but no governed verifier "
            f"contract exists for this layer; semantic authentication not_evaluated."
        )

    # --- key_authentication_finding (trust-bundle recomputation) --------------
    # Runs AFTER the generic four-layer evidence loop above so a structural
    # evidence failure on the receipt's own `key_authentication` layer (absent
    # layer, malformed digest, evidence byte mismatch) is never silently
    # upgraded to a pass by a valid signature. A signature can only add
    # information on top of that generic layer check, never erase a
    # structural fail already found for it.
    #
    # Never a pass on signature alone: a valid signature only proves this key
    # signed the bytes, not that the key is bound to the principal the receipt
    # claims. That binding requires independently-supplied #74 evidence.
    if report.key_authentication_finding != VERDICT_FAIL:
        if report.proof_receipt_signature == VERDICT_FAIL:
            report.key_authentication_finding = VERDICT_FAIL
            report.failure_codes.append("exit_o.key_authentication_signature_failed")
        elif report.proof_receipt_signature == VERDICT_PASS:
            if key_principal_binding is None:
                report.notes.append(
                    "signature recomputation passed but no key<->principal binding "
                    "evidence was supplied; key_authentication stays not_evaluated "
                    "(never a pass on signature alone)."
                )
            elif not isinstance(key_principal_binding, Mapping):
                report.key_authentication_finding = VERDICT_FAIL
                report.failure_codes.append(
                    "exit_o.key_authentication_binding_malformed"
                )
            else:
                binding = key_principal_binding
                recomputed_fp = (
                    _recompute_key_fingerprint(resolved_entry.get("public_key_pem"))
                    if resolved_entry is not None
                    else None
                )
                asserted_key_id = (
                    sig.get("key_id") if isinstance(sig, Mapping) else None
                )
                if recomputed_fp is None:
                    report.key_authentication_finding = VERDICT_FAIL
                    report.failure_codes.append(
                        "exit_o.key_authentication_fingerprint_unrecomputable"
                    )
                elif binding.get("key_fingerprint") != recomputed_fp:
                    report.key_authentication_finding = VERDICT_FAIL
                    report.failure_codes.append(
                        "exit_o.key_authentication_fingerprint_mismatch"
                    )
                elif binding.get("key_id") != asserted_key_id:
                    report.key_authentication_finding = VERDICT_FAIL
                    report.failure_codes.append(
                        "exit_o.key_authentication_binding_key_id_mismatch"
                    )
                elif (
                    binding.get("authority_domain") != _KEY_BINDING_AUTHORITY_DOMAIN
                ):
                    report.key_authentication_finding = VERDICT_FAIL
                    report.failure_codes.append(
                        "exit_o.key_authentication_binding_domain_mismatch"
                    )
                elif (
                    binding.get("relation_purpose")
                    != _KEY_BINDING_RELATION_PURPOSE
                ):
                    report.key_authentication_finding = VERDICT_FAIL
                    report.failure_codes.append(
                        "exit_o.key_authentication_binding_purpose_mismatch"
                    )
                elif genesis_evidence is not None and (
                    not isinstance(genesis_evidence, Mapping)
                    or binding.get("actor_ref") != genesis_evidence.get("actor_ref")
                    or binding.get("semantic_authority_profile_ref")
                    != genesis_evidence.get("semantic_authority_profile_ref")
                    or binding.get("genesis_ref")
                    != genesis_evidence.get("genesis_ref")
                    or binding.get("genesis_digest")
                    != genesis_evidence.get("genesis_digest")
                ):
                    report.key_authentication_finding = VERDICT_FAIL
                    report.failure_codes.append(
                        "exit_o.key_authentication_genesis_mismatch"
                    )
                else:
                    report.key_authentication_finding = VERDICT_PASS

    # --- overall EXIT-O -------------------------------------------------------
    # Structural validity is a prerequisite, not merely diagnostic metadata.
    # A future verifier must never satisfy EXIT-O on a schema-invalid,
    # unpinned, or cross-act-substituted proof even if every semantic verifier
    # happens to return pass.
    report.exit_o_chain_satisfied = _compute_exit_o_chain_satisfied(report)
    return report


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Independent EXIT-O semantic-issuer origin-authentication verifier."
    )
    parser.add_argument("receipt", type=Path, help="path to the proof receipt JSON")
    args = parser.parse_args(argv)
    report = verify_exit_o_origin_authentication_receipt(_load_json(args.receipt))
    print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    return 0 if report.exit_o_chain_satisfied else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
