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

import hashlib
import json
from datetime import datetime
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping

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

    ``trust_bundle`` is reserved: without a verifier-selected trust bundle the
    signature finding is ``not_evaluated`` (never a pass).
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
    else:  # pragma: no cover - reserved until key provisioning exists
        report.proof_receipt_signature = VERDICT_NOT_EVALUATED
        report.notes.append(
            "trust-bundle signature verification is reserved pending key "
            "provisioning (a separate owner act); not a pass."
        )

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
