"""Independent sequence-level verifier for the one-source work sequence.

ARCSV-SOURCESEQ0 recomputes the linkage that threads a SINGLE governed source
session end-to-end, from serialized bytes only:

    governed declaration bytes
        -> acquisition.source_declaration_binding.v0.1  (declaration binding)
        -> acquisition.source_session.manifest.v0.1      (bound session manifest)
        -> acquisition.capture.v0.1                      (capture receipt)
        -> srs.editorial.source_capture.v0.2             (SRS source_capture receipt)
      (optional) acquisition.grounded_content_proposal.v0.1  (grounded proposal)

It answers ONE question per axis: does every serialized artifact in the supplied
evidence refer to the SAME source work (single lineage), recomputed from the
bytes rather than trusted from an emitter's assertion? It decides no truth, no
admission, no standing, no publication. "Linked" is not "true" and is not
"admitted"; sequence validity is not source truth is not admission.

Scope override (operator, ARCSV-SOURCESEQ0)
-------------------------------------------
The emitted chain this verifier recomputes is exactly:

    captured bytes / session -> grounded proposal -> declaration binding
        -> source_capture.v0.2 receipt.

``srs.editorial.source_ingest.v0.1`` was not part of the historical TIT-S02
one-source sequence. By default, therefore, the ``ingest_linkage`` axis is
``NOT_EVALUATED`` and reports that source_ingest is ABSENT — but the absence is
verified: an unexpectedly present source_ingest claim in the historical
baseline is itself a FAIL finding, never a pass. If a literal source_ingest
receipt is supplied as an optional witness, the axis is upgraded from verified
absence to an independently recomputed ingest linkage check. ``citation_pack_linkage``
is ``NOT_EVALUATED`` unless a real citation_pack receipt is present in the
evidence. ``external_source_truth`` is ``NOT_EVALUATED`` permanently.

Independence (arcs-verify's core invariant)
-------------------------------------------
This module imports ZERO producer code (counterpedia_acquisition / acquisition /
dagr_ingest / dagr_mcp / arcs_srs). It recomputes every linkage from the
serialized artifact bytes and the pinned, independently transcribed byte-facts
below. Where a proposal's grounding must be recomputed, it composes the
merged, verifier-LOCAL ARCSV-ACQGROUND0 verifier
(``arcs_verify.acquisition_grounding``); it never imports the producer's
grounder. It performs no network access.

If a linkage cannot be recomputed from the supplied bytes, the responsible
conclusion is ``NOT_EVALUATED`` (disclosed) — it is never silently upgraded to
PASS. In particular, the exact captured source object (an out-of-band raw byte
blob, e.g. a multi-megabyte PDF) is typically NOT part of the serialized
evidence; its raw-byte recompute is reported ``NOT_EVALUATED`` while the
captured-object *digest* agreement across the receipts is still recomputed.

Pinned byte-facts (independently transcribed from the pinned producer contracts;
re-pin only when those contracts advance — these are byte facts, not imports):
  * R1a source_reference_id URN scheme ``urn:counterpedia.source-reference``
    and rule ``{scheme}:{declaring_artifact_ref}:{source_inventory_key}``
    (dagr-ingest ``dagr_ingest/srs/{profiles,editorial}.py`` @ dbe880dc)
  * SRS source_capture.v0.2 identity: profile_id ``srs.editorial.source_capture``
    / profile_version ``v0.2`` / receipt_kind ``capture_attempt`` /
    receipt_version ``srs.core.v5.1`` (arcs-srs @ 4d90b9c)
  * source_ingest identity ``srs.editorial.source_ingest`` (the ABSENT profile)
  * acquisition wire schema ids (counterpedia-acquisition @ d4b1127d)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Optional

from arcs_verify import acquisition_grounding as ag

# --------------------------------------------------------------------------- #
# pinned byte-facts (independent transcription; no producer import)
# --------------------------------------------------------------------------- #
ACQUISITION_PIN_COMMIT = "d4b1127d84816cc8279fc2ea0b16358006b37745"
DAGR_INGEST_PIN_COMMIT = "dbe880dc"
ARCS_SRS_PIN_COMMIT = "4d90b9c"

# R1a declaration-identity derivation (verbatim rule, not the producer function).
R1A_URN_SCHEME = "urn:counterpedia.source-reference"

# SRS source_capture.v0.2 receipt identity.
SOURCE_CAPTURE_PROFILE_ID = "srs.editorial.source_capture"
SOURCE_CAPTURE_PROFILE_VERSION = "v0.2"
SOURCE_CAPTURE_RECEIPT_KIND = "capture_attempt"
SOURCE_CAPTURE_RECEIPT_VERSION = "srs.core.v5.1"

# The profile that was absent from the historical TIT-S02 one-source sequence.
# Its unexpected presence in the historical baseline is a finding, not a pass;
# a supplied literal source_ingest receipt upgrades the axis to a real linkage
# check instead of leaving it NOT_EVALUATED.
SOURCE_INGEST_PROFILE_ID = "srs.editorial.source_ingest"
SOURCE_INGEST_PROFILE_VERSION = "v0.1"
SOURCE_INGEST_RECEIPT_KIND = "source_ingest"
SOURCE_INGEST_RECEIPT_VERSION = "srs.core.v5.1"
SOURCE_INGEST_PARSER_IDENTITY = "dagr-ingest.pdf"
SOURCE_INGEST_CAPTURE_OBSERVATION_REF = "editorial-source-capture-v02-success-TIT-S02-0001"
SOURCE_INGEST_PDO_MODULE_IDENTITY = {"module_id": "garp-ingest", "module_version": "0.1.0"}
SOURCE_INGEST_PROTOCOL_BINDING = "counterpedia-demo-corpus-ingest/wave1"
# A citation_pack receipt, if genuinely present, turns citation_pack_linkage
# from NOT_EVALUATED into a real (composed) result.
CITATION_PACK_PROFILE_MARKER = "citation_pack"

# acquisition wire-contract schema ids.
ACQ_SESSION_MANIFEST_SCHEMA = "acquisition.source_session.manifest.v0.1"
ACQ_BINDING_SCHEMA = "acquisition.source_declaration_binding.v0.1"
ACQ_CAPTURE_SCHEMA = "acquisition.capture.v0.1"
ACQ_UNBOUND_SCHEMA = "acquisition.source_declaration_unbound.v0.1"
GROUNDED_PROPOSAL_SCHEMA = "acquisition.grounded_content_proposal.v0.1"

# Bound status + the raw-source artifact role (a rendered / browser-page-capture
# role must never be substituted for the raw captured source bytes).
BOUND_STATUS = "bound"
CAPTURED_BYTES_ROLE = "captured_bytes"

REPORT_SCHEMA = "arcs_verify.source_work_sequence_report.v0_1"
VERIFICATION_PROFILE = "arcs_verify.source_work_sequence.v0_1"

_SHA256_REF = "sha256:"

_AXIS_FAIL = "FAIL"
_AXIS_PARTIAL = "PARTIAL"
_AXIS_PASS = "PASS"
_NOT_EVALUATED = "NOT_EVALUATED"


# --------------------------------------------------------------------------- #
# small byte helpers (verifier-local; mirror the ACQGROUND0 discipline)
# --------------------------------------------------------------------------- #
def _sha256_ref(content: bytes) -> str:
    return _SHA256_REF + hashlib.sha256(content).hexdigest()


def _is_sha256_ref(value: object) -> bool:
    # Compose the merged ACQGROUND0 verifier-local check (no re-implementation).
    return ag._is_sha256_ref(value)


def derive_source_reference_id(declaring_artifact_ref: str, source_inventory_key: str) -> str:
    """Independently recompute the R1a source_reference_id from its two inputs.

    This is the verbatim derivation rule
    ``{scheme}:{declaring_artifact_ref}:{source_inventory_key}`` transcribed from
    the pinned producer contract; it imports no producer code.
    """

    return f"{R1A_URN_SCHEME}:{declaring_artifact_ref}:{source_inventory_key}"


def _fold(concl: dict[str, str], names: tuple[str, ...]) -> str:
    values = [concl[name] for name in names if name in concl]
    if _AXIS_FAIL in values:
        return _AXIS_FAIL
    if _NOT_EVALUATED in values:
        return _AXIS_PARTIAL
    return _AXIS_PASS


# --------------------------------------------------------------------------- #
# evidence container (serialized bytes only)
# --------------------------------------------------------------------------- #
class SourceWorkEvidence:
    """A parsed, serialized-bytes-only view over one source work sequence.

    Every field is either raw bytes or a JSON-decoded dict/list. No producer
    object is constructed and no producer code is consulted.
    """

    def __init__(
        self,
        *,
        declaration_bytes: Optional[bytes],
        binding: Optional[dict],
        manifest: Optional[dict],
        capture_receipt: Optional[dict],
        source_capture: Optional[dict],
        grounded_proposal: Optional[dict] = None,
        source_ingest: Optional[dict] = None,
        source_ingest_extraction_bytes: Optional[bytes] = None,
        proposal_source_bytes: Optional[bytes] = None,
        captured_source_bytes: Optional[bytes] = None,
        extra_receipts: Optional[list[dict]] = None,
    ) -> None:
        self.declaration_bytes = declaration_bytes
        self.binding = binding
        self.manifest = manifest
        self.capture_receipt = capture_receipt
        self.source_capture = source_capture
        self.grounded_proposal = grounded_proposal
        self.source_ingest = source_ingest
        self.source_ingest_extraction_bytes = source_ingest_extraction_bytes
        self.proposal_source_bytes = proposal_source_bytes
        self.captured_source_bytes = captured_source_bytes
        self.extra_receipts = extra_receipts or []


# --------------------------------------------------------------------------- #
# verification core
# --------------------------------------------------------------------------- #
def verify(evidence: SourceWorkEvidence) -> dict:
    """Recompute the one-source-work sequence axes from serialized bytes only."""

    findings: list[str] = []
    concl: dict[str, str] = {}
    recomputed: dict[str, Any] = {}

    def C(name: str, ok: bool, code: Optional[str] = None) -> bool:
        concl[name] = _AXIS_PASS if ok else _AXIS_FAIL
        if not ok and code:
            findings.append(code)
        return ok

    def NE(name: str) -> None:
        concl[name] = _NOT_EVALUATED

    manifest = evidence.manifest or {}
    binding = evidence.binding or {}
    capture_receipt = evidence.capture_receipt or {}
    source_capture = evidence.source_capture or {}
    embedded_binding = manifest.get("declaration_binding") or {}

    # Reference facts (READ from the artifacts; every use is cross-checked, never
    # trusted on its own).
    declaring_ref = binding.get("declaring_artifact_ref")
    inventory_key = binding.get("source_inventory_key")
    declared_locator = binding.get("declared_locator")
    captured_ref = capture_receipt.get("exact_bytes_sha256")

    # --------------------------------------------------------------------- #
    # axis 1: artifact_integrity
    #   The one governed artifact whose bytes we actually hold (the declaration)
    #   must recompute to the declaring_artifact_ref every downstream artifact
    #   cites; every declared digest ref must be well formed.
    # --------------------------------------------------------------------- #
    if evidence.declaration_bytes is None:
        NE("governed_declaration_digest_recomputes")
        recomputed["declaration_digest_recomputed"] = None
    else:
        recomputed_decl = _sha256_ref(evidence.declaration_bytes)
        recomputed["declaration_digest_recomputed"] = recomputed_decl
        if not C(
            "governed_declaration_digest_recomputes",
            _is_sha256_ref(declaring_ref) and recomputed_decl == declaring_ref,
            "source_work_sequence.declaration_digest_mismatch",
        ):
            pass

    manifest_artifacts = manifest.get("artifacts")
    refs_wellformed = (
        isinstance(manifest_artifacts, list)
        and all(
            isinstance(a, dict) and _is_sha256_ref(a.get("sha256"))
            for a in manifest_artifacts
        )
        and _is_sha256_ref(manifest.get("captured_object_address"))
    )
    C(
        "manifest_artifact_refs_wellformed",
        refs_wellformed,
        "source_work_sequence.manifest_artifact_ref_malformed",
    )

    artifact_integrity = _fold(
        concl,
        ("governed_declaration_digest_recomputes", "manifest_artifact_refs_wellformed"),
    )

    # --------------------------------------------------------------------- #
    # axis 2: capture_linkage
    #   The captured object digest must agree across capture_receipt, session
    #   manifest (address + declared raw artifact), and the source_capture
    #   receipt (single captured object). The raw source bytes themselves are
    #   usually out of evidence -> that recompute is NOT_EVALUATED, disclosed.
    # --------------------------------------------------------------------- #
    C(
        "acquisition_schema_versions_pinned",
        manifest.get("schema_version") == ACQ_SESSION_MANIFEST_SCHEMA
        and capture_receipt.get("schema_version") == ACQ_CAPTURE_SCHEMA,
        "source_work_sequence.acquisition_schema_unpinned",
    )

    manifest_address = manifest.get("captured_object_address")
    sc_captured_ref = source_capture.get("captured_bytes_ref")
    # Locate the raw captured-bytes artifact in the manifest (role must be raw).
    raw_artifact_digest = None
    raw_role_ok = False
    if isinstance(manifest_artifacts, list):
        for a in manifest_artifacts:
            if isinstance(a, dict) and a.get("role") == CAPTURED_BYTES_ROLE:
                raw_artifact_digest = a.get("sha256")
                raw_role_ok = True
                break
    digest_agreement = (
        _is_sha256_ref(captured_ref)
        and captured_ref == manifest_address
        and captured_ref == sc_captured_ref
        and captured_ref == raw_artifact_digest
    )
    recomputed["captured_object_digest"] = captured_ref
    C(
        "captured_object_digest_agreement",
        digest_agreement,
        "source_work_sequence.captured_object_digest_disagreement",
    )
    # No rendered / browser-page-capture artifact silently substituted for raw
    # source bytes: the digest that flows into source_capture must be the digest
    # of an artifact declared with the raw captured_bytes role.
    C(
        "captured_role_is_raw_source",
        raw_role_ok and raw_artifact_digest == sc_captured_ref,
        "source_work_sequence.captured_role_substitution",
    )

    # Raw captured source bytes: recompute iff supplied, else NOT_EVALUATED.
    if evidence.captured_source_bytes is not None:
        recomputed_capture = _sha256_ref(evidence.captured_source_bytes)
        recomputed["captured_source_bytes_recomputed"] = recomputed_capture
        C(
            "raw_captured_bytes_recompute",
            recomputed_capture == captured_ref,
            "source_work_sequence.raw_captured_bytes_mismatch",
        )
    else:
        NE("raw_captured_bytes_recompute")
        recomputed["captured_source_bytes_recomputed"] = None

    capture_linkage = _fold(
        concl,
        (
            "acquisition_schema_versions_pinned",
            "captured_object_digest_agreement",
            "captured_role_is_raw_source",
            "raw_captured_bytes_recompute",
        ),
    )

    # --------------------------------------------------------------------- #
    # axis 3: declaration_binding_linkage
    #   The declaration binds an identity (declaring_artifact_ref + inventory
    #   key) that R1a-derives the SRS source_reference_id/subject_ref, the
    #   locators agree, the manifest and the standalone binding agree, and the
    #   session is genuinely BOUND (an unbound session cannot masquerade as an
    #   SRS-bound sequence). Identity is recomputed, never trusted.
    # --------------------------------------------------------------------- #
    C(
        "binding_schema_pinned",
        binding.get("schema_version") == ACQ_BINDING_SCHEMA,
        "source_work_sequence.binding_schema_unpinned",
    )
    C(
        "inventory_key_present",
        isinstance(inventory_key, str) and bool(inventory_key),
        "source_work_sequence.inventory_key_absent",
    )

    # manifest threads the same identity, and the manifest-embedded binding
    # agrees field-for-field with the standalone binding file.
    manifest_agreement = (
        manifest.get("declaring_artifact_ref") == declaring_ref
        and manifest.get("source_inventory_key") == inventory_key
        and all(
            embedded_binding.get(k) == binding.get(k)
            for k in ("declaring_artifact_ref", "source_inventory_key", "declared_locator")
        )
    )
    C(
        "manifest_binding_agreement",
        manifest_agreement,
        "source_work_sequence.manifest_binding_disagreement",
    )

    # locator agreement across binding / capture receipt / manifest.
    attempted_locator = capture_receipt.get("source_locator")
    C(
        "locator_agreement",
        isinstance(declared_locator, str)
        and bool(declared_locator)
        and declared_locator == attempted_locator
        and declared_locator == manifest.get("source_locator"),
        "source_work_sequence.locator_disagreement",
    )

    # R1a reference recompute: the derived id equals the binding's declared id,
    # the SRS source_reference_id AND subject_ref, and is NOT the acquisition
    # -local (URL-derived) source_id (identity-override guard).
    r1a = None
    if _is_sha256_ref(declaring_ref) and isinstance(inventory_key, str) and inventory_key:
        r1a = derive_source_reference_id(declaring_ref, inventory_key)
    recomputed["r1a_source_reference_id"] = r1a
    acquisition_local_source_id = manifest.get("source_id")
    r1a_ok = (
        r1a is not None
        and binding.get("derived_source_reference_id") == r1a
        and source_capture.get("source_reference_id") == r1a
        and source_capture.get("subject_ref") == r1a
        and r1a != acquisition_local_source_id
    )
    C(
        "r1a_reference_recomputes",
        r1a_ok,
        "source_work_sequence.r1a_reference_mismatch",
    )

    # source_capture receipt binds THIS declaration identity and is the pinned
    # source_capture.v0.2 receipt.
    sc_identity_ok = (
        source_capture.get("profile_id") == SOURCE_CAPTURE_PROFILE_ID
        and source_capture.get("profile_version") == SOURCE_CAPTURE_PROFILE_VERSION
        and source_capture.get("receipt_kind") == SOURCE_CAPTURE_RECEIPT_KIND
        and source_capture.get("receipt_version") == SOURCE_CAPTURE_RECEIPT_VERSION
        and source_capture.get("declaring_artifact_ref") == declaring_ref
        and source_capture.get("source_inventory_key") == inventory_key
    )
    C(
        "source_capture_binds_declaration",
        sc_identity_ok,
        "source_work_sequence.source_capture_identity_mismatch",
    )

    # Session is genuinely bound (unbound-masquerade guard).
    session_bound = (
        manifest.get("source_capture_binding_status") == BOUND_STATUS
        and manifest.get("declaration_binding") not in (None, {})
    )
    C(
        "session_is_bound",
        session_bound,
        "source_work_sequence.session_not_bound",
    )

    declaration_binding_linkage = _fold(
        concl,
        (
            "binding_schema_pinned",
            "inventory_key_present",
            "manifest_binding_agreement",
            "locator_agreement",
            "r1a_reference_recomputes",
            "source_capture_binds_declaration",
            "session_is_bound",
        ),
    )

    # --------------------------------------------------------------------- #
    # axis 4: proposal_grounding
    #   Optional in the one-source chain. When no grounded proposal was emitted
    #   (grounding_summary all-zero), the axis is NOT_EVALUATED and the absence
    #   is verified consistent. When a proposal IS supplied, its grounding is
    #   recomputed by the merged ACQGROUND0 verifier AND its captured artifact
    #   must be THIS session's captured object (single lineage) -- a foreign
    #   proposal (cross-source) fails here.
    # --------------------------------------------------------------------- #
    grounding_summary = manifest.get("grounding_summary") or {}
    summary_is_zero = all(
        grounding_summary.get(k, 0) == 0
        for k in (
            "proposal_fields",
            "extractive_grounded_fields",
            "abstractive_fields",
            "dropped_ungrounded",
        )
    )
    if evidence.grounded_proposal is None:
        # No proposal in evidence: verify the absence is internally consistent
        # (the session declares zero proposal fields), then NOT_EVALUATED.
        recomputed["proposal_in_evidence"] = False
        if not summary_is_zero:
            findings.append("source_work_sequence.grounding_summary_claims_unpresented_proposal")
            proposal_grounding = _AXIS_FAIL
            concl["proposal_grounding_absence_consistent"] = _AXIS_FAIL
        else:
            concl["proposal_grounding_absence_consistent"] = _NOT_EVALUATED
            proposal_grounding = _NOT_EVALUATED
    else:
        recomputed["proposal_in_evidence"] = True
        # (a) lineage: the proposal's captured artifact_digest must be THIS
        # session's captured object. Recomputed before any grounding trust.
        proposal_digest = evidence.grounded_proposal.get("artifact_digest")
        lineage_ok = (
            _is_sha256_ref(proposal_digest)
            and proposal_digest == captured_ref
            and proposal_digest == sc_captured_ref
        )
        C(
            "proposal_lineage_same_source",
            lineage_ok,
            "source_work_sequence.proposal_cross_source",
        )
        # (b) grounding recompute via the merged, verifier-LOCAL ACQGROUND0
        # verifier (no producer import). Needs the proposal's own source bytes.
        if evidence.proposal_source_bytes is not None:
            ag_report = ag.verify(evidence.grounded_proposal, evidence.proposal_source_bytes)
            recomputed["proposal_grounding_report"] = {
                "artifact_integrity": ag_report["artifact_integrity"],
                "grounding_integrity": ag_report["grounding_integrity"],
                "proposal_posture": ag_report["proposal_posture"],
                "failure_codes": ag_report["failure_codes"],
            }
            grounding_recomputes = (
                ag_report["artifact_integrity"] == _AXIS_PASS
                and ag_report["grounding_integrity"] == _AXIS_PASS
                and ag_report["proposal_posture"] == _AXIS_PASS
            )
            C(
                "proposal_grounding_recomputes",
                grounding_recomputes,
                "source_work_sequence.proposal_grounding_failed",
            )
        else:
            NE("proposal_grounding_recomputes")
        proposal_grounding = _fold(
            concl,
            ("proposal_lineage_same_source", "proposal_grounding_recomputes"),
        )

    # --------------------------------------------------------------------- #
    # axis 5: ingest_linkage
    #   Historical TIT-S02 evidence did not include source_ingest and remains
    #   NOT_EVALUATED when absent. If a literal source_ingest receipt is
    #   supplied, verify its linkage to the same captured object and exact
    #   extraction bytes instead of treating its presence as an automatic fail.
    # --------------------------------------------------------------------- #
    unexpected_ingest_present = any(
        isinstance(candidate, dict) and candidate.get("profile_id") == SOURCE_INGEST_PROFILE_ID
        for candidate in (source_capture, manifest, capture_receipt, binding, *evidence.extra_receipts)
    )
    ingest_receipt = evidence.source_ingest
    recomputed["source_ingest_absent"] = ingest_receipt is None
    recomputed["source_ingest_present"] = ingest_receipt is not None

    if ingest_receipt is None:
        if unexpected_ingest_present:
            findings.append("source_work_sequence.unexpected_source_ingest_present")
            ingest_linkage = _AXIS_FAIL
        else:
            ingest_linkage = _NOT_EVALUATED
    else:
        if unexpected_ingest_present:
            findings.append("source_work_sequence.unexpected_source_ingest_present")
            ingest_linkage = _AXIS_FAIL
        else:
            source_artifact_id = ingest_receipt.get("source_artifact_id")
            derivation = ingest_receipt.get("derivation") or {}
            extraction_ref = ingest_receipt.get("extraction_ref")
            pdo_module_identity = ingest_receipt.get("pdo_module_identity")
            ingest_identity_ok = (
                ingest_receipt.get("profile_id") == SOURCE_INGEST_PROFILE_ID
                and ingest_receipt.get("profile_version") == SOURCE_INGEST_PROFILE_VERSION
                and ingest_receipt.get("receipt_kind") == SOURCE_INGEST_RECEIPT_KIND
                and ingest_receipt.get("receipt_version") == SOURCE_INGEST_RECEIPT_VERSION
                and ingest_receipt.get("boundary_type") == "editorial_corpus_boundary"
                and ingest_receipt.get("protocol_binding") == SOURCE_INGEST_PROTOCOL_BINDING
                and ingest_receipt.get("subject_ref") == captured_ref
                and source_artifact_id == captured_ref
                and ingest_receipt.get("capture_observation_ref")
                == SOURCE_INGEST_CAPTURE_OBSERVATION_REF
                and ingest_receipt.get("parser_identity") == SOURCE_INGEST_PARSER_IDENTITY
                and pdo_module_identity == SOURCE_INGEST_PDO_MODULE_IDENTITY
                and _is_sha256_ref(ingest_receipt.get("pdo_ref"))
                and _is_sha256_ref(source_artifact_id)
                and isinstance(derivation, dict)
                and derivation.get("input_hash") == source_artifact_id
                and derivation.get("parser_id") == SOURCE_INGEST_PARSER_IDENTITY
                and extraction_ref == derivation.get("output_hash")
            )
            C(
                "source_ingest_identity_binds_capture",
                ingest_identity_ok,
                "source_work_sequence.source_ingest_identity_mismatch",
            )
            if evidence.source_ingest_extraction_bytes is not None:
                recomputed_ingest_extraction = _sha256_ref(evidence.source_ingest_extraction_bytes)
                recomputed["source_ingest_extraction_ref"] = recomputed_ingest_extraction
                C(
                    "source_ingest_extraction_recomputes",
                    recomputed_ingest_extraction == extraction_ref,
                    "source_work_sequence.source_ingest_extraction_mismatch",
                )
            else:
                recomputed["source_ingest_extraction_ref"] = None
                C(
                    "source_ingest_extraction_recomputes",
                    False,
                    "source_work_sequence.source_ingest_extraction_missing",
                )
            ingest_linkage = _fold(
                concl,
                (
                    "source_ingest_identity_binds_capture",
                    "source_ingest_extraction_recomputes",
                ),
            )

    # --------------------------------------------------------------------- #
    # axis 6: citation_pack_linkage  (NOT_EVALUATED unless a pack is present)
    # --------------------------------------------------------------------- #
    citation_pack_present = any(
        isinstance(r, dict) and CITATION_PACK_PROFILE_MARKER in str(r.get("profile_id", ""))
        for r in evidence.extra_receipts
    )
    recomputed["citation_pack_present"] = citation_pack_present
    if citation_pack_present:
        # A real citation_pack would be linkage-checked here; none is supplied in
        # the in-scope one-source chain, so this branch stays a disclosed hook.
        citation_pack_linkage = _AXIS_PARTIAL
        findings.append("source_work_sequence.citation_pack_linkage_not_implemented")
    else:
        citation_pack_linkage = _NOT_EVALUATED

    # --------------------------------------------------------------------- #
    # axis 7: external_source_truth  (NOT_EVALUATED, permanently)
    # --------------------------------------------------------------------- #
    external_source_truth = _NOT_EVALUATED

    return {
        "schema": REPORT_SCHEMA,
        "verification_profile": VERIFICATION_PROFILE,
        "pins": {
            "counterpedia_acquisition": ACQUISITION_PIN_COMMIT,
            "dagr_ingest": DAGR_INGEST_PIN_COMMIT,
            "arcs_srs": ARCS_SRS_PIN_COMMIT,
        },
        "conclusions": concl,
        # Independent axes -- reported SEPARATELY; there is deliberately no
        # aggregate pass/verdict/trust score.
        "artifact_integrity": artifact_integrity,
        "capture_linkage": capture_linkage,
        "declaration_binding_linkage": declaration_binding_linkage,
        "proposal_grounding": proposal_grounding,
        "ingest_linkage": ingest_linkage,
        "citation_pack_linkage": citation_pack_linkage,
        "external_source_truth": external_source_truth,
        "recomputed": recomputed,
        "failure_codes": sorted(set(findings)),
        "limitations": [
            "Sequence validity is not source truth and is not admission. A PASS "
            "on a linkage axis attests only that the serialized artifacts refer "
            "to the same recomputed source work; it decides no truth, admission, "
            "standing, or publication, and emits no aggregate trust score.",
            "The exact captured source object is typically not part of the "
            "serialized evidence; when absent, its raw-byte recompute is "
            "NOT_EVALUATED (disclosed) while the captured-object digest "
            "agreement across the receipts is still recomputed.",
            "ingest_linkage is NOT_EVALUATED when source_ingest is absent from "
            "the evidence; the historical TIT-S02 one-source sequence does not "
            "include it. If a literal source_ingest receipt is supplied, the axis "
            "upgrades to an independently recomputed ingest linkage check.",
            "external_source_truth is NOT_EVALUATED permanently; this verifier "
            "never establishes that the captured bytes are the true source.",
        ],
    }


# --------------------------------------------------------------------------- #
# loader (serialized bytes only)
# --------------------------------------------------------------------------- #
def _read_json(path: Path) -> dict:
    obj = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise ag.SourceIntegrityError(
            f"{path}: expected a JSON object, got {type(obj).__name__}"
        )
    return obj


def load_sequence(
    session_dir: str | Path,
    *,
    declaration_file: str = "declaration.CAPTURE_WAVE1_P0_MANIFEST.json",
    grounded_proposal_file: Optional[str] = None,
    source_ingest_file: Optional[str] = None,
    source_ingest_extraction_file: Optional[str] = None,
    proposal_source_file: Optional[str] = None,
    captured_source_file: Optional[str] = None,
) -> SourceWorkEvidence:
    """Load one source work sequence directory as serialized-bytes-only evidence."""

    root = Path(session_dir)
    decl_path = root / declaration_file
    declaration_bytes = decl_path.read_bytes() if decl_path.is_file() else None
    binding = _read_json(root / "source_declaration_binding.json")
    manifest = _read_json(root / "session.manifest.json")
    capture_receipt = _read_json(root / "capture_receipt.json")
    source_capture = _read_json(root / "source_capture.v0_2.receipt.json")

    grounded_proposal = None
    source_ingest = None
    proposal_source_bytes = None
    source_ingest_extraction_bytes = None
    if grounded_proposal_file:
        grounded_proposal = _read_json(root / grounded_proposal_file)
    if source_ingest_file:
        source_ingest = _read_json(root / source_ingest_file)
    if proposal_source_file:
        proposal_source_bytes = (root / proposal_source_file).read_bytes()
    if source_ingest_extraction_file:
        source_ingest_extraction_bytes = (root / source_ingest_extraction_file).read_bytes()
    captured_source_bytes = None
    if captured_source_file:
        captured_source_bytes = (root / captured_source_file).read_bytes()

    return SourceWorkEvidence(
        declaration_bytes=declaration_bytes,
        binding=binding,
        manifest=manifest,
        capture_receipt=capture_receipt,
        source_capture=source_capture,
        grounded_proposal=grounded_proposal,
        source_ingest=source_ingest,
        source_ingest_extraction_bytes=source_ingest_extraction_bytes,
        proposal_source_bytes=proposal_source_bytes,
        captured_source_bytes=captured_source_bytes,
    )


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _human(report: dict) -> None:
    print(f"verification_profile: {report['verification_profile']}")
    for axis in (
        "artifact_integrity",
        "capture_linkage",
        "declaration_binding_linkage",
        "proposal_grounding",
        "ingest_linkage",
        "citation_pack_linkage",
        "external_source_truth",
    ):
        print(f"{axis}: {report[axis]}")
    print("conclusions:")
    for name, value in report["conclusions"].items():
        print(f"  {name}: {value}")
    for code in report["failure_codes"]:
        print(f"failure_code: {code}")
    for lim in report["limitations"]:
        print(f"limitation: {lim}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="arcs-verify source-work-sequence",
        description=(
            "Independently verify the one-source work sequence: recompute the "
            "linkage threading a single governed source session (declaration -> "
            "binding -> session -> capture receipt -> source_capture.v0.2). "
            "Reports independent axes; decides no truth/admission and emits no "
            "aggregate trust score. ingest_linkage and external_source_truth are "
            "NOT_EVALUATED."
        ),
    )
    parser.add_argument("session_dir", type=Path)
    parser.add_argument("--declaration-file", default="declaration.CAPTURE_WAVE1_P0_MANIFEST.json")
    parser.add_argument("--grounded-proposal-file", default=None)
    parser.add_argument("--source-ingest-file", default=None)
    parser.add_argument("--source-ingest-extraction-file", default=None)
    parser.add_argument("--proposal-source-file", default=None)
    parser.add_argument("--captured-source-file", default=None)
    parser.add_argument("--json", action="store_true", dest="as_json")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code) if exc.code is not None else 2

    try:
        evidence = load_sequence(
            args.session_dir,
            declaration_file=args.declaration_file,
            grounded_proposal_file=args.grounded_proposal_file,
            source_ingest_file=args.source_ingest_file,
            source_ingest_extraction_file=args.source_ingest_extraction_file,
            proposal_source_file=args.proposal_source_file,
            captured_source_file=args.captured_source_file,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ag.SourceIntegrityError) as exc:
        print(f"source-integrity/usage error: {exc}", file=sys.stderr)
        return 2

    report = verify(evidence)
    if args.as_json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        _human(report)

    # Process exit convention only (NOT a report field): FAIL on any FAIL axis.
    any_fail = _AXIS_FAIL in (
        report["artifact_integrity"],
        report["capture_linkage"],
        report["declaration_binding_linkage"],
        report["proposal_grounding"],
        report["ingest_linkage"],
        report["citation_pack_linkage"],
    )
    return 1 if any_fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
