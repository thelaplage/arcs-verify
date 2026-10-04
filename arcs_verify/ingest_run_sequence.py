"""Independent sequence-level verifier for dagr.ingest_run.v0.1 sequences.

This module recomputes structural, linkage, binding, and coverage/posture
findings for a DAGR editorial ingest sequence from serialized artifacts:
  - a dagr.ingest_run.v0.1 neutral run document,
  - a producer-owned SRS receipt-set manifest
    (dagr-ingest.srs-receipt-set-manifest.v0.1), and
  - the individual SRS publication_ingest receipt files it enumerates,
  - the SRS profile manifest file (for pin + production-authority verification).

The artifact shapes consumed here are the *real* producer contracts emitted by
merged dagr-ingest, not a verifier-invented test shape:

  run_doc (dagr.ingest_run.v0.1)
    - ``file_occurrences[]`` carry rel_path, content_hash, source_type,
      is_duplicate_content, parser_id, root_id, artifact_refs, ...
    - ``unique_artifacts[]`` do NOT carry parser_id, is_duplicate_content, or a
      ``subject`` field; coverage is computed over ``file_occurrences``.

  manifest (dagr-ingest.srs-receipt-set-manifest.v0.1)
    - ``emitted_receipts[]`` = {receipt_id, subject_ref, rel_path, output_path,
      incomplete}
    - ``skipped_duplicate[]``, ``skipped_no_parser[]``,
      ``profile_not_applicable[]`` = lists of rel_paths
    - ``incomplete_receipt_ids[]``, ``counts``, ``run_id``, ``profile_slug``,
      ``profile_manifest_sha256``, ``envelope_version``.

Authority boundaries
--------------------
- This verifier operates on *serialized bytes only* (deserialized from JSON).
  It does not import dagr_ingest, garp_ingest, or any producer code.
- Findings are independently recomputed from the supplied artifacts.
  They are not emitter assertions.
- Receipt files are resolved by ``receipt_id`` under the supplied receipts
  directory. The manifest's ``output_path`` (an absolute machine path recorded
  by the producer) is never trusted as a filesystem authority.
- The profile-manifest pin is checked two ways: the recomputed sha256 of the
  supplied profile-manifest bytes must equal the manifest's declared
  ``profile_manifest_sha256`` (pin integrity), and that declared digest must
  equal the pinned arcs-srs *production* publication_ingest profile-manifest
  digest (production authority). The arcs-verify test-only profile manifest is
  explicitly not a production authority.
- Sequence integrity does not prove the underlying ingest event occurred.
- Sequence integrity does not prove source truth or content completeness.
- Sequence integrity does not prove policy correctness.
- Profile-manifest pin match does not prove the receipts satisfy the profile;
  profile conformance is a separate concern not evaluated by this verifier.
- NOT_EVALUATED is not PASS. not_applicable is not PASS.
"""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

SEQUENCE_SCHEMA = "arcs_verify.ingest_run_sequence_report.v0_1"
SEQUENCE_PROFILE = "arcs_verify.ingest_run_sequence.v0_1"

RUN_DOC_SCHEMA = "dagr.ingest_run.v0.1"
RECEIPT_SET_MANIFEST_SCHEMA = "dagr-ingest.srs-receipt-set-manifest.v0.1"
EXPECTED_PROTOCOL_BINDING = "dagr-ingest/v0.1"

# The authoritative production digest of the arcs-srs
# srs.editorial.publication_ingest.v0.1 profile manifest bytes
# (conformance/profiles/srs.editorial.publication_ingest.v0.1/profile.manifest.json).
# Pinned here as the production authority the receipt-set manifest must declare.
# This is a byte digest, not an import — the verifier still imports no producer
# or standards code.
EXPECTED_PROFILE_MANIFEST_SHA256 = (
    "ec3871e4a1ca0541a0dc81487b0675aa096c15fd5ce5b8da4e93af2a6c49d5e2"
)

# Required boundary declarations in run_doc["boundary"]
REQUIRED_BOUNDARY_DECLARATIONS: tuple[str, ...] = (
    "no_arcs_srs",
    "no_receipts_issued",
    "no_network",
)

# Raw content field names that must not appear in any emitted SRS receipt.
# Reproduced here independently from the binding so the verifier imports no
# producer code.
FORBIDDEN_RAW_RECEIPT_FIELDS: frozenset[str] = frozenset({
    "raw_publication_bytes",
    "raw_frontmatter_yaml",
    "raw_body_text",
})

# Artifact classes that must be present in artifact_classes_excluded for every
# emitted dagr-ingest/v0.1 receipt.
REQUIRED_EXCLUSIONS: frozenset[str] = frozenset({
    "raw_publication_bytes",
    "raw_frontmatter_yaml",
    "raw_body_text",
})

# Manifest skip-category keys, each a list of rel_paths in the real producer
# contract. emitted_receipts is a list of objects and is handled separately.
SKIP_CATEGORY_KEYS: tuple[str, ...] = (
    "skipped_duplicate",
    "skipped_no_parser",
    "profile_not_applicable",
)

# Category label for an occurrence resolved as emitted (a coverage label, not a
# failure code).
EMITTED_CATEGORY = "emitted"

SEQUENCE_LIMITATIONS: list[str] = [
    (
        "Sequence integrity does not prove the underlying ingest event occurred. "
        "A structurally valid sequence does not establish that the files were "
        "read, parsed, or ingested at the declared time."
    ),
    (
        "Sequence integrity does not prove source truth or content completeness. "
        "The verifier does not retrieve or inspect the referenced publication "
        "artifacts."
    ),
    (
        "Sequence integrity does not prove policy correctness. A structurally "
        "valid sequence may not satisfy the governing policy pack."
    ),
    (
        "Profile-manifest pin match does not prove the receipts satisfy the "
        "profile. Profile conformance is a separate concern that the sequence "
        "verifier deliberately does not evaluate."
    ),
    (
        "run_doc boundary declarations are checked structurally — the verifier "
        "confirms they are present and True but does not independently verify "
        "that the run was actually isolated from those systems."
    ),
    (
        "The manifest's output_path values are producer-recorded absolute paths; "
        "the verifier resolves receipt files by receipt_id under the supplied "
        "receipts directory and does not trust output_path as authority."
    ),
    (
        "NOT_EVALUATED is not PASS. not_applicable is not PASS."
    ),
]


class Conclusion(str, Enum):
    TRUE = "true"
    FALSE = "false"
    NOT_EVALUATED = "not_evaluated"


@dataclass(frozen=True, slots=True)
class SequenceFinding:
    code: str
    detail: str


@dataclass(slots=True)
class IngestRunSequenceReport:
    """Independent findings for a dagr.ingest_run.v0.1 editorial sequence.

    No single master status replaces findings. ``passed`` requires the
    structural core findings to be TRUE and no other finding to be FALSE.
    Findings that are NOT_EVALUATED do not gate passed, but FALSE does.
    """

    # Run document findings
    run_doc_schema: Conclusion = Conclusion.NOT_EVALUATED
    boundary_declarations: Conclusion = Conclusion.NOT_EVALUATED

    # Manifest linkage findings
    receipt_set_manifest_schema: Conclusion = Conclusion.NOT_EVALUATED
    run_id_linkage: Conclusion = Conclusion.NOT_EVALUATED
    profile_manifest_pin: Conclusion = Conclusion.NOT_EVALUATED
    profile_manifest_authority: Conclusion = Conclusion.NOT_EVALUATED

    # Per-receipt findings (aggregated over emitted_receipts)
    receipt_file_present: Conclusion = Conclusion.NOT_EVALUATED
    receipt_parse: Conclusion = Conclusion.NOT_EVALUATED
    protocol_binding: Conclusion = Conclusion.NOT_EVALUATED
    receipt_id_binding: Conclusion = Conclusion.NOT_EVALUATED
    subject_ref_manifest: Conclusion = Conclusion.NOT_EVALUATED
    subject_binding: Conclusion = Conclusion.NOT_EVALUATED
    rel_path_binding: Conclusion = Conclusion.NOT_EVALUATED
    corpus_manifest_ref: Conclusion = Conclusion.NOT_EVALUATED
    raw_content_absent: Conclusion = Conclusion.NOT_EVALUATED
    artifact_classes_excluded: Conclusion = Conclusion.NOT_EVALUATED

    # Coverage / posture findings (over run_doc.file_occurrences)
    occurrence_accounting: Conclusion = Conclusion.NOT_EVALUATED
    duplicate_posture: Conclusion = Conclusion.NOT_EVALUATED
    null_parser_posture: Conclusion = Conclusion.NOT_EVALUATED

    findings: list[SequenceFinding] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        def _gates(c: Conclusion) -> bool:
            return c is not Conclusion.FALSE

        return (
            self.run_doc_schema is Conclusion.TRUE
            and self.boundary_declarations is Conclusion.TRUE
            and self.receipt_set_manifest_schema is Conclusion.TRUE
            and self.run_id_linkage is Conclusion.TRUE
            and self.profile_manifest_pin is Conclusion.TRUE
            and self.profile_manifest_authority is Conclusion.TRUE
            and _gates(self.receipt_file_present)
            and _gates(self.receipt_parse)
            and _gates(self.protocol_binding)
            and _gates(self.receipt_id_binding)
            and _gates(self.subject_ref_manifest)
            and _gates(self.subject_binding)
            and _gates(self.rel_path_binding)
            and _gates(self.corpus_manifest_ref)
            and _gates(self.raw_content_absent)
            and _gates(self.artifact_classes_excluded)
            and _gates(self.occurrence_accounting)
            and _gates(self.duplicate_posture)
            and _gates(self.null_parser_posture)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SEQUENCE_SCHEMA,
            "verification_profile": SEQUENCE_PROFILE,
            "findings": [
                {"code": f.code, "detail": f.detail}
                for f in self.findings
            ],
            "conclusions": {
                "run_doc_schema": self.run_doc_schema.value,
                "boundary_declarations": self.boundary_declarations.value,
                "receipt_set_manifest_schema": (
                    self.receipt_set_manifest_schema.value
                ),
                "run_id_linkage": self.run_id_linkage.value,
                "profile_manifest_pin": self.profile_manifest_pin.value,
                "profile_manifest_authority": (
                    self.profile_manifest_authority.value
                ),
                "receipt_file_present": self.receipt_file_present.value,
                "receipt_parse": self.receipt_parse.value,
                "protocol_binding": self.protocol_binding.value,
                "receipt_id_binding": self.receipt_id_binding.value,
                "subject_ref_manifest": self.subject_ref_manifest.value,
                "subject_binding": self.subject_binding.value,
                "rel_path_binding": self.rel_path_binding.value,
                "corpus_manifest_ref": self.corpus_manifest_ref.value,
                "raw_content_absent": self.raw_content_absent.value,
                "artifact_classes_excluded": (
                    self.artifact_classes_excluded.value
                ),
                "occurrence_accounting": self.occurrence_accounting.value,
                "duplicate_posture": self.duplicate_posture.value,
                "null_parser_posture": self.null_parser_posture.value,
            },
            "passed": self.passed,
            "limitations": SEQUENCE_LIMITATIONS,
        }


def _fail(
    report: IngestRunSequenceReport,
    code: str,
    detail: str,
) -> None:
    report.findings.append(SequenceFinding(code=code, detail=detail))


def verify_ingest_run_sequence(
    run_doc_path: Path,
    receipt_set_manifest_path: Path,
    receipts_dir: Path,
    profile_manifest_path: Path,
) -> IngestRunSequenceReport:
    """Independently verify the linkage between a dagr.ingest_run.v0.1 run
    document, a producer-owned SRS receipt-set manifest, and the individual
    SRS receipts it enumerates.

    Parameters
    ----------
    run_doc_path:
        Path to the dagr.ingest_run.v0.1 run document JSON file.
    receipt_set_manifest_path:
        Path to the dagr-ingest.srs-receipt-set-manifest.v0.1 manifest JSON file.
    receipts_dir:
        Directory containing the individual receipt JSON files. Receipts are
        resolved as ``<receipt_id>.json`` under this directory; the manifest's
        output_path is not trusted as a filesystem authority.
    profile_manifest_path:
        Path to the SRS profile manifest file whose sha256 is pinned in
        the receipt-set manifest.
    """
    report = IngestRunSequenceReport()

    # -----------------------------------------------------------------------
    # Load run document
    # -----------------------------------------------------------------------
    try:
        run_doc_text = run_doc_path.read_text(encoding="utf-8")
    except OSError as exc:
        _fail(report, "INGEST_RUN_SCHEMA_MISMATCH", f"run doc unreadable: {exc}")
        report.run_doc_schema = Conclusion.FALSE
        _propagate_false_early(report)
        return report

    try:
        run_doc: dict[str, Any] = json.loads(run_doc_text)
    except json.JSONDecodeError as exc:
        _fail(report, "INGEST_RUN_SCHEMA_MISMATCH", f"run doc malformed JSON: {exc}")
        report.run_doc_schema = Conclusion.FALSE
        _propagate_false_early(report)
        return report

    if not isinstance(run_doc, dict):
        _fail(
            report,
            "INGEST_RUN_SCHEMA_MISMATCH",
            "run doc is not a JSON object",
        )
        report.run_doc_schema = Conclusion.FALSE
        _propagate_false_early(report)
        return report

    # -----------------------------------------------------------------------
    # Check 1: Run doc schema discriminator
    # -----------------------------------------------------------------------
    run_schema = run_doc.get("schema")
    if run_schema != RUN_DOC_SCHEMA:
        _fail(
            report,
            "INGEST_RUN_SCHEMA_MISMATCH",
            (
                f"run_doc[\"schema\"] == {run_schema!r}; "
                f"expected {RUN_DOC_SCHEMA!r}"
            ),
        )
        report.run_doc_schema = Conclusion.FALSE
    else:
        report.run_doc_schema = Conclusion.TRUE

    # -----------------------------------------------------------------------
    # Check 2: Run boundary declarations
    # -----------------------------------------------------------------------
    boundary = run_doc.get("boundary")
    boundary_ok = True
    if not isinstance(boundary, dict):
        _fail(
            report,
            "INGEST_RUN_BOUNDARY_VIOLATION",
            "run_doc[\"boundary\"] is absent or not an object",
        )
        boundary_ok = False
    else:
        for key in REQUIRED_BOUNDARY_DECLARATIONS:
            if boundary.get(key) is not True:
                _fail(
                    report,
                    "INGEST_RUN_BOUNDARY_VIOLATION",
                    (
                        f"run_doc[\"boundary\"][\"{key}\"] is not True "
                        f"(got {boundary.get(key)!r})"
                    ),
                )
                boundary_ok = False

    report.boundary_declarations = (
        Conclusion.TRUE if boundary_ok else Conclusion.FALSE
    )

    # -----------------------------------------------------------------------
    # Load receipt-set manifest
    # -----------------------------------------------------------------------
    try:
        manifest_text = receipt_set_manifest_path.read_text(encoding="utf-8")
    except OSError as exc:
        _fail(
            report,
            "RECEIPT_SET_MANIFEST_SCHEMA_MISMATCH",
            f"manifest unreadable: {exc}",
        )
        report.receipt_set_manifest_schema = Conclusion.FALSE
        _propagate_false_on_missing_manifest(report)
        return report

    try:
        manifest: dict[str, Any] = json.loads(manifest_text)
    except json.JSONDecodeError as exc:
        _fail(
            report,
            "RECEIPT_SET_MANIFEST_SCHEMA_MISMATCH",
            f"manifest malformed JSON: {exc}",
        )
        report.receipt_set_manifest_schema = Conclusion.FALSE
        _propagate_false_on_missing_manifest(report)
        return report

    if not isinstance(manifest, dict):
        _fail(
            report,
            "RECEIPT_SET_MANIFEST_SCHEMA_MISMATCH",
            "manifest is not a JSON object",
        )
        report.receipt_set_manifest_schema = Conclusion.FALSE
        _propagate_false_on_missing_manifest(report)
        return report

    # -----------------------------------------------------------------------
    # Check 3: Receipt-set manifest schema discriminator
    # -----------------------------------------------------------------------
    manifest_schema = manifest.get("schema")
    manifest_schema_ok = True
    if manifest_schema != RECEIPT_SET_MANIFEST_SCHEMA:
        _fail(
            report,
            "RECEIPT_SET_MANIFEST_SCHEMA_MISMATCH",
            (
                f"manifest[\"schema\"] == {manifest_schema!r}; "
                f"expected {RECEIPT_SET_MANIFEST_SCHEMA!r}"
            ),
        )
        manifest_schema_ok = False

    # emitted_receipts must be present as a list of objects.
    emitted_receipts = manifest.get("emitted_receipts")
    if not isinstance(emitted_receipts, list):
        _fail(
            report,
            "RECEIPT_SET_MANIFEST_SCHEMA_MISMATCH",
            "manifest[\"emitted_receipts\"] is absent or not an array",
        )
        manifest_schema_ok = False
        emitted_receipts = []

    report.receipt_set_manifest_schema = (
        Conclusion.TRUE if manifest_schema_ok else Conclusion.FALSE
    )

    # -----------------------------------------------------------------------
    # Check 4: Run ID linkage
    # -----------------------------------------------------------------------
    run_id = run_doc.get("run_id")
    manifest_run_id = manifest.get("run_id")
    if run_id != manifest_run_id:
        _fail(
            report,
            "RUN_ID_MISMATCH",
            (
                f"manifest[\"run_id\"] == {manifest_run_id!r}; "
                f"run_doc[\"run_id\"] == {run_id!r}"
            ),
        )
        report.run_id_linkage = Conclusion.FALSE
    else:
        report.run_id_linkage = Conclusion.TRUE

    # -----------------------------------------------------------------------
    # Check 5: Profile manifest pin (independently recompute sha256) and
    #          production-authority (declared digest == pinned production digest)
    # -----------------------------------------------------------------------
    declared_sha256 = manifest.get("profile_manifest_sha256", "")
    try:
        profile_manifest_bytes = profile_manifest_path.read_bytes()
    except OSError as exc:
        _fail(
            report,
            "PROFILE_MANIFEST_PIN_MISMATCH",
            f"profile manifest unreadable: {exc}",
        )
        report.profile_manifest_pin = Conclusion.FALSE
    else:
        actual_sha256 = hashlib.sha256(profile_manifest_bytes).hexdigest()
        if actual_sha256 != declared_sha256:
            _fail(
                report,
                "PROFILE_MANIFEST_PIN_MISMATCH",
                (
                    f"profile manifest sha256 recomputed as {actual_sha256!r}; "
                    f"manifest declares {declared_sha256!r}"
                ),
            )
            report.profile_manifest_pin = Conclusion.FALSE
        else:
            report.profile_manifest_pin = Conclusion.TRUE

    # Production authority: the digest the manifest declares must be the pinned
    # arcs-srs production publication_ingest profile-manifest digest. This is a
    # separate finding from pin integrity: a self-consistent manifest+profile
    # pair that pins a non-production (e.g. test-only) manifest still fails here.
    if declared_sha256 == EXPECTED_PROFILE_MANIFEST_SHA256:
        report.profile_manifest_authority = Conclusion.TRUE
    else:
        _fail(
            report,
            "PROFILE_MANIFEST_AUTHORITY_MISMATCH",
            (
                f"manifest declares profile_manifest_sha256 {declared_sha256!r}; "
                f"expected the arcs-srs production publication_ingest digest "
                f"{EXPECTED_PROFILE_MANIFEST_SHA256!r}"
            ),
        )
        report.profile_manifest_authority = Conclusion.FALSE

    # -----------------------------------------------------------------------
    # Check 6: Per-receipt checks over emitted_receipts entries
    # -----------------------------------------------------------------------
    expected_corpus_manifest_ref = (
        "sha256:" + run_id if isinstance(run_id, str) else None
    )

    emitted_entries = [e for e in emitted_receipts if isinstance(e, dict)]

    file_present_ok = True
    parse_ok = True
    protocol_binding_ok = True
    receipt_id_ok = True
    subject_ref_manifest_ok = True
    subject_binding_ok = True
    rel_path_ok = True
    corpus_manifest_ref_ok = True
    raw_content_ok = True
    exclusions_ok = True

    has_emitted = bool(emitted_entries)

    for entry in emitted_entries:
        entry_receipt_id = entry.get("receipt_id")
        entry_subject_ref = entry.get("subject_ref")
        entry_rel_path = entry.get("rel_path")

        # 6a: Resolve the receipt file by receipt_id (never by output_path).
        if not isinstance(entry_receipt_id, str) or not entry_receipt_id:
            file_present_ok = False
            _fail(
                report,
                "RECEIPT_FILE_MISSING",
                f"emitted entry has no usable receipt_id: {entry!r}",
            )
            continue

        receipt_path = receipts_dir / f"{entry_receipt_id}.json"
        if not receipt_path.is_file():
            file_present_ok = False
            _fail(
                report,
                "RECEIPT_FILE_MISSING",
                (
                    f"receipt file not found for receipt_id "
                    f"{entry_receipt_id!r}: {receipt_path}"
                ),
            )
            continue

        # 6b: Parse receipt JSON
        try:
            receipt_text = receipt_path.read_text(encoding="utf-8")
        except OSError as exc:
            parse_ok = False
            _fail(
                report,
                "RECEIPT_PARSE_ERROR",
                f"receipt {entry_receipt_id!r} unreadable: {exc}",
            )
            continue

        try:
            receipt: dict[str, Any] = json.loads(receipt_text)
        except json.JSONDecodeError as exc:
            parse_ok = False
            _fail(
                report,
                "RECEIPT_PARSE_ERROR",
                f"receipt {entry_receipt_id!r} malformed JSON: {exc}",
            )
            continue

        if not isinstance(receipt, dict):
            parse_ok = False
            _fail(
                report,
                "RECEIPT_PARSE_ERROR",
                f"receipt {entry_receipt_id!r} is not a JSON object",
            )
            continue

        # 6c: protocol_binding == "dagr-ingest/v0.1"
        pb = receipt.get("protocol_binding")
        if pb != EXPECTED_PROTOCOL_BINDING:
            protocol_binding_ok = False
            _fail(
                report,
                "PROTOCOL_BINDING_MISMATCH",
                (
                    f"receipt {entry_receipt_id!r} protocol_binding == {pb!r}; "
                    f"expected {EXPECTED_PROTOCOL_BINDING!r}"
                ),
            )

        # 6d: receipt["receipt_id"] == entry["receipt_id"]
        receipt_receipt_id = receipt.get("receipt_id")
        if receipt_receipt_id != entry_receipt_id:
            receipt_id_ok = False
            _fail(
                report,
                "RECEIPT_ID_MISMATCH",
                (
                    f"resolved receipt at {receipt_path.name} declares "
                    f"receipt_id {receipt_receipt_id!r}; manifest entry "
                    f"receipt_id == {entry_receipt_id!r}"
                ),
            )

        # 6e: receipt["subject_ref"] == entry["subject_ref"]
        receipt_subject_ref = receipt.get("subject_ref")
        if receipt_subject_ref != entry_subject_ref:
            subject_ref_manifest_ok = False
            _fail(
                report,
                "SUBJECT_REF_MANIFEST_MISMATCH",
                (
                    f"receipt {entry_receipt_id!r} subject_ref == "
                    f"{receipt_subject_ref!r}; manifest entry subject_ref == "
                    f"{entry_subject_ref!r}"
                ),
            )

        # 6f: receipt["subject_ref"] == receipt["publication_artifact_id"]
        pub_artifact_id = receipt.get("publication_artifact_id")
        if receipt_subject_ref != pub_artifact_id:
            subject_binding_ok = False
            _fail(
                report,
                "SUBJECT_BINDING_MISMATCH",
                (
                    f"receipt {entry_receipt_id!r}: "
                    f"subject_ref == {receipt_subject_ref!r} "
                    f"but publication_artifact_id == {pub_artifact_id!r}"
                ),
            )

        # 6g: receipt["relative_path"] == entry["rel_path"]
        receipt_rel_path = receipt.get("relative_path")
        if receipt_rel_path != entry_rel_path:
            rel_path_ok = False
            _fail(
                report,
                "REL_PATH_MISMATCH",
                (
                    f"receipt {entry_receipt_id!r} relative_path == "
                    f"{receipt_rel_path!r}; manifest entry rel_path == "
                    f"{entry_rel_path!r}"
                ),
            )

        # 6h: receipt["corpus_manifest_ref"] == "sha256:" + run_doc["run_id"]
        actual_corpus_manifest_ref = receipt.get("corpus_manifest_ref")
        if actual_corpus_manifest_ref != expected_corpus_manifest_ref:
            corpus_manifest_ref_ok = False
            _fail(
                report,
                "CORPUS_MANIFEST_REF_MISMATCH",
                (
                    f"receipt {entry_receipt_id!r}: "
                    f"corpus_manifest_ref == {actual_corpus_manifest_ref!r}; "
                    f"expected {expected_corpus_manifest_ref!r}"
                ),
            )

        # 6i: No raw content fields present
        for raw_field in FORBIDDEN_RAW_RECEIPT_FIELDS:
            if raw_field in receipt:
                raw_content_ok = False
                _fail(
                    report,
                    "RAW_CONTENT_PRESENT",
                    (
                        f"receipt {entry_receipt_id!r} contains forbidden "
                        f"raw-content field: {raw_field!r}"
                    ),
                )

        # 6j: artifact_classes_excluded contains all required exclusions
        excluded = receipt.get("artifact_classes_excluded")
        if not isinstance(excluded, list):
            exclusions_ok = False
            _fail(
                report,
                "MISSING_REQUIRED_EXCLUSION",
                (
                    f"receipt {entry_receipt_id!r}: "
                    "artifact_classes_excluded is absent or not a list"
                ),
            )
        else:
            excluded_set = set(excluded)
            for req_excl in sorted(REQUIRED_EXCLUSIONS):
                if req_excl not in excluded_set:
                    exclusions_ok = False
                    _fail(
                        report,
                        "MISSING_REQUIRED_EXCLUSION",
                        (
                            f"receipt {entry_receipt_id!r}: "
                            f"artifact_classes_excluded missing {req_excl!r}"
                        ),
                    )

    # Assign per-receipt aggregated conclusions. With no emitted entries these
    # stay NOT_EVALUATED (there is nothing to recompute).
    if has_emitted:
        report.receipt_file_present = (
            Conclusion.TRUE if file_present_ok else Conclusion.FALSE
        )
        report.receipt_parse = (
            Conclusion.TRUE if parse_ok else Conclusion.FALSE
        )
        report.protocol_binding = (
            Conclusion.TRUE if protocol_binding_ok else Conclusion.FALSE
        )
        report.receipt_id_binding = (
            Conclusion.TRUE if receipt_id_ok else Conclusion.FALSE
        )
        report.subject_ref_manifest = (
            Conclusion.TRUE if subject_ref_manifest_ok else Conclusion.FALSE
        )
        report.subject_binding = (
            Conclusion.TRUE if subject_binding_ok else Conclusion.FALSE
        )
        report.rel_path_binding = (
            Conclusion.TRUE if rel_path_ok else Conclusion.FALSE
        )
        report.corpus_manifest_ref = (
            Conclusion.TRUE if corpus_manifest_ref_ok else Conclusion.FALSE
        )
        report.raw_content_absent = (
            Conclusion.TRUE if raw_content_ok else Conclusion.FALSE
        )
        report.artifact_classes_excluded = (
            Conclusion.TRUE if exclusions_ok else Conclusion.FALSE
        )

    # -----------------------------------------------------------------------
    # Coverage / posture over run_doc.file_occurrences and the manifest's
    # emitted/skip categories. Each occurrence, keyed by rel_path (the key the
    # producer itself uses across emitted_receipts and the skip lists), must be
    # accounted for in exactly one category, consistently with its own fields.
    # -----------------------------------------------------------------------
    file_occurrences = run_doc.get("file_occurrences")

    # Validate skip-category shapes independently of coverage so a malformed
    # posture is a distinct, non-vacuous finding.
    skip_sets: dict[str, set[str]] = {}
    skip_categories_ok = True
    for key in SKIP_CATEGORY_KEYS:
        value = manifest.get(key)
        if value is None:
            skip_categories_ok = False
            _fail(
                report,
                "SKIP_CATEGORY_MALFORMED",
                f"manifest[\"{key}\"] is absent",
            )
            skip_sets[key] = set()
        elif not isinstance(value, list) or not all(
            isinstance(v, str) for v in value
        ):
            skip_categories_ok = False
            _fail(
                report,
                "SKIP_CATEGORY_MALFORMED",
                f"manifest[\"{key}\"] is not a list of strings",
            )
            skip_sets[key] = {v for v in (value or []) if isinstance(v, str)}
        else:
            skip_sets[key] = set(value)

    emitted_rel_paths: set[str] = {
        e.get("rel_path")
        for e in emitted_entries
        if isinstance(e.get("rel_path"), str)
    }

    if not isinstance(file_occurrences, list) or not file_occurrences:
        # Cannot recompute coverage without occurrences.
        report.occurrence_accounting = Conclusion.NOT_EVALUATED
        report.duplicate_posture = Conclusion.NOT_EVALUATED
        report.null_parser_posture = Conclusion.NOT_EVALUATED
    else:
        accounting_ok = True
        duplicate_ok = True
        null_parser_ok = True

        for occ in file_occurrences:
            if not isinstance(occ, dict):
                continue
            rel = occ.get("rel_path")
            if not isinstance(rel, str) or not rel:
                accounting_ok = False
                _fail(
                    report,
                    "OCCURRENCE_NOT_ACCOUNTED",
                    f"file occurrence lacks a usable rel_path: {occ!r}",
                )
                continue

            is_dup = occ.get("is_duplicate_content", False) is True
            parser_id = occ.get("parser_id")

            categories = []
            if rel in emitted_rel_paths:
                categories.append(EMITTED_CATEGORY)
            for key in SKIP_CATEGORY_KEYS:
                if rel in skip_sets[key]:
                    categories.append(key)

            if len(categories) == 0:
                accounting_ok = False
                _fail(
                    report,
                    "OCCURRENCE_NOT_ACCOUNTED",
                    (
                        f"file occurrence rel_path={rel!r} appears in no "
                        "manifest category (emitted / skipped_duplicate / "
                        "skipped_no_parser / profile_not_applicable)"
                    ),
                )
            elif len(categories) > 1:
                accounting_ok = False
                _fail(
                    report,
                    "SKIP_CATEGORY_MALFORMED",
                    (
                        f"file occurrence rel_path={rel!r} appears in multiple "
                        f"manifest categories: {categories}"
                    ),
                )

            if is_dup and EMITTED_CATEGORY in categories:
                duplicate_ok = False
                _fail(
                    report,
                    "DUPLICATE_POSTURE_VIOLATION",
                    (
                        f"file occurrence rel_path={rel!r} has "
                        "is_duplicate_content=True but appears as emitted "
                        "in the manifest"
                    ),
                )

            if parser_id is None and EMITTED_CATEGORY in categories:
                null_parser_ok = False
                _fail(
                    report,
                    "NULL_PARSER_POSTURE_VIOLATION",
                    (
                        f"file occurrence rel_path={rel!r} has a null parser_id "
                        "but appears as emitted in the manifest"
                    ),
                )

        report.occurrence_accounting = (
            Conclusion.TRUE
            if (accounting_ok and skip_categories_ok)
            else Conclusion.FALSE
        )
        report.duplicate_posture = (
            Conclusion.TRUE if duplicate_ok else Conclusion.FALSE
        )
        report.null_parser_posture = (
            Conclusion.TRUE if null_parser_ok else Conclusion.FALSE
        )

    return report


def _propagate_false_early(report: IngestRunSequenceReport) -> None:
    """When the run doc is unreadable, mark all dependent findings FALSE."""
    for attr in (
        "boundary_declarations",
        "receipt_set_manifest_schema",
        "run_id_linkage",
        "profile_manifest_pin",
        "profile_manifest_authority",
        "receipt_file_present",
        "receipt_parse",
        "protocol_binding",
        "receipt_id_binding",
        "subject_ref_manifest",
        "subject_binding",
        "rel_path_binding",
        "corpus_manifest_ref",
        "raw_content_absent",
        "artifact_classes_excluded",
        "occurrence_accounting",
        "duplicate_posture",
        "null_parser_posture",
    ):
        if getattr(report, attr) is Conclusion.NOT_EVALUATED:
            setattr(report, attr, Conclusion.FALSE)


def _propagate_false_on_missing_manifest(report: IngestRunSequenceReport) -> None:
    """When the manifest is unreadable, mark manifest-dependent findings FALSE."""
    for attr in (
        "run_id_linkage",
        "profile_manifest_pin",
        "profile_manifest_authority",
        "receipt_file_present",
        "receipt_parse",
        "protocol_binding",
        "receipt_id_binding",
        "subject_ref_manifest",
        "subject_binding",
        "rel_path_binding",
        "corpus_manifest_ref",
        "raw_content_absent",
        "artifact_classes_excluded",
        "occurrence_accounting",
        "duplicate_posture",
        "null_parser_posture",
    ):
        if getattr(report, attr) is Conclusion.NOT_EVALUATED:
            setattr(report, attr, Conclusion.FALSE)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def build_parser() -> "argparse.ArgumentParser":
    import argparse

    parser = argparse.ArgumentParser(
        prog="arcs-verify ingest-run-sequence",
        description=(
            "Independently verify the linkage between a dagr.ingest_run.v0.1 "
            "run document, a producer-owned SRS receipt-set manifest "
            "(dagr-ingest.srs-receipt-set-manifest.v0.1), and the individual "
            "SRS receipts. Imports no dagr_ingest producer code."
        ),
    )
    parser.add_argument(
        "--run-doc",
        required=True,
        type=Path,
        metavar="RUN_DOC_JSON",
        help="Path to the dagr.ingest_run.v0.1 run document JSON file.",
    )
    parser.add_argument(
        "--receipt-set-manifest",
        required=True,
        type=Path,
        metavar="MANIFEST_JSON",
        help=(
            "Path to the dagr-ingest.srs-receipt-set-manifest.v0.1 "
            "receipt-set manifest JSON file."
        ),
    )
    parser.add_argument(
        "--receipts-dir",
        required=True,
        type=Path,
        metavar="RECEIPTS_DIR",
        help=(
            "Directory containing the individual receipt JSON files, each "
            "named <receipt_id>.json."
        ),
    )
    parser.add_argument(
        "--profile-manifest",
        required=True,
        type=Path,
        metavar="PROFILE_MANIFEST_JSON",
        help=(
            "Path to the SRS profile manifest file whose sha256 is pinned "
            "in the receipt-set manifest."
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Emit report as JSON.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
    except SystemExit as exc:
        return int(exc.code)

    for attr, label in (
        ("run_doc", "--run-doc"),
        ("receipt_set_manifest", "--receipt-set-manifest"),
        ("receipts_dir", "--receipts-dir"),
        ("profile_manifest", "--profile-manifest"),
    ):
        p: Path = getattr(args, attr)
        if attr == "receipts_dir":
            if not p.is_dir():
                sys.stderr.write(f"error: {label} is not a directory: {p}\n")
                return 2
        else:
            if not p.is_file():
                sys.stderr.write(f"error: {label} not found: {p}\n")
                return 2

    report = verify_ingest_run_sequence(
        run_doc_path=args.run_doc,
        receipt_set_manifest_path=args.receipt_set_manifest,
        receipts_dir=args.receipts_dir,
        profile_manifest_path=args.profile_manifest,
    )
    data = report.to_dict()

    if args.as_json:
        json.dump(data, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        print(f"profile: {data['verification_profile']}")
        conclusions = data["conclusions"]
        for name, value in conclusions.items():
            print(f"{name}: {value.upper()}")
        print(f"passed: {str(data['passed']).lower()}")
        for finding in data["findings"]:
            print(f"finding: {finding['code']}: {finding['detail']}")

    return 0 if report.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
