"""Independent verifier for counterpedia-acquisition grounded content proposals.

ARCSV-ACQGROUND0 verifies that the serialized grounded proposal is correctly
bound to the serialized acquisition evidence it claims to derive from. It does
NOT verify that the source is true or that the proposal is admitted.

"Grounded" is not "correct". This verifier decides no truth, admission,
standing, or publication. A PASS attests only that:

  * artifact_integrity — the proposal's ``artifact_digest`` recomputes from the
    exact captured source bytes supplied to the verifier;
  * grounding_integrity — the envelope is the pinned grounded-proposal contract,
    and every EXTRACTIVE field's claimed span, sliced out of an independently
    recomputed extraction projection and normalized, matches the proposed field
    text EXACTLY (no fuzzy / semantic / substring rescue), while ABSTRACTIVE
    (synthesis) fields are explicitly typed and never carry a verified anchor,
    and every dropped-ungrounded disposition is well formed;
  * proposal_posture — the wrapped record remains proposal-only and carries no
    admission / standing / canonical-id authority field.

The three axes are reported SEPARATELY. There is no master trust score, and no
axis means "the claim is true" or "the source is trustworthy" or "admitted".
``NOT_EVALUATED`` is never PASS.

Independence (arcs-verify's core invariant)
-------------------------------------------
This module imports ZERO counterpedia_acquisition / dagr_ingest / producer code.
The ``acquisition.html-visible-text.v0.1`` extraction projection below is an
independent transcription of the deterministic, stdlib-only algorithm specified
by the pinned producer contract (counterpedia-acquisition commit
``d4b1127d84816cc8279fc2ea0b16358006b37745``,
``src/acquisition/model_grounding.py`` @
sha256:74808a5cf56d73ebb61ff5fa9b856b301dde2cdb17fada5a759ec599859517d8):
decode UTF-8 with replacement, collect visible text via the standard-library
``html.parser`` (ignoring ``script`` / ``style`` subtrees), collapse each
non-empty node's Unicode whitespace to a single ASCII space, join non-empty
nodes with a newline; offsets are code-point indexes into that string. The
verifier recomputes this from bytes; it never runs or imports the producer.

Pinned facts (byte-frozen; re-pin only when the producer contract advances):
  * grounded-proposal envelope schema id ``acquisition.grounded_content_proposal.v0.1``
    schema bytes @ sha256:ec1d99e4af43761ee7d7c2bf6a6978315c8fdf69dd05e055ee98d4af605d0894
    (vendored at vendor/counterpedia-acquisition/schemas/grounded_content_proposal.schema.json)
  * extraction profile id ``acquisition.html-visible-text.v0.1``
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Optional

import jsonschema

# --------------------------------------------------------------------------- #
# pinned producer contract facts
# --------------------------------------------------------------------------- #
ACQUISITION_PIN_COMMIT = "d4b1127d84816cc8279fc2ea0b16358006b37745"
GROUNDED_ENVELOPE_SCHEMA_ID = "acquisition.grounded_content_proposal.v0.1"
CONTENT_PROPOSAL_SCHEMA_ID = "acquisition.content_proposal.v0.1"
EXTRACTION_PROFILE_ID = "acquisition.html-visible-text.v0.1"

_VENDOR_SCHEMA = (
    Path(__file__).resolve().parent.parent
    / "vendor"
    / "counterpedia-acquisition"
    / "schemas"
    / "grounded_content_proposal.schema.json"
)
# sha256 of the vendored schema bytes, byte-identical to the pinned producer
# schema at ACQUISITION_PIN_COMMIT. Recomputed at verification time so a
# tampered local schema fails closed rather than silently changing the contract.
GROUNDED_ENVELOPE_SCHEMA_SHA256 = (
    "ec1d99e4af43761ee7d7c2bf6a6978315c8fdf69dd05e055ee98d4af605d0894"
)
# sha256 of the pinned producer spec source (model_grounding.py) that this
# module's projection independently transcribes. Provenance only; never loaded.
EXTRACTION_PROFILE_SPEC_SHA256 = (
    "74808a5cf56d73ebb61ff5fa9b856b301dde2cdb17fada5a759ec599859517d8"
)

# Closed v0.1 vocabularies transcribed from the pinned contract.
GROUNDING_KINDS = ("extractive", "abstractive")
GROUNDING_DROP_REASONS = (
    "missing_span",
    "span_out_of_range",
    "span_text_mismatch",
    "invalid_span",
    "artifact_digest_mismatch",
    "extraction_profile_mismatch",
)
# Fields the producer contract states are explicitly ABSENT from a proposal;
# their presence anywhere would assert authority the proposal must not claim.
FORBIDDEN_AUTHORITY_FIELDS = frozenset(
    {
        "admitted",
        "refused",
        "standing",
        "canonical_id",
        "trace_id",
        "srs_verified",
        "counterpedia_id",
    }
)

REPORT_SCHEMA = "arcs_verify.acquisition_grounding_report.v0_1"
VERIFICATION_PROFILE = "arcs_verify.counterpedia_acquisition.grounded_proposal.v0_1"

_SHA256_REF = "sha256:"


# --------------------------------------------------------------------------- #
# independent extraction projection: acquisition.html-visible-text.v0.1
# (stdlib-only transcription of the pinned spec — imports no producer code)
# --------------------------------------------------------------------------- #
class _VisibleTextParser(HTMLParser):
    """Collect visible text nodes, ignoring ``script`` / ``style`` subtrees."""

    _SKIP_TAGS = frozenset({"script", "style"})

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._skip_depth = 0
        self.nodes: list[str] = []

    def handle_starttag(self, tag: str, attrs: object) -> None:
        if tag in self._SKIP_TAGS:
            self._skip_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in self._SKIP_TAGS and self._skip_depth > 0:
            self._skip_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._skip_depth == 0:
            self.nodes.append(data)


def normalize_whitespace(text: str) -> str:
    """Collapse Unicode whitespace runs to one ASCII space and strip.

    ``" ".join(text.split())`` is exactly the pinned spec's normalization.
    """

    return " ".join(text.split())


def project_html_visible_text(content: bytes) -> str:
    """Independently derive the ``acquisition.html-visible-text.v0.1`` projection.

    Decode UTF-8 with replacement, collect visible text (ignoring script/style),
    normalize each node's whitespace, join non-empty nodes with a newline.
    Offsets are Python str code-point indexes into the result. Deterministic.
    """

    text = content.decode("utf-8", errors="replace")
    parser = _VisibleTextParser()
    parser.feed(text)
    parser.close()
    normalized = [normalize_whitespace(node) for node in parser.nodes]
    return "\n".join(node for node in normalized if node)


def _artifact_digest(content: bytes) -> str:
    return _SHA256_REF + hashlib.sha256(content).hexdigest()


def _is_sha256_ref(value: object) -> bool:
    if not isinstance(value, str) or not value.startswith(_SHA256_REF):
        return False
    hex_part = value[len(_SHA256_REF):]
    return len(hex_part) == 64 and all(c in "0123456789abcdef" for c in hex_part)


# --------------------------------------------------------------------------- #
# schema (offline, byte-pinned)
# --------------------------------------------------------------------------- #
class SourceIntegrityError(Exception):
    """Unreadable / malformed input: usage posture, exit 2 (not a verdict)."""


def _load_schema() -> tuple[dict, str]:
    raw = _VENDOR_SCHEMA.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    return json.loads(raw), digest


def _all_keys(obj: Any) -> set[str]:
    keys: set[str] = set()
    if isinstance(obj, dict):
        for key, value in obj.items():
            keys.add(str(key))
            keys |= _all_keys(value)
    elif isinstance(obj, (list, tuple)):
        for value in obj:
            keys |= _all_keys(value)
    return keys


# --------------------------------------------------------------------------- #
# verification core
# --------------------------------------------------------------------------- #
_ARTIFACT_CONCL = ("artifact_digest_format", "artifact_digest_recomputes")
_GROUNDING_CONCL = (
    "schema_digest",
    "schema_version_pinned",
    "envelope_schema_valid",
    "extraction_profile_pinned",
    "field_grounding_binding",
    "extractive_anchors_recompute",
    "abstractive_typing",
    "dropped_dispositions_wellformed",
)
_POSTURE_CONCL = ("lifecycle_is_proposal", "no_authority_fields")


_AXIS_FAIL = "FAIL"
_AXIS_PARTIAL = "PARTIAL"
_AXIS_PASS = "PASS"


def _fold(concl: dict[str, str], names: tuple[str, ...]) -> str:
    values = [concl[name] for name in names if name in concl]
    axis = _AXIS_PASS
    if "FAIL" in values:
        axis = _AXIS_FAIL
    elif "NOT_EVALUATED" in values:
        axis = _AXIS_PARTIAL
    return axis


def verify(envelope: dict, source_bytes: bytes) -> dict:
    """Recompute the three grounding axes from serialized bytes only.

    ``envelope`` is the serialized grounded-proposal JSON (already parsed to a
    dict); ``source_bytes`` are the exact captured source bytes the proposal
    claims to derive from. No producer code is consulted.
    """

    findings: list[str] = []
    concl: dict[str, str] = {}
    recomputed: dict[str, Any] = {}

    def C(name: str, ok: bool) -> bool:
        concl[name] = "PASS" if ok else "FAIL"
        return ok

    def NE(name: str) -> None:
        concl[name] = "NOT_EVALUATED"

    # ----- schema: vendored bytes pinned, then structural validation --------
    schema_ok = True
    try:
        schema, schema_digest = _load_schema()
    except (OSError, json.JSONDecodeError):
        schema = None
        schema_digest = ""
    recomputed["schema_digest"] = schema_digest
    if schema is None or schema_digest != GROUNDED_ENVELOPE_SCHEMA_SHA256:
        findings.append("acquisition_grounding.schema_digest_mismatch")
        C("schema_digest", False)
        schema_ok = False
    else:
        C("schema_digest", True)

    declared_version = envelope.get("schema_version")
    if not C("schema_version_pinned", declared_version == GROUNDED_ENVELOPE_SCHEMA_ID):
        findings.append("acquisition_grounding.schema_version_mismatch")

    if schema_ok:
        errors = sorted(
            jsonschema.Draft202012Validator(schema).iter_errors(envelope),
            key=lambda e: e.path,
        )
        if not C("envelope_schema_valid", not errors):
            findings.append("acquisition_grounding.envelope_schema_invalid")
    else:
        NE("envelope_schema_valid")

    # ----- artifact_integrity: digest form + exact-byte recomputation -------
    claimed_digest = envelope.get("artifact_digest")
    if not C("artifact_digest_format", _is_sha256_ref(claimed_digest)):
        findings.append("acquisition_grounding.artifact_digest_malformed")
    recomputed_digest = _artifact_digest(source_bytes)
    recomputed["artifact_digest"] = recomputed_digest
    if not C("artifact_digest_recomputes", recomputed_digest == claimed_digest):
        findings.append("acquisition_grounding.artifact_digest_mismatch")

    # ----- extraction profile pinned (envelope level) -----------------------
    if not C(
        "extraction_profile_pinned",
        envelope.get("extraction_profile") == EXTRACTION_PROFILE_ID,
    ):
        findings.append("acquisition_grounding.extraction_profile_unknown")

    # ----- independent projection over the supplied bytes -------------------
    projection = project_html_visible_text(source_bytes)
    projection_len = len(projection)
    recomputed["projection_length"] = projection_len

    content_proposal = envelope.get("content_proposal")
    fields = content_proposal.get("fields") if isinstance(content_proposal, dict) else None
    field_grounding = envelope.get("field_grounding")

    # ----- field_grounding binding to fields (producer inseparability) ------
    binding_ok = (
        isinstance(fields, list)
        and isinstance(field_grounding, list)
        and len(field_grounding) == len(fields)
        and all(isinstance(fg, dict) for fg in field_grounding)
        and sorted(
            fg.get("field_index") for fg in field_grounding
        ) == list(range(len(fields)))
    )
    if not C("field_grounding_binding", binding_ok):
        findings.append("acquisition_grounding.field_grounding_binding_invalid")

    # ----- per-field grounding recomputation --------------------------------
    if binding_ok:
        extractive_ok = True
        abstractive_ok = True
        anchors_recomputed = 0
        for fg in field_grounding:
            index = fg.get("field_index")
            field = fields[index]
            proposed_value = field.get("proposed_value") if isinstance(field, dict) else None
            kind = fg.get("grounding_kind")
            anchor = fg.get("verified_anchor")

            if kind not in GROUNDING_KINDS:
                findings.append("acquisition_grounding.grounding_kind_invalid")
                extractive_ok = False
                abstractive_ok = False
                continue

            if kind == "abstractive":
                # Synthesis: explicitly typed, must NOT be treated as exact-span
                # grounded — it may never carry a verified anchor.
                if anchor is not None:
                    findings.append("acquisition_grounding.abstractive_carries_anchor")
                    abstractive_ok = False
                continue

            # kind == "extractive": must prove its location by recomputation.
            if not isinstance(anchor, dict):
                findings.append("acquisition_grounding.extractive_anchor_missing")
                extractive_ok = False
                continue
            # A model-supplied anchor may not point at a different artifact than
            # the envelope's captured-source digest (identity is not overridable).
            if anchor.get("artifact_digest") != claimed_digest:
                findings.append("acquisition_grounding.anchor_artifact_digest_mismatch")
                extractive_ok = False
            if anchor.get("extraction_profile") != EXTRACTION_PROFILE_ID:
                findings.append("acquisition_grounding.anchor_extraction_profile_unknown")
                extractive_ok = False
            start = anchor.get("start")
            end = anchor.get("end")
            if (
                not isinstance(start, int)
                or not isinstance(end, int)
                or isinstance(start, bool)
                or isinstance(end, bool)
                or start < 0
                or end < start
                or end > projection_len
                or start > projection_len
            ):
                findings.append("acquisition_grounding.anchor_span_out_of_range")
                extractive_ok = False
                continue
            # Exact normalized match ONLY: no fuzzy / semantic / substring
            # rescue, and no searching for the text elsewhere in the projection.
            slice_text = projection[start:end]
            if not isinstance(proposed_value, str) or normalize_whitespace(
                slice_text
            ) != normalize_whitespace(proposed_value):
                findings.append("acquisition_grounding.anchor_span_text_mismatch")
                extractive_ok = False
                continue
            anchors_recomputed += 1

        recomputed["extractive_anchors_recomputed"] = anchors_recomputed
        C("extractive_anchors_recompute", extractive_ok)
        C("abstractive_typing", abstractive_ok)
    else:
        NE("extractive_anchors_recompute")
        NE("abstractive_typing")

    # ----- dropped-ungrounded dispositions are well formed, never silent ----
    dropped = envelope.get("dropped_ungrounded")
    if isinstance(dropped, list):
        dropped_ok = True
        for entry in dropped:
            if not isinstance(entry, dict):
                dropped_ok = False
                continue
            if not isinstance(entry.get("field_name"), str):
                dropped_ok = False
            if entry.get("grounding_kind") not in GROUNDING_KINDS:
                dropped_ok = False
            if entry.get("reason") not in GROUNDING_DROP_REASONS:
                dropped_ok = False
            claimed_span = entry.get("claimed_span")
            if claimed_span is not None:
                if not (
                    isinstance(claimed_span, dict)
                    and isinstance(claimed_span.get("start"), int)
                    and isinstance(claimed_span.get("end"), int)
                    and not isinstance(claimed_span.get("start"), bool)
                    and not isinstance(claimed_span.get("end"), bool)
                ):
                    dropped_ok = False
            pvs = entry.get("proposed_value_sha256")
            if pvs is not None and not _is_sha256_ref(pvs):
                dropped_ok = False
        if not C("dropped_dispositions_wellformed", dropped_ok):
            findings.append("acquisition_grounding.dropped_disposition_malformed")
    else:
        # Absent list is the schema default ([]); a present non-list is malformed.
        if dropped is None:
            C("dropped_dispositions_wellformed", True)
        else:
            findings.append("acquisition_grounding.dropped_disposition_malformed")
            C("dropped_dispositions_wellformed", False)

    # ----- proposal_posture: proposal-only, no authority --------------------
    lifecycle_ok = (
        isinstance(content_proposal, dict)
        and content_proposal.get("lifecycle_state") == "proposal"
        and content_proposal.get("is_proposal") is True
        and envelope.get("is_proposal") is True
    )
    if not C("lifecycle_is_proposal", lifecycle_ok):
        findings.append("acquisition_grounding.lifecycle_not_proposal")

    present_authority = FORBIDDEN_AUTHORITY_FIELDS & _all_keys(envelope)
    if not C("no_authority_fields", not present_authority):
        findings.append("acquisition_grounding.authority_field_present")

    artifact_integrity = _fold(concl, _ARTIFACT_CONCL)
    grounding_integrity = _fold(concl, _GROUNDING_CONCL)
    proposal_posture = _fold(concl, _POSTURE_CONCL)

    return {
        "schema": REPORT_SCHEMA,
        "verification_profile": VERIFICATION_PROFILE,
        "acquisition_pin_commit": ACQUISITION_PIN_COMMIT,
        "grounded_envelope_schema_id": GROUNDED_ENVELOPE_SCHEMA_ID,
        "extraction_profile_id": EXTRACTION_PROFILE_ID,
        "conclusions": concl,
        "artifact_integrity": artifact_integrity,
        "grounding_integrity": grounding_integrity,
        "proposal_posture": proposal_posture,
        "recomputed": recomputed,
        "failure_codes": sorted(set(findings)),
        "limitations": [
            "Verifies that the serialized grounded proposal is bound to the "
            "serialized acquisition evidence it claims to derive from. It does "
            "NOT verify that the source is true or that the proposal is "
            "admitted; 'grounded' is not 'correct'. No truth, admission, "
            "standing, or publication is decided, and no master trust score is "
            "emitted.",
            "The extraction projection is an independent transcription of the "
            "pinned producer spec (counterpedia-acquisition "
            f"{ACQUISITION_PIN_COMMIT}); it recomputes from bytes and imports "
            "no producer code.",
        ],
    }


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _human(report: dict) -> None:
    print(f"verification_profile: {report['verification_profile']}")
    print(f"acquisition_pin_commit: {report['acquisition_pin_commit']}")
    print(f"artifact_integrity: {report['artifact_integrity']}")
    print(f"grounding_integrity: {report['grounding_integrity']}")
    print(f"proposal_posture: {report['proposal_posture']}")
    print("conclusions:")
    for name, value in report["conclusions"].items():
        print(f"  {name}: {value}")
    for code in report["failure_codes"]:
        print(f"failure_code: {code}")
    for lim in report["limitations"]:
        print(f"limitation: {lim}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="arcs-verify acquisition-grounding",
        description=(
            "Independently verify that a serialized counterpedia-acquisition "
            "grounded content proposal is correctly bound to the exact captured "
            "source bytes it claims to derive from. Reports artifact_integrity, "
            "grounding_integrity, and proposal_posture as separate axes. Does "
            "NOT decide truth, admission, standing, or publication; emits no "
            "master trust score."
        ),
    )
    parser.add_argument("--envelope", required=True, type=Path, help="serialized grounded-proposal JSON")
    parser.add_argument("--source", required=True, type=Path, help="exact captured source bytes the proposal claims to derive from")
    parser.add_argument("--json", action="store_true", dest="as_json")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code) if exc.code is not None else 2

    try:
        envelope_text = args.envelope.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        print(f"source-integrity/usage error: cannot read envelope {args.envelope}: {exc}", file=sys.stderr)
        return 2
    try:
        envelope = json.loads(envelope_text)
    except json.JSONDecodeError as exc:
        print(f"source-integrity/usage error: envelope is not valid JSON: {exc}", file=sys.stderr)
        return 2
    if not isinstance(envelope, dict):
        print(f"source-integrity/usage error: envelope top-level JSON is {type(envelope).__name__}, not an object", file=sys.stderr)
        return 2
    try:
        source_bytes = args.source.read_bytes()
    except OSError as exc:
        print(f"source-integrity/usage error: cannot read source {args.source}: {exc}", file=sys.stderr)
        return 2

    report = verify(envelope, source_bytes)
    if args.as_json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        _human(report)
    passed = "FAIL" not in (
        report["artifact_integrity"],
        report["grounding_integrity"],
        report["proposal_posture"],
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
