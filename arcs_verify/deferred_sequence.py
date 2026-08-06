"""Independent sequence-level verifier for srs.deferred_operation.v0.1 receipt chains.

This module recomputes structural, linkage, digest-continuity, replay, and
terminal-state findings for a deferred-operation sequence from serialized,
signed SRS receipts.

Authority boundaries
--------------------
- This verifier operates on *serialized bytes only* (deserialized from JSON).
  It does not import DAGR producer code, runtime code, or identity-provider
  code.
- Findings are independently recomputed from the supplied receipt set and
  trust bundle. They are not emitter assertions.
- Sequence integrity ≠ policy correctness.
- Sequence integrity ≠ human intent.
- Sequence integrity ≠ side-effect reality.
- condition_response.response_status == approved ≠ operation admissible.
- operation_digest match ≠ same real-world operation.
- receipt_gap present ≠ sequence valid.
- terminal_admission present ≠ sequence complete.
- NOT_EVALUATED is not PASS. not_applicable is not PASS.

Independent findings produced
-----------------------------
- event_presence: All declared receipt_kinds are structurally present and
  individually conformant under srs.deferred_operation.v0.1.
- sequence_id_continuity: All receipts share the same sequence_id.
- predecessor_linkage: Each non-defer_request receipt references the
  receipt_id of the immediately preceding receipt in declared order.
- defer_receipt_linkage: terminal_admission and execution_outcome reference
  the originating defer_request receipt_id.
- condition_receipt_linkage: reevaluation and terminal_admission carry
  condition_receipt_ref consistent with the supplied condition_response
  receipt.
- operation_digest_continuity: defer_request, reevaluation,
  terminal_admission, and execution_outcome that share a sequence carry
  consistent operation_digest values (the field is present and non-empty).
  Digest equality across kinds is NOT asserted — that is an emitter claim,
  not a verifiable cross-receipt structural fact.
- response_expiry_honoured: A condition_response with response_status=expired
  is not followed by a reevaluation receipt in the supplied set.
- terminal_state_present: At least one terminal_admission is present.
- terminal_disposition_valid: terminal_admission disposition is admitted or
  refused (not deferred_for_review).
- refused_has_no_execution_outcome: A terminal_admission with
  disposition=refused is not followed by an execution_outcome.
- outcome_links_admitted_terminal: Any execution_outcome
  terminal_admission_ref resolves to a terminal_admission with
  disposition=admitted.
- receipt_gap_disclosed: Whether any receipt_gap receipt is present.
  (Informational; does not contribute to passed.)
- replay_clean: No receipt_id appears more than once in the supplied set.
- individual_receipts_valid: Each receipt individually passes
  srs.deferred_operation.v0.1 profile conformance (envelope shape, profile
  fields, raw-content exclusion, base attestation limit).

Signature and key findings are produced per-receipt by verify_receipt() and
are included in individual_receipt_reports. They are NOT_EVALUATED at the
sequence level because key trust is a function of the trust bundle supplied to
the caller, not a sequence-structural property.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from .verifier import (
    DEFERRED_OPERATION_PROFILE,
    VerificationReport,
    verify_receipt,
)

SEQUENCE_SCHEMA = "arcs_verify.deferred_sequence_report.v0_1"

# The profile uses srs-envelope-v0.2.1 (per profile manifest
# compatible_envelope_identities). The schema digest is pinned in verifier.py.
_DATA_DIR = Path(__file__).resolve().parent / "data"
DEFERRED_SEQUENCE_SCHEMA_PATH = _DATA_DIR / "srs-envelope-v0.2.1.schema.json"

SEQUENCE_LIMITATIONS = [
    (
        "Sequence integrity does not establish policy correctness. A structurally "
        "valid sequence may not satisfy the governing policy pack."
    ),
    (
        "Sequence integrity does not establish human intent. A conformant "
        "condition_response does not prove the responder understood or intended "
        "the governed action."
    ),
    (
        "Sequence integrity does not establish side-effect reality. Receipt "
        "presence and structural soundness do not prove the underlying operation "
        "executed, was received, or produced the declared outcome."
    ),
    (
        "operation_digest match does not prove the same real-world operation. "
        "The digest covers declared identity material at the time of issuance."
    ),
    (
        "condition_response.response_status == approved does not make the "
        "operation admissible. This verifier does not assert admissibility."
    ),
    (
        "receipt_gap present does not restore sequence validity. A gap receipt "
        "is an honest declaration of incompleteness, not a correction."
    ),
    (
        "key_resolved and key_trusted are evaluated per-receipt by the "
        "signature verifier, not at the sequence level. Sequence structural "
        "findings do not substitute for trust-bundle validation."
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
class DeferredSequenceReport:
    """Independent findings for a deferred-operation sequence.

    No single master status replaces findings. ``passed`` requires all
    structural sequence findings to be TRUE. Signature findings are
    per-receipt and not gated into sequence ``passed``.
    """

    # Structural sequence findings
    event_presence: Conclusion = Conclusion.NOT_EVALUATED
    sequence_id_continuity: Conclusion = Conclusion.NOT_EVALUATED
    predecessor_linkage: Conclusion = Conclusion.NOT_EVALUATED
    defer_receipt_linkage: Conclusion = Conclusion.NOT_EVALUATED
    condition_receipt_linkage: Conclusion = Conclusion.NOT_EVALUATED
    operation_digest_continuity: Conclusion = Conclusion.NOT_EVALUATED
    response_expiry_honoured: Conclusion = Conclusion.NOT_EVALUATED
    terminal_state_present: Conclusion = Conclusion.NOT_EVALUATED
    terminal_disposition_valid: Conclusion = Conclusion.NOT_EVALUATED
    refused_has_no_execution_outcome: Conclusion = Conclusion.NOT_EVALUATED
    outcome_links_admitted_terminal: Conclusion = Conclusion.NOT_EVALUATED
    replay_clean: Conclusion = Conclusion.NOT_EVALUATED
    individual_receipts_valid: Conclusion = Conclusion.NOT_EVALUATED

    # Informational (does not gate passed)
    receipt_gap_disclosed: Conclusion = Conclusion.NOT_EVALUATED

    # Per-receipt full verification reports (includes signature findings)
    individual_receipt_reports: list[dict[str, Any]] = field(
        default_factory=list
    )

    findings: list[SequenceFinding] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(
            c is Conclusion.TRUE
            for c in (
                self.event_presence,
                self.sequence_id_continuity,
                self.predecessor_linkage,
                self.defer_receipt_linkage,
                self.condition_receipt_linkage,
                self.operation_digest_continuity,
                self.response_expiry_honoured,
                self.terminal_state_present,
                self.terminal_disposition_valid,
                self.refused_has_no_execution_outcome,
                self.outcome_links_admitted_terminal,
                self.replay_clean,
                self.individual_receipts_valid,
            )
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SEQUENCE_SCHEMA,
            "verification_profile": DEFERRED_OPERATION_PROFILE,
            "findings": [
                {"code": f.code, "detail": f.detail}
                for f in self.findings
            ],
            "conclusions": {
                "event_presence": self.event_presence.value,
                "sequence_id_continuity": self.sequence_id_continuity.value,
                "predecessor_linkage": self.predecessor_linkage.value,
                "defer_receipt_linkage": self.defer_receipt_linkage.value,
                "condition_receipt_linkage": self.condition_receipt_linkage.value,
                "operation_digest_continuity": (
                    self.operation_digest_continuity.value
                ),
                "response_expiry_honoured": self.response_expiry_honoured.value,
                "terminal_state_present": self.terminal_state_present.value,
                "terminal_disposition_valid": (
                    self.terminal_disposition_valid.value
                ),
                "refused_has_no_execution_outcome": (
                    self.refused_has_no_execution_outcome.value
                ),
                "outcome_links_admitted_terminal": (
                    self.outcome_links_admitted_terminal.value
                ),
                "replay_clean": self.replay_clean.value,
                "individual_receipts_valid": (
                    self.individual_receipts_valid.value
                ),
                # Informational — does not gate passed
                "receipt_gap_disclosed": self.receipt_gap_disclosed.value,
            },
            "passed": self.passed,
            "individual_receipt_reports": list(self.individual_receipt_reports),
            "limitations": SEQUENCE_LIMITATIONS,
        }


def _fail(
    report: DeferredSequenceReport,
    code: str,
    detail: str,
) -> None:
    report.findings.append(SequenceFinding(code=code, detail=detail))


def verify_deferred_sequence(
    receipts: list[dict[str, Any]],
    keyring: dict[str, Any],
    *,
    schema_path: Path | None = None,
) -> DeferredSequenceReport:
    """Independently verify a deferred-operation sequence from serialized receipts.

    Parameters
    ----------
    receipts:
        Ordered list of receipt dicts in declared sequence order.
        The verifier does not sort; ordering is the caller's responsibility.
    keyring:
        Trust bundle dict with an ``issuers`` list, in the same format as the
        signed-SRS path.
    schema_path:
        Path to the pinned SRS envelope schema. Defaults to the vendored
        srs-envelope-v0.2.1.schema.json.
    """
    report = DeferredSequenceReport()
    effective_schema = schema_path or DEFERRED_SEQUENCE_SCHEMA_PATH

    if not isinstance(receipts, list) or not receipts:
        _fail(
            report,
            "sequence_empty_or_malformed",
            "receipts must be a non-empty list",
        )
        report.event_presence = Conclusion.FALSE
        report.sequence_id_continuity = Conclusion.FALSE
        report.predecessor_linkage = Conclusion.FALSE
        report.defer_receipt_linkage = Conclusion.FALSE
        report.condition_receipt_linkage = Conclusion.FALSE
        report.operation_digest_continuity = Conclusion.FALSE
        report.response_expiry_honoured = Conclusion.FALSE
        report.terminal_state_present = Conclusion.FALSE
        report.terminal_disposition_valid = Conclusion.FALSE
        report.refused_has_no_execution_outcome = Conclusion.FALSE
        report.outcome_links_admitted_terminal = Conclusion.FALSE
        report.replay_clean = Conclusion.FALSE
        report.individual_receipts_valid = Conclusion.FALSE
        report.receipt_gap_disclosed = Conclusion.FALSE
        return report

    # --- Replay detection (duplicate receipt_ids) ---
    seen_ids: set[str] = set()
    replay_ok = True
    for idx, receipt in enumerate(receipts):
        rid = receipt.get("receipt_id")
        if not isinstance(rid, str) or not rid:
            _fail(
                report,
                "receipt_missing_receipt_id",
                f"receipt at index {idx} has no receipt_id",
            )
            replay_ok = False
        elif rid in seen_ids:
            _fail(
                report,
                "duplicate_receipt_id",
                f"receipt_id {rid!r} appears more than once",
            )
            replay_ok = False
        else:
            seen_ids.add(rid)
    report.replay_clean = Conclusion.TRUE if replay_ok else Conclusion.FALSE

    # --- Individual receipt verification ---
    all_individual_valid = True
    for idx, receipt in enumerate(receipts):
        single_report: VerificationReport = verify_receipt(
            receipt,
            keyring,
            schema_path=effective_schema,
            selected_profile=DEFERRED_OPERATION_PROFILE,
        )
        individual_result = {
            "index": idx,
            "receipt_id": receipt.get("receipt_id"),
            "receipt_kind": receipt.get("receipt_kind"),
            "report": single_report.to_dict(),
        }
        report.individual_receipt_reports.append(individual_result)

        # Profile, envelope, raw-content, and attestation-limit findings gate
        # individual_receipts_valid. Signature findings are informational at
        # the sequence level.
        if not (
            single_report.envelope
            and single_report.profile
            and single_report.raw_content_exclusion
            and single_report.attestation_limits_present
        ):
            all_individual_valid = False
            _fail(
                report,
                "individual_receipt_invalid",
                (
                    f"receipt at index {idx} "
                    f"(id={receipt.get('receipt_id')!r}, "
                    f"kind={receipt.get('receipt_kind')!r}) "
                    f"failed individual verification: "
                    + ", ".join(single_report.failure_codes)
                ),
            )

    report.individual_receipts_valid = (
        Conclusion.TRUE if all_individual_valid else Conclusion.FALSE
    )

    # --- Build lookup index ---
    by_id: dict[str, dict[str, Any]] = {}
    for receipt in receipts:
        rid = receipt.get("receipt_id")
        if isinstance(rid, str) and rid:
            by_id[rid] = receipt

    # --- Event presence: at least a defer_request must be present ---
    defer_receipts = [
        r for r in receipts if r.get("receipt_kind") == "defer_request"
    ]
    event_presence_ok = bool(defer_receipts)
    if not event_presence_ok:
        _fail(
            report,
            "no_defer_request",
            "no defer_request receipt found in the supplied set",
        )
    report.event_presence = (
        Conclusion.TRUE if event_presence_ok else Conclusion.FALSE
    )

    # --- sequence_id continuity ---
    sequence_ids = {
        r.get("sequence_id")
        for r in receipts
        if isinstance(r.get("sequence_id"), str)
    }
    if len(sequence_ids) == 1:
        report.sequence_id_continuity = Conclusion.TRUE
    else:
        report.sequence_id_continuity = Conclusion.FALSE
        _fail(
            report,
            "sequence_id_discontinuity",
            f"receipts carry {len(sequence_ids)} distinct sequence_id values: "
            + ", ".join(repr(s) for s in sorted(sequence_ids)),
        )

    # --- Predecessor linkage: each non-defer_request must reference prior ---
    predecessor_ok = True
    for idx in range(1, len(receipts)):
        receipt = receipts[idx]
        kind = receipt.get("receipt_kind")
        if kind == "defer_request":
            # A second defer_request is a structural anomaly (different
            # sequence); skip predecessor check — sequence_id check will catch.
            continue
        pred_ref = receipt.get("predecessor_receipt_ref")
        if not isinstance(pred_ref, str) or not pred_ref:
            predecessor_ok = False
            _fail(
                report,
                "missing_predecessor_receipt_ref",
                (
                    f"receipt at index {idx} "
                    f"(kind={kind!r}) has no predecessor_receipt_ref"
                ),
            )
            continue
        expected_pred_id = receipts[idx - 1].get("receipt_id")
        if pred_ref != expected_pred_id:
            predecessor_ok = False
            _fail(
                report,
                "predecessor_ref_mismatch",
                (
                    f"receipt at index {idx} (kind={kind!r}) "
                    f"predecessor_receipt_ref={pred_ref!r} "
                    f"but preceding receipt_id={expected_pred_id!r}"
                ),
            )
    report.predecessor_linkage = (
        Conclusion.TRUE if predecessor_ok else Conclusion.FALSE
    )

    # --- defer_receipt_linkage ---
    defer_ok = True
    defer_id: str | None = (
        defer_receipts[0].get("receipt_id") if defer_receipts else None
    )
    for receipt in receipts:
        kind = receipt.get("receipt_kind")
        if kind not in ("terminal_admission", "execution_outcome"):
            continue
        dfr = receipt.get("defer_receipt_ref")
        if not isinstance(dfr, str) or not dfr:
            defer_ok = False
            _fail(
                report,
                "missing_defer_receipt_ref",
                f"{kind} (id={receipt.get('receipt_id')!r}) has no defer_receipt_ref",
            )
        elif defer_id is not None and dfr != defer_id:
            defer_ok = False
            _fail(
                report,
                "defer_receipt_ref_mismatch",
                (
                    f"{kind} (id={receipt.get('receipt_id')!r}) "
                    f"defer_receipt_ref={dfr!r} "
                    f"but defer_request receipt_id={defer_id!r}"
                ),
            )
    report.defer_receipt_linkage = (
        Conclusion.TRUE if defer_ok else Conclusion.FALSE
    )

    # --- condition_receipt_linkage ---
    cond_ok = True
    cond_receipts = [
        r for r in receipts if r.get("receipt_kind") == "condition_response"
    ]
    cond_id: str | None = (
        cond_receipts[0].get("receipt_id") if cond_receipts else None
    )
    for receipt in receipts:
        kind = receipt.get("receipt_kind")
        if kind not in ("reevaluation", "terminal_admission"):
            continue
        crr = receipt.get("condition_receipt_ref")
        if not isinstance(crr, str) or not crr:
            cond_ok = False
            _fail(
                report,
                "missing_condition_receipt_ref",
                f"{kind} (id={receipt.get('receipt_id')!r}) has no condition_receipt_ref",
            )
        elif cond_id is not None and crr != cond_id:
            cond_ok = False
            _fail(
                report,
                "condition_receipt_ref_mismatch",
                (
                    f"{kind} (id={receipt.get('receipt_id')!r}) "
                    f"condition_receipt_ref={crr!r} "
                    f"but condition_response receipt_id={cond_id!r}"
                ),
            )
    # If there are reevaluation/terminal_admission receipts but no
    # condition_response, linkage fails.
    needs_cond = [
        r for r in receipts
        if r.get("receipt_kind") in ("reevaluation", "terminal_admission")
    ]
    if needs_cond and not cond_receipts:
        cond_ok = False
        _fail(
            report,
            "condition_response_absent",
            "reevaluation/terminal_admission receipts present but no condition_response",
        )
    report.condition_receipt_linkage = (
        Conclusion.TRUE if cond_ok else Conclusion.FALSE
    )

    # --- operation_digest_continuity ---
    # All receipts that bear operation_digest must have it as a sha256: ref.
    # We do not assert equality across kinds — that is an emitter claim.
    # We verify that every kind that requires it actually has a non-empty value.
    op_digest_kinds = frozenset([
        "defer_request", "reevaluation", "terminal_admission", "execution_outcome"
    ])
    op_ok = True
    for receipt in receipts:
        kind = receipt.get("receipt_kind")
        if kind not in op_digest_kinds:
            continue
        op_digest = receipt.get("operation_digest")
        if not isinstance(op_digest, str) or not op_digest:
            op_ok = False
            _fail(
                report,
                "missing_operation_digest",
                f"{kind} (id={receipt.get('receipt_id')!r}) has no operation_digest",
            )
    report.operation_digest_continuity = (
        Conclusion.TRUE if op_ok else Conclusion.FALSE
    )

    # --- response_expiry_honoured ---
    # A condition_response with response_status=expired must not be followed
    # by a reevaluation in the supplied set.
    expiry_ok = True
    for cond_r in cond_receipts:
        if cond_r.get("response_status") == "expired":
            reevals_after = [
                r for r in receipts
                if r.get("receipt_kind") == "reevaluation"
            ]
            if reevals_after:
                expiry_ok = False
                _fail(
                    report,
                    "expired_condition_followed_by_reevaluation",
                    (
                        f"condition_response (id={cond_r.get('receipt_id')!r}) "
                        f"has response_status=expired but "
                        f"{len(reevals_after)} reevaluation receipt(s) are present"
                    ),
                )
    report.response_expiry_honoured = (
        Conclusion.TRUE if expiry_ok else Conclusion.FALSE
    )

    # --- terminal_state_present ---
    terminal_receipts = [
        r for r in receipts if r.get("receipt_kind") == "terminal_admission"
    ]
    report.terminal_state_present = (
        Conclusion.TRUE if terminal_receipts else Conclusion.FALSE
    )
    if not terminal_receipts:
        _fail(
            report,
            "no_terminal_admission",
            "no terminal_admission receipt found in the supplied set",
        )

    # --- terminal_disposition_valid ---
    term_disp_ok = True
    for term in terminal_receipts:
        disp = term.get("disposition")
        if disp not in {"admitted", "refused"}:
            term_disp_ok = False
            _fail(
                report,
                "terminal_admission_invalid_disposition",
                (
                    f"terminal_admission (id={term.get('receipt_id')!r}) "
                    f"has disposition={disp!r}; must be admitted or refused"
                ),
            )
    report.terminal_disposition_valid = (
        Conclusion.TRUE if term_disp_ok else Conclusion.FALSE
    )

    # --- refused_has_no_execution_outcome ---
    refused_ok = True
    refused_ids = {
        r.get("receipt_id")
        for r in terminal_receipts
        if r.get("disposition") == "refused"
    }
    outcome_receipts = [
        r for r in receipts if r.get("receipt_kind") == "execution_outcome"
    ]
    for outcome in outcome_receipts:
        tar = outcome.get("terminal_admission_ref")
        if tar in refused_ids:
            refused_ok = False
            _fail(
                report,
                "execution_outcome_after_refused_terminal",
                (
                    f"execution_outcome (id={outcome.get('receipt_id')!r}) "
                    f"terminal_admission_ref={tar!r} which has disposition=refused"
                ),
            )
    report.refused_has_no_execution_outcome = (
        Conclusion.TRUE if refused_ok else Conclusion.FALSE
    )

    # --- outcome_links_admitted_terminal ---
    outcome_link_ok = True
    admitted_ids = {
        r.get("receipt_id")
        for r in terminal_receipts
        if r.get("disposition") == "admitted"
    }
    for outcome in outcome_receipts:
        tar = outcome.get("terminal_admission_ref")
        if not isinstance(tar, str) or not tar:
            outcome_link_ok = False
            _fail(
                report,
                "execution_outcome_missing_terminal_admission_ref",
                f"execution_outcome (id={outcome.get('receipt_id')!r}) "
                "has no terminal_admission_ref",
            )
        elif tar not in admitted_ids and tar not in refused_ids:
            outcome_link_ok = False
            _fail(
                report,
                "execution_outcome_terminal_ref_unresolved",
                (
                    f"execution_outcome (id={outcome.get('receipt_id')!r}) "
                    f"terminal_admission_ref={tar!r} does not resolve to a "
                    "terminal_admission in this set"
                ),
            )
        # refused case is already caught by refused_has_no_execution_outcome
    report.outcome_links_admitted_terminal = (
        Conclusion.TRUE if outcome_link_ok else Conclusion.FALSE
    )

    # --- receipt_gap_disclosed (informational) ---
    gap_receipts = [r for r in receipts if r.get("receipt_kind") == "receipt_gap"]
    report.receipt_gap_disclosed = (
        Conclusion.TRUE if gap_receipts else Conclusion.FALSE
    )

    return report


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def build_parser() -> "argparse.ArgumentParser":
    import argparse

    parser = argparse.ArgumentParser(
        prog="arcs-verify deferred-sequence",
        description=(
            "Independently verify a srs.deferred_operation.v0.1 receipt sequence. "
            "Receipts are supplied as a JSON array file or as individual JSON files."
        ),
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--sequence",
        type=Path,
        metavar="SEQUENCE_JSON",
        help="Path to a JSON file containing an array of receipt objects.",
    )
    group.add_argument(
        "--receipts",
        type=Path,
        nargs="+",
        metavar="RECEIPT_JSON",
        help="Paths to individual receipt JSON files in declared sequence order.",
    )
    parser.add_argument(
        "--keyring",
        required=True,
        type=Path,
        help="Path to an SRS trust bundle JSON file.",
    )
    parser.add_argument(
        "--schema",
        type=Path,
        default=DEFERRED_SEQUENCE_SCHEMA_PATH,
        help="Path to the pinned SRS envelope schema (default: vendored v0.2.1).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Emit report as JSON.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    import argparse

    try:
        args = build_parser().parse_args(argv)
    except SystemExit as exc:
        return int(exc.code)

    try:
        if args.sequence is not None:
            raw = json.loads(
                args.sequence.read_text(encoding="utf-8")
            )
            if not isinstance(raw, list):
                sys.stderr.write(
                    f"error: {args.sequence} must contain a JSON array\n"
                )
                return 2
            receipts = raw
        else:
            receipts = [
                json.loads(p.read_text(encoding="utf-8"))
                for p in args.receipts
            ]
        keyring = json.loads(
            args.keyring.read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2

    schema_path: Path = args.schema

    if not schema_path.is_file():
        sys.stderr.write(
            f"error: schema file not found: {schema_path}\n"
        )
        return 2

    report = verify_deferred_sequence(
        receipts,
        keyring,
        schema_path=schema_path,
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
