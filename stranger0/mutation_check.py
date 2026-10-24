#!/usr/bin/env python3
"""Mutation check for the stranger0 package: APPLIED mutants, not claimed ones.

For each mutant this copies the working tree into a scratch directory, checks
that the target tests are green on the unmodified copy, applies exactly one
textual edit (asserting the old text occurs exactly once), re-runs the same
target tests, and records the unified diff and which tests turned red. A mutant
whose target tests stay green SURVIVED and is reported as such. A mutant that
does not change behaviour is reported by hand as equivalent, never silently
dropped.

    python3 stranger0/mutation_check.py --out /tmp/stranger0-mutation.json [--only M01 ...]

Stdlib only. Needs pytest and the verifier dependencies in the interpreter given
by --python. Runs one pytest process at a time.
"""
from __future__ import annotations

import argparse
import difflib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
COPY_DIRS = ("arcs_verify", "packs", "stranger0", "tests", "tools")
R = "tests/test_stranger0_receiver.py::"
I = "tests/test_stranger0_independence.py::"
O = "tests/test_stranger0_run.py::"
RECV = "stranger0/receiver.py"
ORCH = "stranger0/run_stranger0.py"

MUTANTS: list[dict[str, Any]] = [
    {
        "id": "M01", "file": RECV,
        "what": "receiver self-trusts: adds a receipt's own claimed key to the keyring it verifies with",
        "old": '    keyring = trust["keyring"]\n    default_profile = trust["default_profile"]\n',
        "new": (
            '    keyring = trust["keyring"]\n'
            '    for _it in items:\n'
            '        _claim = ((_it.parsed or {}).get("extensions") or {}).get("stranger0_claimed_issuer_key")\n'
            '        if isinstance(_claim, dict):\n'
            '            keyring = dict(keyring, issuers=list(keyring["issuers"]) + [{"algorithm": "Ed25519", "issuer_id": _it.parsed.get("issuer_id"), "key_id": _claim.get("key_id"), "not_after": "2099-01-01T00:00:00Z", "not_before": "2000-01-01T00:00:00Z", "public_key": _claim.get("public_key"), "trusted": True}])\n'
            '    default_profile = trust["default_profile"]\n'
        ),
        "targets": [R + "test_receipt_cannot_vouch_for_its_own_key"],
    },
    {
        "id": "M02", "file": RECV,
        "what": "signature promoted to reliance: the gate becomes 'signature_valid' instead of the verifier's passed",
        "old": '        elif item.report.get("passed") is not True:\n',
        "new": '        elif item.report.get("signature_valid") is not True:\n',
        "targets": [R + "test_valid_signature_is_not_receiver_trust", R + "test_validly_signed_raw_content_fails_raw_content_exclusion_only"],
    },
    {
        "id": "M03", "file": RECV,
        "what": "refused and deferred receipts silently dropped from the decision record",
        "old": '        decisions.append(entry)\n',
        "new": '        if (item.parsed or {}).get("disposition") not in ("refused", "deferred_for_review"):\n            decisions.append(entry)\n',
        "targets": [R + "test_refused_and_deferred_are_represented_not_dropped_and_not_upgraded"],
    },
    {
        "id": "M04", "file": RECV,
        "what": "receiver boundary policy ignored",
        "old": '        if receipt.get("boundary_id") not in policy["accepted_boundary_ids"]:\n',
        "new": '        if False:\n',
        "targets": [R + "test_every_verifier_check_passes_and_the_receiver_still_declines"],
    },
    {
        "id": "M05", "file": RECV,
        "what": "receiver issuer policy ignored",
        "old": '        if receipt.get("issuer_id") not in policy["accepted_issuer_ids"]:\n',
        "new": '        if False:\n',
        "targets": [R + "test_every_verifier_check_passes_and_the_receiver_still_declines"],
    },
    {
        "id": "M06", "file": RECV,
        "what": "duplicate-in-submission detection removed",
        "old": '            elif position > 0:\n',
        "new": '            elif False:\n',
        "targets": [R + "test_duplicate_in_one_submission_is_relied_upon_once"],
    },
    {
        "id": "M07", "file": RECV,
        "what": "prior-reliance ledger replay detection removed",
        "old": '            elif ledger_digest is not None:\n',
        "new": '            elif False:\n',
        "targets": [R + "test_replay_of_a_receipt_already_in_the_receivers_ledger"],
    },
    {
        "id": "M08", "file": RECV,
        "what": "receipt_id conflict detection removed",
        "old": '            if conflict:\n',
        "new": '            if False:\n',
        "targets": [R + "test_two_validly_signed_receipts_with_one_id_are_both_refused"],
    },
    {
        "id": "M09", "file": RECV,
        "what": "missing admission link no longer reduces reliance",
        "old": '            if "admission_receipt_unresolved" in codes and policy["require_admission_link_for_outcome"]:\n',
        "new": '            if False:\n',
        "targets": [R + "test_outcome_without_its_admission_is_insufficient_evidence_even_though_it_verifies"],
    },
    {
        "id": "M10", "file": RECV,
        "what": "inconsistent admission/outcome linkage no longer reduces reliance",
        "old": '            if "admission_outcome_linkage_mismatch" in codes:\n',
        "new": '            if False:\n',
        "targets": [R + "test_inconsistent_linkage_is_not_relied_upon", R + "test_ealink_arrival_only_still_refuses_a_call_id_mismatch"],
    },
    {
        "id": "M11", "file": RECV,
        "what": "unaccepted profile no longer reduces reliance",
        "old": '        if item.selected_profile not in accepted_profiles:\n',
        "new": '        if False:\n',
        "targets": [R + "test_unknown_profile_is_never_silently_replaced_by_the_default"],
    },
    {
        "id": "M12", "file": RECV,
        "what": "unaccepted receipt_version no longer reduces reliance",
        "old": '        if receipt.get("receipt_version") not in accepted_versions:\n',
        "new": '        if False:\n',
        "targets": [R + "test_unknown_receipt_version"],
    },
    {
        "id": "M13", "file": RECV,
        "what": "receiver alters the recorded verifier report (flips issuer_key_trusted)",
        "old": '            item.report = report.to_dict()\n',
        "new": '            item.report = dict(report.to_dict(), issuer_key_trusted=True)\n',
        "targets": [R + "test_valid_signature_is_not_receiver_trust", R + "test_findings_and_decision_are_distinct_records_and_findings_are_unaltered"],
    },
    {
        "id": "M14", "file": RECV,
        "what": "a reliance field is written into the verifier findings record (records no longer distinct)",
        "old": '        "record_kind": "verifier_findings",\n',
        "new": '        "record_kind": "verifier_findings",\n        "decision": "rely",\n',
        "targets": [R + "test_findings_and_decision_are_distinct_records_and_findings_are_unaltered"],
    },
    {
        "id": "M15", "file": RECV,
        "what": "network tripwire never installed",
        "old": '    install_network_tripwire()\n    if args.selfcheck:\n',
        "new": '    if args.selfcheck:\n',
        "targets": [I + "test_selfcheck_positive_controls_all_fire"],
    },
    {
        "id": "M16", "file": RECV,
        "what": "producer-module predicate can never fire",
        "old": '    return top_level_name in _PRODUCER_EXACT or top_level_name.startswith(\n        _PRODUCER_PREFIXES\n    )\n',
        "new": '    return False\n',
        "targets": [I + "test_selfcheck_positive_controls_all_fire", I + "test_receiver_predicate_covers_every_root_the_release_guard_forbids"],
    },
    {
        "id": "M17", "file": RECV,
        "what": "module inventory reports nothing",
        "old": '    tops = {name.split(".", 1)[0] for name in module_names if name}\n    return sorted(top for top in tops if is_producer_module(top))\n',
        "new": '    return []\n',
        "targets": [I + "test_selfcheck_positive_controls_all_fire", I + "test_planted_producer_module_is_detected_in_a_fresh_process"],
    },
    {
        "id": "M18", "file": RECV,
        "what": "receiver gains a producer-package import (guarded, so it still starts)",
        "old": 'from pathlib import Path\nfrom typing import Any\n',
        "new": 'from pathlib import Path\nfrom typing import Any\n\ntry:\n    import dagr_runtime  # noqa: F401\nexcept ImportError:\n    pass\n',
        "targets": [I + "test_receiver_source_imports_only_stdlib_and_the_verifier"],
    },
    {
        "id": "M19", "file": RECV,
        "what": "receiver gains signing capability (guarded import of a private-key type)",
        "old": 'from pathlib import Path\nfrom typing import Any\n',
        "new": 'from pathlib import Path\nfrom typing import Any\n\ntry:\n    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519Private' 'Key  # noqa: F401\nexcept ImportError:\n    pass\n',
        "targets": [I + "test_receiver_contains_no_signing_capability", I + "test_receiver_source_imports_only_stdlib_and_the_verifier"],
    },
    {
        "id": "M20", "file": RECV,
        "what": "relied-upon records stop stating what is not relied upon",
        "old": '            entry["not_relied_upon"] = not_relied\n',
        "new": '            entry["not_relied_upon"] = []\n',
        "targets": [R + "test_positive_controls_are_relied_upon_with_scoped_claims"],
    },
    {
        "id": "M21", "file": RECV,
        "what": "stale records from an earlier run are no longer cleared",
        "old": '        (args.out_dir / stale).unlink(missing_ok=True)\n',
        "new": '        pass\n',
        "targets": [R + "test_stale_records_from_an_earlier_run_are_never_left_beside_a_usage_error"],
    },
    {
        "id": "M22", "file": RECV,
        "what": "every admission is described as an admitted disposition (refusal represented as admission)",
        "old": '        claim = f"issuer_attests_admission_disposition_{disposition}"\n',
        "new": '        claim = "issuer_attests_admission_disposition_admitted"\n',
        "targets": [R + "test_refused_and_deferred_are_represented_not_dropped_and_not_upgraded", R + "test_forged_refusal_to_admission_is_rejected_and_the_real_refusal_is_not_an_admission"],
    },
    {
        "id": "M23", "file": RECV,
        "what": "three-way decision collapsed: insufficient_evidence becomes do_not_rely",
        "old": '        return "insufficient_evidence"\n',
        "new": '        return "do_not_rely"\n',
        "targets": [R + "test_outcome_without_its_admission_is_insufficient_evidence_even_though_it_verifies"],
    },
    {
        "id": "M24", "file": RECV,
        "what": "E-A-LINK: the strict dependent-reliance requirement never runs",
        "old": '    if policy["require_relied_admission_for_outcome"]:\n',
        "new": '    if False:\n',
        "targets": [
            R + "test_ealink_refused_admission_stops_reliance_on_its_linked_outcome",
            R + "test_ealink_decision_does_not_depend_on_submission_order",
            R + "test_ealink_duplicate_admission_receipt_id_is_not_a_unique_relied_admission",
            R + "test_ealink_admission_declined_from_the_receivers_own_ledger_stops_the_outcome",
        ],
    },
    {
        "id": "M25", "file": RECV,
        "what": "E-A-LINK: the referenced admission's own receiver decision is ignored, so arrival is enough",
        "old": '                elif provisional[admission.index] != "rely":\n',
        "new": '                elif False:\n',
        "targets": [
            R + "test_ealink_refused_admission_stops_reliance_on_its_linked_outcome",
            R + "test_ealink_admission_declined_from_the_receivers_own_ledger_stops_the_outcome",
        ],
    },
    {
        "id": "M26", "file": RECV,
        "what": "E-A-LINK: a matching receipt id is accepted as linkage, without comparing logical_call_id",
        "old": '                if parsed.get("logical_call_id") != item.parsed.get("logical_call_id"):\n',
        "new": '                if False:\n',
        "targets": [R + "test_ealink_matching_receipt_id_with_a_different_call_id_is_not_the_linked_admission"],
    },
    {
        "id": "M27", "file": RECV,
        "what": "E-A-LINK: duplicate carriers of the referenced admission id are not refused; the first is taken",
        "old": '            if len(group) > 1:\n',
        "new": '            if False:\n',
        "targets": [R + "test_ealink_duplicate_admission_receipt_id_is_not_a_unique_relied_admission"],
    },
    {
        "id": "M28", "file": RECV,
        "what": "E-A-LINK: a referenced admission that arrived and was refused is downgraded to missing evidence",
        "old": 'INSUFFICIENT_TOKENS = frozenset({"chain.admission_receipt_unresolved"})\n',
        "new": 'INSUFFICIENT_TOKENS = frozenset({"chain.admission_receipt_unresolved", "chain.admission_not_relied_upon"})\n',
        "targets": [R + "test_ealink_refused_admission_stops_reliance_on_its_linked_outcome"],
    },
    {
        "id": "M29", "file": RECV,
        "what": "E-A-LINK: a reference resolving to a non-admission is treated as a refused admission rather than an unresolved one",
        "old": '                if parsed.get("receipt_kind") != "admission":\n',
        "new": '                if False:\n',
        "targets": [R + "test_ealink_a_reference_to_a_non_admission_is_unresolved_not_refused"],
    },
    {
        "id": "M30", "file": RECV,
        "what": "E-A-LINK: the strict setting is not type-checked, so a truthy string silently turns it on",
        "old": '    if not isinstance(policy["require_relied_admission_for_outcome"], bool):\n',
        "new": '    if False:\n',
        "targets": [R + "test_ealink_a_non_boolean_linkage_setting_is_refused"],
    },
    {
        "id": "M31", "file": RECV,
        "what": "E-A-LINK: the admission kind is compared case-insensitively, so 'Admission' satisfies the reference",
        "old": '                if parsed.get("receipt_kind") != "admission":\n',
        "new": '                if str(parsed.get("receipt_kind", "")).strip().lower() != "admission":\n',
        "targets": [R + "test_ealink_only_an_exact_admission_kind_satisfies_the_reference"],
    },
    {
        "id": "M32", "file": RECV,
        "what": "E-A-LINK: only an outcome referent is skipped, so a missing or odd kind falls through",
        "old": '                if parsed.get("receipt_kind") != "admission":\n',
        "new": '                if parsed.get("receipt_kind") == "outcome":\n',
        "targets": [R + "test_ealink_only_an_exact_admission_kind_satisfies_the_reference"],
    },
    {
        "id": "M33", "file": RECV,
        "what": "E-A-LINK: the decision record stops naming the receiver version whose meaning changed",
        "old": '        "receiver_id": trust["receiver_id"],\n        "receiver_version": RECEIVER_ID,\n',
        "new": '        "receiver_id": trust["receiver_id"],\n',
        "targets": [R + "test_ealink_the_decision_record_names_the_receiver_version"],
    },
    {
        "id": "O01", "file": ORCH,
        "what": "orchestrator stops comparing verifier failure codes with the stated reason",
        "old": '("decision", "verifier_passed", "failed_checks", "verifier_failure_codes", "reason_tokens")',
        "new": '("decision", "verifier_passed", "failed_checks", "reason_tokens")',
        "targets": [O + "test_orchestrator_fails_when_a_stated_expectation_is_wrong"],
    },
    {
        "id": "O02", "file": ORCH,
        "what": "orchestrator stops requiring that a control relies on every receipt",
        "old": '                if not all(e["decision"] == "rely" for e in ctrl["expect"]):\n',
        "new": '                if False:\n',
        "targets": [O + "test_orchestrator_rejects_a_control_whose_catalog_expectation_is_not_rely"],
    },
    {
        "id": "O03", "file": ORCH,
        "what": "orchestrator stops comparing the receiver's findings with the existing CLI",
        "old": '            if cli_report != report:\n',
        "new": '            if False:\n',
        "targets": [O + "test_orchestrator_detects_an_altered_findings_record"],
    },
    {
        "id": "O04", "file": ORCH,
        "what": "orchestrator stops counting receiver processes that loaded producer modules",
        "old": '"processes_with_producer_modules_loaded": sum(1 for r in process_rows if r["producer_modules_loaded"]),',
        "new": '"processes_with_producer_modules_loaded": 0,',
        "targets": [O + "test_orchestrator_reports_falsified_when_a_receiver_process_loads_a_producer_module"],
    },
    {
        "id": "O05", "file": ORCH,
        "what": "orchestrator stops counting receiver network attempts",
        "old": '"processes_with_network_attempts": sum(1 for r in process_rows if r["network_blocked_attempts"]),',
        "new": '"processes_with_network_attempts": 0,',
        "targets": [O + "test_orchestrator_reports_falsified_when_a_receiver_process_attempts_network_use"],
    },
    {
        "id": "O06", "file": ORCH,
        "what": "orchestrator stops detecting reliance without a verifier pass",
        "old": '            if dec == "rely" and passed is not True:\n',
        "new": '            if False:\n',
        "targets": [O + "test_orchestrator_reports_falsified_when_a_valid_signature_is_promoted_to_reliance"],
    },
    {
        "id": "O07", "file": ORCH,
        "what": "orchestrator stops checking isolation claims against the actual inputs",
        "old": '                if same_bytes != claim["same_receipt_bytes"] or same_trust != claim["same_trust_input"]:\n',
        "new": '                if False:\n',
        "targets": [O + "test_orchestrator_fails_a_false_isolation_claim"],
    },
    {
        "id": "O08", "file": ORCH,
        "what": "orchestrator accepts a negative with no positive control",
        "old": '            if not neg.get("controls"):\n',
        "new": '            if False:\n',
        "targets": [O + "test_orchestrator_fails_a_negative_without_a_positive_control"],
    },
]


def copy_tree(dst: Path) -> None:
    for name in COPY_DIRS:
        shutil.copytree(REPO / name, dst / name, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))


def run_pytest(python: str, root: Path, targets: list[str]) -> dict[str, Any]:
    proc = subprocess.run(
        [python, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-rf", *targets],
        cwd=root, capture_output=True, text=True, timeout=1800,
    )
    failed = sorted(set(re.findall(r"^FAILED (\S+)", proc.stdout, flags=re.MULTILINE)))
    summary = next((line for line in reversed(proc.stdout.splitlines()) if re.search(r"\b(passed|failed|error)", line)), "")
    return {"exit_code": proc.returncode, "failed_tests": failed, "summary": summary.strip()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--only", action="append", default=None)
    args = parser.parse_args(argv)

    results = []
    for mutant in MUTANTS:
        if args.only and mutant["id"] not in args.only:
            continue
        with tempfile.TemporaryDirectory(prefix="stranger0-mut-") as scratch:
            root = Path(scratch)
            copy_tree(root)
            path = root / mutant["file"]
            original = path.read_text(encoding="utf-8")
            occurrences = original.count(mutant["old"])
            row: dict[str, Any] = {
                "id": mutant["id"], "file": mutant["file"], "what": mutant["what"],
                "targets": mutant["targets"], "old_text_occurrences": occurrences,
            }
            if occurrences != 1 or mutant["old"] == mutant["new"]:
                row["verdict"] = "INVALID_EDIT"
                results.append(row)
                print(f"{mutant['id']}: INVALID_EDIT (occurrences={occurrences})")
                continue
            baseline = run_pytest(args.python, root, mutant["targets"])
            mutated = original.replace(mutant["old"], mutant["new"])
            path.write_text(mutated, encoding="utf-8")
            row["diff"] = "".join(difflib.unified_diff(
                original.splitlines(keepends=True), mutated.splitlines(keepends=True),
                fromfile=f"a/{mutant['file']}", tofile=f"b/{mutant['file']}", n=1))
            after = run_pytest(args.python, root, mutant["targets"])
            row["target_tests_on_unmutated_copy"] = baseline
            row["target_tests_on_mutant"] = after
            if baseline["exit_code"] != 0:
                row["verdict"] = "BASELINE_NOT_GREEN"
            elif after["exit_code"] == 0:
                row["verdict"] = "SURVIVED"
            else:
                row["verdict"] = "KILLED"
            results.append(row)
            print(f"{mutant['id']}: {row['verdict']:<10} {mutant['what']}  killed_by={after['failed_tests']}")
    summary = {v: sum(1 for r in results if r["verdict"] == v) for v in sorted({r["verdict"] for r in results})}
    doc = {"schema": "arcs.verify.stranger0.mutation_results.v0.1", "summary": summary, "mutants": results}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print(f"\nsummary: {summary}")
    return 0 if set(summary) <= {"KILLED"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
