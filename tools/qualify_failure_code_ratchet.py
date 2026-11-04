#!/usr/bin/env python3
"""Mutation battery for tests/failure_code_ratchet.py (SCITT-RATCHET0).

The ratchet tests are only worth what they bind. Each mutant below sabotages ONE
decision site of the ratchet implementation in its OWN fresh snapshot of the
tree, then runs ONLY the named tests that must notice. A mutant is KILLED when
every named test failed. "pytest exited non-zero" is never accepted as a kill:

* the unmutated control must run a non-zero number of tests, skip none
  (ARCS_VERIFY_RATCHET_REQUIRED=1 turns an unresolvable base into a failure,
  not a skip) and pass entirely, before any verdict is believed;
* the verdict is a NAMED test taken from the junit report, not an exit code;
* each mutation is applied by an exact-count replacement (must hit exactly one
  site) and the real checkout is digest-inventoried before and after.

usage: python3 tools/qualify_failure_code_ratchet.py [--python PY]
exit: 0 all killed / 1 a mutant survived or the harness is unsound
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TREES = ("arcs_verify", "docs", "tests", "tools")
FILES = ("pyproject.toml",)
TARGET = "tests/failure_code_ratchet.py"
TEST = "tests/test_failure_code_ratchet.py"
GUARDED_FILES = (
    "tests/failure_code_ratchet.py",
    "tests/failure_code_judge.py",
    "tests/test_failure_code_ratchet.py",
    "tests/failure_code_census.py",
    "tests/test_failure_code_census.py",
    "tests/test_failure_code_registry.py",
    "tools/qualify_failure_code_census.py",
    "tools/qualify_failure_code_ratchet.py",
)
GIT = ["git", "-c", "user.name=ratchet", "-c", "user.email=ratchet@example.invalid", "-c", "commit.gpgsign=false"]


def _edit_ids(prefix: str) -> list[str]:
    return [f"{prefix}[{path}]" for path in GUARDED_FILES]


# id, description, (regex, replacement) applied with DOTALL, named tests that must fail
MUTANTS: list[tuple] = [
    (
        "permission-from-candidate-ledger",
        "the permitted set is the candidate's own ledger (the original defect)",
        (r"permitted = base_ledger\.get\(module\)\n        if permitted is None:\n            out\.append\(\n                Violation\(GROWTH_NEW_MODULE",
         "permitted = candidate_ledger.get(module)\n        if permitted is None:\n            out.append(\n                Violation(GROWTH_NEW_MODULE"),
        ["test_growth_new_code_in_gap_module_rejected_when_ledger_expanded_in_same_commit",
         "test_growth_rejected_when_the_base_is_a_committed_branch_tip_the_candidate_cannot_move",
         "test_growth_count_neutral_swap_rejected"],
    ),
    (
        "base-ledger-read-from-working-tree",
        "the base ledger is read from the candidate's working tree instead of the pinned commit",
        (r"raw = show\(root, sha, LEDGER\)", "raw = (root / LEDGER).read_bytes()"),
        ["test_growth_new_code_in_gap_module_rejected_when_ledger_expanded_in_same_commit",
         "test_growth_count_neutral_swap_rejected"],
    ),
    (
        "new-module-branch-silenced",
        "a module absent from the base ledger is not reported",
        (r"out\.append\(\n                Violation\(GROWTH_NEW_MODULE, module, f\"[^\n]*\n            \)\n            continue",
         "continue"),
        ["test_growth_new_emitting_module_with_a_ledger_entry_rejected",
         "test_growth_undocumented_code_in_a_registered_module_rejected_even_with_a_fresh_ledger_key"],
    ),
    (
        "family-branch-silenced",
        "undocumented families are never compared",
        (r"prefixes - set\(permitted\[\"families\"\]\)", "set()"),
        ["test_growth_new_undocumented_family_in_gap_module_rejected"],
    ),
    (
        "ledger-growth-loop-removed",
        "the candidate ledger is not required to be a subset of the base ledger",
        (r"for module in sorted\(candidate_ledger\):", "for module in sorted(()):"),
        ["test_growth_ledger_only_widening_rejected_without_any_emission",
         "test_growth_ledger_only_family_widening_rejected"],
    ),
    (
        "selection-edit-ignored",
        "a differing guarded file is not reported",
        (r"elif mine != theirs:", "elif False:"),
        _edit_ids("test_selection_edit_to_each_guarded_file_is_detected_by_name"),
    ),
    (
        "selection-deletion-ignored",
        "a deleted guarded file is not reported",
        (r"elif mine == \"ABSENT\":", "elif False:"),
        _edit_ids("test_selection_deletion_of_each_guarded_file_is_detected_by_name"),
    ),
    (
        "selection-always-accepted",
        "any change is accepted without the out-of-band digest",
        (r"if sel and accept and accept == selection_digest\(manifest\):", "if sel:"),
        ["test_selection_acceptance_with_a_wrong_digest_is_refused",
         "test_selection_acceptance_cannot_be_granted_from_inside_the_tree"],
    ),
    (
        "explicit-pin-need-not-be-on-main",
        "an explicit base pin is not required to be an ancestor of origin/main",
        (r"if _git\(root, \"merge-base\", \"--is-ancestor\", sha, tip_sha\)\.returncode != 0:", "if False:"),
        ["test_base_explicit_pin_not_on_main_is_refused"],
    ),
    (
        "explicit-pin-shape-unchecked",
        "an explicit base need not be a full 40-hex SHA",
        (r"if not _HEX40\.match\(spec\):", "if False:"),
        ["test_base_explicit_pin_must_be_a_full_resolvable_sha[main]",
         "test_base_explicit_pin_must_be_a_full_resolvable_sha[HEAD]",
         "test_base_explicit_pin_must_be_a_full_resolvable_sha[origin/main]"],
    ),
    (
        "judge-staged-from-candidate-tree",
        "the judge runs from the candidate's tests/ directory instead of base bytes (both reviewer-reproduced bypasses)",
        (r"judge_dir, result\.provenance, problems = stage_judge\(root, sha, stage, allow_introduction\)",
         "judge_dir, result.provenance, problems = (root / 'tests'), f'base {sha}', []"),
        ["test_source_shadow_of_any_stdlib_module_in_the_candidate_never_runs[ast]",
         "test_a_candidate_modified_judge_and_census_do_not_affect_the_verdict"],
    ),
    (
        "judge-from-candidate-tree-with-bytecode-cache-enabled",
        "the judge runs from the candidate's tests/ and the clean pycache prefix / -B are gone (the unchecked-hash .pyc bypass)",
        [(r"judge_dir, result\.provenance, problems = stage_judge\(root, sha, stage, allow_introduction\)",
          "judge_dir, result.provenance, problems = (root / 'tests'), f'base {sha}', []"),
         (r"\"-I\", \"-S\", \"-B\", \"-X\", f\"pycache_prefix=\{pyc\}\",", "\"-I\", \"-S\","),
         (r"\"PYTHONDONTWRITEBYTECODE\": \"1\", ", "")],
        ["test_committed_unchecked_hash_pyc_of_a_guarded_module_never_runs_and_cannot_force_pass[tests/failure_code_census.py]"],
    ),
    (
        "judge-isolation-removed",
        "the judge interpreter loses -I -S -B, the pycache prefix and the cleared environment",
        (r"env = \{\"PYTHONDONTWRITEBYTECODE\": \"1\", \"LC_ALL\": \"C\.UTF-8\"\}\n    cmd = \[\n        sys\.executable, \"-I\", \"-S\", \"-B\", \"-X\", f\"pycache_prefix=\{pyc\}\",",
         "env = dict(os.environ)\n    cmd = [\n        sys.executable,"),
        ["test_python_environment_variables_cannot_route_candidate_code_into_the_judge"],
    ),
    (
        "introduction-reads-as-independent",
        "a judge taken from the candidate is labelled as coming from the base",
        (r"return target, \"INTRODUCTION\", \[\]", "return target, f'base {sha}', []"),
        ["test_judge_introduction_is_labelled_and_never_reads_as_an_independent_pass"],
    ),
    (
        "absent-judge-allowed-without-the-flag",
        "a base without a judge silently falls back to the candidate's judge",
        (r"if not allow_introduction:", "if False:"),
        ["test_base_without_a_judge_is_not_established_not_a_pass"],
    ),
    (
        "judge-failure-reads-as-pass",
        "a judge that crashes or prints nothing is treated as an empty result",
        (r"if done\.returncode != 0 or not isinstance\(payload, dict\) or \"modules\" not in payload:", "if False:"),
        ["test_unparseable_candidate_source_fails_closed_not_as_an_empty_set"],
    ),
    (
        "launcher-runs-without-isolation",
        "the launcher no longer refuses a non-isolated interpreter",
        (r"if not sys\.flags\.isolated:", "if False:"),
        ["test_launcher_refuses_to_run_without_isolation"],
    ),
    (
        "judge-drops-a-not-codes-entry",
        "the judge's NOT_CODES table drifts from the census test's",
        (r"NOT_CODES\.add\(\(\"arcs_verify/okf_attested_computation\.py\", \"unreadable:\"\)\)", "pass"),
        ["test_judge_parity_with_the_census_test_on_the_real_tree"],
        "tests/failure_code_judge.py",
    ),
    (
        "judge-counts-documented-families-as-undocumented",
        "the judge stops excluding documented family prefixes",
        (r" and p not in registry\n", "\n"),
        ["test_judge_parity_with_the_census_test_on_the_real_tree"],
        "tests/failure_code_judge.py",
    ),
    (
        "unresolved-base-reads-as-pass",
        "failing to resolve a base records no problem",
        (r"sha, problems = resolve_base\(root, explicit_base\)\n    result\.violations \+= problems",
         "sha, problems = resolve_base(root, explicit_base)"),
        ["test_base_missing_origin_main_is_unresolved_not_a_pass"],
    ),
    (
        "unreadable-base-ledger-reads-as-pass",
        "an absent base ledger records no problem",
        (r"base_ledger, problems = read_base_ledger\(root, sha\)\n    result\.violations \+= problems",
         "base_ledger, problems = read_base_ledger(root, sha)"),
        ["test_base_without_a_readable_ledger_is_refused"],
    ),
]


def inventory(base: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for rel in FILES:
        if (base / rel).is_file():
            out[rel] = hashlib.sha256((base / rel).read_bytes()).hexdigest()
    for tree in TREES:
        for path in sorted((base / tree).rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
                out[path.relative_to(base).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return out


def snapshot(dst: Path, with_git: bool) -> None:
    for rel in FILES:
        shutil.copyfile(REPO / rel, dst / rel)
    for tree in TREES:
        shutil.copytree(REPO / tree, dst / tree, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    if with_git:
        for args in (["init", "-q", "-b", "main"], ["add", "-A"], ["commit", "-q", "-m", "snapshot"]):
            subprocess.run([*GIT, *args], cwd=dst, check=True, capture_output=True)
        sha = subprocess.run([*GIT, "rev-parse", "HEAD"], cwd=dst, check=True, capture_output=True, text=True).stdout.strip()
        subprocess.run([*GIT, "update-ref", "refs/remotes/origin/main", sha], cwd=dst, check=True)


def run(python: str, tree: Path, tag: str, work: Path, nodes: list[str]) -> tuple[dict[str, tuple[str, str]], str]:
    report = work / f"{tag}.xml"
    cmd = [python, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-p", "no:warnings", "--junitxml", str(report), *nodes]
    env = {k: v for k, v in os.environ.items() if k not in ("PYTEST_ADDOPTS", "PYTEST_PLUGINS") and not k.startswith("ARCS_VERIFY_RATCHET")}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["ARCS_VERIFY_RATCHET_REQUIRED"] = "1"
    cp = subprocess.run(cmd, cwd=tree, env=env, capture_output=True, text=True, timeout=1800)
    cases: dict[str, tuple[str, str]] = {}
    if report.is_file():
        for case in ET.parse(report).getroot().iter("testcase"):
            state, text = "pass", ""
            for child in case:
                if child.tag in ("failure", "error"):
                    state, text = "fail", (child.get("message") or "") + "\n" + (child.text or "")
                elif child.tag == "skipped":
                    state = "skip"
            cases[case.get("name") or "?"] = (state, text)
    last = (cp.stdout or cp.stderr).strip().splitlines()
    return cases, last[-1] if last else ""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--python", default=sys.executable)
    args = parser.parse_args()

    before = inventory(REPO)
    work = Path(tempfile.mkdtemp(prefix="ratchet-controls."))
    problems: list[str] = []
    killed = 0
    try:
        control = work / "control"
        control.mkdir()
        snapshot(control, with_git=True)
        cases, tail = run(args.python, control, "control", work, [TEST])
        bad = sorted(n for n, (s, _) in cases.items() if s != "pass")
        skipped = sorted(n for n, (s, _) in cases.items() if s == "skip")
        print(f"control (unmutated): {len(cases)} tests ran, {len(bad)} not passing, {len(skipped)} skipped -- {tail}")
        if not cases or bad:
            print("HARNESS UNSOUND: the control must run a non-zero number of tests, skip none, and be green")
            for name in bad[:10]:
                print(f"    not passing: {name}: {cases[name][1][:300]}")
            return 1

        for entry in MUTANTS:
            mid, description, spec, expected = entry[:4]
            pattern, replacement = spec if isinstance(spec, tuple) else (spec, None)
            target = entry[4] if len(entry) > 4 else TARGET
            tree = work / "m"
            if tree.exists():
                shutil.rmtree(tree)
            tree.mkdir()
            snapshot(tree, with_git=False)
            path = tree / target
            text = path.read_text(encoding="utf-8")
            edits = pattern if isinstance(pattern, list) else [(pattern, replacement)]
            mutated, bad = text, None
            for one_pattern, one_replacement in edits:
                mutated, count = re.subn(one_pattern, one_replacement, mutated, flags=re.S)
                if count != 1:
                    bad = count
                    break
            if bad is not None:
                print(f"HARNESS ERROR {mid}: a mutation matched {bad} sites (must be exactly 1)")
                problems.append(mid)
                continue
            path.write_text(mutated, encoding="utf-8")
            nodes = [f"{TEST}::{name}" for name in expected]
            got, tail = run(args.python, tree, mid, work, nodes)
            survivors = [n for n in expected if got.get(n, ("missing", ""))[0] != "fail"]
            ok = bool(got) and not survivors
            killed += ok
            print(f"{'KILLED  ' if ok else 'SURVIVED'} {mid}: {description}")
            for name in expected:
                state, text = got.get(name, ("missing", ""))
                first = next((l.strip() for l in text.splitlines() if l.strip()), "")[:110]
                print(f"    {state:7} {name}" + (f"  <- {first}" if state == "fail" else ""))
            if not ok:
                problems.append(mid)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    after = inventory(REPO)
    if before != after:
        problems.append("the real tree changed during the run")
    print(f"\n{killed}/{len(MUTANTS)} mutants killed by their named tests; real tree unchanged: {before == after}")
    if problems:
        print("PROBLEMS: " + ", ".join(problems))
        return 1
    print("RATCHET_CONTROLS=ALL_KILLED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
