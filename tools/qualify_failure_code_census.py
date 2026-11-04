#!/usr/bin/env python3
"""Adversarial deletion battery for tests/test_failure_code_census.py.

Each mutant is applied to its OWN fresh copy of the tree in a private temp
directory; the real checkout is never written (it is digest-inventoried before
and after). A mutant is KILLED only when the whole selected suite ran, the
NAMED test expected to catch it failed, and the failure text names the mutated
code. "pytest exited non-zero" is never accepted as a kill: a harness that
collects nothing exits non-zero too, so the unmutated control must be green with
a non-zero test count first.

Mutants
  doc:<code>   remove one emitted code from the registry text
               -> test_every_emitted_code_is_documented[<module>] must fail
  src:<code>   rename every emission of one documented signed-lane code
               -> test_bound_section_rows_equal_emitted_codes must fail

Every code of the C2PA-SIGNED0 lane is deleted both ways (the lane whose census
was 10/20 at the P2 head), plus one doc-deletion per other registered module.

usage: python3 tools/qualify_failure_code_census.py [--python PY]
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
TREES = ("arcs_verify", "docs", "tests")
FILES = ("pyproject.toml",)
CENSUS_TEST = "tests/test_failure_code_census.py"
LEGACY_TEST = "tests/test_failure_code_registry.py"
SELECT = (
    "test_every_emitted_code_is_documented or test_bound_section_rows_equal_emitted_codes "
    "or test_known_gap_is_exactly or test_inventory_scans or test_census_is_a_superset "
    "or test_not_codes_entries"
)
LANE_MODULE = "arcs_verify/c2pa_test_signature0.py"
REGISTRY_FILES = ("docs/FAILURE_CODES.md", "docs/FAILURE_CODES_EXTERNAL_PROFILE.md")


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


def snapshot(dst: Path) -> None:
    for rel in FILES:
        shutil.copyfile(REPO / rel, dst / rel)
    for tree in TREES:
        shutil.copytree(REPO / tree, dst / tree, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))


def run(python: str, tree: Path, tag: str, work: Path) -> tuple[dict[str, tuple[str, str]], str]:
    report = work / f"{tag}.xml"
    cmd = [python, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-p", "no:warnings",
           "--junitxml", str(report), "-k", SELECT, CENSUS_TEST, LEGACY_TEST]
    env = {k: v for k, v in os.environ.items() if k not in ("PYTEST_ADDOPTS", "PYTEST_PLUGINS")}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    cp = subprocess.run(cmd, cwd=tree, env=env, capture_output=True, text=True, timeout=300)
    cases: dict[str, tuple[str, str]] = {}
    if report.is_file():
        for case in ET.parse(report).getroot().iter("testcase"):
            state, text = "pass", ""
            for child in case:
                if child.tag in ("failure", "error"):
                    state, text = "fail", (child.get("message") or "") + "\n" + (child.text or "")
                elif child.tag == "skipped":
                    state = "skip"
            cases[f"{case.get('classname', '').rsplit('.', 1)[-1]}::{case.get('name')}"] = (state, text)
    return cases, (cp.stdout or cp.stderr).strip().splitlines()[-1] if (cp.stdout or cp.stderr) else ""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--python", default=sys.executable)
    args = parser.parse_args()
    sys.path.insert(0, str(REPO / "tests"))
    import failure_code_census as census_lib  # noqa: PLC0415
    import test_failure_code_census as gate  # noqa: PLC0415

    before = inventory(REPO)
    work = Path(tempfile.mkdtemp(prefix="census-controls."))
    problems: list[str] = []
    killed = total = 0
    try:
        control = work / "control"
        control.mkdir()
        snapshot(control)
        cases, tail = run(args.python, control, "control", work)
        bad = sorted(n for n, (s, _) in cases.items() if s != "pass")
        print(f"control (unmutated): {len(cases)} tests ran, {len(bad)} not passing -- {tail}")
        if not cases or bad:
            print("HARNESS UNSOUND: the control must run a non-zero number of tests and be green")
            return 1

        lane_codes = sorted(set(census_lib.extract(LANE_MODULE).static) - gate.STATUS_WORDS)
        mutants: list[tuple[str, str, str, str]] = []  # id, kind, module, code
        for code in lane_codes:
            mutants.append((f"doc:{code}", "doc", LANE_MODULE, code))
            mutants.append((f"src:{code}", "src", LANE_MODULE, code))
        for module in gate.REGISTERED:
            if module == LANE_MODULE:
                continue
            codes = sorted(gate._effective(module, census_lib.extract(module))[0])
            if codes:
                mutants.append((f"doc:{module.rsplit('/', 1)[-1]}:{codes[0]}", "doc", module, codes[0]))

        for mid, kind, module, code in mutants:
            total += 1
            tree = work / "m"
            if tree.exists():
                shutil.rmtree(tree)
            tree.mkdir()
            snapshot(tree)
            if kind == "doc":
                for rel in REGISTRY_FILES:
                    path = tree / rel
                    path.write_text(path.read_text(encoding="utf-8").replace(f"`{code}`", "`__deleted__`"), encoding="utf-8")
                expected = f"test_failure_code_census::test_every_emitted_code_is_documented[{module}]"
                needle = f"{module}: {code}"
            else:
                path = tree / module
                text = path.read_text(encoding="utf-8")
                mutated = re.sub(rf'(["\']){re.escape(code)}\1', '"zz_deleted"', text)
                assert mutated != text
                path.write_text(mutated, encoding="utf-8")
                expected = "test_failure_code_census::test_bound_section_rows_equal_emitted_codes[## C2PA-SIGNED0 test-only receipt signature lane]"
                needle = code
            cases, tail = run(args.python, tree, mid.replace(":", "_").replace("/", "_"), work)
            failed = sorted(n for n, (s, _) in cases.items() if s == "fail")
            hit = next((n for n in failed if n == expected), None)
            named = hit is not None and needle in cases[hit][1]
            ok = len(cases) > 0 and named
            killed += ok
            print(f"{'KILLED  ' if ok else 'SURVIVED'} {mid}\n    by: {hit or '(expected test did not fail)'}"
                  f"\n    all failing: {failed or 'none'}")
            if not ok:
                problems.append(mid)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    after = inventory(REPO)
    if before != after:
        problems.append("the real tree changed during the run")
    print(f"\n{killed}/{total} mutants killed by their named test; real tree unchanged: {before == after}")
    if problems:
        print("PROBLEMS: " + ", ".join(problems))
        return 1
    print("CENSUS_CONTROLS=ALL_KILLED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
