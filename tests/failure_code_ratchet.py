"""SCITT-RATCHET0: the failure-code known-gaps ledger is shrink-only, judged by a
SEALED JUDGE taken from an INDEPENDENTLY PINNED base.

The defect this closes
----------------------
``tests/test_failure_code_census.py::test_known_gap_is_exactly_the_undocumented_set``
compares the undocumented code-shaped emissions of the working tree with
``tests/failure_code_known_gaps.json`` *of the same working tree*. A commit that
adds an undocumented code and the matching ledger entry satisfies it: the
candidate wrote both sides of the comparison. Review then showed the checker
itself must not run candidate code either (a planted ``tests/pytest.py`` source
shadow, and a committed unchecked-hash ``.pyc`` of a guarded module, each forced
PASS on a real growth violation).

Architecture: the candidate checkout is DATA, never code
--------------------------------------------------------
1. BASELINE. Permitted set = ``git show <base>:tests/failure_code_known_gaps.json``.
   Base = tip of ``refs/remotes/origin/main`` by default, or an explicit 40-hex
   SHA supplied out of band (``--base`` / ``ARCS_VERIFY_RATCHET_BASE``) that must
   be an ancestor of ``origin/main``. No file in the candidate tree selects it.
2. JUDGE PROVENANCE. The code that analyses the candidate
   (``failure_code_judge.py`` + ``failure_code_census.py``) is extracted with
   ``git show`` from the BASE commit into a fresh directory. If the base does not
   contain them the result is ``BASE_JUDGE_ABSENT`` (NOT_ESTABLISHED) unless an
   out-of-band ``--allow-judge-introduction`` is given, in which case the
   verdict is labelled ``PASS_INTRODUCTION`` and is NOT independently established.
3. ISOLATION. The judge runs in a separate interpreter started ``-I -S -B -X
   pycache_prefix=<fresh>`` with a cleared environment and its working directory
   set to the fresh directory. The candidate tree is on no import path; candidate
   source is read as bytes and ``ast.parse``d; candidate ``__pycache__``/``.pyc``,
   ``.pth``, ``sitecustomize``/``usercustomize`` and ``PYTHON*`` variables cannot
   reach it. The launcher itself imports nothing from the candidate either.
4. DECISION (this file, taken from the base by the operator): every candidate
   undocumented ``(module, code|family)`` must be in the BASE ledger; the
   candidate ledger must be a subset of the base ledger; the candidate's ledger is
   never an input to the permission decision.
5. READ-AS-PYTHON-RUNS. The judge parses bytes (coding cookie and BOM honoured),
   enumerates the package itself, and refuses symlinks and source-less importable
   files under ``arcs_verify/``; this launcher refuses a package that is missing
   or collapsed relative to the BASE commit's module count (no hard-coded floor).
6. REVIEW PRESSURE. Files that define the judge or this launcher are GUARDED;
   a difference from the base is ``SELECTION_CHANGED`` unless an out-of-band
   digest of the candidate's guarded files is supplied after a human read the diff.
   They cannot affect the verdict of the change that edits them (the judge is the
   base's); they take effect from the next base.

Threat model and limits: see ``docs/FAILURE_CODE_RATCHET.md``. In short: the
operator must obtain THIS launcher from the base (``git show``), run it with
``python -I``, and trust git, the Python interpreter and the host; this is a
qualified local control, not a repository-enforced policy.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LEDGER = "tests/failure_code_known_gaps.json"
DEFAULT_BASE_REF = "refs/remotes/origin/main"
ENV_BASE = "ARCS_VERIFY_RATCHET_BASE"
ENV_ACCEPT = "ARCS_VERIFY_RATCHET_ACCEPT_SELECTION"
ENV_REQUIRED = "ARCS_VERIFY_RATCHET_REQUIRED"
ENV_INTRO = "ARCS_VERIFY_RATCHET_ALLOW_INTRODUCTION"

# Extracted from the BASE commit and run sealed. (repo path -> staged file name)
JUDGE_FILES = ("tests/failure_code_judge.py", "tests/failure_code_census.py")
JUDGE_TIMEOUT_SECONDS = 300

# Everything that decides the base, the undocumented computation, or the verdict.
GUARDED = (
    "tests/failure_code_ratchet.py",
    "tests/failure_code_judge.py",
    "tests/test_failure_code_ratchet.py",
    "tests/failure_code_census.py",
    "tests/test_failure_code_census.py",
    "tests/test_failure_code_registry.py",
    "tools/qualify_failure_code_census.py",
    "tools/qualify_failure_code_ratchet.py",
)

# Violation codes. Each adversarial case names the one it must produce.
BASE_UNRESOLVED = "BASE_UNRESOLVED"
BASE_NOT_ON_MAIN = "BASE_NOT_ON_MAIN"
BASE_LEDGER_UNREADABLE = "BASE_LEDGER_UNREADABLE"
GROWTH_NEW_MODULE = "GROWTH_NEW_MODULE"
GROWTH_CODE = "GROWTH_CODE"
GROWTH_FAMILY = "GROWTH_FAMILY"
LEDGER_GROWTH = "LEDGER_GROWTH"
SELECTION_CHANGED = "SELECTION_CHANGED"
BASE_JUDGE_ABSENT = "BASE_JUDGE_ABSENT"
JUDGE_ERROR = "JUDGE_ERROR"
PACKAGE_MISSING = "PACKAGE_MISSING"
PACKAGE_COLLAPSED = "PACKAGE_COLLAPSED"
SYMLINK_IN_PACKAGE = "SYMLINK_IN_PACKAGE"
UNSCANNED_IMPORTABLE = "UNSCANNED_IMPORTABLE"
# A candidate that keeps fewer than this fraction of the BASE's package modules
# is a collapse (moved/emptied package), not a refactor. Relative to the base on
# purpose: no hard-coded module count.
COLLAPSE_FRACTION = 0.5

_HEX40 = re.compile(r"^[0-9a-f]{40}$")


@dataclass(frozen=True)
class Violation:
    code: str
    subject: str
    detail: str = ""

    def __str__(self) -> str:
        return f"{self.code}: {self.subject}" + (f" -- {self.detail}" if self.detail else "")


@dataclass
class Result:
    base: str | None = None
    violations: list[Violation] = field(default_factory=list)
    introduced: list[str] = field(default_factory=list)
    selection_accepted: bool = False
    modules_checked: int = 0
    provenance: str = "unresolved"

    @property
    def ok(self) -> bool:
        return not self.violations

    def codes(self) -> set[str]:
        return {v.code for v in self.violations}


# ---------------------------------------------------------------------------
# git access (read-only)
# ---------------------------------------------------------------------------


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    return subprocess.run(["git", "-C", str(root), *args], capture_output=True, env=env, timeout=60)


def resolve_base(root: Path, explicit: str | None) -> tuple[str | None, list[Violation]]:
    """Return (full 40-hex SHA, problems). Never trusts any file in the tree."""
    spec = explicit or os.environ.get(ENV_BASE) or DEFAULT_BASE_REF
    if explicit or os.environ.get(ENV_BASE):
        if not _HEX40.match(spec):
            return None, [Violation(BASE_UNRESOLVED, spec, "an explicit base must be a full 40-hex commit SHA")]
    tip = _git(root, "rev-parse", "--verify", "--quiet", "--end-of-options", f"{DEFAULT_BASE_REF}^{{commit}}")
    tip_sha = tip.stdout.decode().strip() if tip.returncode == 0 else None
    got = _git(root, "rev-parse", "--verify", "--quiet", "--end-of-options", f"{spec}^{{commit}}")
    if got.returncode != 0 or not _HEX40.match(got.stdout.decode().strip()):
        return None, [Violation(BASE_UNRESOLVED, spec, "cannot be resolved to a commit in this repository")]
    sha = got.stdout.decode().strip()
    if spec != DEFAULT_BASE_REF:
        if tip_sha is None:
            return None, [Violation(BASE_UNRESOLVED, spec, f"{DEFAULT_BASE_REF} is not present, so the pin cannot be shown to be on main")]
        if _git(root, "merge-base", "--is-ancestor", sha, tip_sha).returncode != 0:
            return None, [Violation(BASE_NOT_ON_MAIN, sha, f"not an ancestor of {DEFAULT_BASE_REF} ({tip_sha})")]
    return sha, []


def show(root: Path, sha: str, path: str) -> bytes | None:
    got = _git(root, "show", f"{sha}:{path}")
    return got.stdout if got.returncode == 0 else None


def read_base_ledger(root: Path, sha: str) -> tuple[dict[str, dict] | None, list[Violation]]:
    raw = show(root, sha, LEDGER)
    if raw is None:
        return None, [Violation(BASE_LEDGER_UNREADABLE, f"{sha}:{LEDGER}", "absent at the base commit")]
    try:
        modules = json.loads(raw.decode("utf-8"))["modules"]
        for entry in modules.values():
            list(entry["codes"]), list(entry["families"])
        return modules, []
    except (ValueError, KeyError, TypeError) as exc:
        return None, [Violation(BASE_LEDGER_UNREADABLE, f"{sha}:{LEDGER}", f"{type(exc).__name__}: {exc}")]


# ---------------------------------------------------------------------------
# the decision (pure)
# ---------------------------------------------------------------------------


def growth_violations(
    candidate: dict[str, tuple[set[str], set[str]]],
    base_ledger: dict[str, dict],
    candidate_ledger: dict[str, dict],
) -> list[Violation]:
    """``candidate``: module -> (undocumented codes, undocumented family prefixes),
    recomputed from the candidate's own source and registry. The candidate's
    ledger is consulted ONLY to forbid it from exceeding the base ledger."""
    out: list[Violation] = []
    for module in sorted(candidate):
        codes, prefixes = candidate[module]
        if not codes and not prefixes:
            continue
        permitted = base_ledger.get(module)
        if permitted is None:
            out.append(
                Violation(GROWTH_NEW_MODULE, module, f"codes={sorted(codes)} families={sorted(prefixes)} not permitted by the base")
            )
            continue
        for code in sorted(codes - set(permitted["codes"])):
            out.append(Violation(GROWTH_CODE, f"{module}: {code}", "undocumented and not permitted by the base ledger"))
        for prefix in sorted(prefixes - set(permitted["families"])):
            out.append(Violation(GROWTH_FAMILY, f"{module}: {prefix}<...>", "undocumented family not permitted by the base ledger"))
    for module in sorted(candidate_ledger):
        permitted = base_ledger.get(module)
        entry = candidate_ledger[module]
        if permitted is None:
            out.append(Violation(LEDGER_GROWTH, module, "ledger names a module the base ledger does not"))
            continue
        for code in sorted(set(entry["codes"]) - set(permitted["codes"])):
            out.append(Violation(LEDGER_GROWTH, f"{module}: {code}", "ledger entry absent from the base ledger"))
        for prefix in sorted(set(entry["families"]) - set(permitted["families"])):
            out.append(Violation(LEDGER_GROWTH, f"{module}: {prefix}<...>", "ledger family absent from the base ledger"))
    return out


def selection_manifest(root: Path) -> dict[str, str]:
    """path -> sha256 of the candidate's bytes, or 'ABSENT'."""
    out: dict[str, str] = {}
    for path in GUARDED:
        target = root / path
        out[path] = hashlib.sha256(target.read_bytes()).hexdigest() if target.is_file() else "ABSENT"
    return out


def selection_digest(manifest: dict[str, str]) -> str:
    text = "".join(f"{path}\0{manifest[path]}\n" for path in sorted(manifest))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def selection_violations(
    manifest: dict[str, str], base_manifest: dict[str, str | None]
) -> tuple[list[Violation], list[str]]:
    """(violations, first-introductions). base_manifest value None = absent at base."""
    out: list[Violation] = []
    introduced: list[str] = []
    for path in GUARDED:
        mine, theirs = manifest[path], base_manifest[path]
        if theirs is None:
            if mine != "ABSENT":
                introduced.append(path)
        elif mine == "ABSENT":
            out.append(Violation(SELECTION_CHANGED, path, "guarded file deleted relative to the base"))
        elif mine != theirs:
            out.append(Violation(SELECTION_CHANGED, path, "guarded file differs from the base commit's copy"))
    return out, introduced


def base_manifest(root: Path, sha: str) -> dict[str, str | None]:
    out: dict[str, str | None] = {}
    for path in GUARDED:
        raw = show(root, sha, path)
        out[path] = None if raw is None else hashlib.sha256(raw).hexdigest()
    return out


# ---------------------------------------------------------------------------
# candidate computation (uses the candidate's own census)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# the sealed judge (taken from the base commit, run isolated)
# ---------------------------------------------------------------------------


def stage_judge(root: Path, sha: str, stage: Path, allow_introduction: bool) -> tuple[Path | None, str, list[Violation]]:
    """Write the judge files into ``stage/judge`` from BASE bytes (``git show``).

    Returns (directory, provenance, problems). The directory contains no file
    that came from a working tree unless the out-of-band introduction flag was
    given, in which case the provenance says so."""
    target = stage / "judge"
    target.mkdir(parents=True)
    from_base = {path: show(root, sha, path) for path in JUDGE_FILES}
    if all(raw is not None for raw in from_base.values()):
        for path, raw in from_base.items():
            (target / Path(path).name).write_bytes(raw)
        return target, f"base {sha}", []
    missing = sorted(path for path, raw in from_base.items() if raw is None)
    if not allow_introduction:
        return None, "NOT_ESTABLISHED", [
            Violation(BASE_JUDGE_ABSENT, ", ".join(missing), f"not present at base {sha}; no independent judge exists to run")
        ]
    for path in JUDGE_FILES:  # candidate bytes, copied as DATA into the fresh directory
        (target / Path(path).name).write_bytes((root / path).read_bytes())
    return target, "INTRODUCTION", []


def run_judge(root: Path, judge_dir: Path, stage: Path) -> tuple[dict | None, list[Violation]]:
    pyc = stage / "pyc"
    pyc.mkdir()
    env = {"PYTHONDONTWRITEBYTECODE": "1", "LC_ALL": "C.UTF-8"}
    cmd = [
        sys.executable, "-I", "-S", "-B", "-X", f"pycache_prefix={pyc}",
        str(judge_dir / "failure_code_judge.py"), "--root", str(root),
    ]
    try:
        done = subprocess.run(cmd, cwd=judge_dir, env=env, capture_output=True, timeout=JUDGE_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        return None, [Violation(JUDGE_ERROR, "judge", f"timed out after {JUDGE_TIMEOUT_SECONDS}s")]
    text = done.stdout.decode("utf-8", "replace").strip()
    try:
        payload = json.loads(text.splitlines()[-1]) if text else None
    except ValueError:
        payload = None
    if done.returncode != 0 or not isinstance(payload, dict) or "modules" not in payload:
        detail = (payload or {}).get("error") if isinstance(payload, dict) else None
        detail = detail or (done.stderr.decode("utf-8", "replace").strip().splitlines() or ["no usable output"])[-1]
        return None, [Violation(JUDGE_ERROR, "judge", f"exit {done.returncode}: {detail}")]
    return payload, []


def base_module_count(root: Path, sha: str) -> int:
    got = _git(root, "ls-tree", "-r", "--name-only", sha, "--", "arcs_verify")
    names = got.stdout.decode("utf-8", "replace").splitlines() if got.returncode == 0 else []
    return sum(1 for name in names if name.endswith(".py"))


def package_violations(payload: dict, base_count: int) -> list[Violation]:
    out: list[Violation] = []
    scanned = int(payload["package_modules"])
    if scanned == 0:
        out.append(Violation(PACKAGE_MISSING, "arcs_verify", "the candidate has no scannable package modules; nothing was judged"))
    elif base_count and scanned < base_count * COLLAPSE_FRACTION:
        out.append(Violation(
            PACKAGE_COLLAPSED, "arcs_verify",
            f"{scanned} modules scanned against {base_count} at the base (< {COLLAPSE_FRACTION:.0%}); the package moved or was emptied",
        ))
    for path in payload.get("symlinks", []):
        out.append(Violation(SYMLINK_IN_PACKAGE, path, "a symlink under the package is importable but was not scanned; refused"))
    for path in payload.get("unscanned_importable", []):
        out.append(Violation(UNSCANNED_IMPORTABLE, path, "a source-less importable file cannot be censused; refused"))
    return out


def evaluate(
    root: Path,
    explicit_base: str | None = None,
    accept: str | None = None,
    allow_introduction: bool | None = None,
) -> Result:
    result = Result()
    sha, problems = resolve_base(root, explicit_base)
    result.violations += problems
    if sha is None:
        return result
    result.base = sha
    base_ledger, problems = read_base_ledger(root, sha)
    result.violations += problems
    if base_ledger is None:
        return result
    if allow_introduction is None:
        allow_introduction = os.environ.get(ENV_INTRO, "") == "1"

    stage = Path(tempfile.mkdtemp(prefix="ratchet-judge."))
    try:
        judge_dir, result.provenance, problems = stage_judge(root, sha, stage, allow_introduction)
        result.violations += problems
        if judge_dir is None:
            return result
        payload, problems = run_judge(root, judge_dir, stage)
        result.violations += problems
    finally:
        shutil.rmtree(stage, ignore_errors=True)

    # The candidate ledger is read as JSON DATA; it only has to stay within the base ledger.
    try:
        candidate_ledger = json.loads((root / LEDGER).read_bytes().decode("utf-8"))["modules"]
    except (OSError, ValueError, KeyError) as exc:
        result.violations.append(Violation(JUDGE_ERROR, LEDGER, f"candidate ledger unreadable: {type(exc).__name__}"))
        candidate_ledger = {}
    if payload is not None:
        result.modules_checked = int(payload["package_modules"])
        result.violations += package_violations(payload, base_module_count(root, sha))
        candidate = {m: (set(v["codes"]), set(v["families"])) for m, v in payload["modules"].items()}
        result.violations += growth_violations(candidate, base_ledger, candidate_ledger)

    manifest = selection_manifest(root)
    sel, introduced = selection_violations(manifest, base_manifest(root, sha))
    result.introduced = introduced
    accept = accept if accept is not None else os.environ.get(ENV_ACCEPT)
    if sel and accept and accept == selection_digest(manifest):
        result.selection_accepted = True
    else:
        result.violations += sel
    return result


def required() -> bool:
    return os.environ.get(ENV_REQUIRED, "") == "1"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SCITT-RATCHET0 launcher (see module docstring)")
    parser.add_argument("--root", default=str(ROOT), help="candidate checkout (default: this file's repository)")
    parser.add_argument("--base", default=None, help="full 40-hex base commit (must be on origin/main)")
    parser.add_argument("--accept-selection-change", default=None, help="out-of-band digest for a reviewed guarded-file change")
    parser.add_argument("--allow-judge-introduction", action="store_true",
                        help="out-of-band: the base has no judge yet (first introduction); verdict is PASS_INTRODUCTION, not independent")
    parser.add_argument("--print-selection-digest", action="store_true")
    args = parser.parse_args(argv)
    if not sys.flags.isolated:
        print("RATCHET=NOT_ESTABLISHED: run with `python3 -I` so PYTHON* variables, the working directory and user "
              "site-packages cannot route code into this process (see docs/FAILURE_CODE_RATCHET.md)")
        return 2
    root = Path(args.root).resolve()
    if args.print_selection_digest:
        print(selection_digest(selection_manifest(root)))
        return 0
    result = evaluate(root, args.base, args.accept_selection_change, True if args.allow_judge_introduction else None)
    print(f"base: {result.base}")
    print(f"judge provenance: {result.provenance}")
    print(f"modules checked: {result.modules_checked}")
    if result.introduced:
        print("guarded files first introduced (absent at base; covered by owner review): " + ", ".join(result.introduced))
    if result.selection_accepted:
        print("selection change ACCEPTED by out-of-band digest")
    for violation in result.violations:
        print(f"VIOLATION {violation}")
    if result.ok:
        print("RATCHET=PASS" if result.provenance.startswith("base ") else "RATCHET=PASS_INTRODUCTION")
    else:
        print("RATCHET=FAIL " + ",".join(sorted(result.codes())))
    if not result.ok and result.codes() <= {BASE_UNRESOLVED, BASE_NOT_ON_MAIN, BASE_LEDGER_UNREADABLE, BASE_JUDGE_ABSENT}:
        return 2
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
