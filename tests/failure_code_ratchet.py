"""SCITT-RATCHET0: the failure-code known-gaps ledger is shrink-only against an
INDEPENDENTLY PINNED base.

The defect this closes
----------------------
``tests/test_failure_code_census.py::test_known_gap_is_exactly_the_undocumented_set``
compares the undocumented code-shaped emissions of the working tree with
``tests/failure_code_known_gaps.json`` *of the same working tree*. A commit that
(a) introduces an undocumented failure code and (b) adds that code to the ledger
satisfies it: the candidate wrote both sides of the comparison.

The mechanism
-------------
The permitted set is read from a commit the candidate cannot edit, and the
candidate's ledger file is never an input to the permission decision:

* BASE = the tip of ``refs/remotes/origin/main`` by default, or an explicit
  40-hex commit supplied OUT OF BAND (``--base`` / ``ARCS_VERIFY_RATCHET_BASE``).
  It is resolved with ``git rev-parse`` to a full SHA and the permitted set is
  read with ``git show <sha>:tests/failure_code_known_gaps.json``. A commit on a
  feature branch cannot move ``origin/main``, an environment variable, or a CLI
  flag. An explicit pin must be an ancestor of (or equal to) ``origin/main``.
* The tip, not the merge-base, is used on purpose: the ledger only shrinks, so
  an older base is strictly more permissive. Branching from a stale commit
  cannot buy a larger allowance; a branch behind a shrunk ledger must catch up.
* CANDIDATE undocumented set = recomputed from the candidate's source and
  registry by the census (every package module, registered or not). Every
  ``(module, code)`` / ``(module, family)`` in it must appear in the BASE ledger.
  Growth is rejected whatever the candidate's ledger says.
* The candidate ledger must also be a subset of the base ledger (so the file
  cannot be quietly widened for a later commit to lean on).
* BASELINE-SELECTION INTEGRITY. Everything that decides what "undocumented"
  means or which base is used is a GUARDED file (``GUARDED``). Each must be
  byte-identical to the base commit's copy, or be absent from both, or be a
  first introduction (absent at the base). A changed or deleted guarded file is
  ``SELECTION_CHANGED``. The only release valve is a digest of the candidate's
  guarded files supplied OUT OF BAND (``--accept-selection-change`` /
  ``ARCS_VERIFY_RATCHET_ACCEPT_SELECTION``) after a human has read the diff. A
  file in the tree cannot grant it.

Honest limits
-------------
* A candidate can edit this very file. The in-tree test therefore proves the
  mechanism; the AUTHORITATIVE run executes the BASE's copy of this file against
  the candidate tree (``git show <base>:tests/failure_code_ratchet.py`` then
  ``python <copy> --root <candidate>``), which a candidate cannot weaken. The
  guarded-digest comparison then reports any edit to the candidate's copy.
* The first introduction of this mechanism (the commit that adds this file)
  has no base copy to compare against; that one event is covered by owner review.
* "Documented" keeps its existing meaning: the code appears in backticks in the
  registry text. Adding a bogus registry row is a documentation edit, visible in
  review, and is not what this ratchet polices.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LEDGER = "tests/failure_code_known_gaps.json"
DEFAULT_BASE_REF = "refs/remotes/origin/main"
ENV_BASE = "ARCS_VERIFY_RATCHET_BASE"
ENV_ACCEPT = "ARCS_VERIFY_RATCHET_ACCEPT_SELECTION"
ENV_REQUIRED = "ARCS_VERIFY_RATCHET_REQUIRED"

# Everything that decides the base, the undocumented computation, or the verdict.
GUARDED = (
    "tests/failure_code_ratchet.py",
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
    not_evaluated: str | None = None

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


def candidate_undocumented(gate) -> dict[str, tuple[set[str], set[str]]]:
    """module -> undocumented (codes, families) for EVERY package module."""
    import failure_code_census as census_lib  # noqa: PLC0415

    out: dict[str, tuple[set[str], set[str]]] = {}
    for module in census_lib.package_modules():
        codes, prefixes = gate._undocumented(module, gate._census(module), gate.REGISTRY)
        if codes or prefixes:
            out[module] = (codes, prefixes)
    return out


UNGUARDED_MODULE_LOADED = "UNGUARDED_MODULE_LOADED"
GATE_IMPORT_FAILED = "GATE_IMPORT_FAILED"
GROWTH_NOT_EVALUATED = "growth not evaluated: a guarded file differs from the base and no out-of-band acceptance was given, so no candidate code was imported"


def load_gate_sealed(root: Path):
    """Import the candidate's census test WITHOUT letting any unguarded
    candidate file execute in this process.

    The candidate tree is the thing under test, so nothing in it may run before
    the verdict unless a guarded (hash-checked) file asks for it. Python's
    default of putting the candidate's ``tests/`` directory FIRST on ``sys.path``
    lets a planted ``tests/pytest.py`` (or ``json.py``, ``functools.py``, ...)
    shadow what the guarded files import and run inside the checker. So:

    1. every ``sys.path`` entry that is, or resolves to, the candidate's
       ``tests/`` directory or the working directory is removed;
    2. everything the guarded files import from outside the candidate is
       imported NOW, from the real interpreter and site-packages;
    3. the candidate's ``tests/`` directory is appended LAST, so it can only
       supply a name nothing earlier provides (the guarded siblings);
    4. afterwards, every module loaded from under the candidate root must be a
       guarded file; anything else is ``UNGUARDED_MODULE_LOADED``.

    Returns (module, problems).
    """
    tests = (root / "tests").resolve()
    keep = []
    for entry in sys.path:
        if entry in ("", "."):
            continue
        try:
            if Path(entry).resolve() == tests:
                continue
        except OSError:
            pass
        keep.append(entry)
    sys.path[:] = keep
    for name in ("ast", "json", "re", "collections.abc", "contextlib", "functools", "dataclasses", "pathlib", "pytest"):
        __import__(name)
    sys.path.append(str(tests))
    problems: list[Violation] = []
    try:
        import test_failure_code_census as gate  # noqa: PLC0415
    except Exception as exc:  # a broken candidate must fail closed, not crash with a traceback-as-pass
        return None, [Violation(GATE_IMPORT_FAILED, "tests/test_failure_code_census.py", f"{type(exc).__name__}: {exc}")]
    allowed = {(root / g).resolve() for g in GUARDED}
    for name, module in sorted(sys.modules.items()):
        file = getattr(module, "__file__", None)
        if not file:
            continue
        try:
            path = Path(file).resolve()
        except OSError:
            continue
        if root in path.parents and path not in allowed and "arcs_verify" not in path.relative_to(root).parts[:1]:
            problems.append(Violation(UNGUARDED_MODULE_LOADED, path.relative_to(root).as_posix(), f"imported as {name!r}; it is not a guarded file"))
    return gate, problems


def evaluate(root: Path, gate=None, explicit_base: str | None = None, accept: str | None = None) -> Result:
    """``gate`` is an already-imported census test module (in-process use under
    pytest). When ``None`` (the CLI) the candidate's code is imported only after
    its guarded files have been hash-checked against the base, and sealed."""
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

    # Hash checks first: they read bytes and import nothing from the candidate.
    manifest = selection_manifest(root)
    sel, introduced = selection_violations(manifest, base_manifest(root, sha))
    result.introduced = introduced
    accept = accept if accept is not None else os.environ.get(ENV_ACCEPT)
    if sel and accept and accept == selection_digest(manifest):
        result.selection_accepted = True
    elif sel:
        result.violations += sel
        result.not_evaluated = GROWTH_NOT_EVALUATED
        return result

    if gate is None:
        gate, problems = load_gate_sealed(root)
        result.violations += problems
        if gate is None or problems:
            return result

    import failure_code_census as census_lib  # noqa: PLC0415

    candidate = candidate_undocumented(gate)
    result.modules_checked = len(census_lib.package_modules())
    candidate_ledger = json.loads((root / LEDGER).read_text(encoding="utf-8"))["modules"]
    result.violations += growth_violations(candidate, base_ledger, candidate_ledger)
    return result


def required() -> bool:
    return os.environ.get(ENV_REQUIRED, "") == "1"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--root", default=str(ROOT), help="candidate checkout (default: this file's repository)")
    parser.add_argument("--base", default=None, help="full 40-hex base commit (must be on origin/main)")
    parser.add_argument("--accept-selection-change", default=None, help="out-of-band digest for a reviewed guarded-file change")
    parser.add_argument("--print-selection-digest", action="store_true")
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    if args.print_selection_digest:
        print(selection_digest(selection_manifest(root)))
        return 0
    result = evaluate(root, None, args.base, args.accept_selection_change)
    print(f"base: {result.base}")
    print(f"modules checked: {result.modules_checked}")
    if result.introduced:
        print("guarded files first introduced (absent at base; covered by owner review): " + ", ".join(result.introduced))
    if result.selection_accepted:
        print("selection change ACCEPTED by out-of-band digest")
    if result.not_evaluated:
        print("NOT_EVALUATED " + result.not_evaluated)
    for violation in result.violations:
        print(f"VIOLATION {violation}")
    print("RATCHET=PASS" if result.ok else "RATCHET=FAIL " + ",".join(sorted(result.codes())))
    if not result.ok and result.codes() <= {BASE_UNRESOLVED, BASE_NOT_ON_MAIN, BASE_LEDGER_UNREADABLE}:
        return 2
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
