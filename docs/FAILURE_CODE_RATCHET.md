# Failure-code known-gaps ratchet (SCITT-RATCHET0 / CORR2)

`tests/failure_code_known_gaps.json` lists code-shaped emissions in modules whose
codes are not yet in `docs/FAILURE_CODES.md`. It must only shrink.

## What this is — the claim, stated at its real size

RATCHET0 is a **sealed-judge (code-execution-proof), best-effort growth detector
for statically-apparent, honestly-written failure codes.** It is **not** an
adversary-proof completeness gate. A candidate commit cannot make the judge run
its code, choose its baseline, or widen the permitted set; but a contributor who
deliberately evades static analysis can still emit an unregistered code. The
evasions that are known and **deliberately not chased** are listed in
"Bounded threat model" below and are part of the claim.

## What this is, and is not, enforcing

A passing ratchet run is a **qualified local control**, not an automatically
enforced repository policy. This repository has no required status checks and
GitHub Actions is not a merge gate, so **GitHub will not block a violating
merge**. Enforcement is whoever runs the authoritative command (below) on the
exact head before merging. No CI gate is added by this change.

## The hole this closes

`tests/test_failure_code_census.py` compares the undocumented emissions of the
working tree with the ledger **in the same working tree**. A commit that adds an
undocumented code and adds it to the ledger satisfies that check: the candidate
writes both sides of the comparison.

Two further bypasses were found in review of earlier heads, both of the form
"candidate code runs inside the judge": a planted `tests/pytest.py` imported
ahead of real pytest, and a committed `UNCHECKED_HASH` `.pyc` for a guarded
module. Both replaced the growth check from inside the checker process. Filtering
filenames cannot close that class; the architecture below does.

## Architecture: the candidate checkout is DATA, never code

| Concern | Mechanism |
|---|---|
| Baseline | `git show <base>:tests/failure_code_known_gaps.json`. Base = tip of `refs/remotes/origin/main`, or an out-of-band full 40-hex SHA (`--base` / `ARCS_VERIFY_RATCHET_BASE`) that must be an ancestor of `origin/main`. No file in the candidate selects it. |
| Judge provenance | `failure_code_judge.py` + `failure_code_census.py` are extracted with `git show` from the **base commit** into a fresh temporary directory. If the base does not contain them: `BASE_JUDGE_ABSENT`, i.e. NOT_ESTABLISHED (exit 2). |
| Isolation | The judge runs in its own interpreter: `python -I -S -B -X pycache_prefix=<fresh dir>`, environment cleared, working directory = the fresh directory. The candidate tree is on no import path. |
| Candidate handling | Candidate `.py` files are read as bytes and `ast.parse`d; the registry is read as text; the ledger as JSON. Nothing from the candidate is imported or executed. Any judge failure (unparseable source, timeout, crash, no output) is `JUDGE_ERROR`, never an empty set. |
| Read as Python runs it | The judge parses candidate source as **bytes** (`ast.parse(bytes)`), so a PEP 263 coding cookie (`# coding: utf-7`) or a BOM is honoured exactly as the interpreter honours it; decoding to text first let a cookie hide a code. It enumerates the package itself (no `rglob`) and **refuses** what a source scan cannot see but the interpreter can import: any symlink under `arcs_verify/` (`SYMLINK_IN_PACKAGE`) and source-less `.pyc` / extension files (`UNSCANNED_IMPORTABLE`). Undecodable source is `JUDGE_ERROR`. |
| Importable-set superset | The scanned set must be a superset of what Python can import from the package. Nothing is pruned: a `.py` placed inside a `__pycache__` directory is an ordinary namespace-package module, so it is scanned **and** refused (`IMPORTABLE_IN_PYCACHE`); ordinary `.pyc` caches there are ignored; symlinks and extension modules anywhere, `__pycache__` included, are refused. |
| Constant folding | Compile-time-constant string expressions are folded before the code-shape check, so the value the interpreter computes is what is judged: `"a" + "b"`, `"zz_%s" % "x"`, `"zz_" * 2`, and f-strings of constants. `"prefix" + variable` keeps its family-prefix treatment. |
| Package floor | Scanning zero modules is `PACKAGE_MISSING`; keeping fewer than half of the **base commit's** package modules is `PACKAGE_COLLAPSED` (relative to `git ls-tree` of the base, no hard-coded count). Removing a few modules is not a collapse. |
| Decision | Every candidate undocumented `(module, code)` / `(module, family)` must be in the **base** ledger (`GROWTH_CODE`, `GROWTH_FAMILY`, `GROWTH_NEW_MODULE`); the candidate ledger must be a subset of the base ledger (`LEDGER_GROWTH`). The candidate ledger is never an input to the permission decision. Shrinkage and newly documented codes are permitted. |
| Review pressure | The judge, the launcher, the census and their tests are GUARDED. A difference from the base is `SELECTION_CHANGED` unless an out-of-band digest of the candidate's guarded files is supplied after a human read the diff. A change to the judge cannot affect the verdict of the commit that makes it (the judge is the base's); it takes effect from the next base. |

The tip rather than the merge-base is used on purpose: the ledger only shrinks,
so an older base is strictly more permissive. A branch cut before a shrink must
catch up.

### Why candidate source, bytecode, `.pth`, `sitecustomize` and environment cannot reach the verdict

* The judge process never imports from the candidate: its only import location is
  the fresh directory written from base bytes, so a planted `pytest.py`, `json.py`,
  `ast.py`, ... (or a sourceless `.pyc`) has no path to be found.
* `-I` removes the script directory, the working directory, user site and every
  `PYTHON*` variable from the equation; the launcher also passes a cleared
  environment, so `PYTHONPATH`/`PYTHONSTARTUP`/`PYTHONPYCACHEPREFIX` set by the
  operator's shell do not reach it either.
* `-S` means `site` never runs, so no `.pth` file and no `sitecustomize` /
  `usercustomize` is processed.
* `-B` plus a fresh `pycache_prefix` means no bytecode cache is read, including a
  committed `UNCHECKED_HASH` `.pyc`; nothing is written back either.
* The launcher is stdlib-only and imports nothing from the candidate; it refuses
  to run unless the interpreter is isolated (`RATCHET=NOT_ESTABLISHED`).

## Authoritative run

```bash
mkdir -p /tmp/ratchet_base && git show origin/main:tests/failure_code_ratchet.py > /tmp/ratchet_base/ratchet.py
python3 -I /tmp/ratchet_base/ratchet.py --root <candidate checkout>
```

Get the launcher from the **base**, not from the candidate: a candidate can
rewrite its own launcher to approve everything (proven in
`test_authoritative_base_copy_run_defeats_a_neutered_candidate_checker`). Exit 0
pass, 1 violations, 2 not established (unresolvable base, base lacks the judge,
not isolated). `ARCS_VERIFY_RATCHET_REQUIRED=1` turns the in-suite skip into a
failure; the qualifier sets it. A skip is NOT_EXERCISED, never a pass.

Helpers: `--print-selection-digest`, `--accept-selection-change <digest>` (or
`ARCS_VERIFY_RATCHET_ACCEPT_SELECTION`) for a reviewed change to guarded files;
acceptance never excuses growth.

## Bounded threat model and remaining limitations

In scope (a contributor controls the candidate commit(s) and nothing else): the
candidate source tree, its bytecode, its configuration, its test helpers, its
ledger, the registry text and the `.pth` / `sitecustomize` files it carries.

### Known evasions of the static census — recorded, not fixed

1. **Aliased sink.** `from x import _sink as emit; emit("zz_growth")` is missed:
   sinks are matched by the callee's NAME (a function whose parameter name
   contains `code`), not resolved through import aliases.
2. **Outside the package.** A code emitted from a module outside `arcs_verify/`
   but imported in is out of census scope. The ratchet is scoped to the package;
   failure codes are expected to live in it.
3. **Runtime construction.** A code assembled purely at runtime is unreachable by
   any static census: `exec`/`eval`, `getattr`, `.format`, `str.join`, computed
   strings beyond constant folding and the family-prefix handling, codes read from
   data files. This narrows the honest path; it does not prove absence.

### Other limits

* **Bootstrap.** The change that first adds the judge has no base copy. Run
  against a base that predates it the result is `BASE_JUDGE_ABSENT`; with the
  out-of-band `--allow-judge-introduction` the verdict is `PASS_INTRODUCTION`
  and is **not** independently established. From the first base that contains the
  judge onward the code-execution boundary holds. That one introduction rests on
  owner review.
* **Bytecode caches.** A committed `__pycache__` `.pyc` (including an
  `UNCHECKED_HASH` one) for a package module would run instead of the source the
  judge scanned. Judging is of the source; run the verifier from a fresh source
  checkout.
* **The operator and host.** Git, the Python interpreter and standard library,
  the operator's environment and the launcher copy they run are trusted. A
  launcher taken from the candidate, or a non-isolated interpreter, is outside the
  guarantee (the latter is refused).
* **Parser denial of service.** The judge `ast.parse`s attacker-controlled
  source. Hostile input is bounded by a 300 s timeout and fails closed as
  `JUDGE_ERROR`; it cannot produce a PASS.
* **A malicious base.** If `origin/main` already carries a permissive ledger or a
  weakened base judge, the ratchet inherits it. Changes to the judge are visible
  as `SELECTION_CHANGED` and need a human to read the diff.
* **Judge parity.** The judge duplicates the census test's `NOT_CODES` table and
  undocumented computation so it can run without pytest;
  `test_judge_parity_with_the_census_test_on_the_real_tree` fails on drift.
* **"Documented"** keeps its existing meaning: the code appears in backticks in
  the registry text. A bogus registry row is a documentation edit, visible in
  review.
* This does not document, fix or reduce the existing gaps, and adds no CI gate.

## Qualification

`python3 tools/qualify_failure_code_ratchet.py` sabotages one decision site at a
time in a private snapshot and requires the **named** tests to fail; the
unmutated control must run a non-zero number of tests, skip none and be green,
and the real tree is digest-inventoried before and after. Mutants include running
the judge from the candidate tree (source-shadow bypass), running it from the
candidate tree with the bytecode cache enabled (the unchecked-hash `.pyc`
bypass), removing the isolation flags, and letting an introduction read as an
independent pass.
