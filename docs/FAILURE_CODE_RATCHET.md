# Failure-code known-gaps ratchet (SCITT-RATCHET0)

`tests/failure_code_known_gaps.json` lists code-shaped emissions in modules whose
codes are not yet in `docs/FAILURE_CODES.md`. It must only shrink.

## The hole this closes

`tests/test_failure_code_census.py` compares the undocumented emissions of the
working tree with the ledger **in the same working tree**. A commit that adds an
undocumented code and adds it to the ledger satisfies that check, because the
candidate writes both sides of the comparison.

## Mechanism

`tests/failure_code_ratchet.py` takes the permitted set from a commit the
candidate cannot edit and never lets the candidate's ledger decide anything:

| Input | Source |
|---|---|
| Permitted undocumented set | `git show <base>:tests/failure_code_known_gaps.json` |
| Base | tip of `refs/remotes/origin/main`, or a full 40-hex SHA supplied out of band (`--base` / `ARCS_VERIFY_RATCHET_BASE`) that must be an ancestor of `origin/main` |
| Candidate undocumented set | recomputed by the census from the candidate's source and registry, for **every** package module |
| Candidate ledger | only required to be a subset of the base ledger |

Rules: every candidate `(module, code)` and `(module, family)` that is
undocumented must appear in the base ledger (`GROWTH_CODE`, `GROWTH_FAMILY`,
`GROWTH_NEW_MODULE`); the candidate ledger may not exceed the base ledger
(`LEDGER_GROWTH`). Documenting a code and removing it from the ledger is
permitted. A new code that is documented is not undocumented, so it is permitted.

The tip rather than the merge-base is used on purpose: the ledger only shrinks,
so an older base is strictly more permissive. A branch cut before a shrink must
catch up.

## Baseline-selection integrity

The files that decide the base, the undocumented computation, or the verdict are
guarded (`GUARDED` in `failure_code_ratchet.py`). Each must equal the base
commit's copy, or be absent from both, or be a first introduction. An edit or
deletion is `SELECTION_CHANGED`. After a human has read the diff, a change is
accepted only by an out-of-band digest:

```bash
python3 tests/failure_code_ratchet.py --print-selection-digest
python3 tests/failure_code_ratchet.py --accept-selection-change <digest>
```

(or `ARCS_VERIFY_RATCHET_ACCEPT_SELECTION`). A file in the tree cannot grant it.
Acceptance never excuses growth.

## Authoritative run

A candidate can rewrite its own checker. The authoritative run therefore
executes the **base's** copy against the candidate tree:

```bash
mkdir -p /tmp/ratchet_base && git show origin/main:tests/failure_code_ratchet.py > /tmp/ratchet_base/ratchet.py
python3 -I /tmp/ratchet_base/ratchet.py --root <candidate checkout>
```

Run it from an otherwise empty directory with `-I` (isolated: no `PYTHON*`
environment, no script or working directory on `sys.path`).

## No candidate code runs before the verdict

The checker must import the candidate's census (that is how the undocumented set
is computed). Importing from the candidate tree is only safe if nothing the
candidate controls but the guards do not cover can run first. A planted
`tests/pytest.py` (reproduced by independent review against an earlier head) was
imported ahead of the real pytest and replaced the growth check inside the
checker process. The class is closed in three layers, in this order:

1. **Hash before import.** The guarded files are compared with the base commit's
   bytes first. If one differs and no out-of-band acceptance was given, the run
   stops with `SELECTION_CHANGED` and `NOT_EVALUATED`; no candidate code is
   imported at all.
2. **Sealed import** (`load_gate_sealed`). The candidate's `tests/` directory and
   the working directory are removed from `sys.path`; everything the guarded
   files import from outside the candidate (`ast`, `json`, `re`, `contextlib`,
   `functools`, `dataclasses`, `pathlib`, `pytest`) is imported first from the
   real interpreter; the candidate `tests/` directory is appended **last**, so it
   can only supply a name nothing earlier provides (the guarded siblings).
3. **Loaded-module audit.** Afterwards every module loaded from under the
   candidate root must be a guarded file or part of `arcs_verify/`; anything else
   is `UNGUARDED_MODULE_LOADED`.

A planted file with any other name is simply never imported (no guarded file
imports it), and the audit catches a reviewed guarded change that starts to.

Exit 0 pass, 1 violations, 2 base unresolved. An unresolvable base is a failure
(`ARCS_VERIFY_RATCHET_REQUIRED=1` turns the in-suite skip into a failure; the
qualifier sets it). The skip is reported as NOT_EXERCISED, never as a pass.

## What this is, and is not, enforcing

A passing ratchet run is a **qualified local control**, not an automatically
enforced repository policy. This repository has no required status checks and
GitHub Actions is not a merge gate, so GitHub will not block a violating merge.
Enforcement is whoever runs the authoritative check (above) on the exact head
before merging. No CI gate is added by this change.

## Limits

* Environment variables the operator sets (`PYTHONPATH`, `PYTHONSTARTUP`) are
  outside the candidate's control; `-I` ignores them.
* The commit that first adds the ratchet has no base copy to compare with; that
  one introduction is covered by owner review and is listed by the checker.
* "Documented" keeps its existing meaning (the code appears in backticks in the
  registry text). A bogus registry row is a documentation edit, visible in review.
* This does not document, fix or reduce the existing gaps.

## Qualification

`python3 tools/qualify_failure_code_ratchet.py` sabotages one decision site of
the checker at a time in a private snapshot and requires the **named** tests to
fail; the unmutated control must run a non-zero number of tests, skip none and be
green. The real tree is digest-inventoried before and after.
