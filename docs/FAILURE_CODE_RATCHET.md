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
git show origin/main:tests/failure_code_ratchet.py > /tmp/ratchet_base.py
python3 /tmp/ratchet_base.py --root <candidate checkout>
```

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
