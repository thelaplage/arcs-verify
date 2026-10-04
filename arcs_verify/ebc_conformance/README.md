# EBC conformance harness (provisional, non-normative)

> Status: PROTOTYPE for an UNRATIFIED doctrine candidate. Nothing in this
> directory is authoritative, is a runtime dependency of anything, or amends
> `arcs_verify.verifier.VerificationReport` or any other existing module in
> this repository.

This package prototypes conformance checking for candidate artifacts of
`dagr.candidates.epistemic-boundary-commitment.v0.1` -- a **proposed and not
yet ratified** doctrine candidate. It exists to let candidate artifact shapes
be exercised against a concrete, testable canonicalization scheme while the
candidate itself is still under discussion. It does not participate in, and
must never be cited as, ratification of that candidate.

## What this harness does

Given a JSON "vector" carrying a horizon, a context packet, an omission
record, a doctrine manifest, a boundary join, an execution commitment, and
optional witness material -- each with a declared `digest` -- the harness:

1. Independently recomputes every derivable digest from the vector's own
   bytes, using its own reimplementation of a candidate canonicalization and
   domain-separation scheme (`sha256(ascii(domain_prefix) +
   canonical_json(payload))`, `arcs_verify/ebc_conformance/canonical.py`).
2. Compares each recomputed digest against the vector's declared value.
3. Cross-checks that the boundary's own `horizon_digest` / `context_digest` /
   `omission_digest` / `doctrine_manifest_digest` fields match the
   independently recomputed digests of those sections (not merely each
   section's own self-reported digest).
4. Flags out-of-scope fields (e.g. an injected `standing` key on a horizon
   projection) rather than silently accepting them.
5. Reports one `EBCConclusion` (`TRUE` / `FALSE` / `NOT_EVALUATED`) per check,
   plus a list of findings, via `EBCConformanceReport`
   (`arcs_verify/ebc_conformance/harness.py`).

Entry point: `verify_ebc_vector(vector: dict) -> EBCConformanceReport`.

## What a PASS (`report.reproducible is True`) means -- and does not mean

A PASS means: **every declared digest in this vector is byte-reproducible
under this scheme, and every cross-artifact digest reference is internally
consistent.** That is the entire claim.

A PASS does **not** mean, and must never be read to mean:

- the horizon correctly or completely describes what was excluded from an
  action's context;
- the omission's stated reasons are true, sufficient, or in good faith;
- the boundary join was computed by an authorized party;
- the execution commitment corresponds to anything that actually ran;
- the artifact has standing, admission, trust, or any other normative status;
- the underlying candidate doctrine (`dagr.candidates.epistemic-boundary-
  commitment.v0.1`) is itself correct, complete, or ratified.

This mirrors the repository-wide invariant already in force for ratified
SRS verification: `not_evaluated != false != pass`, and a structural pass is
never truth, admission, or standing (see the top-level `CLAUDE.md`
"Critical invariants" and the same disclaimer in
`arcs_verify/semantic_projection.py`).

## Relationship to `arcs_verify.verifier.VerificationReport`

This package is **not** a variant, extension, or subclass of
`VerificationReport`. `EBCConformanceReport`:

- lives in its own module (`arcs_verify.ebc_conformance.harness`), not
  `arcs_verify/verifier.py`, which is unmodified by this work;
- has its own, differently-named fields and its own `reproducible` aggregate
  (deliberately not named `passed`, to avoid inviting the SRS reading);
- is not exported from `arcs_verify.__init__` and is not imported by any
  admission or execution path in this repository or elsewhere;
- carries its own report schema string,
  `arcs.verify.ebc_conformance_report.v0.1.provisional`, distinct from every
  `REPORT_CONTRACT_*` constant in `verifier.py`.

Because the underlying doctrine candidate is unratified, this harness is
deliberately **not** given the trappings of a finished verification
vocabulary (no 8-boolean report shape, no `chain_status`, no canonical
profile registry entry). Doing so would misrepresent an unratified candidate
as though it had the same standing as the ratified SRS profile family.

## Open normative questions this harness does NOT resolve

This harness recomputes bytes; it does not, and cannot, answer any of the
following. They remain open questions for the candidate doctrine
(`dagr.candidates.epistemic-boundary-commitment.v0.1`) and its eventual
ratification path, not for this repository:

1. **Horizon authority** -- who is authorized to declare a horizon (the set
   of included/excluded fields) for a given action, and what makes that
   declaration binding rather than merely descriptive?
2. **Omission-producer authority** -- who is authorized to produce an
   omission record, and what recourse exists if an omission's stated reason
   is contested?
3. **Boundary-join authority** -- who is authorized to join a horizon,
   context, omission, and doctrine manifest into a boundary, and under what
   conditions (if any) is that join itself revocable or supersedable?
4. **Standing authority** -- what, if anything, gives an EBC artifact
   standing (admission, trust, enforceability) once it structurally
   conforms? This harness explicitly refuses to answer this question for
   the `standing` field on a horizon (see
   `FORBIDDEN_HORIZON_KEYS`/`horizon_no_out_of_scope_fields` in
   `harness.py`) and refuses it everywhere else too, by simply never
   emitting an opinion on it.

Any future work that resolves these questions belongs in `garp-doctrine`
(the ratification authority) or in a successor to the candidate document
itself -- never inferred from this harness passing.

## Fixtures

`tests/fixtures/ebc-conformance/*.json` -- one positive vector, one
order-reordering variant proving the canonicalizer is order-insensitive
(sorted-key JSON, matching the repository's existing
`arcs_verify/amnesiac/canonical.py` convention), and nine negative vectors
covering: mutated context digest, mutated omission reason, mutated horizon,
mutated doctrine manifest digest, wrong domain prefix, malformed digest
format, an illegally injected `standing` field on a horizon, a boundary
referencing an incomplete horizon, and an execution commitment missing its
pre-commit reference. Each fixture's top-level `expected` field states the
specific check it is meant to exercise; `tests/test_ebc_conformance.py`
asserts against it directly.
