# CLAUDE.md
> Status: agent guidance only; non-normative. Repository contracts, cited authorities, and admitted artifacts control where they differ.

## Repository lifecycle
ACTIVE

## Ecosystem rule
One authority per contract family. If another repository owns a contract, profile, schema, verifier, semantic rule, or custody invariant, consume or pin that authority. Do not recreate a convenient local dialect.

## Cross-repository evidence rule
A green local test suite does not prove interoperability. Where this repository verifies another repository's artifact, tests should use literal output from the real producer at a pinned commit whenever practical, preserving original bytes and provenance.

## Repository role
arcs-verify independently verifies SRS artifacts — structural and cryptographic validity under an explicitly selected profile. It re-derives conformance from the artifact's own bytes plus the pinned profile authority, and trusts no producer claim.

## Authority boundary
AUTHORITATIVE FOR:
- Verification verdicts and named failure codes
- Explicit profile selection; mutation / negative vectors
- The `not_evaluated` / `not_applicable` discipline (never collapsed into pass or fail)

NOT AUTHORITATIVE FOR:
- SRS serialization / profile bytes (arcs-srs)
- Semantic truth, adoption, non-equivalence (garp-doctrine / arcs-standard)
- Runtime receipt emission (dagr-mcp and other producers)
- Custody (arcs-srs-store)

## Upstream authorities
- SRS envelopes / profiles / vectors -> arcs-srs (pin the profile digest)
- Semantic / normative rules -> garp-doctrine, arcs-standard

## Downstream consumers
- dagr-ops, counterpedia-agent, dagr packs, dagr-quickstart -> invoke this verifier as an independent process for verdicts

## Critical invariants
- verification != truth ; valid signature != trusted issuer ; profile-valid != runtime-authorized
- not_evaluated != false != pass
- a verifier reference is not a verification

## Repository-specific red lines
- NEVER import producer implementation code to make verification convenient — issuer/verifier separation is inviolate.
- Verification fixtures derived from a producer preserve the LITERAL producer bytes at a pinned commit; never invent the producer's representation to simplify a test here.
- No aggregate trust badge; unknown profiles fail closed.
- Do not reinterpret SRS semantics locally; consume arcs-srs.

## Required validation
- `python -m pytest` (full suite) green
- public-release independence checker green (no producer imports)

## Related repositories
- arcs-srs — SRS serialization / profile authority (upstream)
- dagr-mcp, dagr-ingest — producers whose literal artifacts this repo verifies
- garp-doctrine, arcs-standard — semantic authorities
- arcs-srs-store — custody
