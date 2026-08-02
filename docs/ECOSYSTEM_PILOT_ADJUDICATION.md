# Ecosystem Pilot Adjudication

## Scope

This document evaluates how the emerging ecosystem-doctrine schemas need to
model ARCS Verify. It is input for `arcs-ecosystem-kit`; it does not patch that
repository and does not create a local competing schema.

The model being tested here is proposed, not ratified doctrine:

```text
Layer -> Authority -> Contracts -> Implementations -> Repositories
```

The requested `garp-doctrine` files are not available in this checkout, so this
adjudication uses repository-local truth: verifier code, README boundary prose,
vendored provenance, contracts, fixtures, and tests.

Status values used here:

`PASS`, `FAIL`, `PARTIAL`, `NOT_APPLICABLE`, `NOT_EVALUATED`, `AMBIGUOUS`,
`OVER_SPECIFIED`, `MISSING_FROM_SCHEMA`.

## Schema Area Findings

| Schema area | Status | ARCS Verify need |
|---|---|---|
| Repository classification | PASS | Support independent `types` such as `verifier` and `reference_app` without forcing emitter or runtime-binding classification. |
| Layer schema | PARTIAL | Support `L6 independent_verification` as a proposed layer without claiming ratified doctrine. |
| Authority schema | PARTIAL | Declare arcs-srs as semantic authority for consumed SRS schemas/profiles while preserving arcs-verify as implementation authority only. |
| Capability inventory | PARTIAL | Allow implementation support for verifier capabilities without canonical ownership of capability semantics. |
| Contract inventory | PARTIAL | Represent consumed, validated, and repository-owned output contracts with authority, version, stability, evidence path, and producer/consumer relationships. |
| Dependency inventory | PARTIAL | Model DAGR MCP as producer/contract counterpart and fixture source, not a runtime package dependency. |
| Compatibility | PARTIAL | Represent pinned implementation compatibility without public standard ratification. |
| Conformance | OVER_SPECIFIED | A single A-E grade is too coarse for a verifier because execution enforcement can be `NOT_APPLICABLE` while verifier independence can be `PASS`. |
| Release state | PARTIAL | Support provisional declarations whose schema validation is `NOT_EVALUATED` pending external kit schemas. |
| Exceptions | PASS | Support real transitional exceptions without requiring semantic degradation. |

## Layer Schema Test

ARCS Verify should project to primary layer `L6 independent_verification`. The
schema must allow a repository to declare a proposed layer mapping while making
no ratification claim for the layer model itself.

Status: `PARTIAL` until the kit validates layer identity, proposed-model status,
and non-ratification fields together.

## Authority Schema Test

The authority schema must model three separate facts:

- `arcs-srs` is the semantic authority for consumed SRS envelope schemas,
  profile semantics, and vectors;
- `arcs-verify` owns verifier implementation behavior and native
  verifier-report output contracts;
- DAGR MCP implementations are producer/contract counterparts, not imported
  runtime dependencies.

Status: `PARTIAL` until the kit can validate authority scope without promoting
local compatibility pins into public ratification.

## Repository Report Value Domains

This pilot does not introduce a shared, repository-independent findings
taxonomy. It only records the value domains already present in ARCS Verify's
repository-owned reports.

The kit must support non-Boolean findings. ARCS Verify has:

- eight signed-SRS Boolean results;
- separate `chain_status` enum/status values;
- Amnesiac-chain conclusions in `true`, `false`, and `not_evaluated`;
- validation errors and source-integrity errors that are not Boolean verifier
  findings.

Status: `MISSING_FROM_SCHEMA` until the shared model explicitly supports these
domains.

## `not_evaluated`

The kit must preserve `not_evaluated` as a first-class value. It is not PASS and
not necessarily failure. ARCS Verify uses it for reserved Amnesiac-chain
conclusions such as `authenticity_verified` and `signature_verified`.

Status: `MISSING_FROM_SCHEMA` if the model has only Boolean or pass/fail
domains.

## `not_applicable`

The kit must preserve `not_applicable` separately from PASS. For signed-SRS
standalone verification, `chain_status: not_applicable` means no chain was in
scope. It is not a chain pass.

Status: `MISSING_FROM_SCHEMA` if the model collapses not-applicable statuses
into success.

## Assertion Versus Recomputed Result

The kit must distinguish emitter assertions from independently recomputed
findings. `subject_ref_origin` is read from validated receipt bytes and rendered
as `subject_ref_origin_disclosed`; it is a disclosure, not a verifier verdict.
By contrast, signature validity, schema digest, and receipt hashes are
recomputed by the verifier.

Status: `MISSING_FROM_SCHEMA` unless assertion provenance and recomputation
provenance are separate fields.

## Producer Relationships That Are Not Package Dependencies

The kit must support producer relationships that are not runtime package
dependencies. DAGR MCP is referenced here through DAGR producer fixtures and as
a report-contract counterpart, but ARCS Verify does not import DAGR producer
code and does not depend on a DAGR package to verify receipts.

Status: `PARTIAL` if dependency schemas only model package imports.

## Downstream Consumer Relationships

The kit must support downstream consumer relationships separately from local
runtime dependencies. Countervail receipt-ingest verification is referenced as a
downstream consumer relationship for native verifier-report outputs. This pilot
does not add Countervail code or a local Countervail contract implementation.

Status: `MISSING_FROM_SCHEMA` if downstream contract relationships must be
represented as package dependencies.

## Pinned Vendored Authority

The kit must support vendored frozen authority records and local runtime copies
with byte digests. ARCS Verify references arcs-srs schema and vector authority
through `VENDORED_FROM`, `vendor/arcs-srs/schemas/`, `vendor/arcs-srs/vectors/`,
and runtime schema copies under `arcs_verify/data/`.

Status: `PARTIAL` unless normative source, vendored copy, and runtime copy can
be linked explicitly.

## garp-sdk Reference Rule

`garp-sdk` should be referenced only where shared envelope or contract shapes
are genuinely consumed. This checkout does not consume such shapes from
`garp-sdk`, so the pilot does not declare it as an authority or dependency.

Status: `NOT_APPLICABLE` for this repository state.

## Integrity Digests

The kit must support integrity digests as first-class facts. This repository
uses schema SHA-256 pins, receipt artifact hashes, trust-bundle digests,
configuration digests, report digests, and fixture digests.

Status: `PASS` if digest fields can name algorithm, canonicalization where
needed, subject, and evidence path.

## Profile-Specific Compatibility

The kit must model compatibility by profile. `srs.mcp.sdk_enforcement.v0.1` and
`srs.connection.lifecycle.v0.1` are both supported, while the DAGR report
contracts are scoped only to `srs.mcp.sdk_enforcement.v0.1` admission/outcome
receipts.

Status: `MISSING_FROM_SCHEMA` if compatibility is only repository-wide.

## Verifier-Specific Conformance

The kit must support verifier-specific dimensions. Execution enforcement is
`NOT_APPLICABLE` for ARCS Verify, but verifier independence, pinned-schema
integrity, cryptographic verification, trust evaluation, and report-contract
stability are meaningful dimensions.

Status: `OVER_SPECIFIED` for any model that forces all repositories into
runtime-enforcement conformance levels.

## Usage/Source-Integrity Errors Versus Verification Failures

The kit must distinguish validation errors and source-integrity errors from
verification failures. CLI exit `2` is not a failed verification result; it
means the verifier could not evaluate a subject. CLI exit `1` is a negative
verification result.

Status: `MISSING_FROM_SCHEMA` if result models only represent pass and fail.

## Coordination Notes For `arcs-ecosystem-kit`

Recommended schema support:

- repository classifications as independent axes;
- proposed layer declarations, including `L6 independent_verification`, without
  claiming doctrine ratification;
- authority status separate from canonical normative ownership;
- finding domains wider than Boolean;
- `not_evaluated` and `not_applicable` as first-class values;
- assertion provenance separate from recomputation provenance;
- producer/consumer relationships separate from runtime package dependencies;
- downstream consumer relationships such as Countervail receipt-ingest without
  local package dependency implications;
- pinned vendored authority and digest records;
- profile-scoped compatibility;
- verifier-specific conformance dimensions;
- usage/source-integrity errors separate from verification failures;
- provisional declaration status separate from validated schema status.
