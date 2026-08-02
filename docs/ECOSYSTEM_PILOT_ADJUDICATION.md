# Ecosystem Pilot Adjudication

## Scope

This document evaluates how the finalized `arcs-ecosystem-kit` v0.1 schema
shape accommodates ARCS Verify. It is input for `arcs-ecosystem-kit`; it does
not patch that repository, vendor its schemas, or create a competing local
schema.

The architecture model tested by this pilot is proposed, not ratified doctrine:

```text
Layer -> Authority -> Contracts -> Implementations -> Repositories
```

ARCS Verify is projected as primary layer `L6 independent_verification`.

The A0-A6 architecture inputs referenced by this pilot are exact proposed
document IDs:

| ID | Status in this pilot |
|---|---|
| `arcs.architecture.a0.reference-architecture.v0.1` | Proposed, unratified, not canonical |
| `arcs.architecture.a1.constitutional-layer-model.v0.1` | Proposed, unratified, not canonical |
| `arcs.architecture.a2.architectural-ontology.v0.1` | Proposed, unratified, not canonical |
| `arcs.architecture.a3.authority-model.v0.1` | Proposed, unratified, not canonical |
| `arcs.architecture.a4.repository-taxonomy.v0.1` | Proposed, unratified, not canonical |
| `arcs.architecture.a5.federated-repository-development-doctrine.v0.1` | Proposed, unratified, not canonical |
| `arcs.architecture.a6.ecosystem-coordination-doctrine.v0.1` | Proposed, unratified, not canonical |

The original `garp-doctrine` files requested for doctrine reconciliation are
not present in this repository checkout. This adjudication therefore uses
repository-local truth plus the concurrent proposed A0-A6 architecture inputs.

Status values used below:

`PASS`, `FAIL`, `PARTIAL`, `NOT_APPLICABLE`, `NOT_EVALUATED`, `AMBIGUOUS`,
`OVER_SPECIFIED`, `MISSING_FROM_SCHEMA`.

## Validation Result

The schema-backed declarations validate against `arcs-ecosystem-kit` v0.1
schemas from the sibling checkout without adding the kit as a runtime
dependency:

- `REPOSITORY.yaml`
- `ARCHITECTURE_PASSPORT.yaml`
- `AUTHORITY_REFERENCES.yaml`
- `CAPABILITY_BINDINGS.yaml`
- `CONTRACT_BINDINGS.yaml`
- `DEPENDENCIES.yaml`
- `LANES.yaml`
- `COMPATIBILITY_PROJECTION.yaml`
- `CONFORMANCE_PROJECTION.yaml`
- `EXCEPTIONS.yaml`
- `RELEASE_STATE.yaml`

`BOUNDARIES.yaml` and `RESPONSIBILITIES.yaml` are repository-local provisional
declarations because the kit v0.1 catalog does not define those schema areas.

## Schema Area Findings

| Schema area | Status | ARCS Verify finding |
|---|---|---|
| Repository classification | PASS | Supports independent `verifier` and `reference_app` repository axes without forcing emitter or runtime-binding classification. |
| Architecture passport | PASS | Supports primary layer `L6`, imported concerns, exported contracts, prohibited dependencies, and non-ratified model notes. |
| Authority references | PASS | Separates `arcs-srs` consumed SRS authority from `arcs-verify` implementation/output authority. |
| Capability bindings | PASS | Represents verifier-oriented implementation bindings without declaring canonical ownership of capability semantics. |
| Contract bindings | PASS | Represents repository-owned verifier-report outputs and consumed SRS contracts with separate semantic authority. |
| Dependency declarations | PARTIAL | Can mark DAGR and Countervail as non-runtime relationships, but richer producer/downstream roles still require local notes. |
| Compatibility projection | PASS | Represents pinned SRS bytes, profile compatibility, DAGR fixture compatibility, and historical-reference boundaries. |
| Conformance projection | PARTIAL | Supports A-E projection and gate lists, but verifier-specific status dimensions remain partly expressed in notes. |
| Release state | PASS | Supports preview release posture and gates without claiming public release. |
| Exceptions | PASS | Supports real transitional exceptions. |
| Boundaries | MISSING_FROM_SCHEMA | No kit v0.1 schema for serialized-artifact, trust, producer/verifier, and report-output boundaries. |
| Responsibilities | MISSING_FROM_SCHEMA | No kit v0.1 schema for owned and explicitly unowned repository concerns. |

## Required Verifier Boundaries

ARCS Verify needs the coordination model to preserve these boundaries:

- Serialized-artifact input boundary: receipt bytes, trust-bundle bytes, pinned
  schema bytes, profile identifiers, receipt-set manifests, and optional
  serialized artifact chains.
- Producer/verifier independence boundary: DAGR emitters and Amnesiac producers
  are fixture or contract counterparts, not runtime imports.
- Trust boundary: supplied trust bundles support key and trust-window checks;
  they do not prove real-world event truth.
- Verification-report output boundary: native verifier-report contracts are
  repository-owned outputs and must not be confused with SRS standard authority.

Status: `MISSING_FROM_SCHEMA` for first-class boundary declarations in kit
v0.1.

## Repository Report Value Domains

This pilot does not introduce a shared, repository-independent findings
ontology. It records ARCS Verify's existing repository-owned report value
domains only.

The kit must accommodate:

- eight signed-SRS Boolean results;
- separate `chain_status` enum/status values;
- Amnesiac-chain conclusions in `true`, `false`, and `not_evaluated`;
- validation errors distinct from source-integrity errors;
- emitter assertions distinct from independently recomputed findings.

Status: `PARTIAL`. The current schemas can carry these facts in notes and local
declarations, but do not provide a first-class verifier result-domain schema.

## `not_evaluated`

`not_evaluated` is not PASS and not necessarily failure. ARCS Verify uses it for
reserved Amnesiac-chain conclusions such as `authenticity_verified` and
`signature_verified`.

Status: `PARTIAL`. Conformance gates can record the distinction, but report
value domains need first-class representation.

## `not_applicable`

`chain_status: not_applicable` means no chain was in scope for standalone
signed-SRS verification. It is not a chain PASS.

Status: `PARTIAL`. The conformance projection can gate the distinction, but a
findings/value-domain model should represent it directly.

## Assertion Versus Recomputed Result

`subject_ref_origin` is an emitter assertion read from validated receipt bytes
and rendered as `subject_ref_origin_disclosed`; it is not a verifier verdict.
By contrast, schema digest, signature validity, trust checks, and receipt hashes
are independently recomputed findings.

Status: `MISSING_FROM_SCHEMA` for a first-class assertion/recomputation axis.

## Producer Relationships That Are Not Dependencies

DAGR implementations are producer and contract counterparts for serialized
fixtures. They are not package dependencies and are not imported by the
verifier. The dependency schema can represent this as a non-required
implementation relationship, while the richer producer-counterpart semantics
are recorded in local boundary and responsibility declarations.

Status: `PARTIAL`.

## Downstream Consumer Relationships

Countervail receipt-ingest verification is a downstream consumer relationship
for native verifier-report outputs. This repository does not import Countervail
code and does not own a local Countervail contract implementation.

Status: `PARTIAL`. The dependency schema supports `optional_consumer`, but
downstream contract role details remain mostly in contract bindings and local
responsibility notes.

## Pinned Authority And Digest Custody

ARCS Verify consumes `arcs-srs` schema and vector authority through vendored
records and runtime schema copies:

- `VENDORED_FROM`;
- `vendor/arcs-srs/schemas/`;
- `vendor/arcs-srs/vectors/`;
- `arcs_verify/data/srs-envelope-v0.2.0.schema.json`;
- `arcs_verify/data/srs-envelope-v0.2.1.schema.json`.

Historical vendored bytes and profile pins are compatibility facts. They do not
ratify public SRS standards, and `srs.core.v5.1` is not described here as the
current public SRS release.

Status: `PASS` for digest and historical-reference fields; `PARTIAL` for full
custody-chain modeling across vendored and runtime copies.

## garp-sdk Reference Rule

`garp-sdk` should be referenced only where shared envelope or contract shapes
are genuinely consumed. This checkout does not consume such shapes from
`garp-sdk`, so the pilot records it only as a non-required optional relationship
with no current runtime dependency.

Status: `NOT_APPLICABLE` for runtime dependency modeling.

## Profile-Specific Compatibility

Compatibility must be profile-scoped. This verifier currently supports:

- `srs.mcp.sdk_enforcement.v0.1`;
- `srs.connection.lifecycle.v0.1`;
- DAGR report contracts scoped to MCP SDK enforcement admission/outcome
  receipts;
- independently serialized Amnesiac-chain structural verification.

Status: `PASS` for compatibility projection shape.

## Verifier-Specific Conformance

A-E conformance labels cannot be reduced to one universal runtime-enforcement
grade for this repository. Execution enforcement is `NOT_APPLICABLE`; verifier
independence, pinned-schema integrity, cryptographic verification, trust
evaluation, report-contract stability, and public-release guard behavior remain
meaningful verifier dimensions.

Status: `PARTIAL`. Gates can express this, but verifier-specific dimensions
would benefit from a dedicated conformance dimension model.

## Usage/Source-Integrity Errors Versus Verification Failures

CLI exit `2` means a usage or source-integrity error; it is not a failed
verification verdict. CLI exit `1` means the verifier evaluated the supplied
subject and produced a negative verification result.

Status: `MISSING_FROM_SCHEMA` for first-class error-domain separation.

## Schema Changes Still Required

Recommended schema support for `arcs-ecosystem-kit`:

- first-class boundary declarations for serialized-artifact, producer/verifier,
  trust, and report-output boundaries;
- responsibility declarations for owned and explicitly unowned repository
  concerns;
- verifier report value-domain modeling wider than Boolean;
- `not_evaluated` and `not_applicable` as first-class values;
- assertion provenance separate from recomputation provenance;
- producer-counterpart and downstream-consumer roles separate from runtime
  package dependencies;
- digest custody across normative source, vendored copy, and runtime copy;
- verifier-specific conformance dimensions where enforcement-oriented gates are
  `NOT_APPLICABLE`;
- usage/source-integrity error domains separate from verification failures.
