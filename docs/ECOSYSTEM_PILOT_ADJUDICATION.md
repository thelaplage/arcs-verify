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

All thirteen declarations validate against a sibling `arcs-ecosystem-kit`
checkout's v0.1 schemas without adding the kit as a runtime dependency:

- `REPOSITORY.yaml`
- `ARCHITECTURE_PASSPORT.yaml`
- `AUTHORITY_REFERENCES.yaml`
- `BOUNDARIES.yaml`
- `RESPONSIBILITIES.yaml`
- `CAPABILITY_BINDINGS.yaml`
- `CONTRACT_BINDINGS.yaml`
- `DEPENDENCIES.yaml`
- `LANES.yaml`
- `COMPATIBILITY_PROJECTION.yaml`
- `CONFORMANCE_PROJECTION.yaml`
- `EXCEPTIONS.yaml`
- `RELEASE_STATE.yaml`

This validation runs in `tests/test_ecosystem_declarations.py` against a
pinned `arcs-ecosystem-kit` commit (`0a0e25674fbe8afca9705d16ca937cb4940969a0`),
resolved from `$ARCS_ECOSYSTEM_KIT_PATH` or a local sibling checkout. A
checkout on any other commit is treated the same as no checkout at all.
`.github/workflows/test.yml` performs a dev/test-only, non-vendored
`actions/checkout` of that exact commit from the private `arcs-ecosystem-kit`
repository whenever the `ECOSYSTEM_KIT_CHECKOUT_TOKEN` repository secret is
configured, and points `$ARCS_ECOSYSTEM_KIT_PATH` at the result; the kit is
never installed as a package and never imported by verifier code. Without
that secret configured, the checkout step is skipped and the schema-validation
test skips with a reason that names the exact pin, instead of faking a pass.
CI unconditionally enforces file existence, YAML parseability, and the
repository-local boundary/semantics assertions in the same test file
regardless of whether the secret is present. See `.ecosystem/EXCEPTIONS.yaml`
`AV-003`.

## Fixture Drift Against `arcs-ecosystem-kit`

`arcs-ecosystem-kit` carries an imported pilot fixture for this repository at
`fixtures/pilots/arcs-verify/.ecosystem/`, captured (per
`fixtures/pilots/arcs-verify/FIXTURE.yaml`) from `arcs-verify` commit
`489daf1e995cb794d98124261edc3c09131d9704` on the (separate, still-open,
unmerged) `feat/ecosystem-doctrine-pilot-v0-1` branch. That commit is not the
tip of that branch, and it is not this lane's source commit. Comparing the
kit's imported fixture against the declarations produced by this lane found
three files with byte-level drift, all confined to a single closed exception:

| File | Drift |
|---|---|
| `.ecosystem/EXCEPTIONS.yaml` | Fixture has open exception `AV-002` ("The kit v0.1 schema catalog does not define BOUNDARIES.yaml or RESPONSIBILITIES.yaml files."). That gap no longer exists: the kit now ships `ecosystem.boundaries.v0.1.schema.json` and `ecosystem.responsibilities.v0.1.schema.json` (see `schemas/` in the kit checkout). This lane instead carries exception `AV-003`, which records that kit-schema validation is pinned to a specific kit commit and CI-wireable, but only runs for real in CI once the `ECOSYSTEM_KIT_CHECKOUT_TOKEN` repository secret is provisioned for the private kit repository. |
| `.ecosystem/ARCHITECTURE_PASSPORT.yaml` | `known_exceptions` references `AV-002` in the fixture; this lane references `AV-003`, consistent with the exception rename above. |
| `.ecosystem/CONFORMANCE_PROJECTION.yaml` | `unresolved_exceptions` names `boundaries_responsibilities_schema_not_in_kit_v0_1` in the fixture; this lane names `kit_schema_validation_not_enforced_in_ci`, consistent with the same rename. |

No other declaration file differs from the kit's imported fixture at the
field level; this lane's content is otherwise the same shape produced against
the same finalized kit v0.1 schema set.

This lane also adds one output contract that is not present in the kit
fixture at all: `arcs_verify.receipt_set_report.v0_1` in
`CONTRACT_BINDINGS.yaml`'s `provided` list. `arcs_verify/receipt_set.py`
emits a `"schema": "arcs_verify.receipt_set_report.v0_1"` field on every
receipt-set report it produces (see `ReceiptSetReport.to_dict`), so it is a
repository-owned output contract independent of the already-declared
`dagr.workflow_receipt_set.v0_1` consumed input contract for the DAGR
workflow manifest shape. Its absence from both the kit fixture and this
repository's prior provisional declarations was a gap, not an intentional
omission.

`arcs-ecosystem-kit` should refresh `fixtures/pilots/arcs-verify/.ecosystem/`
from this lane's commit in a follow-up kit-side PR so the imported fixture
tracks a merged `arcs-verify` state rather than an intermediate commit on an
unmerged branch.

## Schema Area Findings

| Schema area | Status | ARCS Verify finding |
|---|---|---|
| Repository classification | PASS | Supports independent `verifier` and `reference_app` repository axes without forcing emitter or runtime-binding classification. |
| Architecture passport | PASS | Supports primary layer `L6`, imported concerns, exported contracts, prohibited dependencies, and non-ratified model notes. |
| Authority references | PASS | Separates `arcs-srs` consumed SRS authority from `arcs-verify` implementation/output authority. |
| Capability bindings | PASS | Represents verifier-oriented implementation bindings without declaring canonical ownership of capability semantics. |
| Contract bindings | PASS | Represents repository-owned verifier-report outputs and consumed SRS contracts with separate semantic authority. |
| Boundaries | PASS | Current kit boundary schema represents serialized-artifact input, producer/verifier isolation, SRS semantic-authority, trust, report-output, and result-domain boundaries through boundary records, forbidden dependencies, evidence refs, and notes. |
| Responsibilities | PASS | Current kit responsibility schema represents verifier-owned responsibilities and explicitly unowned concerns without claiming producer, SRS, policy, truth, or certification authority. |
| Dependency declarations | PARTIAL | Can mark DAGR and Countervail as non-runtime relationships, but richer producer/downstream roles still require local notes. |
| Compatibility projection | PASS | Represents pinned SRS bytes, profile compatibility, DAGR fixture compatibility, and historical-reference boundaries. |
| Conformance projection | PARTIAL | Supports A-E projection and gate lists, but verifier-specific status dimensions remain partly expressed in notes. |
| Release state | PASS | Supports preview release posture and gates without claiming public release. |
| Exceptions | PASS | Supports real transitional exceptions. |

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

Status: `PASS` for schema validation. The current boundary schema can preserve
these facts, though repository-specific value domains still live in boundary
notes rather than a dedicated result-domain schema.

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

Status: `PARTIAL`. The current schemas can carry these facts in schema-backed
boundary notes and contract compatibility notes, but do not provide a
first-class verifier result-domain schema.

## `not_evaluated`

`not_evaluated` is not PASS and not necessarily failure. ARCS Verify uses it for
reserved Amnesiac-chain conclusions such as `authenticity_verified` and
`signature_verified`.

Status: `PARTIAL`. Conformance gates and boundary notes record the distinction,
but report value domains need first-class representation.

## `not_applicable`

`chain_status: not_applicable` means no chain was in scope for standalone
signed-SRS verification. It is not a chain PASS.

Status: `PARTIAL`. The conformance projection and boundary notes preserve the
distinction, but a findings/value-domain model should represent it directly.

## Assertion Versus Recomputed Result

`subject_ref_origin` is an emitter assertion read from validated receipt bytes
and rendered as `subject_ref_origin_disclosed`; it is not a verifier verdict.
By contrast, schema digest, signature validity, trust checks, and receipt hashes
are independently recomputed findings.

Status: `PARTIAL`. The distinction is preserved in schema-backed boundary and
contract notes, but there is no first-class assertion/recomputation axis.

## Producer Relationships That Are Not Dependencies

DAGR implementations are producer and contract counterparts for serialized
fixtures. They are not package dependencies and are not imported by the
verifier. The dependency schema can represent this as a non-required
implementation relationship, while the richer producer-counterpart semantics
are recorded in schema-backed boundary and responsibility declarations.

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
- serialized DAGR workflow receipt-set verification;
- independently serialized Amnesiac-chain structural verification.

Status: `PASS` for compatibility projection shape.

## Verifier-Specific Conformance

A-E conformance labels cannot be reduced to one universal runtime-enforcement
grade for this repository. Execution enforcement is `NOT_APPLICABLE`; verifier
independence, pinned-schema integrity, cryptographic verification, trust
evaluation, report-contract stability, and public-release guard behavior remain
meaningful verifier dimensions.

This lane declares conformance level `B` only: verifier-specific gates
(independence, pinned-schema integrity, Boolean/status-result boundary,
public-release guard) validate against live repository behavior. Levels `C`
and `D` are not declared. Nothing in this lane or in the fact that DAGR MCP
adapters use this verifier makes runtime-enforcement or execution-oriented
conformance levels automatically applicable to an L6 serialized-artifact
verifier; those levels would require evidence this repository does not have
(it does not enforce execution, admission, or policy).

Status: `PARTIAL`. Gates can express this, but verifier-specific dimensions
would benefit from a dedicated conformance dimension model.

## Usage/Source-Integrity Errors Versus Verification Failures

CLI exit `2` means a usage or source-integrity error; it is not a failed
verification verdict. CLI exit `1` means the verifier evaluated the supplied
subject and produced a negative verification result.

Status: `PARTIAL`. The distinction is preserved in schema-backed boundary and
responsibility notes, but there is no first-class error-domain separation.

## Schema Changes Still Required

Recommended schema support for `arcs-ecosystem-kit`:

- verifier report value-domain modeling wider than Boolean;
- `not_evaluated` and `not_applicable` as first-class values;
- assertion provenance separate from recomputation provenance;
- producer-counterpart and downstream-consumer roles separate from runtime
  package dependencies;
- digest custody across normative source, vendored copy, and runtime copy;
- verifier-specific conformance dimensions where enforcement-oriented gates are
  `NOT_APPLICABLE`;
- usage/source-integrity error domains separate from verification failures.
