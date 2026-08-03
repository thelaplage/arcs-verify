# ARCS Verify Architecture Passport

## Status

This passport is provisional for the distributed ecosystem-doctrine pilot. The
schema-backed declarations validate against `arcs-ecosystem-kit` v0.1 from a
sibling checkout; this repository does not vendor those schemas and does not add
the kit as a runtime dependency.

The architecture model tested by this pilot is proposed, not ratified doctrine:

```text
Layer -> Authority -> Contracts -> Implementations -> Repositories
```

The requested historical `garp-doctrine` files are not present in this checkout.
The A0-A6 architecture inputs were inspected from concurrent proposed doctrine
material and are referenced only as unratified inputs. This passport otherwise
uses repository-local truth: `README.md`, `VENDORED_FROM`, the verifier
implementation, local contracts, tests, packs, and vendored provenance.

## Verifier Role

ARCS Verify is an independent verifier and reference app. It reads serialized
evidence, recomputes findings from that evidence, and emits verification
reports. It is not an emitter, runtime binding, SRS authority, certification
service, or public truth authority.

Primary layer: `L6 independent_verification`.

Role: `substrate`.

Lifecycle stage: `preview`.

## Authority Boundary

`arcs-srs` is the semantic authority for consumed SRS schemas, profiles, and
vectors. ARCS Verify is the implementation authority for verifier behavior and
for native verifier-report output contracts it owns locally. Those authorities
are separate.

The verifier imports no producer implementation. It consumes pinned local bytes
and named profile identifiers:

| Surface | Status | Evidence |
|---|---|---|
| SRS Envelope v0.2.0 | Compatibility fact from pinned schema bytes | `arcs_verify/data/srs-envelope-v0.2.0.schema.json` |
| SRS Envelope v0.2.1 | Compatibility fact from pinned schema bytes | `arcs_verify/data/srs-envelope-v0.2.1.schema.json` |
| arcs-srs vectors | Vendored schema/vector authority | `vendor/arcs-srs/vectors/` |
| `srs.core.v5.1` | Internal pre-public lineage compatibility value | `arcs_verify/verifier.py` |
| `srs.mcp.sdk_enforcement.v0.1` | Supported named profile | `arcs_verify/verifier.py` |
| `srs.connection.lifecycle.v0.1` | Supported named profile | `arcs_verify/verifier.py` |
| RFC8785 JCS | Canonicalization dependency | `pyproject.toml` |
| Ed25519 verification | Cryptographic dependency | `pyproject.toml` |

`srs.core.v5.1` is a current repository compatibility fact. It is not described
here as a current public SRS release.

`garp-sdk` is not referenced as an authority or dependency in this pilot because
this checkout does not genuinely consume shared envelope or contract shapes from
that package.

## Native Verifier-Report Outputs

Signed-SRS verification exports the existing implementation report with eight
Boolean results plus a separate `chain_status`.

Repository-owned verifier-report contracts are exported as deterministic output
surfaces:

| Contract | Status | Evidence |
|---|---|---|
| `srs.dagr_verification_report.v0.1` | Frozen | `arcs_verify/contracts/dagr-srs-verification-report-v0-1/` |
| `srs.dagr_verification_report.v0.2` | Release-closed | `arcs_verify/contracts/dagr-srs-verification-report-v0-2/` |

Receipt-set verification exports `arcs_verify.receipt_set_report.v0_1`, which
wraps the enumerated per-receipt signed-SRS reports with manifest integrity
and admission/outcome linkage findings without changing the per-receipt eight
Boolean results.

Amnesiac-chain verification exports `arcs_verify.report.v0_1_1`, whose
conclusion domain includes `true`, `false`, and `not_evaluated`.

## Trust Boundary

The verifier boundary is serialized-artifact-only:

| Input | Role |
|---|---|
| Serialized receipt bytes | Evidence under verification |
| Serialized trust-bundle bytes | Issuer-key and trust-window input |
| Pinned schema bytes | Structure-validation authority used by this implementation |
| Selected named profile | Profile-check selector |
| Optional serialized artifact chain | Structural chain input |

A clean result means the supplied artifacts satisfy the checks that were in
scope. It does not certify the producer, prove the underlying event occurred,
or prove historical authenticity without an external anchor.

## Producer Boundary

DAGR MCP is a producer and contract counterpart, not an imported runtime
requirement. The verifier consumes DAGR-produced fixture bytes and report
contracts, but it does not import DAGR producer code to verify DAGR receipts.

Amnesiac-chain verification follows the same boundary. It recomputes structure
from serialized bundle bytes and imports no Amnesiac producer SDK.

## Downstream Consumer Boundary

Countervail receipt-ingest verification is referenced as a downstream consumer
relationship for repository-owned verifier-report outputs. No Countervail code,
service behavior, or receipt-ingest contract implementation is added here.

## Compatibility Facts

The implementation enforces local compatibility facts:

| Authority fact | Status |
|---|---|
| SRS Envelope v0.2.0 SHA-256 `d03aad1d5517e2acb65d5c866905aed7219bcbbfadd1a4a97eac546dd23f0333` | Pinned |
| SRS Envelope v0.2.1 SHA-256 `2afa1ec9f093fd7c06c4f5db7bfd37cc63e64e3dcbe47c963f4df586a1c18ca1` | Pinned |
| Frozen vendored upstream documents and vectors | Recorded in `VENDORED_FROM` |
| Subject-reference-origin disclosure vocabulary | Supported as disclosure, not verdict |

Pinned local compatibility does not by itself establish public standard
ratification.

## Public-Release Guard

`tools/check_public_release.py` checks public-release and producer-independence
constraints, including private producer import roots. This lane adds
declarations and docs only; it does not change the guard or verifier logic.

## Extension Points

Future work can add additional pinned envelope schemas, named profiles,
verification-report contracts, and serialized-chain profiles. Such additions
must preserve the verifier boundary: independently recomputed findings from
serialized evidence, with producer implementation imports remaining out of
scope.

## Profile-Specific Behavior

Signed-SRS verification produces eight Boolean results:

`schema_digest`, `envelope`, `profile`, `raw_content_exclusion`,
`signature_valid`, `issuer_key_resolved`, `issuer_key_trusted`, and
`attestation_limits_present`.

`chain_status` is reported separately and is not a ninth Boolean.

Amnesiac-chain structural verification reports gating conclusions plus reserved
conclusions. `authenticity_verified` and `signature_verified` remain
`not_evaluated`; they are not converted to success.

## Limitations And Non-Goals

ARCS Verify does not own receipt emission, runtime admission, execution
enforcement, producer truthfulness, source-system retention behavior,
organization policy, GARPedia presentation, DAGR runtime semantics, or SRS
normative authority.

It limits its claims to what the supplied artifacts establish.
