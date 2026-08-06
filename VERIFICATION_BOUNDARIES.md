# Verification Boundaries

## Core Boundary

ARCS Verify verifies supplied artifacts. It does not verify the producer
implementation that emitted them.

The signed-SRS path reads:

- serialized receipt bytes;
- serialized trust-bundle bytes;
- pinned schema bytes;
- the selected named profile.

It then independently recomputes structure, profile, raw-content exclusion,
signature, key-resolution, trust-window, and attestation-limit findings.

## Claimed, Checked, And Reserved

The pilot declarations preserve these states as separate concepts:

| State | Meaning in this repository |
|---|---|
| `declared` | A local declaration or emitter assertion exists. |
| `validated` | Input passed a structural or contract validation step. |
| `independently_recomputed` | The verifier recomputed the finding from serialized bytes. |
| `verified` | A concrete verifier check completed with a positive result in its domain. |
| `not_evaluated` | The verifier deliberately did not evaluate the conclusion. |
| `not_applicable` | The question was out of scope for the invocation. |
| `validation_error` | A structural or contract-validation error produced while evaluating an input. |
| `source_integrity_error` | A missing, unreadable, malformed, or digest-mismatched source artifact condition. |
| `ratified` | A governing authority has accepted the contract or doctrine. |
| `canonical` | A governing authority owns the normative definition. |

The same value must not be promoted across those states. In particular, an
emitter assertion is not an independently recomputed verifier result.

## Signed-SRS Path

The signed-SRS path has exactly eight Boolean results:

| Boolean result | Boundary |
|---|---|
| `schema_digest` | Local schema bytes match a pinned digest. |
| `envelope` | Receipt validates against the selected pinned envelope schema. |
| `profile` | Receipt satisfies the selected named profile implemented here. |
| `raw_content_exclusion` | Receipt carries references and digests rather than governed source material. |
| `signature_valid` | Ed25519 signature verifies over the canonicalized verification preimage. |
| `issuer_key_resolved` | Signature key ID resolves in the supplied trust bundle. |
| `issuer_key_trusted` | Resolved issuer key is trusted and valid for `issued_at`. |
| `attestation_limits_present` | Attestation limits are present and non-empty. |

`chain_status` is reported beside those results. It is not a ninth Boolean.
For a standalone signed receipt, `chain_status: not_applicable` means no
cross-artifact chain was in scope for the run.

## Receipt-Set Path

The receipt-set path consumes a DAGR workflow manifest containing references and
digests. It checks manifest integrity, verifies each enumerated signed-SRS
receipt, and verifies admission/outcome linkage inside the set.

The workflow index is unsigned. A clean receipt-set result does not verify
Amnesiac producer semantics, durable-memory admission, or the truth of the
underlying event.

## Amnesiac-Chain Path

The Amnesiac-chain path consumes serialized artifact bundles and recomputes
structural consistency. Its conclusion domain is wider than Boolean:

`true`, `false`, and `not_evaluated`.

The structural gating conclusions can pass. Reserved conclusions such as
`authenticity_verified` and `signature_verified` remain `not_evaluated`.

## Error Boundary

The CLI distinguishes verification failure from usage or source-integrity
errors:

| Exit code | Meaning |
|---|---|
| `0` | Verification passed for the checks in scope. |
| `1` | Verification failed. |
| `2` | Usage or source-integrity error, such as unreadable or malformed input. |

Exit `2` is not a negative verification verdict.

Validation errors and source-integrity errors must remain distinct in ecosystem
declarations. A validation error means an evaluated artifact failed a structural
or contract constraint. A source-integrity error means the verifier could not
reliably obtain or trust the source artifact as an evaluation subject.

## Unowned Claims

ARCS Verify does not claim to:

- certify the producer implementation;
- prove the underlying real-world event occurred;
- prove historical authenticity absent an external anchor;
- convert `not_evaluated` into PASS;
- treat `chain_status: not_applicable` as PASS;
- import DAGR producer code to verify DAGR receipts;
- own SRS normative semantics.

## One Name, Two Domains

The signed-SRS path reports `signature_valid` as a Boolean result: the
signature check ran and verified, or ran and failed. The `amnesiac-chain`
profile reports `signature_verified` as a reserved conclusion that is always
`not_evaluated`: no signature check is in scope for the chain profile. The
adjacent names carry different domains on purpose, and the README's
"One name, two domains" table is the reading guide. A
`signature_verified: not_evaluated` in a chain report is a disclosure of
scope, never a failed check.
