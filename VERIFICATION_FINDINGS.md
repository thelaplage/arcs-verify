# Verification Findings

## Repository Report Value Domains

This document inventories ARCS Verify's local report values. It is not a
proposal for a shared, repository-independent findings taxonomy.

ARCS Verify currently uses several result shapes:

| Domain | Example | Meaning |
|---|---|---|
| Boolean verification result | `signature_valid: true` | A verifier check passed or failed. |
| Enum/status result | `chain_status: not_applicable` | A non-Boolean status reported outside Boolean verdicts. |
| Gating conclusion | `integrity_valid: true` | A structural Amnesiac-chain conclusion included in `passed`. |
| Reserved conclusion | `authenticity_verified: not_evaluated` | A conclusion deliberately outside the verifier's current scope. |
| Usage/source-integrity error | CLI exit `2` | Input could not be read or interpreted as a verification subject. |
| Verifier limitation | Historical authenticity needs an external anchor. | A documented boundary, not a failed check. |
| Emitter assertion | `subject_ref_origin` in a receipt. | A producer-declared field read from validated bytes. |
| Independently recomputed finding | Recomputed receipt hash or signature result. | A verifier-derived result from serialized artifacts. |

Any coordination schema that records these repository-owned reports must be able
to represent these local values without promoting one into another.

## Signed-SRS Boolean Results

Signed-SRS verification reports exactly eight Boolean results:

1. `schema_digest`
2. `envelope`
3. `profile`
4. `raw_content_exclusion`
5. `signature_valid`
6. `issuer_key_resolved`
7. `issuer_key_trusted`
8. `attestation_limits_present`

These are the Boolean result set. `chain_status` is not part of this set.

## Why `chain_status: not_applicable` Is Not PASS

For standalone signed-SRS verification, `chain_status: not_applicable` means no
cross-artifact chain was in scope for that invocation. It is a scoped status,
not a positive chain verification result.

Overall signed-SRS pass currently requires all eight Boolean results to be
`true` and `chain_status == not_applicable`. That implementation rule must not
be misread as "the chain passed." No chain was evaluated in that path.

## Why `not_evaluated` Is Not PASS Or Failure

The independent Amnesiac-chain verifier reserves some conclusions:

- `authenticity_verified`
- `signature_verified`

Those conclusions are deliberately set to `not_evaluated`. They do not
contribute a PASS, and they are not necessarily failures. They say the verifier
did not evaluate that question.

A structurally clean Amnesiac-chain report can pass its gating conclusions while
still leaving authenticity and signature validity as `not_evaluated`.

## Source-Integrity Errors

Usage and source-integrity errors are outside the verification-failure domain.
For example, unreadable files, malformed JSON, invalid arguments, and invalid
report-generation inputs return CLI exit `2`.

That is distinct from exit `1`, where the verifier did evaluate the supplied
subject and produced a negative verification result.

## Disclosure Versus Verdict

`subject_ref_origin_disclosed` in the DAGR report v0.2 contract is a disclosure,
not a verdict. It reports what the validated receipt bytes declared, or
`not_declared` for genuine absence. It does not upgrade, downgrade, excuse, or
replace any Boolean result.

The coordination schema should allow a report field to be a disclosed emitter
assertion without treating it as an independently recomputed verifier finding.
