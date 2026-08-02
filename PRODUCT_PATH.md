# Product Path

## Human Problem

Recipients need to evaluate portable evidence without trusting or importing the
implementation that emitted it.

## Existing Workflow

Users often rely on the producer's own logs, dashboard, or self-validation.
That can be useful operationally, but it keeps the recipient inside the
producer's runtime and trust boundary.

## Invariant

Evidence must remain evaluable outside the producer runtime.

## Integration Point

The integration point is serialized evidence:

- receipt;
- trust bundle;
- pinned schema;
- profile;
- optional serialized artifact chain.

The verifier consumes those artifacts directly.

## First Proof Moment

A bundled committed receipt validates independently from serialized bytes
without importing its producer, while a deliberately malformed receipt fails
with a precise finding.

For the signed-SRS path, the first clean result is the eight Boolean results
plus the separate `chain_status: not_applicable` value. For the negative path,
the signature mutation fixture fails with `signature_invalid`.

## Portable Result

The portable result is a machine-readable verification report that distinguishes
findings, statuses, limitations, and source-integrity errors.

The report must not collapse all values into Boolean success. It must preserve
`not_evaluated` and `not_applicable` as distinct result-domain values.

## Expansion

The same verifier-side boundary can support:

- GARPedia;
- proof packs;
- CI verification;
- cross-organizational evidence exchange;
- Countervail receipt-ingest verification and supervisory review.

The expansion path is verification and review, not certification.
