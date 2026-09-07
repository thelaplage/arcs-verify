# SCITT-VECTORS0

**Status:** executable downstream interoperability lane  
**Base:** exact `SCITT-VERIFY0` head at branch creation  
**Authority movement:** `0`

This branch adds no verifier semantics. It executes the existing
`arcs.scitt_verification_report.v0.1` implementation against an independently
published cross-implementation SCITT vector corpus.

## External corpus pin

Repository:

`ietf-wg-scitt/examples`

Exact commit:

`727ee03d86fa2c2ca8c534584b870235a1b252df`

Exact suite path:

`test-vectors/scitt-cose/`

Pinned suite identities visible at that commit:

- suite tree: `d5135903624421fe53567cf2f12d1247f5595c52`;
- `manifest.json` Git blob: `facf1200f9d49bc9c802783e2d74e96afd476672`;
- `SHA256SUMS` Git blob: `5e6c912c46b702020a98d2a9115303716ba64bef`;
- v1 tree: `d26b826acf6b79797ee267530b1f740844c7a2f8`.

The IETF examples commit records the vector set as vendored from
`action-state-group/scitt-cose@7796e7ef82955e28646195fe439be1a6fe0ad092`
and states that a clean-room Go runner exercises the same manifest. That makes
this more useful than merely regenerating vectors inside ARCS Verify, while the
shared `scitt-cose` provenance remains disclosed rather than hidden.

## Corpus

Five v1 vectors are required and checksum-pinned by the upstream
`SHA256SUMS` (30 public files):

- `valid-eddsa` — statement + RFC9162 receipt valid;
- `valid-es256` — statement + RFC9162 receipt valid;
- `fail-tampered-path` — valid statement, invalid receipt inclusion path;
- `fail-unsupported-vds` — valid statement, unsupported receipt VDS;
- `fail-bad-statement-sig` — invalid statement signature, receipt valid over
  the tampered statement bytes.

The manifest's field-level expected values are the oracle. The ARCS runner does
not require our failure-code strings to copy the upstream implementation's
labels; it requires the same statement-signature Boolean, receipt-verification
Boolean, and overall valid/invalid outcome.

## Execution

`.github/workflows/scitt-vectors.yml` checks out the IETF repository at the
exact commit above, asserts the checkout SHA, installs this verifier branch,
and runs:

```bash
python tools/check_scitt_external_vectors.py \
  ../scitt-examples/test-vectors/scitt-cose
```

The runner first recomputes all 30 upstream SHA-256 checksums before invoking
ARCS Verify. Any missing/changed vector file fails before semantic comparison.

## Negative-space rule

This lane does not convert the IETF examples repository into an ARCS authority.
It is interoperability evidence for the cryptographic/transparency properties
represented by those exact vectors. It says nothing about underlying truth,
DAGR admission, Counterpedia standing, or CHECK support.
