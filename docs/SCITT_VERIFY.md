# SCITT verification

`arcs-verify scitt` independently evaluates serialized SCITT artifacts from
caller-supplied bytes. It performs no registration, key discovery, network I/O,
or producer import.

## Scope

The v0.1 report (`arcs.scitt_verification_report.v0.1`) evaluates:

- the Signed Statement signature under a supplied public key;
- authenticated presence of the SCITT-required CWT `iss` and `sub` claims;
- when supplied, the COSE Receipt against the exact Signed Statement bytes and
  a supplied Transparency Service public key.

The COSE/receipt primitives are delegated to the pinned neutral
`scitt-cose==0.1.1` substrate rather than reimplemented here. The published
0.1.1 source distribution SHA-256 is
`419cf26b1d56a5c092f4b4b0044f3f926fd34cff209c6042302f0013aec050b8`.

This lane does **not** claim a complete SCITT protected-header conformance
profile. In particular, the field `required_cwt_claims_valid` means exactly
that authenticated `iss` and `sub` are present; it does not imply every
key-identification or application-profile rule has been evaluated.

## Use

```bash
arcs-verify scitt statement.cose \
  --statement-pubkey issuer.pem \
  --receipt receipt.cose \
  --transparency-service-pubkey ts.pem \
  --json
```

The standalone alias `arcs-verify-scitt` exposes the same operation.

## Result discipline

There is deliberately no aggregate `scitt_verified` conclusion. The report
keeps its findings field-level and permanently reserves these domains as
`not_evaluated`:

- underlying content truth;
- underlying real-world event occurrence;
- DAGR admission;
- Counterpedia standing;
- source/claim support.

A valid transparency receipt establishes only the cryptographic/inclusion facts
actually evaluated by the underlying receipt verifier. It does not promote any
of those reserved conclusions.

## Exit codes

- `0`: all in-scope gating checks passed;
- `1`: an in-scope verification check failed;
- `2`: source/usage error (not a verification verdict).

## Vector follow-up

`SCITT-VECTORS0` is a separate lane. It will pin independent external vector
bytes and their exact upstream commit/digests after this report/API surface is
reviewed, rather than mixing interoperability evidence into the first
implementation contract.
