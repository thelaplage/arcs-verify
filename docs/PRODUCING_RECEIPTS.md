# Producing Receipts

The natural next question after the quickstart passes is "how do I emit a
receipt from my own runtime?" This repository will not answer it with code,
on purpose, and this page explains the boundary and then points you to the
right places.

## Why there is no emitter here

The party that emits a receipt and the party that verifies it are separate
roles, and keeping them in separate codebases is what makes the verifier's
verdict worth something: ARCS Verify imports no producer implementation, so
passing it cannot be an artifact of shared code. An example emitter living in
this repository would blur exactly the boundary the eight results depend on.

## Where the emitter side lives

- **Runtime binding (MCP first).** The receipt emitter/runtime binding lives
  in the separate DAGR repository; MCP is the first supported binding. That
  runtime sits at the tool-call admission boundary, applies a policy pack,
  and emits admission and outcome receipts of the kind this repository's
  sample pack contains.
- **Protocol and profiles (SRS).** The receipt shape, named profiles, limitation-code vocabulary, and trust-bundle format are defined by the SRS authority. ARCS Verify consumes pinned verifier-side authority bytes; producer implementations should follow the corresponding SRS profile rather than infer emission rules from verifier code.

- **Signing mechanics reference.** The public normative example pack under `packs/srs.mcp.sdk_enforcement/v0.1/normative/` contains signed valid and mutation receipts plus the trust bundle used by the quickstart. Use those as verification examples; the verifier remains separate from any producer implementation.


## The shortest honest path for your own runtime

1. Read [RECEIPT_ANATOMY.md](RECEIPT_ANATOMY.md) against the sample receipt,
   then consult the corresponding SRS profile authority for the profile you intend to emit.
2. Produce a candidate receipt with your runtime's real identifiers and
   digests, references and digests only, never raw content.
3. Sign it over the RFC 8785 preimage with an Ed25519 key you control, and
   describe that key in a trust bundle of the same shape as the sample under
   `packs/.../trust/`.
4. Verify with this repository's CLI. Iterate until all eight results pass.
   Machine-readable failure codes emitted by the CLI will name each gap.

A receipt that passes step 4 is structurally and cryptographically conformant.
Whether anyone should trust your issuer key is a separate question answered by
trust-bundle governance, not by this verifier, and that separation is the
point.
