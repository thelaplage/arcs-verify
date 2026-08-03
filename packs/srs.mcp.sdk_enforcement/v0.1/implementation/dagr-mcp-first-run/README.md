# First-run capture fixtures (DAGR MCP)

Implementation fixtures captured from the DAGR MCP first-run proof harness.

## Provenance

| Field | Value |
|---|---|
| Producer repo | `dagr-mcp` |
| Generator commit | `362f7a565a3813924892b0fb7da046b63b1b080a` |
| Command | `dagr-mcp first-run --capture --output ./dagr-first-run-output` |
| Profile | `srs.mcp.sdk_enforcement.v0.1` |
| Signing identity | `issuer:dagr:first-run-capture` (fixed key, injected clock) |

All receipt bytes, `issuer-keys.json`, `side_effects.json`, and `quickstart.txt`
are copied verbatim from that capture run. Nothing in this directory was
hand-authored except `expectations.json`, `manifest.json`, and this README.

Capture mode uses a fixed signing identity and an injected clock, so the emitted
bytes are byte-identical across runs. This was confirmed here by running the
capture twice into separate directories and comparing: all six files matched,
and the receipt digests equal the values pinned in `manifest.json`.

These fixtures live in their own directory rather than extending
`dagr-mcp-fastmcp-demo` because they are signed by a different issuer
(`issuer:dagr:first-run-capture` versus `issuer:dagr:fastmcp-fixture`), and
`expectations.json` declares exactly one keyring per directory.

## The refusal semantic

**A refused admission receipt is a valid, signature-valid receipt.**

`urn_srs_receipt_admission_first-run-capture-0002.json` carries
`disposition: "refused"` and `reason_code: "policy_refused"`. Verifying it
**passes** — it is authentic evidence *that a refusal occurred*. Its declared
vector therefore has `signature_valid: true` and `expected_failure_codes: []`.

Enforcement is **not** proven by the refused receipt failing verification. That
would be a category error. It is proven by two separate things:

1. the refused receipt verifying as authentic (this repository's job); and
2. the producer's observed execution record showing the native action did not
   run (`side_effects.json`, the producer's job).

Note that `inner_invocation_count` for the refused scenario is `1 → 1`, not
`0 → 0`: the sentinel counter is shared across the admitted-then-refused
sequence, so non-execution is proven by the **delta being 0**, not by an
absolute count of zero.

`side_effects.json` is the producer's observed output. Its booleans are not
authored or altered here.

## What this evidence does and does not support

It supports the claim that the admitted, refused, and mutation receipts are
independently verifiable from bytes alone, with no emitter code imported by the
verifier.

It does not establish any AEDS conformance level, and none is claimed here.
It also does not make non-execution a verifier property: the verifier checks
evidence authenticity, and non-execution is the producer's observed fact.

## Verifying

```bash
for receipt in urn_srs_receipt_*.json; do
  arcs-verify "$receipt" \
    --keyring issuer-keys.json \
    --profile srs.mcp.sdk_enforcement.v0.1
done
```

The mutation step of the journey is
`normative/mutations/semantic-field-change-fail.json`, which is **referenced,
not regenerated** — it is a permanent byte-identical WP2A standard vector, and
its expected `signature_invalid` failure is already declared in
`expected/expectations.json`. See `../../proof-pack-manifest.json`.
