# ARCS Verify

<!-- layer-map -->

| Role | Surface |
|---|---|
| Standard | ARCS |
| Receipt protocol and profiles | SRS |
| Open runtime and adapters | DAGR |
| Public reference implementations | ARCS Verify and examples |
| Public read and demo surfaces | GARPedia, Overlay, Showcase |
| Commercial operator products | Countervail, Workbench, managed deployments |

MCP is DAGR's first supported binding. ARCS Verify is the implementation-neutral verifier for signed SRS envelopes, named conformance profiles, and independently serialized artifact chains.

## Use

```bash
arcs-verify receipt.json --keyring issuer-keys.json --profile srs.mcp.sdk_enforcement.v0.1
```

The existing signed-SRS invocation remains the default. To verify the full
Amnesiac Heppner artifact chain:

```bash
arcs-verify amnesiac-chain \
  packs/amnesiac.heppner_public_proof/v0.1/producer/proof_bundle.json \
  --stage revised
```

The verifier reports independent envelope, profile, content-exclusion, signature, key-resolution, key-trust, attestation, and chain verdicts. It does not require access to the issuer's operating infrastructure.

The frozen upstream standard documents are retained byte-identically in `vendor/arcs-srs/frozen-standard-docs.zip`. Schemas and vectors remain directly addressable under `vendor/arcs-srs/`.


## Amnesiac artifact-chain profile

The `amnesiac-chain` profile independently recomputes ClaimGraph, packet-time
bindings, packet, walk, locked renderer output, inspection projection, and
receipt artifact hashes from serialized bytes. It imports neither
`arcs_amnesiac` nor `garp_sdk`.

A clean report establishes structural consistency for the supplied artifact
set. It does not establish historical authenticity, signature validity, or
trusted publication identity. Those conclusions remain `not_evaluated`.
