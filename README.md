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

MCP is DAGR's first supported binding. ARCS Verify is the implementation-neutral verifier for signed SRS envelopes and named conformance profiles.

## Use

```bash
arcs-verify receipt.json --keyring issuer-keys.json --profile srs.mcp.sdk_enforcement.v0.1
```

The verifier reports independent envelope, profile, content-exclusion, signature, key-resolution, key-trust, attestation, and chain verdicts. It does not require access to the issuer's operating infrastructure.

The frozen upstream standard documents are retained byte-identically in `vendor/arcs-srs/frozen-standard-docs.zip`. Schemas and vectors remain directly addressable under `vendor/arcs-srs/`.
