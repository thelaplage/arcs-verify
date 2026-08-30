# SRS-VNEXT-VERIFY0

**Status:** DRAFT / candidate verifier implementation  
**Authority movement:** `0`

`arcs_verify.external_profile` independently evaluates an SRS vNext receipt
against an application-supplied external-profile declaration.

## Independent inputs

The verifier consumes:

- serialized receipt bytes;
- serialized external-profile declaration bytes;
- the vNext envelope JSON Schema bytes;
- the external-profile-declaration JSON Schema bytes;
- an independently supplied issuer keyring/trust context.

It imports no `dagr-mcp`, Counterpedia, or `arcs-srs` producer/runtime code.

The candidate schema byte identities are pinned independently to reviewed
arcs-srs #57 head `e22fd69218451a86cf639bcce4691f7e1d6975c9`:

- Envelope v0-next SHA-256:
  `71a9b365eb7c3d320d173772f6b823bb2bc3c15174eef30f6038ea7b84bde967`
- external-profile-declaration v0.1 SHA-256:
  `342642f4b2f120541f2094a8aadc5d6de9b0ea4548a12363b05333c92f524eaf`

Caller-supplied schema bytes must match those pins before a report can PASS.

## Recomputed axes

The report keeps these findings separate:

- envelope schema byte identity;
- profile schema byte identity;
- envelope conformance;
- profile-declaration schema conformance;
- profile cross-field set conformance;
- receipt → profile identity/type/classification binding;
- receipt `contract_refs` → exact envelope/profile bytes;
- raw-content exclusion;
- Ed25519 / RFC8785-JCS signature validity;
- issuer key resolution;
- issuer trust-window validity at `issued_at`;
- attestation-limit presence.

`selected_receipt_class` is a disclosure derived from the profile mapping. It is
not a truth, authorization, or standing verdict.

## Non-equivalences

```text
schema bytes pinned     != profile ratified
profile conformant      != domain authorized
receipt class           != semantic equivalence
signature valid         != issuer trusted
issuer trusted          != event true
verification PASS       != DAGR standing
verification PASS       != Counterpedia evidence standing
```

## DAGR boundary

This verifier does not require or infer a `dagr_binding`. If an application
profile carries one, it remains an extension payload whose DAGR-specific
contract must be verified separately against the applicable DAGR binding bytes.
No `mcp_action -> action` or other implicit domain bridge is introduced here.

## Integration obligation

The downstream Counterpedia MCP lane must supply the exact pinned schema bytes,
its exact application profile bytes, a real receipt emitted by the reviewed
vNext emitter, and an independently supplied trust bundle. That source-bound
producer → verifier proof is stronger than unit tests over either side alone.
