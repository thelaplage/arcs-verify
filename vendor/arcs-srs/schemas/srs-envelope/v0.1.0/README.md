# SRS Envelope Schema — v0.1.0 (pre-release)

This is the **canonical SRS envelope schema**, ARCS-authored, published version **`0.1.0`**,
release stage **pre-release**.

## What this is

SRS is a satellite specification authored under the ARCS standard, the canonical Sovereignty
Receipt envelope. This directory is the **canonical home** for the machine-readable envelope
schema. Until now the schema existed only as vendored-and-pinned copies inside implementation
repos; this is the separable canonical source those copies mirror.

- **ARCS authors it.** The canonical home is an ARCS-family surface. Implementations — including
  GARP — *conform to and mirror* this schema; they do not define it. A GARP copy is a conformant
  mirror, never the definition.
- **VCP-stewarded, for now.** This repo (`arcs-srs`) is the ARCS-family SRS satellite home under
  VCP stewardship. The identity model (below) is what lets the home later move to a more separable
  ARCS-standard surface without breaking any adopter's pin.
- **Cut from internal revision `0.5.1`.** That revision number is **provenance only** — it records
  that the schema was cut from internal pre-1.0 revision 0.5.1. It is **not** the public version and
  appears nowhere in the identity string. The public version is `0.1.0`.

## Identity and pinning

The artifact's identity is **`published_version` + `sha256`**, portable across home relocation:

```
srs-envelope@0.1.0+sha256:e866eabf1cef537df6dc98f56f74021d8af585c94dc689f9fdd4ee97618d6b61
```

**Pin to `published_version` + `sha256`, never to a repository URL or path.** Because adopters and
mirrors pin to version+digest, the home can relocate later without breaking pins. See
`srs-envelope.schema.manifest.json` for the locked identity.

## Versioning and the minimal change story

The envelope is versioned as a **separately-versioned ARCS satellite**:

- **Additive within a major version**, per the extension policy.
- A **breaking change is a new version with a migration note** — not an in-place edit of these bytes.

## Pre-release and the road to 1.0

`0.1.0` is deliberately **not** `1.0`. A leading zero is the honest maturity signal: **pre-release
means breaking changes may occur before `1.0`.** `1.0` is a *future milestone* — earned when the
envelope has the maturity to promise stability — not the starting point.

## Scope

ARCS SRS **envelope only**. No GARP body-kind semantics live at this home.
