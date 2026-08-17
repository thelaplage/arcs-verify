# MONA0-VERIFY3 — independent capture-bundle verification pilot v0.1

Status: **PROPOSED / VERIFIER-SIDE / NON-ADMITTING**

Pinned `arcs-verify` base: `236f61b114a67cc56d5ec0b21ccba9ecb0034aad`.

This pilot is the verifier-side continuation of the Mona Lisa universal-object
proofcase. It consumes only serialized handoff artifacts from MONA0-CAPTURE1:

```text
mona0-capture1.json
mona0-capture1-object-manifest.v0.1.json
mona0-object-store/**
```

It imports **no** `counterpedia-acquisition` implementation.

## Upstream chain

```text
counterpedia-acquisition #82
  canonical HTTP capture + durable exact-byte custody
            ↓
counterpedia-test-corpus-aug-15 #33
  strict revision-pinned producer-fact import
            ↓
counterpedia-registry #10
  REG0 Locator / Observation / Artifact candidate projection
            ↓
MONA0-VERIFY3 (this pilot)
  independently re-read and hash serialized captured objects
```

Registry projection is not required to run this verifier; both consume the same
validated capture handoff for different purposes.

## What this verifier recomputes

From serialized files alone, `verify_bundle.py` evaluates these gating conclusions:

- `producer_lineage_consistent`
- `manifest_contract_consistent`
- `receipt_object_bindings_valid`
- `object_bytes_integrity_valid`
- `capture_topology_valid`
- `authority_boundary_valid`

It independently opens every manifested object file and computes SHA-256 itself. It
checks the result against the producer receipt, producer Artifact grouping, manifest,
byte count, and deterministic object-store path. It also proves the bundle is closed:
no required object is missing and no unmanifested file is silently present in the
content-addressed store.

## Reserved conclusions

The report deliberately leaves these conclusions outside the evaluated domain:

```text
authenticity_verified          = not_evaluated
claim_truth_verified           = not_evaluated
source_independence_verified   = not_evaluated
signature_verified             = not_evaluated
```

A clean byte-integrity report therefore does **not** establish that the represented
painting is authentic, that a factual Mona Lisa claim is true, that two locators are
independent evidentiary sources, or that a signed SRS receipt was verified.

This is the same discipline used elsewhere in ARCS Verify: structural consistency and
cryptographic/content-address checks establish exactly those properties and nothing
beyond them.

## Important coherent-rewrite limitation

A fully rewritten but internally coherent bundle can pass this pilot if all serialized
digests, receipts, manifests, and bytes are changed together. The test suite includes
that case deliberately. Its report still says `authenticity_verified = not_evaluated`.

Historical authenticity requires an external anchor that this pilot does not have.

## Usage

```bash
python3 verify_bundle.py \
  /path/to/mona0-capture1.json \
  /path/to/mona0-capture1-object-manifest.v0.1.json \
  /path/to/mona0-object-store \
  --verifier-revision <exact-40-hex-arcs-verify-commit> \
  --json
```

Exit codes:

- `0` — all gating conclusions true;
- `1` — a verification conclusion failed;
- `2` — usage/source-integrity error such as unreadable or malformed JSON.

## Authority posture

**AUTHORITY MOVEMENT = 0.**

The verifier does not admit claims, mint registry identities, assert source
independence, publish standing, or promote memory. It only reports properties it can
recompute from the supplied serialized bundle.
