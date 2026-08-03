# First-run capture fixtures (DAGR MCP)

Implementation fixtures captured from the DAGR MCP first-run proof harness.

## Provenance

| Field | Value |
|---|---|
| Producer repo | `dagr-mcp` |
| Pinned producer commit | `acb6943b63da51e5513d9ab4906e02d41069328d` |
| Pinned producer tree | `493d78b300567418f3464288d978385f9519e788` |
| Source commit | `362f7a565a3813924892b0fb7da046b63b1b080a` |
| Command | `python -m dagr_mcp.demo first-run --capture --output ./dagr-first-run-output` |
| Profile | `srs.mcp.sdk_enforcement.v0.1` |
| Signing identity | `issuer:dagr:first-run-capture` (fixed key, injected clock) |

The pinned commit is the merge commit that landed the F0 producer. The source
commit authored it, is an ancestor of the pinned commit, and the producer
sources are identical between the two; per-receipt `generator_commit` entries
in `manifest.json` name the source commit.

### Captured versus derived

**Captured** — copied verbatim from the producer run, never edited here:
the three receipts, `issuer-keys.json`, `side_effects.json`, `quickstart.txt`.

**Derived** — generated from those captured bytes by
`tools/generate_first_run_proof_pack.py`, never hand-authored:
`mutations/`, `verification/`, `digests.json`.

Hand-authored: `expectations.json`, `manifest.json`, and this README.

### Reproducibility

Capture mode uses a fixed signing identity and an injected clock. Running the
capture twice from the pinned commit into two separate directories produces
byte-identical output for the three receipts, `issuer-keys.json` and
`quickstart.txt`, and all five match the bytes committed here.

`side_effects.json` is byte-stable **for a given `--output` argument**. It
embeds that argument in its `arcs_verify_command` field, so reproducing the
committed bytes exactly requires the recorded relative path
`./dagr-first-run-output`. Its observed-execution booleans and counters are
output-path independent. This is a property of the recorded command, not a
claim that the default non-capture path is byte-deterministic — it is not, and
no such claim is made here.

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

## Reproducing the capture

Check out the exact producer commit and install it:

```bash
git clone https://github.com/thelaplage/dagr-mcp
cd dagr-mcp
git checkout acb6943b63da51e5513d9ab4906e02d41069328d
git rev-parse HEAD^{tree}   # expect 493d78b300567418f3464288d978385f9519e788

python3 -m venv .venv
source .venv/bin/activate    # Windows: .venv\Scripts\activate
python -m pip install -e .
```

Run F0 in capture mode, using the recorded relative output path:

```bash
python -m dagr_mcp.demo first-run --capture --output ./dagr-first-run-output
ls ./dagr-first-run-output
```

That directory holds the six captured artifacts committed here.

> `quickstart.txt` is producer output and names a published distribution
> (`pip install dagr-mcp`). It is reproduced verbatim as captured; installing
> from the pinned source checkout above is what this pack is pinned to.

## Verifying

Verify the three captured receipts with `arcs-verify` — no DAGR MCP import:

```bash
for receipt in urn_srs_receipt_*.json; do
  arcs-verify "$receipt" \
    --keyring issuer-keys.json \
    --profile srs.mcp.sdk_enforcement.v0.1 --json
done
```

Each passes. The committed results are under `verification/`.

## The mutation

`mutations/admitted-admission-disposition-flip.json` is derived from this
pack's own captured admitted admission receipt by flipping the single signed
semantic field `/disposition` from `admitted` to `refused`, leaving the
signature untouched:

```bash
arcs-verify mutations/admitted-admission-disposition-flip.json \
  --keyring issuer-keys.json \
  --profile srs.mcp.sdk_enforcement.v0.1 --json
```

It fails with exactly `signature_invalid`. Envelope, profile, issuer trust and
raw-content exclusion all still pass, so the failure is attributable to the
mutated field — not to corrupted JSON or altered trust material. The committed
result is `verification/admitted-admission-disposition-flip.json`.

The permanent WP2A standard vector
`normative/mutations/semantic-field-change-fail.json` remains referenced, not
regenerated, and keeps its own expectation in `expected/expectations.json`.

## Regenerating the derived half

```bash
python tools/generate_first_run_proof_pack.py           # rewrite
python tools/generate_first_run_proof_pack.py --check   # verify, write nothing
```

`digests.json` is the SHA-256 inventory of every committed artifact in this
directory. To recompute it independently:

```bash
shasum -a 256 README.md expectations.json manifest.json quickstart.txt \
  side_effects.json issuer-keys.json urn_srs_receipt_*.json \
  mutations/*.json verification/*.json
```

See `../../proof-pack-manifest.json` for the full journey.
