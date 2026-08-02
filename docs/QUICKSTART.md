# ARCS Verify — five-minute quickstart

Verify a signed receipt from a clean clone with no undocumented steps. Every
command below is copy-pasteable and every input is committed in this repository.

## 1. Clone and enter the repository

```bash
git clone https://github.com/thelaplage/arcs-verify.git arcs-verify
cd arcs-verify
```

The published distribution name and `pip install` command are not finalized yet
(see [NAMING.md](NAMING.md)), so this quickstart installs from the clone.

## 2. Create and activate a clean virtual environment

Requires Python **3.11 or newer**.

```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
python -m pip install --upgrade pip
```

## 3. Install the verifier from this clone

```bash
python -m pip install -e .
```

This installs the `arcs-verify` console command from the local source tree — not
from any package index.

## 4. Verify a bundled valid receipt

Both the receipt and the trust bundle are committed under `packs/` — nothing is
hand-authored and no network fetch happens during verification.

```bash
arcs-verify \
  packs/srs.mcp.sdk_enforcement/v0.1/normative/valid/admission-admitted.json \
  --keyring packs/srs.mcp.sdk_enforcement/v0.1/normative/trust/issuer-keys.json \
  --profile srs.mcp.sdk_enforcement.v0.1
```

Expected results — eight Boolean results, then the separate `chain_status`:

| Result | Expected |
|---|---|
| `schema_digest` | PASS |
| `envelope` | PASS |
| `profile` | PASS |
| `raw_content_exclusion` | PASS |
| `signature_valid` | PASS |
| `issuer_key_resolved` | PASS |
| `issuer_key_trusted` | PASS |
| `attestation_limits_present` | PASS |
| `chain_status` | `not_applicable` (reported separately; **not** a ninth PASS) |

Expected exit code: **0**.

```bash
echo "exit code: $?"   # 0
```

For the full machine-readable report (including `passed` and any
`failure_codes`), add `--json` to the command above.

## 5. Run a negative check

Use a committed mutation fixture whose signature no longer matches its bytes.
This does not modify any committed file.

```bash
arcs-verify \
  packs/srs.mcp.sdk_enforcement/v0.1/normative/mutations/signature-bytes-fail.json \
  --keyring packs/srs.mcp.sdk_enforcement/v0.1/normative/trust/issuer-keys.json \
  --profile srs.mcp.sdk_enforcement.v0.1
echo "exit code: $?"   # 1
```

Expected: `signature_valid` is FAIL, a `failure_code: signature_invalid` line is
printed, and the exit code is **1** (verification failure — distinct from exit
`2`, which signals a usage or unreadable-input error).

## What a clean result means

A clean signed-receipt result establishes that the receipt matches the pinned
SRS envelope schema and named profile and was not modified after issuance under
the resolved, trusted issuer key. It does not certify the producing
implementation and does not prove the underlying event was true. See the
**Limitations and claim discipline** section of the [README](../README.md).

## Verify a DAGR governed-memory receipt set

After running `dagr-mcp governed-memory-demo --output "$OUT"` in the separate
DAGR environment, verify the serialized set here:

```bash
arcs-verify receipt-set "$OUT/governed-memory-workflow.json"
echo "exit code: $?"
```

A clean result means the index hashes match, every enumerated receipt verifies,
and every outcome links to its corresponding admission receipt. It does not
prove durable-memory admission or the truth of the underlying event.
