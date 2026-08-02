# ARCS Verify

ARCS Verify independently checks a signed receipt against a pinned SRS envelope
schema and a named conformance profile. It verifies the structure of the
evidence and its cryptographic and profile properties; it does not certify the
producing implementation and does not prove that the original real-world event
described by the receipt actually occurred.

<!-- layer-map -->

| Role | Surface |
|---|---|
| Standard | ARCS |
| Receipt protocol and profiles | SRS |
| Open runtime and adapters | Open receipt-emitter/runtime binding (separate repository) |
| Public reference implementations | ARCS Verify and examples |
| Public read and demo surfaces | GARPedia, Overlay, Showcase |
| Commercial operator products | Countervail, Workbench, managed deployments |

MCP is the first supported binding: the receipt-emitter/runtime lives in the separate DAGR repository. ARCS Verify is the implementation-neutral
verifier for signed SRS envelopes, named conformance profiles, and independently
serialized artifact chains.

## Layer boundary

The party that issues/emits a receipt and the party that verifies it are
separate roles. ARCS Verify sits entirely on the verifier side:

- The verifier imports no producer or emitter implementation. It reads a
  serialized receipt, a serialized trust bundle, and a pinned schema, and
  recomputes every property from those bytes.
- Passing the generic SRS envelope schema does **not** override a named-profile
  failure. Envelope validity and profile conformance are reported as separate
  results, and a receipt that satisfies the envelope but violates the selected
  profile fails overall.
- The receipt emitter/runtime binding lives in a separate repository. ARCS
  Verify does not depend on it and does not need access to the issuer's
  operating infrastructure to produce a verdict.

## Five-minute path

Follow [docs/QUICKSTART.md](docs/QUICKSTART.md). It installs the CLI into a clean
virtual environment from this cloned repository and verifies a **bundled,
committed** sample receipt against a **bundled, committed** trust bundle. No
receipt is hand-authored and no network fetch happens during verification.

The default signed-SRS invocation is:

```bash
arcs-verify \
  packs/srs.mcp.sdk_enforcement/v0.1/normative/valid/admission-admitted.json \
  --keyring packs/srs.mcp.sdk_enforcement/v0.1/normative/trust/issuer-keys.json \
  --profile srs.mcp.sdk_enforcement.v0.1
```

## Result semantics

The signed-SRS verifier reports **eight Boolean results** and, separately, a
`chain_status` string. Add `--json` for the full machine-readable report.

The eight Boolean results (in report order):

| Result | Meaning |
|---|---|
| `schema_digest` | The pinned SRS envelope schema file matches the frozen SHA-256. |
| `envelope` | The receipt validates against the pinned SRS envelope JSON Schema. |
| `profile` | The receipt satisfies the requirements of the selected named profile. |
| `raw_content_exclusion` | The receipt carries references and digests only; no raw governed content or credential material is present. |
| `signature_valid` | The Ed25519 signature over the RFC8785-JCS preimage verifies and the version binding matches the selected profile. |
| `issuer_key_resolved` | The signature `key_id` resolves to an entry in the trust bundle. |
| `issuer_key_trusted` | The resolved key is marked trusted, its `issuer_id` matches the receipt, and `issued_at` falls inside the key's validity window. |
| `attestation_limits_present` | `attestation_limits` is present and holds non-empty strings. |

`chain_status` is reported **separately** and is not a ninth Boolean. For a
standalone signed receipt it is `not_applicable`. **`chain_status:
not_applicable` is not a PASS**: it means no cross-artifact chain was in scope
for this run. Overall pass requires all eight Boolean results to be true **and**
`chain_status == not_applicable`.

## Exit codes

The exit code is derived from the CLI and distinguishes verification failure
from usage/source-integrity failure:

| Exit | Meaning |
|---|---|
| `0` | All verifications passed. |
| `1` | Verification failed — at least one Boolean result is FAIL (or, for a chain, a gating conclusion is not `true`). |
| `2` | Usage or source-integrity error — invalid arguments, or an unreadable / malformed input file. This is not a verification verdict. |

## Reserved conclusions

The independent `amnesiac-chain` profile (see below) reports conclusions in the
domain `{true, false, not_evaluated}`. Two conclusions are **reserved** and are
hard-coded to `not_evaluated` — the profile deliberately does not evaluate them:

- `authenticity_verified`
- `signature_verified`

A clean chain report therefore establishes structural consistency only. It does
**not** assert authenticity or signature validity, and those two conclusions
remain `not_evaluated` rather than `true`. The `passed` flag is computed only
from the gating conclusions (`integrity_valid`,
`producer_artifacts_consistent`, `packet_time_bindings_valid`,
`inspection_reproduced`, `receipt_hashes_valid`); the reserved conclusions never
contribute a PASS.

## Pinned authority

The verifier binds to fixed, in-repo authority. These values are enforced by the
verifier bytes, not by prose:

- **Envelope schema identity:** SRS Envelope v0.2.0, file
  `arcs_verify/data/srs-envelope-v0.2.0.schema.json`, `$id`
  `https://arcs.example/schemas/srs/srs-envelope-v0.2.0.schema.json`.
- **Runtime-enforced schema digest (SHA-256):**
  `d03aad1d5517e2acb65d5c866905aed7219bcbbfadd1a4a97eac546dd23f0333`. The
  `schema_digest` result fails if the loaded schema file does not hash to this.
- **Canonical envelope discriminator:** `receipt_version` must equal
  `srs.core.v5.1`.
- **Named MCP profile:** `srs.mcp.sdk_enforcement.v0.1` (the default `--profile`).
  A second profile, `srs.connection.lifecycle.v0.1`, is also supported.
- **Frozen vendored provenance:** `VENDORED_FROM` records the byte-identical
  digests of the upstream `arcs-srs` schema, signed-receipt and MCP profile
  documents, vectors manifest, and trust bundle. The frozen standard documents
  are retained byte-identically in
  `vendor/arcs-srs/frozen-standard-docs.zip`, with schemas and vectors directly
  addressable under `vendor/arcs-srs/`.

## Verify a DAGR workflow receipt set

A DAGR governed-memory demo writes `governed-memory-workflow.json`, an unsigned
refs/digests-only index of its receipt files and trust bundle. Verify every
enumerated receipt and the admission/outcome linkage in one command:

```bash
arcs-verify receipt-set /path/to/governed-memory-workflow.json
```

The command verifies manifest hashes, each receipt under its pinned SRS envelope
schema and named profile, and each outcome receipt's link to an admission receipt
in the same set. It reports `subject_ref_origin` as a disclosure, never a
verdict. The command does not verify Amnesiac producer semantics or turn the
unsigned workflow index into an authenticity claim. Use `--json` for the full
machine-readable report.

## Independently serialized artifact chains

The `amnesiac-chain` profile recomputes ClaimGraph, packet-time bindings,
packet, walk, locked renderer output, inspection projection, and receipt
artifact hashes from serialized bytes. It imports neither `arcs_amnesiac` nor any
producer SDK:

```bash
arcs-verify amnesiac-chain \
  packs/amnesiac.heppner_public_proof/v0.1/producer/proof_bundle.json \
  --stage revised
```

A clean report establishes structural consistency for the supplied artifact set.
It does not establish historical authenticity, signature validity, or trusted
publication identity — those conclusions remain `not_evaluated` (see **Reserved
conclusions**).

## Limitations and claim discipline

- ARCS Verify does not provide operator-independent proof that the original
  record or event was true. That would require an external anchor (an
  independent signature, a trusted publication record, or a previously anchored
  digest) outside this verifier's inputs.
- A valid signature means the signed receipt has not been modified after
  issuance under the resolved issuer key. It does not mean the underlying event
  was true, complete, or correctly described.
- ARCS Verify makes no certification, no comparative claim, and no product
  superlative. It reports structural and cryptographic results and nothing
  beyond them.

## Development

```bash
# Run the test suite (72 tests as of this revision):
python -m pytest -q

# Producer-import / public-release guard (must report PASS: 0 finding(s)):
python tools/check_public_release.py .
```

Supported Python: **3.11 and newer** (`requires-python >= 3.11`).

## Naming and distribution

The published distribution name and install command are not finalized in this
repository. Until then, install from source as shown in the Quickstart. A future
published-package path (`pip install @@VERIFY_DISTRIBUTION@@`) will be available
once the distribution name is resolved; the placeholder token and its resolution
are recorded in [docs/NAMING.md](docs/NAMING.md).

## License

Apache-2.0. See [LICENSE](LICENSE). Security reports: see [SECURITY.md](SECURITY.md).
