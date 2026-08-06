# ARCS Verify

When an AI runtime acts through a tool boundary, the record of what it was
allowed to do is usually a claim made by the same system that did it. ARCS
Verify is the other half of that story: an independent verifier that checks a
signed receipt against a pinned envelope schema and a named conformance
profile, from serialized bytes alone. It imports nothing from the producer. It
verifies the structure of the evidence and its cryptographic and profile
properties; it does not certify the producing implementation and does not prove
that the original real-world event described by the receipt actually occurred.

## Try it in five minutes

From a clean clone (Python 3.11+, no network needed during verification, every
input committed in this repository):

```bash
python3 -m venv .venv && source .venv/bin/activate
python -m pip install -e .

arcs-verify \
  packs/srs.mcp.sdk_enforcement/v0.1/normative/valid/admission-admitted.json \
  --keyring packs/srs.mcp.sdk_enforcement/v0.1/normative/trust/issuer-keys.json \
  --profile srs.mcp.sdk_enforcement.v0.1
```

Expected output: eight PASS lines and `chain_status: not_applicable`, exit 0.
Now replace `disposition` in a copy of that receipt with
`"not-a-valid-disposition"` and rerun. Verification fails with exit 1 and two
named failure codes: `profile.invalid_disposition` and `signature_invalid`.
Replace it instead with `"refused"`, a value the profile allows, and only
`signature_invalid` fires: the profile cannot tell a plausible forgery from
the truth, and the signature is what catches it. That loop is the product:
the receipt's content either matches what was attested, or the verifier
tells you exactly which property broke.

One precision worth knowing from the start: the signature covers the
receipt's RFC 8785 canonical JSON content, not the source file's formatting.
Reindenting or reordering the file's keys leaves verification passing,
because the parsed content is unchanged; altering any signed field value
breaks it. The verifier authenticates what the receipt says, not how the
bytes happen to be laid out on disk.

[docs/QUICKSTART.md](docs/QUICKSTART.md) walks the same path step by step.
[docs/RECEIPT_ANATOMY.md](docs/RECEIPT_ANATOMY.md) annotates the sample
receipt field by field, including why it carries digests and references
instead of raw content.

## Result semantics

The signed-SRS verifier reports **eight Boolean results** and, separately, a
`chain_status` string. Add `--json` for the full machine-readable report
(shape documented in [docs/REPORT_SCHEMAS.md](docs/REPORT_SCHEMAS.md)).

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

`chain_status` is reported separately and is not a ninth Boolean. For a
standalone signed receipt the required value is `not_applicable`: it states
that no cross-artifact chain was in scope for this run. Any other value means
a chain was in scope, and the chain's own result governs. Overall pass
requires all eight Boolean results to be true and `chain_status ==
not_applicable`.

There is no aggregate verified badge, by design. Each result answers one
question, and the questions the verifier does not evaluate stay visibly
unevaluated.

Failure codes (for example `profile.invalid_disposition`,
`signature_invalid`) are enumerated in
[docs/FAILURE_CODES.md](docs/FAILURE_CODES.md).

## Named profiles

`--list-profiles` prints the profiles this verifier evaluates:

| Profile | Scope |
|---|---|
| `srs.mcp.sdk_enforcement.v0.1` | MCP tool-call admission receipts at an SDK enforcement boundary (default). |
| `srs.connection.lifecycle.v0.1` | MCP connection lifecycle receipts (connect, scope grant, revoke, disconnect). |
| `srs.broadcast_control.v0.1` | Broadcast-control receipts for governed one-to-many distribution events. |
| `srs.deferred_operation.v0.1` | Deferred-operation receipts (deferral, review linkage, outcome, disclosed gaps). |

Profile selection is explicit. A name outside this set yields the
`profile.unsupported_selection` failure code rather than a silent fallback,
and passing the generic SRS envelope schema does **not** override a
named-profile failure: envelope validity and profile conformance are separate
results, and a receipt that satisfies the envelope but violates the selected
profile fails overall.

## Exit codes

This table is the contract for the default signed-SRS subcommand. The other
subcommands do not yet route source problems uniformly through exit 2;
unifying their source-error semantics is queued work, and until it lands
their exit behavior on unreadable input should not be treated as a
verification verdict either.

| Exit | Meaning |
|---|---|
| `0` | All verifications passed. |
| `1` | Verification failed. At least one Boolean result is FAIL (or, for a chain, a gating conclusion is not `true`). |
| `2` | Usage or source-integrity error: invalid arguments, or an unreadable / malformed input file. This is not a verification verdict. |

## Use it in CI and in code

A ready-to-copy GitHub Actions workflow that verifies every receipt in a
directory lives at
[docs/examples/verify-receipts.yml](docs/examples/verify-receipts.yml).

The Python entry point is `arcs_verify.verifier.verify_receipt`, documented
with a stability note in [docs/PYTHON_API.md](docs/PYTHON_API.md).

## Producing receipts

This repository is verifier-side only and deliberately contains no emitter.
The receipt emitter/runtime binding lives in the separate DAGR repository;
MCP is the first supported binding. The emitter side, the signing mechanics,
and where to start if you want your own runtime to emit conformant receipts
are described in
[docs/PRODUCING_RECEIPTS.md](docs/PRODUCING_RECEIPTS.md).

## Layer boundary

The party that issues/emits a receipt and the party that verifies it are
separate roles. ARCS Verify sits entirely on the verifier side:

- The verifier imports no producer or emitter implementation. It reads a
  serialized receipt, a serialized trust bundle, and a pinned schema, and
  recomputes every property from those bytes.
- The receipt emitter/runtime binding lives in a separate repository. ARCS
  Verify does not depend on it and does not need access to the issuer's
  operating infrastructure to produce a verdict.

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

A clean report establishes structural consistency for the supplied artifact
set. A fully rewritten, internally coherent artifact set can pass. The report
does not establish historical authenticity, signature validity, or trusted
publication identity; those conclusions remain `not_evaluated` (see
**Reserved conclusions**).

## Reserved conclusions

The independent `amnesiac-chain` profile reports conclusions in the
domain `{true, false, not_evaluated}`. Two conclusions are **reserved** and are
hard-coded to `not_evaluated`, because the profile deliberately does not
evaluate them:

- `authenticity_verified`
- `signature_verified`

A clean chain report therefore establishes structural consistency only. The
`passed` flag is computed only from the gating conclusions
(`integrity_valid`, `producer_artifacts_consistent`,
`packet_time_bindings_valid`, `inspection_reproduced`,
`receipt_hashes_valid`); the reserved conclusions never contribute a PASS.

### One name, two domains

The signed-SRS path and the chain path report signature findings under
adjacent names with different domains. Read them by subcommand:

| Subcommand | Field | Domain | Meaning |
|---|---|---|---|
| signed-SRS (default) | `signature_valid` | Boolean | The Ed25519 signature over the receipt's preimage was checked and verified (or not). |
| `amnesiac-chain` | `signature_verified` | `{true, false, not_evaluated}` | Reserved; always `not_evaluated`. The chain profile does not evaluate signatures. |

A `signature_verified: not_evaluated` in a chain report is not a failed
check. It records that no signature check was in scope.

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
- **Frozen vendored provenance:** `VENDORED_FROM` records the byte-identical
  digests of the upstream `arcs-srs` schema, signed-receipt and MCP profile
  documents, vectors manifest, and trust bundle. The frozen standard documents
  are retained byte-identically in
  `vendor/arcs-srs/frozen-standard-docs.zip`, with schemas and vectors directly
  addressable under `vendor/arcs-srs/`.

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
# Run the test suite:
python -m pytest -q

# Producer-import / public-release guard:
python tools/check_public_release.py .
# Add --require-denylist to fail rather than pass vacuously while the
# brand denylist is unpopulated.
```

Supported Python: **3.11 and newer** (`requires-python >= 3.11`).

## Where this sits

<!-- layer-map -->

| Role | Surface |
|---|---|
| Standard | ARCS |
| Receipt protocol and profiles | SRS |
| Open runtime and adapters | Open receipt-emitter/runtime binding (separate repository) |
| Public reference implementations | ARCS Verify and examples |
| Public read and demo surfaces | GARPedia, Overlay, Showcase |
| Commercial operator products | Countervail, Workbench, managed deployments |

MCP is the first supported binding: the receipt-emitter/runtime lives in the
separate DAGR repository. ARCS Verify is the implementation-neutral verifier
for signed SRS envelopes, named conformance profiles, and independently
serialized artifact chains.

Repository map for first-time readers: `README.md` and `docs/QUICKSTART.md`
are the user path; `VERIFICATION_BOUNDARIES.md` states what results do and do
not establish; `ARCHITECTURE_PASSPORT.md`, `BUILD_REPORT.md`,
`PRODUCT_PATH.md`, and `VERIFICATION_FINDINGS.md` are governance and build
artifacts retained for provenance, not required reading for using the tool.

## Naming and distribution

The published distribution name and install command are not finalized in this
repository. Until then, install from source as shown in the Quickstart. A future
published-package path (`pip install @@VERIFY_DISTRIBUTION@@`) will be available
once the distribution name is resolved; the placeholder token and its resolution
are recorded in [docs/NAMING.md](docs/NAMING.md).

## License

Apache-2.0. See [LICENSE](LICENSE). Security reports: see [SECURITY.md](SECURITY.md).
