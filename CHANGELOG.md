# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
The versioning policy is described in [docs/VERSIONING.md](docs/VERSIONING.md).

## [Unreleased]

### Added
- OKF-ARCS-BRIDGE0: first verifier-side interoperability bridge to Open
  Knowledge Format (OKF) v0.2 "Attested Computation" declarations.
  - `arcs_verify/okf_attested_computation.py` and the `okf-attested-computation`
    subcommand: independently binds a declaration's `executor.resource` /
    `attester.resource` (safe-path-resolved under `--bundle-root`, no network
    fetch, no execution) and checks `executor.receipt` field-name presence in
    separately supplied run evidence (`--run`).
  - Explicitly **not** an execution engine: the referenced executor/attester
    resources are never run. `execution_verified`, `attester_verdict_verified`,
    and `truth_verified` are permanent reserved conclusions (`not_evaluated`);
    `authority_conferred` is a permanent reserved constant (`false`). A
    structural PASS (`declaration_valid`, `resource_bindings_valid`,
    `receipt_shape_satisfied`) never promotes any of the four.
  - Ships a small, intentionally restricted block-YAML-subset frontmatter
    parser scoped to exactly the declared surface, rather than adding a
    general-purpose YAML dependency (none exists in this repository); see
    `docs/OKF_ARCS_BRIDGE0.md` for the dependency-decision rationale, the full
    interoperability layering, and the deferred
    `OKF-ARCS-EXECUTION-ADAPTER0` execution-side lane (owned by a
    runtime/emitter repository, not this one).
  - New failure-code family: `okf_attested_computation.*` (see
    `docs/FAILURE_CODES.md`).
- ARCSV-C2PA0: hermetic native C2PA recomputation and comparison v0.1.
  - `arcs_verify/contracts/c2pa-native-finding/v0.1/`: the C2PA independent
    verification report and comparison contract. `contract.manifest.json` pins
    only the machine semantic artifacts (both schemas and the taxonomy).
  - The downstream pin is a **canonical semantic projection** of that manifest,
    not the manifest file's digest. A manifest cannot exempt its own bytes from
    a digest a consumer computes over the file, and the manifest carries prose
    (`authority`, `scope_note`, `pin_rationale`), so a raw-file digest would
    move on a prose clarification. `contract_semantic_digest()` hashes the RFC
    8785 canonical form of `contract_semantic_projection()`, covering only the
    contract identity, the digests of the three pinned machine members, and the
    native semantic pins. Reports carry it as `contract_semantic_digest`; no
    report carries a manifest file digest. Tests assert both directions: prose
    edits leave the pin stable, any pinned machine member moves it.
  - `arcs_verify/c2pa_native.py` and the `c2pa-native` subcommand: invokes a
    pinned build of the official native implementation (`c2patool` 0.27.15) over
    frozen inputs under mandatory hermetic settings, normalizes the scoped
    `validation_results` object into eight per-axis canonical findings, and
    compares against a supplied observation when one exists.
  - `recomputed` is required; `observed` is optional; `comparison` exists if and
    only if `observed` does. There is deliberately no aggregate match Boolean,
    and an absent observation yields an absent comparison rather than synthetic
    `not_evaluated` entries.
  - Causal explanation (`comparison_reason`) is separated from integrity
    inference (`integrity_posture`). Exactly one combination reaches
    `possible_substantive_divergence`; divergence attributable to wall-clock
    passage, validator version, trust basis, or policy never produces an
    integrity accusation.
  - Each axis carries a reproducibility class. The verifier records that network
    access, remote resource fetch, trust-list dereference, and OCSP were all
    disabled while simultaneously recording that the validation clock is wall
    clock and not caller-pinnable: hermetic is not timeless.
  - Revocation is always `not_evaluated`. It is reachable only via network OCSP
    and captured responses cannot be injected for offline replay, so silence is
    never represented as non-revocation.
  - Semantic status is derived from the machine report, never from process exit
    status; the pinned validator exits 0 for both `Valid` and `Invalid`. The
    legacy flattened `validation_status` array is never read.
  - Public-safe hermetic fixtures under `tests/fixtures/c2pa-native/`, with the
    upstream specimens re-acquired under an explicit commit pin. Every
    `observed`-side fixture is constructed and labelled as such; it proves the
    optional input slot, the comparison machinery, and comparability discipline,
    and does not prove end-to-end producer→verifier interoperability. That proof
    is recorded as a deferred obligation on PROV-PACK0, owed once
    `SRS-C2PA-BIND0` emits a real native observation artifact.
  - `VENDORED_FROM` records the sibling lanes as **reconciliation notes marked
    NON-RUNTIME DEPENDENCY**, not as pins with a repin-before-merge gate.
    Nothing is vendored from either sibling and this repo consumes no bytes or
    semantics from either, so no pin is warranted.
  - C2PA contract-conformance codes registered in `docs/FAILURE_CODES.md`.
- `--list-profiles` flag on the signed-SRS subcommand, printing the four named
  profiles the verifier evaluates, and argument help text plus a worked
  example in `--help`.
- `docs/RECEIPT_ANATOMY.md`: field-by-field annotation of the committed sample
  receipt.
- `docs/FAILURE_CODES.md`: registry of the complete failure-code space by
  result, subcommand, and profile family.
- `docs/PYTHON_API.md`: the supported programmatic entry point
  (`arcs_verify.verifier.verify_receipt`) with a stability note.
- `docs/PRODUCING_RECEIPTS.md`: emitter-side orientation that preserves the
  producer/verifier layer boundary.
- `docs/REPORT_SCHEMAS.md` with committed descriptive JSON Schemas for both
  CLI report shapes under `docs/schemas/`.
- `docs/examples/verify-receipts.yml`: copy-ready GitHub Actions workflow that
  verifies a directory of receipts against a pinned verifier ref.
- `srs.editorial.publication_ingest.v0.1` profile support in the signed-SRS
  verifier, with its `editorial_ingest.*` failure codes (twelve static codes
  and two dynamic families) documented in `docs/FAILURE_CODES.md`, and listed
  by `--list-profiles` and the README profile table.
- Failure-code registry coverage extended to `arcs_verify/governed_memory_sequence.py`
  (the `governed-memory-sequence` subcommand): its twenty-six codes are
  documented in `docs/FAILURE_CODES.md`, its `--json` surface is named among the
  not-yet-schema-documented reports, and a module-discovery guard now fails if
  any emitting module under `arcs_verify/` is absent from the registry sweep.
- `tools/check_public_release.py` brand gate is **fail-closed** on an empty
  denylist: an empty `brand_denylist.txt` emits PR013 and the gate fails.
  An explicit `# BRAND_GATE: acknowledged-empty` waiver keeps the gate green
  while disclosing (WARNING and `brand_check_performed: false` under `--json`)
  that brand exposure is not covered. `--require-denylist` rejects even the
  waiver, requiring real brand tokens. This supersedes the earlier
  pass-by-default-with-warning behavior.
- `tools/check_public_release.py`: real brand tokens now take precedence over
  the acknowledged-empty waiver in `load_brand_denylist`, and a waiver line left
  behind alongside real tokens fails loudly as **PR014** (rather than silently
  overriding the tokens). Closes the stale-waiver footgun (#22).
- Source-integrity errors on the default subcommand now honor the documented
  exit-code contract: missing, unreadable, non-UTF-8, malformed, and
  non-object receipt, keyring, and schema inputs (including a malformed
  `--schema` override) report `source_integrity_error: <kind>` without a
  traceback and exit 2 (structured JSON under `--json`), with adversarial
  tests in `tests/test_cli_source_errors.py`. The README's exit-code table is
  explicitly scoped to the default subcommand pending source-error
  unification across subcommands.
- `tests/test_failure_code_registry.py` extracts codes structurally from the
  emitting call sites (helper calls, list appends, list-literal returns,
  bare string and f-string returns, `code=` keyword arguments, and
  `ValueError` constant arguments) with no recognition allowlist and one
  structural filter (codes never contain spaces), across all five emitting
  modules including the public-proof lane, and fails when a code or dynamic
  family is absent from `docs/FAILURE_CODES.md`; a phantom guard fails when
  the receipt-set or deferred-sequence tables document codes those modules do
  not emit, and a direct membership assertion covers every
  `SIGNATURE_FAILURE_CODES` entry. The test was proven by temporarily
  injecting an undocumented code at each of the six emission shapes and
  confirming a failure for every one. The
  registry adds the receipt-set integrity codes, the full deferred-sequence
  code set, the 26 public-proof lane codes,
  `preimage_canonicalization_failed`, `signature_encoding_invalid`, and
  `public_key_encoding_invalid`, removes the phantom `manifest_integrity`,
  `receipt_gap`, and `receipt_gap_disclosed` entries (report fields and
  conclusions, not codes), corrects every dynamic completion set to the
  bytes (including `receipt_version` under `profile.invalid_<key>`, the full
  predecessor/condition/defer reference fields in the five deferred-operation
  missing-field families, the three governance fields, and the three revoke
  free-form keys), and states the source-error kinds as one Cartesian rule
  over three roles and six conditions, eighteen kinds in all.
- `tests/test_report_schemas.py` generates both documented reports and
  validates them against the committed schemas; `REPORT_SCHEMAS.md` is scoped
  to the two documented shapes and names the not-yet-documented JSON
  surfaces.

### Changed
- The failure-code registry now covers the complete emitted space: the
  broadcast-control and deferred-operation static codes previously absent,
  every dynamic family with its prefix, completion rule, and current
  completion set, the `deferred-sequence` subcommand's codes, the full
  amnesiac-chain finding vocabulary, and corrected attribution
  (`receipt_hash_mismatch` and the manifest-refs mismatches are chain
  findings, not receipt-set codes).
- The CI example installs the verifier from an exact immutable commit via
  init/fetch/detach (branch names are not pins) and refuses to pass when the
  receipt directory matches zero files.
- README tamper language is canonical-content accurate and exact: replacing
  `disposition` with an invalid value yields the two-code result, replacing
  it with a profile-valid value yields `signature_invalid` alone (stated as
  the lesson it is), and reformatting the file changes nothing because the
  signature covers RFC 8785 canonical JSON content.
- README restructured problem-first: quickstart and tamper loop up front, the
  layer map moved to the end, `chain_status` semantics stated positively, all
  four named profiles documented, and a "One name, two domains" table
  disambiguating `signature_valid` (signed-SRS Boolean) from
  `signature_verified` (chain reserved conclusion, always `not_evaluated`).
- `VERIFICATION_BOUNDARIES.md` gains the same naming-domain section.
- The three tracked-file closure tests skip with an explanatory message when
  run outside a git checkout (for example from a source export) instead of
  failing on the environment.

## [0.1.1] - Unreleased

The release date is intentionally unset. A date is assigned only by the P4 /
go-day tagging commit that creates the `v0.1.1` tag. The version recorded here
and in package metadata does not by itself mean that a tag, a release, or public
availability exists.

### Added
- Independent verifier for signed ARCS/SRS receipts. From the serialized receipt
  bytes alone, the verifier recomputes eight Boolean results — schema digest,
  envelope, profile, raw-content exclusion, signature validity, issuer-key
  resolution, issuer-key trust, and attestation-limits presence — and reports a
  separate `chain_status`, which is `not_applicable` when no cross-artifact chain
  is in scope.
- `arcs-verify` console command taking a receipt path, an explicit `--keyring`
  trust bundle, and a named `--profile`, with an optional `--json`
  machine-readable report.
- Exit-code contract: `0` when every Boolean result passes, `1` on a verification
  failure, and `2` on a usage or unreadable-input error.
- `arcs-verify amnesiac-chain` subcommand for the independent Amnesiac
  artifact-chain profile.
- `arcs_verify.amnesiac.verify_public_proof_bundle`, a stable entrypoint for
  the full two-stage Amnesiac public proof envelope (as produced by
  `amnesiac-proof`, distinct from the single already-extracted stage that
  `verify_bundle` requires). Each stage is verified independently, and three
  cross-stage facts already represented in the artifact are independently
  recomputed and reported in a separate section: source/proofcase identity
  continuity, the designated reconsiderable-to-admitted candidate transition,
  and the initial packet's structural staleness against the revised graph. No
  aggregate verified badge is produced.
- Conformance packs, the pinned SRS envelope schema, and the
  `srs.mcp.sdk_enforcement.v0.1` and `srs.connection.lifecycle.v0.1` verifier
  profiles.
- DAGR SRS verification report contract v0.2
  (`arcs_verify/contracts/dagr-srs-verification-report-v0-2/`), which is the
  frozen v0.1 report plus exactly one field: `subject_ref_origin_disclosed`.
  It discloses the SRS envelope v0.2.1 `subject_ref_origin` declaration and
  carries one of five declared values — `supplied_subject`,
  `derived_from_session`, `derived_from_request`,
  `derived_from_supplied_correlation`, `binding_minted` — or `not_declared`
  for a genuinely absent field. The disclosure is never a verdict: the same
  eight Booleans and the same `chain_status` are reported unchanged, and no
  origin value can upgrade, downgrade, override, excuse, or replace any
  verification result. Absence means the field was not declared and nothing
  more; it supports no inference about emitter vintage and is never collapsed
  into any declared class. A present but out-of-vocabulary value is invalid
  input and is never rendered as `not_declared`. `not_declared` is a report
  rendering only: it is not an envelope enum member and is never an emitted
  receipt value. The v0.1 report and execution-record contracts are frozen and
  unchanged. Deterministic report generation is available
  (`tools/generate_dagr_report_v0_2_goldens.py`, which requires an explicit
  `--verifier-commit` and `--output-dir` and never infers execution identity),
  and the authoritative report goldens are generated by a post-merge closure
  pull request against the exact implementation merge commit. That closure is
  now complete; see below.
- DAGR SRS verification report contract v0.2 release closure. The
  implementation merged as squash-merge commit
  `c26af32fcb638489217f4cb43845eca7b2824516`, and the post-merge closure pull
  request generated the authoritative goldens against exactly that commit into
  `arcs_verify/contracts/dagr-srs-verification-report-v0-2/golden/`: six
  receipts, six verification reports, the fixture trust bundle, and
  `expectations.json`. Every generated report and `expectations.json` carries
  `verifier_commit` `c26af32fcb638489217f4cb43845eca7b2824516` and no other.
  `golden-digest-manifest.json` pins the sha256 of all fourteen generated files,
  and regenerating with the same commit reproduces them byte for byte. The
  contract is now release-closed: `contract-status.json` records
  `status: release_closed`, `release_closed: true`,
  `merged_authoritative_report_goldens_exist: true`, and the implementation
  merge commit. The distinction between `input-fixtures/` (generator inputs, not
  authoritative) and `golden/` (authoritative output) is retained. Closure adds
  no verifier behavior, no origin semantics, no verdict, and no schema pin: the
  same eight Booleans, the same `chain_status`, the same v0.1/v0.2 parity, and
  every frozen v0.1 contract and golden digest are unchanged.
- `arcs-verify dagr-report-v0-2` subcommand emitting the v0.2 report.
- SRS envelope schema v0.2.1 vendored from arcs-srs merge
  `ccc4e4bbcd195914be70be392c89094bf8e2781b`
  (`sha256:2afa1ec9f093fd7c06c4f5db7bfd37cc63e64e3dcbe47c963f4df586a1c18ca1`),
  accepted alongside the retained v0.2.0 pin. Accepting the second pin is
  additive: every input that verified under the v0.2.0 pin verifies
  identically, and an unpinned schema still fails the `schema_digest` verdict.
- Apache-2.0 packaging metadata: the complete license text, trove classifiers,
  repository and issue URLs, and declared runtime dependencies (`cryptography`,
  `rfc8785`, `jsonschema`).

### Notes
- The final published distribution name and its install command are
  operator-gated and resolved in a single substitution step at launch; see
  [docs/NAMING.md](docs/NAMING.md). The current project name `arcs-verify` is a
  byte-grounded fact, not the final published distribution name.
