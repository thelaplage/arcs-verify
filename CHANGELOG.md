# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
The versioning policy is described in [docs/VERSIONING.md](docs/VERSIONING.md).

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
  unchanged. The v0.2 contract is an implementation candidate: deterministic
  report generation is available
  (`tools/generate_dagr_report_v0_2_goldens.py`, which requires an explicit
  `--verifier-commit` and `--output-dir` and never infers execution identity),
  merged-authoritative report goldens do not yet exist, and the contract is not
  release-closed until a post-merge closure pull request generates them against
  the exact implementation merge commit.
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
