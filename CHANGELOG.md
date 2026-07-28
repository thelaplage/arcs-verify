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
- Apache-2.0 packaging metadata: the complete license text, trove classifiers,
  repository and issue URLs, and declared runtime dependencies (`cryptography`,
  `rfc8785`, `jsonschema`).

### Notes
- The final published distribution name and its install command are
  operator-gated and resolved in a single substitution step at launch; see
  [docs/NAMING.md](docs/NAMING.md). The current project name `arcs-verify` is a
  byte-grounded fact, not the final published distribution name.
