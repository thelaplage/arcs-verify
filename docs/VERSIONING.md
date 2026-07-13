# Versioning policy

## Semantic Versioning

This project follows [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).
A release version is `MAJOR.MINOR.PATCH`:

- `MAJOR` increments on incompatible public-surface changes;
- `MINOR` increments on backward-compatible additions;
- `PATCH` increments on backward-compatible fixes.

## Source of truth

`[project].version` in `pyproject.toml` is the single source of truth for the
package version. The current value is `0.1.1`.

The package also exposes a convenience mirror, `arcs_verify.__version__`, which
is currently coherent with `[project].version` at `0.1.1`. When bumping the
version, both are updated together in the same commit so they never disagree; if
they ever diverge that is a version-coherence defect to be fixed on its own, not
in a packaging change.

## Tags and releases

- A release is published by creating an annotated Git tag of the form `vX.Y.Z`
  (for example `v0.1.1`) at the go-day tagging commit.
- **A tag or release does not exist merely because a version appears in source.**
  The presence of `0.1.1` in `pyproject.toml`, in this document, or in the
  changelog is not itself a tag, a release, or a claim of public availability.
- Until that tag is created, the changelog entry for the current version stays
  marked `Unreleased` with no assigned date.

## Protocol identifiers are independent

Package versions and protocol identifiers are separate namespaces and do not
track each other:

- The SRS **envelope** schema version (for example `srs-envelope-v0.2.0`), the
  named **profile** versions (`srs.mcp.sdk_enforcement.v0.1`,
  `srs.connection.lifecycle.v0.1`), and any binding identifier a receipt carries
  (for example `fastmcp.middleware.v0.1`, which is a binding identifier and
  **not** the FastMCP package version) are independent protocol identifiers.
- Bumping the `arcs-verify` package version does not bump any envelope, profile,
  or binding identifier, and vice versa. Those identifiers change only through
  their own governed processes.

## Distribution-name substitution

The final published distribution name is operator-gated (see
[NAMING.md](NAMING.md)). Substituting that name at launch changes only the
declared distribution/install string; it does **not** change the import root
(`arcs_verify`), the repository clone URL, or any protocol identifier, unless
such a change is separately reviewed.

## Pre-1.0 discipline

While the version is below `1.0.0`, the public surface may still change between
minor versions. Compatibility is offered on a best-effort basis and breaking
changes are called out in the changelog. Stronger compatibility guarantees begin
at `1.0.0`.

## Release ordering for P4 / go-day

The go-day sequence is, in order:

1. finalize the changelog entry for the version and record its release date;
2. apply any operator-gated distribution-name substitution;
3. create the `vX.Y.Z` tag on that commit;

so that the changelog date and the tag are assigned together and no earlier than
the tag exists. Building or installing the package from source before that point
does not constitute a release.
