# Naming substitution

This repository does not select a final published distribution name. The name,
the package index it is published to, and the resulting install command are
operator-gated and are resolved in a single substitution step at launch, not in
this documentation.

Every naming-dependent string in the public documentation references a
substitution token declared here. A one-commit substitution rewrites the tokens
below to their resolved values; until then the documentation carries the tokens
and the working quickstart uses the concrete source-clone install path, which
needs no substitution.

## Tokens

| Token | Resolves to | Status |
|---|---|---|
| `@@VERIFY_DISTRIBUTION@@` | The published distribution/install name for the verifier (e.g. the argument to `pip install`). | Not selected. Operator-gated; a known package-index name collision and the final install command are pending resolution. |

Only tokens actually referenced by the current documentation are declared here.
Additional tokens (for example an emitter distribution name, a public docs base,
or a badge base) are added when the documentation that needs them is added, and
not before.

## Go-day substitution locations

The package is deliberately kept locally buildable *before* substitution: the
current values below are byte-grounded facts, not the final published names, and
the package builds and installs from them today. At go-day a single substitution
commit rewrites only the following locations to the operator-cleared published
distribution name; nothing else needs to change.

| Location | Current byte-grounded value | Substituted at go-day? |
|---|---|---|
| `pyproject.toml` → `[project].name` | `arcs-verify` | **Yes** — this is the exact metadata field the go-day commit may change to the resolved published distribution name. |
| README / quickstart package-index install command | Not present; the documented install path is the source-clone `pip install -e .` (the `@@VERIFY_DISTRIBUTION@@` token above stands in for the eventual `pip install <name>` line). | Only when the index-install line is added at/after go-day. |
| Package-index URL field (e.g. a future `[project.urls]` "PyPI"/index entry) | Not present. | Only when such a field is added at go-day. |
| Import root | `arcs_verify` | **No** — the import root is stable and is not a distribution name. |
| Repository clone URL | `https://github.com/thelaplage/arcs-verify` | **No** — retained unless G1 explicitly changes the repository slug. |

The `[project.urls]` entries currently declared (`Repository`, `Issues`) point at
the existing canonical GitHub repository and are not package-index URLs; they are
not substitution locations.

## Rules

- No candidate distribution name, package-index name, or domain appears anywhere
  in this repository outside this file. The public-release checker enforces this
  against the tokens declared in `tools/brand_denylist.txt`.
- The quickstart and README install path must remain the concrete source-clone
  path and must not require substitution to run.
