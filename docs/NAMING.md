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

## Rules

- No candidate distribution name, package-index name, or domain appears anywhere
  in this repository outside this file. The public-release checker enforces this
  against the tokens declared in `tools/brand_denylist.txt`.
- The quickstart and README install path must remain the concrete source-clone
  path and must not require substitution to run.
