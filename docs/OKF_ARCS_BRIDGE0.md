# OKF-ARCS-BRIDGE0

The first verifier-side interoperability bridge between Open Knowledge Format
(OKF) v0.2 "Attested Computation" declarations and ARCS Verify.

This is **not** an execution engine. Despite the upstream name "Attested
Computation," Bridge0 never runs the declared executor or attester. It reads
serialized bytes only, independently recomputes content digests and
structural findings, and reports what it did and did not check.

## Layers

```text
OKF declaration (declaration.md, YAML frontmatter + Markdown body)
        |
        v
Bridge0 serialized-input verification (arcs_verify/okf_attested_computation.py)
   - parses the narrow supported frontmatter subset
   - safely resolves executor.resource / attester.resource under --bundle-root
   - recomputes sha256 digests of the referenced resource bytes
   - checks declared executor.receipt field NAMES for presence in --run evidence
        |
        v
ARCS structural / binding findings
   declaration_valid, resource_bindings_valid, receipt_shape_satisfied
   + reserved: execution_verified, attester_verdict_verified, truth_verified
     = "not_evaluated" (permanent); authority_conferred = False (permanent)
```

Each layer answers a narrower question than the one above it. Reading a
Bridge0 PASS as answering the layer above's question is the exact mistake
this document exists to head off.

## Supported OKF surface (v0.2 "Attested Computation", minimum interoperable subset)

```yaml
---
type: Attested Computation
runtime: <opaque declared runtime identifier>
parameters:            # optional, flat mapping, never interpreted
  ...
executor:
  resource: <path, relative to bundle root>
  receipt:              # list of field NAMES a run should return
    - <field name>
    - <field name>
attester:
  resource: <path, relative to bundle root>
---
(Markdown body — not read by Bridge0)
```

Any other frontmatter key is read and ignored; it can never change a
conclusion (see `test_unknown_frontmatter_key_is_inert` in
`tests/test_okf_attested_computation.py`).

The upstream OKF format deliberately does not define a universal runtime
receipt/verdict protocol inside the static bundle — what it *means* for an
executor to "pass," or how an attester's opinion is structurally encoded, is
left to the runtime layer. Bridge0 treats that as a boundary to respect, not
a gap to fill in with an invented protocol. `executor.receipt` is checked for
field-name presence only; no value semantics are assumed for any field.

## Input model

| Input | CLI flag | What it is |
|---|---|---|
| `declaration.md` | positional | The OKF declaration (frontmatter + body; body unread) |
| `bundle_root/` | `--bundle-root` | Local directory `executor.resource` / `attester.resource` resolve under |
| `serialized_run_evidence.json` | `--run` | A JSON object a caller asserts came from running the declared executor |

```bash
arcs-verify okf-attested-computation \
  declaration.md \
  --bundle-root ./bundle \
  --run ./run.json \
  --json
```

Exit codes follow repository convention: `0` verification passed, `1`
verification failed (see `failure_codes`), `2` usage or source-integrity
error (an unreadable declaration, run-evidence file, or bundle root — not a
verification verdict).

## Report shape

Three Booleans this bridge always reaches a concrete verdict for from the
supplied bytes:

| Result | Boundary |
|---|---|
| `declaration_valid` | The frontmatter is a well-formed instance of the supported surface (`type`, `runtime`, `executor.resource`, `executor.receipt`, `attester.resource` all present and well-typed). |
| `resource_bindings_valid` | Both referenced resources resolve safely under `--bundle-root`, exist as regular files, and — if the run evidence claims a resource digest — the claim matches the independently recomputed digest. |
| `receipt_shape_satisfied` | Every field name listed in `executor.receipt` is present as a key in the supplied run evidence, and the run evidence itself is a well-formed JSON object. |

Four permanent reserved conclusions, never promoted by any of the three
Booleans above:

| Reserved conclusion | Value | Why |
|---|---|---|
| `execution_verified` | `"not_evaluated"` | Whether the executor actually ran, and ran as declared, is outside what static bytes can show. |
| `attester_verdict_verified` | `"not_evaluated"` | Whether an attester actually ran, and what it concluded, is outside what static bytes can show. |
| `truth_verified` | `"not_evaluated"` | A resource digest matching does not mean the underlying real-world computation, or its result, is true. |
| `authority_conferred` | `False` | This bridge confers no DAGR governance authority under any circumstance. |

`non_equivalences` is always present in the report (see below).

## Explicit non-equivalences

```text
okf_declaration != execution
declared_receipt_shape != verified_event
resource_digest_match != truth
arcs_finding != dagr_authority
verifier != producer
receipt_field_present != executor_ran_correctly
```

Concretely:

- `receipt_shape_satisfied: true` means the run evidence *contains keys with
  the declared names*. It does not mean those values are correct, that the
  executor produced them, or that any claim inside them is true.
- `resource_bindings_valid: true` means the referenced resource bytes hash to
  what the declaration/run-evidence claim. It does not mean the resource is
  safe, correct, or was ever actually run.
- A Bridge0 PASS is an ARCS Verify structural/binding finding. It is not a
  DAGR admission, not a governance receipt, and confers no authority.

## Resource safety

`executor.resource` and `attester.resource` are untrusted, declaration-supplied
paths. Bridge0 resolves them only under `--bundle-root`, and rejects (with a
named failure code — see `docs/FAILURE_CODES.md`):

- `..` traversal that would escape the bundle root;
- absolute-path escapes;
- symlink escapes (containment is checked *after* `Path.resolve()`, which
  follows symlinks);
- a missing referenced resource;
- a non-file resource (e.g. a directory) where a file is required.

Bridge0 never fetches a referenced resource over the network. If a resource
does not resolve safely and locally, verification fails closed with a named
code — it never silently skips the check.

## Dependency decision

No YAML dependency exists anywhere in this repository (`pyproject.toml` pins
only `cryptography`, `rfc8785`, `jsonschema`). The supported surface above is
narrow — flat scalars, one level of nested mapping, flat lists of scalars —
so Bridge0 ships a small, intentionally restricted block-YAML-subset
frontmatter parser scoped to exactly those constructs, rather than widening
the dependency footprint with a general-purpose YAML engine whose fuller
feature set (anchors, aliases, flow collections, multi-document streams) this
surface does not need. Anything outside the supported subset (tabs, `{...}` /
`[...]` flow syntax, an unterminated fence, trailing unparsed content) fails
closed as `okf_attested_computation.declaration_malformed` rather than being
silently approximated. See the module docstring in
`arcs_verify/okf_attested_computation.py` for the exact grammar. Real OKF
Markdown/YAML interoperability was the goal — not a fake JSON-only format —
within a dependency footprint that stays reviewable; if a future lane needs
the fuller OKF surface, that is the point to reconsider a real YAML
dependency, not before.

## Deferred: OKF-ARCS-EXECUTION-ADAPTER0

Bridge0 deliberately stops at the boundary of *verifying serialized bytes*.
It does not, and will not, execute an OKF executor or attester resource —
doing so would make arcs-verify a producer/emitter, which breaks the
independence this repository exists to guarantee (see
`VERIFICATION_BOUNDARIES.md` and this repository's `CLAUDE.md`).

A future execution-side adapter — one that actually runs a declared executor
and/or attester inside a governed runtime boundary, and emits a receipt for
what happened — belongs in a runtime/emitter repository (e.g. a `dagr-*`
adapter), not here. That lane is tracked as
**OKF-ARCS-EXECUTION-ADAPTER0** and is explicitly out of scope for this one.
When it lands, ARCS Verify's role stays the same: verify the emitted
receipt's serialized bytes independently, importing no code from that
adapter either.
