# c2pa-native-finding v0.1

**Status: PROVISIONAL.** Provisional status is not ratification, and support for
a contract does not stabilize it.

This bundle fixes how ARCS Verify reports an **independent recomputation of a
native C2PA validation**, and how it compares that recomputation against an
observation somebody else supplied.

## What this bundle is not

It is not a C2PA implementation. ARCS Verify does not reimplement C2PA
validation; it invokes a pinned build of the official native implementation and
recomputes from that. Reimplementing would produce a second dialect whose
disagreements with the real one would be indistinguishable from findings.

It is not **SRS receipt verification**. Those are different objects, different
signatures, different bytes, and different authorities:

| | native C2PA validation | SRS receipt verification |
|---|---|---|
| what is signed | a C2PA claim over asset bytes | an SRS receipt envelope |
| who signs | a content signer | a receipt issuer |
| who is authoritative | C2PA | ARCS / SRS |
| what this bundle reports | this column | nothing in this column |

A valid SRS signature may coexist with an invalid C2PA manifest, and a valid
C2PA manifest may coexist with an untrusted SRS issuer. Neither tells you
anything about the other.

## Authority

| Layer | Owner |
|---|---|
| generic provenance-signal semantics | `arcs-standard` |
| native observation receipt serialization | `arcs-srs` |
| **C2PA independent verification report and comparison contract** | **`arcs-verify` — this bundle** |

Signal observation, native validity, independent recomputation, comparison,
governed consequence, proposition support, and public standing are independent
authority layers. This bundle owns exactly one of them.

## Files

| File | Pinned | Role |
|---|---|---|
| `canonical-native-finding.schema.json` | yes | one side of an evaluation, normalized per axis |
| `native-finding-report.schema.json` | yes | the report: `recomputed`, optional `observed`, conditional `comparison` |
| `comparison-taxonomy.json` | yes | axes, states, reasons, postures, reproducibility classes, the reason/posture matrix |
| `contract.manifest.json` | — | the pin itself |
| `README.md` | **no** | this prose |

`contract.manifest.json` pins only the machine semantic artifacts. **Downstream
consumers pin that manifest's digest** — not the implementing commit, which
moves for reasons unrelated to semantics, and not README bytes, which change
when prose is clarified. If a prose edit moved the pin, consumers would learn to
ignore pin movement, and the pin would stop meaning anything.

## Shape

```
recomputed   REQUIRED   always ARCS Verify's own evaluation
observed     OPTIONAL   an assertion by a producer or third party
comparison   present if and only if `observed` is present
comparability present if and only if `observed` is present
```

When there is no observation there is **no comparison** — not an array of
`not_evaluated` comparisons. `not_evaluated` describes an evaluation that was in
scope and did not happen. No comparison was ever in scope.

There is deliberately **no aggregate match Boolean**. Ratified doctrine §13
prohibits the word `verified` without an axis in conforming verifier output, and
an aggregate would collapse causally distinct divergences: a certificate that
aged out between observation and recomputation would report the same value as a
genuine disagreement.

## Axes and reproducibility

Each axis carries a reproducibility class, because "the two runs differed" means
completely different things depending on it.

| Axis | Class |
|---|---|
| `manifest_structure` | `byte_deterministic` |
| `asset_binding` | `byte_deterministic` |
| `claim_signature` | `byte_deterministic` |
| `signer_trust` | `policy_dependent` |
| `signer_validity` | `time_dependent` |
| `timestamp` | `time_dependent` (policy- and time-contributing) |
| `revocation` | `resource_dependent` |
| `ingredient` | inherits from the codes actually present |

`signer_validity` is held separate from `signer_trust` on empirical grounds: a
production specimen fails expiry entirely independently of trust, and collapsing
them would lose the difference between "we do not trust this issuer" and "this
was fine and aged out."

Every axis is additionally **validator-version dependent**. The same bytes have
been observed to validate differently across validator versions, which is why
the native implementation is pinned to an exact version rather than resolved.

## Hermetic is not timeless

ARCS Verify can prove, of its own invocation:

```
network_access_permitted        false
remote_resource_fetch_attempted false
trust_list_uri_dereferenced     false
ocsp_fetch_permitted            false
```

and must **simultaneously** record:

```
validation_clock: { source: wall_clock, caller_pinnable: false }
```

The pinned validator exposes no validation-clock control anywhere in its
settings hierarchy. Sealing the inputs does not seal the clock.

The consequence is a rule: **a certificate or trust difference caused by
wall-clock passage is not a failed hermetic replay and never produces an
integrity accusation.** A trusted timestamp on the manifest anchors the
validation instant and is the only thing that makes a time-dependent axis
substantively comparable.

## Cause and inference are separate questions

`comparison_reason` answers *why* two evaluations differ. `integrity_posture`
answers *what that licenses you to infer*. Conflating them is how a clock skew
becomes an accusation.

Exactly one combination reaches `possible_substantive_divergence`: state
`mismatch` with reason `same_inputs_same_semantics` — identical bytes, identical
validator identity and version, identical policy basis, on a byte-deterministic
axis. Everything else is `no_integrity_inference` or `not_assessable`.

And even that one is a prompt to investigate, not a finding of tampering, bad
faith, or falsity.

## Revocation

Always `not_evaluated`. Revocation is reachable only via network OCSP, which is
default-off, requires network I/O, and offers no mechanism to inject captured
responses for offline replay. Under hermetic settings it cannot be evaluated,
and **silence about revocation is not evidence of non-revocation.**

## Two rules the obvious implementation gets wrong

**Never read process exit status for semantics.** The pinned validator exits `0`
for `validation_state: Valid` *and* `0` for `validation_state: Invalid`, and
exits non-zero only when a required input is unavailable. A harness gating on
`exit == 0` classifies a tampered asset as a success. Exit status separates
*could not evaluate* from *evaluated*; it does not separate valid from invalid.
There is a dedicated regression test for this.

**Never read the legacy flattened `validation_status` array.** Parse the scoped
`validation_results` object — `activeManifest` (a severity map) and
`ingredientDeltas` (a *list* of scoped delta objects). The legacy array collapses
active-manifest and ingredient findings together with no scope marker and has
been observed emitting each code twice.

## The conformance checker, not the schema

JSON Schema validates shape. It cannot express that the comparison axis set is
exactly the canonical set with no repeats, that a divergence attributed to a
trust-basis delta must not carry an integrity accusation, that comparability
predicates must be recomputed from the two sides rather than asserted, or that a
comparison must be *absent* rather than synthesized. Those live in
`check_report()` in `arcs_verify/c2pa_native.py`, and the test suite demonstrates
for each one a report the schema accepts and the checker rejects.

## Unexercised paths

`comparison-taxonomy.json` records paths this contract does **not** evidence —
revocation codes, sidecar and durable-recovery acquisition, fragmented BMFF,
redacted assertions, and a signer chaining to the official public C2PA trust
list. No input was manufactured to create coverage of any of them.

In particular: no specimen here is on the official public C2PA trust list.
Trust-by-supplied-allowed-list proves the trust plumbing works and that trust is
a function of caller-supplied material. That is a different claim, and it is the
only one evidenced.
