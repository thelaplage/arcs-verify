# DAGR SRS verification report contract v0.2 (subject-reference origin)

v0.2 is v0.1 plus exactly one field.

It adds `subject_ref_origin_disclosed`, which discloses how the emitter said it
obtained `subject_ref`, read from the optional `subject_ref_origin` field
introduced by SRS envelope v0.2.1. It changes nothing else: the same eight
Boolean verdicts, the same `chain_status`, the same receipt/trust/configuration
hash semantics, the same supported profile
(`srs.mcp.sdk_enforcement.v0.1`, `admission` and `outcome` only).

The v0.1 report contract and the v0.1 execution-record contract in
`../dagr-srs-verification-report-v0-1/` are frozen. This lane does not modify a
byte of either, and does not regenerate their goldens.

## The disclosure is a disclosure

`subject_ref_origin_disclosed` is not a verdict. It is not a ninth Boolean, it
is not a companion to `chain_status`, and it never appears inside the `verdicts`
object, which remains closed at exactly eight Boolean members.

**No value it can carry upgrades, downgrades, overrides, excuses, or replaces
any verification result.** A receipt that declares `supplied_subject` and a
receipt that declares `binding_minted` are verified identically; a receipt that
declares nothing is verified identically to both. The golden fixtures prove
this directly: all six share one `subject_ref`, one trust bundle, one
configuration digest, and one set of eight `true` verdicts, and differ only in
their receipt bytes and their disclosed origin.

## Vocabulary

Five declared values, copied verbatim from a well-formed
`subject_ref_origin` — one supplied class, three derived, one minted:

| value | class |
|---|---|
| `supplied_subject` | supplied |
| `derived_from_session` | derived |
| `derived_from_request` | derived |
| `derived_from_supplied_correlation` | derived |
| `binding_minted` | minted |

Plus one rendering for genuine absence:

| value | meaning |
|---|---|
| `not_declared` | the field was absent from the receipt |

`not_declared` is a report rendering only. It is **not** a member of the SRS
envelope enum, it does not appear in the envelope schema, and it is never an
emitted receipt value.

## What absence means

Absence means the field was not declared. Full stop.

It is not evidence of emitter vintage, of the producing binding, or of whether
a subject was in fact supplied, and it is never collapsed into `supplied_subject`
or any other declared class. A v0.2.0-era receipt that predates the field is
indistinguishable, for this purpose, from a v0.2.1-era receipt that declined to
declare one. Nothing further may be inferred from it.

## Reader rules

The reader (`arcs_verify/subject_ref_origin.py`) is deliberately incurious:

- read `subject_ref_origin` from the **validated receipt bytes**;
- a valid declared field discloses the exact declared token, verbatim;
- a genuinely absent field discloses `not_declared`;
- a **present malformed value is invalid input**, never `not_declared` — a
  present `null`, a non-string JSON type, or an unrecognized string raises
  `MalformedSubjectRefOrigin`, and under the v0.2.1 envelope pin it also fails
  the `envelope` verdict on exact-membership rejection;
- origin is **never inferred** from `subject_ref`, request identifiers, session
  identifiers, correlation shape, or emitter identity;
- **no emitter package is imported.** The verifier continues to recompute every
  reported value from the receipt bytes independently.

Only true absence becomes `not_declared`.

## v0.1 / v0.2 parity

Parity is structural, not merely asserted.
`arcs_verify.dagr_report_v0_2.build_verification_report` delegates to the frozen
v0.1 builder and then does exactly three things: restates `report_version`,
restates `report_contract_id`, and inserts `subject_ref_origin_disclosed`.
There is no second verdict path and no second verifier.

For every input that existed before this change, verified under the same
configuration, v0.1 and v0.2 produce the same pass/fail disposition, the same
eight Boolean values, the same `chain_status`, the same hashes, and the same
failure codes. Only the added disclosure differs.

## Envelope schema pins

Both pins are accepted; see `envelope-schema-pin-contract.json`.

| version | sha256 | status |
|---|---|---|
| v0.2.0 | `d03aad1d5517e2acb65d5c866905aed7219bcbbfadd1a4a97eac546dd23f0333` | retained — verifies historical v0.2.0-era receipts |
| v0.2.1 | `2afa1ec9f093fd7c06c4f5db7bfd37cc63e64e3dcbe47c963f4df586a1c18ca1` | added — adds `subject_ref_origin` with exact-membership rejection |

Accepting the second pin is additive. An input that verified under the v0.2.0
pin before this change verifies identically after it, and an input offered with
any unpinned schema still fails the `schema_digest` verdict. No pre-existing
disposition moves.

The v0.2.1 schema is byte-identical to arcs-srs merge commit
`ccc4e4bbcd195914be70be392c89094bf8e2781b` and is vendored at
`vendor/arcs-srs/schemas/srs-envelope/v0.2.1/srs-envelope.schema.json` with the
runtime copy at `arcs_verify/data/srs-envelope-v0.2.1.schema.json`.

`published_version` in the vendored envelope manifest is pre-release artifact
metadata. It names a manifested pre-release envelope artifact version and is
not evidence that a public SRS release occurred. `receipt_version`
`srs.core.v5.1` is an internal pre-public-release compatibility value; it is
unchanged by this lane and is not a public, current-public, or forward public
identifier.

## Files

| File | Purpose |
|---|---|
| `verification-report.schema.json` | JSON Schema (draft 2020-12) for the v0.2 report. `additionalProperties: false`; unknown fields fail closed. |
| `origin-disclosure-contract.json` | Pins the five declared values, the `not_declared` rendering, the absence semantics, the malformed-value rule, and the reader rules. |
| `envelope-schema-pin-contract.json` | Pins both accepted SRS envelope schemas and the S1 provenance for v0.2.1, including the four governed origin vector digests. |
| `golden/` | Six generated fixtures — one per declared value plus one genuine absence — with their deterministic reports and pinned `expectations.json`. |

Implementation: `arcs_verify/dagr_report_v0_2.py` (report) and
`arcs_verify/subject_ref_origin.py` (reader). Gate:
`tests/test_dagr_srs_report_contract_v0_2.py`.

Emission surface:

```
arcs-verify dagr-report-v0-2 RECEIPT --keyring TRUST_BUNDLE \
  --profile srs.mcp.sdk_enforcement.v0.1 \
  --schema arcs_verify/data/srs-envelope-v0.2.1.schema.json \
  --verifier-commit <full-40-hex-sha>
```

## Golden fixtures

`golden/origin-*-receipt.json` are six local DAGR MCP admission receipts. They
are signed by a fixture key derived from a fixed, published seed label recorded
in `golden/expectations.json` and in
`tools/generate_dagr_report_v0_2_goldens.py`, so the receipt bytes — and every
hash derived from them — reproduce exactly on any machine. That key has no
authority: it signs nothing outside this directory and appears in no trust
bundle other than `golden/trust-bundle.json`.

All six share one `subject_ref` on purpose. Six receipts that carry the same
subject reference and differ only in what they declare must still disclose six
different origins — that is the no-inference rule made into a fixture.

`golden/origin-*-report.json` are generated by calling the real
`verify_receipt` path and the real v0.2 builder, never hand-authored. Regenerate
with:

```
python3 tools/generate_dagr_report_v0_2_goldens.py
```

The four governed S1 origin vectors vendored at
`vendor/arcs-srs/vectors/subject-ref-origin-v0.2.1/` pin the reader against
arcs-srs directly. They are unsigned envelope vectors: they pin origin-reading
behavior only and prove nothing about signing.

**Golden regeneration note.** The `verifier_commit` recorded in these fixtures
is the branch base commit at authoring time. Per repository precedent (see
`docs/VERSIONING.md` and the v0.1 contract's `golden_regeneration_note`), it
MUST be regenerated and reconciled to the squash-merge commit before this
contract is treated as merged-authoritative. The separate, pre-existing v0.1
golden-regeneration obligation is untouched by this lane and remains its own
hygiene item.

## Boundary guards

This contract adds none of the following: an authenticated exporter; a DAGR
runtime change; storage; API routes; UI; live session fixtures; production
signing keys; a new admission decision; a new verdict; or new package
dependencies. It imports no emitter package.
