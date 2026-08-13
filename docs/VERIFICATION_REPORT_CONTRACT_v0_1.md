# VerificationReport contract v0.1 — self-identifying report

`report_contract = "arcs.verify.srs_receipt_verification_report.v0.1"`

The first formally versioned `VerificationReport`. It adds intrinsic identity to
the report so a consumer can tell **what was verified** without relying on
filenames, argument order, or an out-of-band ledger. Introduced by SRS-RECON0-VR0
to close three findings from the RECON0-C1 golden-chain run
(`C1-VERIFY-REPORT-NONIDENTIFYING`, `C1-VERIFY-PROVISIONAL-POSTURE-NONDISCLOSURE`,
`C1-VERIFY-METADATA-DRIFT`).

## Constitutional invariant

**Self-identification is not self-authorization.** These fields identify the
receipt, selected profile, schema, and profile posture involved in a
verification event. They do **not** establish source truth, issuer trust,
producer authority, admission, standing, or publication eligibility. No new field
participates in `passed`; identity/posture is descriptive, never a hidden verdict
axis.

## Additive fields (never affect `passed`)

| field | meaning |
|---|---|
| `report_contract` | `arcs.verify.srs_receipt_verification_report.v0.1` |
| `selected_profile` | the exact profile slug requested for evaluation |
| `selected_profile_release_stage` | `"provisional"` \| other known stage \| `null`. `null` = not established by pinned metadata. **Never infer `stable` from absence.** |
| `verified_receipt_id` | the receipt's own declared `receipt_id` |
| `verified_receipt_version` | the receipt's `receipt_version` |
| `verified_receipt_profile_id` / `verified_receipt_profile_version` | the profile the **receipt declared** — kept distinct from `selected_profile` so a mismatch report says both "asked to evaluate X" and "receipt declared Y" |
| `verified_receipt_canonical_json_sha256` | `sha256:` of RFC8785 canonical JSON of the receipt. Explicitly **canonical JSON**, not the original serialized bytes (the library verifier receives a parsed object). |
| `envelope_schema_identity` | `{published_version, sha256}` of the schema used; `published_version` is `null` if the digest maps to no pinned version. |

## Downstream feature-detection (binary boundary)

```
report_contract absent   → legacy / unversioned VerificationReport (verdict-only shape)
report_contract == v0.1  → enriched self-identifying contract (complete field set)
```

The serialized shape is a clean binary: a report is stamped **only** when
`verify_receipt` populates it, and `to_dict()` emits the stamp together with the
whole VR0 field set, or omits the stamp **and** all VR0 fields. There is no
ambiguous `"report_contract": null` third state, and the version can never exist
without the identity it is supposed to guarantee. Reports produced before VR0
(e.g. the RECON0-C1 evidence reports) legitimately lack the field and must be
treated as legacy — never retroactively labeled.

## Nullability

`verified_receipt_canonical_json_sha256` is **nullable**. Canonicalization is
best-effort for verifier robustness: if RFC8785 canonicalization fails it yields
`null`, and that never becomes a verification verdict axis here. A consumer that
requires content-bound verification (e.g. a future HOP-6 authoring intake) MUST
**fail closed** if it receives a v0.1 report whose
`verified_receipt_canonical_json_sha256` is absent or `null`, rather than
proceeding as if the receipt were content-addressed.

## Anti-drift

Profile identity, the CLI `--list-profiles` listing, the report release-stage,
and the provisional advisory are all **projected from one canonical
`PROFILE_REGISTRY`** in `verifier.py`. There is no separately maintained
supported-profile set that can drift from what the verifier actually routes; a
regression asserts the projections match the registry.

## Not in scope

`arcs-srs-store` is unchanged. Its `attach_verification_report` keeps retaining
opaque report bytes plus a caller-supplied pack hint; a later store lane can
detect `report_contract` and structurally extract the newly-available identity.
That extraction is deliberately **not** bundled here.
