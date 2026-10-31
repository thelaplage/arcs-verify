# C2PA-BRIDGE0: consuming untrusted SRS native observations

**Status: PROVISIONAL / EXPERIMENTAL. Owner acceptance outstanding. AUTHORITY_MOVEMENT = 0.**
Merge disposition: not delegated; a separate owner merge disposition is required (C2PA-I0).

`arcs_verify/c2pa_srs_observed.py` is an **untrusted adapter**. It reads a serialized
`srs.c2pa.validation_observation.v0.1` observation plus the native-report evidence the
producer retained, and feeds the existing `arcs_verify.c2pa_native` comparison. It is not an
SRS receipt verifier, it does not change the provisional `c2pa-native-finding` contract, and
it imports no producer code. Producer output enters as serialized bytes only.

## Ownership

| Responsibility | Owner |
|---|---|
| C2PA SRS profile and vocabulary | arcs-srs (vendored here byte-exact, pinned) |
| Provisional unsigned emitter | `dagr-ingest` (separate lane, C2PA-EMIT0) |
| Untrusted extraction and independent comparison | arcs-verify (this module) |
| Operational issuer, keys, publication | not selected; held for a separate owner decision |

Counterpedia owns its documentary semantics. C2PA is an optional interoperability adapter
and never an authority over Source identity, classification, admission or evidence
relationships.

## Fixed order

The run stops at the first stage that does not complete. A later stage is `not_run`, never
`completed`.

| # | Stage | What it does |
|---|---|---|
| 0 | `input_parse` | strict JSON: UTF-8, no duplicate keys, no NaN/Infinity, object root, bounded size and depth |
| 1 | `input_correspondence` | every digest the observation names is checked against the retained bytes; its claims about the native report are checked against that report |
| 2 | `profile_conformance` | conformance to the pinned arcs-srs profile (field schema, manifest, rules, limitation registry, envelope v0.2.1) |
| 3 | `observed_finding_construction` | only now is the observed-side canonical finding built; a value with no canonical representation is refused |
| 4 | `native_recomputation` | the verifier's own pinned native-validator path (`c2pa_native.recompute`) under its own hermetic settings |
| 5 | `comparison` | the existing axis-by-axis comparison, behind a source-digest gate |

`construct_observed_side` raises `OrderingViolation` unless stages 1 and 2 are `completed`.

### Step 1: correspondence

Checked against retained bytes: `asset_digest`, `subject_ref`, `manifest_store.digest`,
`native_report.report_digest`, `native_validator.configuration_digest`. For the native
report the claimed `native_validation_state` and `native_findings` must also equal what the
retained report says (parsed with the verifier's own parser; the legacy flattened
`validation_status` array is never read).

Every other digest the observation names (`build_digest`, trust-material digests, the TSA
reference, the replay-report digest, the prior-report digest) has no retained-bytes slot and
is listed under `unchecked`. **Unchecked is not a match.** A digest that is not strictly
`sha256:` plus 64 lowercase hex characters is refused: the upstream schema pattern ends in
`$`, which Python's regex also matches before a trailing newline.

### Step 2: profile pin

The four profile artifacts are vendored under
`arcs_verify/contracts/c2pa-srs-observation/v0.1/` as exact copies of arcs-srs at
`3219ff83eb47f46582eefbd53dc46a9d78ef5d4b`. Their sha256 and git-blob ids are held **in code**
(`PINNED_CONTRACT_FILES`) and re-checked on every load; `source-pin.json` is provenance and
is cross-checked, so it cannot move the pin. The SRS envelope v0.2.1 schema is the existing
pinned `arcs_verify/data/srs-envelope-v0.2.1.schema.json`. A mismatch raises
`ContractPinError`; it is never a quiet fallback. The binding manifest's semantic digest is
recorded but not recomputed here, because it also covers 27 fixtures this package does not
vendor.

Rule-level refusal codes use the pinned checker's names. Two adapter policies sit on top: an
unknown top-level field and a non-empty `extensions` object are refused (the profile schema
permits extra fields; this adapter will not silently drop what it cannot map).

### Step 3: mapping

Refused (never defaulted): an `official_trust_list` or `unknown_not_captured` basis (the
canonical finding has no mode for either), more than one trust-material digest, trust
material under a basis that supplies none, acquisition mode `none`, an evaluation posture
with no native evaluation, no settings digest (`validator_defaults`), hermeticity that is
not stated or not established, a pinned validation clock, a native state outside
`Trusted | Valid | Invalid`, and producer assertions that contradict the observation's own
native findings (trust, signer validity).

The observed axes come from the observation's native findings through the verifier's single
normalizer. Producer-asserted trust, validity, timestamp, revocation, issuer id and process
exit code are reported under `producer_asserted`, labelled as such; none feeds an axis.
An embedded store's digest is not separate bytes in the canonical finding (null); the
observation's value is still checked when the bytes are retained.

## Typed outcomes

Every refusal carries a stable code and the field it concerns. Families: `OBS_*` (parse),
`CORR_*` (correspondence), the pinned checker's own rule names plus `ENVELOPE_SCHEMA`,
`FIELD_SCHEMA` and `ADAPTER_*` (profile), `MAP_*` (mapping), `RECOMPUTE_*` and `COMPARISON_*`
(later stages), and `*_INTERNAL_ERROR` (an unexpected error is a refusal, never a pass).
A stage status is one of `completed`, `refused`, `not_evaluated`, `not_run`; `completed` means
only that the stage ran with no refusal.

## Authentication

The profile is unsigned (`requires_signing: false`). `signature_shape`, `signature_valid`,
`key_resolved`, `key_trusted` and `issuance_authentication` are always `not_evaluated`,
whether or not a `receipt_signature` is present. This adapter accepts no key material.
An unsigned or unverified observation is never reported as authenticated issuance.

## What is compared

The recomputation uses the verifier's own hermetic settings, so the producer's configuration
digest must equal `sha256(HERMETIC_SETTINGS_TOML)` for sides to be comparable; any other
configuration is `policy_delta`. The verifier cannot replicate a producer trust basis, so
`signer_trust` under a supplied allowed list or anchors is `trust_basis_delta`
(`not_comparable`), never `match` or `mismatch`. Time-dependent axes differing without a
trusted timestamp on both sides are `validation_clock_delta`. Revocation is `not_evaluated` on
both sides. If either side has no native evaluation the comparison is `not_evaluated`; two
non-evaluations are not a match and one is not a mismatch.

Report-to-asset binding is composed by the producer: nothing in a native report ties it to
the asset it was produced for, so an unrelated report can be paired with an asset while every
named digest matches the bytes retained. Correspondence cannot see that. The verifier's own
recomputation over the frozen asset is the control: the producer's retained report is never the
independent result, and a foreign report surfaces as a `mismatch` on the byte-deterministic
axes (or a `not_evaluated` comparison when the verifier's own run yields no report), never as
a `match`.

The existing comparison reports `match` when both sides carry the same status, including
when neither evaluated the axis. The report adds `agreement_basis`
(`same_status` or `both_sides_not_evaluated`) so absence of evidence on both sides is not read
as agreement. There is no aggregate verdict key anywhere in the report.

## Running

```
python -m arcs_verify.c2pa_srs_observed --observation OBS.json --asset ASSET \
    --native-report REPORT.json [--manifest-store STORE] [--configuration CFG] \
    [--asset-name NAME.ext] --c2patool /path/to/pinned/c2patool
```

Exit 0 means every stage completed (a comparison was produced; that says nothing about
whether the sides match). Exit 1: a stage refused or was not evaluated. Exit 2: usage or
source-integrity error. Without `--c2patool` or `ARCS_VERIFY_C2PATOOL` the recomputation is
`not_evaluated`; the verifier never falls back to an executable on `PATH`.

Tests: `python -m pytest tests/c2pa_srs`. The live pinned-validator tests are skipped (NOT
EXERCISED) unless `ARCS_VERIFY_C2PATOOL` names c2patool 0.27.15.

## What this does not establish

All fixtures in Phase A are SYNTHETIC. They exercise ordering, refusals and typed outcomes;
they prove nothing about end-to-end producer-to-verifier interoperability, which is owed to a
replay over bytes a real producer emitted. Nothing here establishes content truth,
depicted-event truth, signer trust in general, trust-list membership, issuer standing, or
operational issuance readiness.

## Open items

* The canonical finding has no mode for `official_trust_list` or `unknown_not_captured`;
  supporting either needs a separate owner-reviewed contract PR.
* The pinned native path cannot recompute an embedded store's digest (no separate bytes).
* The public `arcs-verify` and `arcs-verify-dev` trees are separate owners; this module, its
  tests and the vendored profile files exist only here. Mirroring them to the development
  tree, if wanted, is a later act.
