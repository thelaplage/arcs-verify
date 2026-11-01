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

Rule-level refusal codes use the pinned checker's names. One adapter policy sits on top: an
unknown top-level field is refused (the profile schema permits extra fields; this adapter will
not silently drop what it cannot map). `extensions` is the envelope's place for
producer-namespaced content: it is never interpreted and feeds no axis, and is reported
verbatim under `producer_asserted.extensions`. (Phase A refused any non-empty `extensions`; the
first really produced observation carries a provisional-emission notice there, which showed
that policy to be stricter than the profile.)

### Step 3: mapping

Refused (never defaulted): an `official_trust_list` or `unknown_not_captured` basis (the
canonical finding has no mode for either), more than one trust-material digest, trust
material under a basis that supplies none, acquisition mode `none`, an evaluation posture
with no native evaluation, no settings digest (`validator_defaults`), hermeticity that is
not stated or not established, a pinned validation clock, a native state outside
`Trusted | Valid | Invalid`, and producer assertions that contradict the observation's own
native findings (trust).

The observed axes come from the observation's native findings through the verifier's single
normalizer. Producer-asserted trust, validity, timestamp, revocation, issuer id and process
exit code are reported under `producer_asserted`, labelled as such; none feeds an axis.
An embedded store's digest is not separate bytes in the canonical finding (null); the
observation's value is still checked when the bytes are retained.

### Signer validity and the expired-certificate pair

A real expired-certificate report carries `claimSignature.insideValidity` (validity at signing
time) and `signingCredential.expired` (validity at validation time) together. That is two
facts on two axes, never a contradiction: the canonical `signer_validity` axis comes from the
native findings only, and the producer's scalar is annotated
`consistency_with_native_findings` as `consistent`, `uncorroborated`, `time_basis_differs` or
`not_evaluated_by_producer`. It is never refused as inconsistent.

### Timestamps

If the producer disclosed `unavailable_inputs[].input == "tsa_trust_material"`, the disclosure is
kept under `axes.timestamp.trust_material_disclosure` (the reason text is the producer's and is
never interpreted) and the reading is `producer_observed_tsa_trust_material_unavailable`. The
other readings are `no_trusted_timestamp_claimed`,
`producer_observed_tsa_trust_material_digest_named_unchecked` and
`producer_observed_tsa_trust_basis_not_disclosed`. A timestamp `match` compares two native
validator runs under timestamp-authority trust anchors that are not digest-bound input; the
report says so and never reads it as independent trust.

### Comparability restriction (owner rule: conservative and receipt-wide)

The adapter consumes both `later_comparison_posture` and `unavailable_inputs` on the
native-validation-performed path and keeps their reasons **separate**. Each reason is read only
from its own field and is never inferred from `not_comparable` alone (nor `not_comparable` from a
reason):

| Reason | Read from |
|---|---|
| `signer_trust_inputs_uncaptured` | `signer_trust.trust_basis == unknown_not_captured` |
| `tsa_trust_material_uncaptured` | an `unavailable_inputs` entry whose `input` is `tsa_trust_material` (the reason text is the producer's and is never interpreted) |
| `declared_without_a_stated_reason` | `not_comparable` with neither of the above |

**Scope.** If `later_comparison_posture == not_comparable`, the restriction is **receipt-wide**
(`axes.comparability_restriction.scope`). Every supported axis is still recomputed by the
verifier's own validator run and reported independently (`axes.independent_recomputation`,
and each axis's `observed_status` and `recomputed_status`). But no axis is reported as an
effective match or mismatch: its effective state is `restricted_receipt_wide`, so a
byte-deterministic agreement can never read as an overall match, and there is no overall result.
The unchanged contract entry stays in `native_comparison_report` and is echoed per axis as
`contract_comparison` (a divergence therefore stays visible; the restriction hides agreement,
never disagreement). The comparison stage's status is `restricted`, the pipeline's `stopped_at`
is `comparison`, and the CLI exits 1.

If the producer disclosed `tsa_trust_material` as unavailable but declared the receipt
`comparable`, only the `timestamp` axis is restricted (`not_comparable`,
`tsa_trust_material_not_captured`); the disclosure alone does not make the receipt
`not_comparable`.

**Grounding.** The pinned profile (`thelaplage/arcs-srs@3219ff83eb47f46582eefbd53dc46a9d78ef5d4b`)
defines the posture as observation-wide:

* `docs/profiles/SRS_C2PA_VALIDATION_OBSERVATION_PROFILE_v0_1.md:278-281` (section 11):
  "`later_comparison_posture` records whether a later observation can be compared to this one at
  all. When `signer_trust.trust_basis` is `unknown_not_captured`, `later_comparison_posture` MUST
  be `not_comparable`: without the exact trust inputs, a later native result is not comparable to
  this one."
* `...PROFILE_v0_1.md:285-286`: "There is no per-axis comparison output in this profile;
  comparison and recomputation belong to the independent verifier, not to the receipt."
* `schemas/c2pa-profiles/v0.1/srs.c2pa.validation_observation.v0.1.schema.json:375-378`
  (the field) and `:516-528` (the one forcing rule); `conformance/profiles/.../conformance-rules.json:68-71`;
  `tools/validate_srs_profile.py:4751-4764`.

The profile names no axis and gives the verifier the comparison decision, so the receipt-wide
scope follows its literal "at all". (An earlier revision of this adapter restricted only the
trust- and clock-dependent axes; the owner's receipt-wide rule replaced that.)

**Independent recomputation is not stopped.** A mapping refusal of the observed side (for
example `unknown_not_captured`, which the canonical finding cannot express) no longer prevents
the verifier's own recomputation, which does not depend on the producer's claims. It is reported
on its own, and the comparison is `not_evaluated` with `COMPARISON_OBSERVED_SIDE_NOT_CONSTRUCTED`.

**Trusted timestamps.** The producer's native findings are preserved as observations
(`producer_asserted.native_findings_as_observations`). A timestamp-trust finding is never
promoted to independently established TSA trust when the retained basis is missing:
`axes.timestamp.reliance.status` is `not_established` whenever a trusted timestamp is claimed,
with every restriction in force named in `restricted_by` (`tsa_trust_material_uncaptured`,
`tsa_trust_material_named_but_unchecked`, `tsa_trust_basis_not_disclosed`,
`receipt_not_comparable`), and `independent_tsa_appraisal` is always `not_evaluated`.

### Decisions awaiting independent review

Three behaviours were not specified by the dispatch or the owner rule. They follow the owner's
requirement that a restriction "must not stop BRIDGE0 from independently recomputing" and that no
overall success may be reported. They are **not settled** until the independent reviewer has
judged them.

1. **The verifier's recomputation runs even when the observed side cannot be built.** If the
   observation has no canonical form (for example `unknown_not_captured`), the observed-side
   construction stage is `refused`, the verifier's own recomputation still runs and is reported
   under `axes.independent_recomputation`, and the comparison stage is `not_evaluated` with
   `COMPARISON_OBSERVED_SIDE_NOT_CONSTRUCTED`. Earlier stages (parse, correspondence, profile
   conformance) still stop the run.
2. **`stopped_at` names the first stage that did not complete**, whatever its status:
   `refused`, `not_evaluated`, `restricted` or `not_run`. It is `null` only when every stage
   completed. For a receipt-wide restriction it is `comparison`, although the comparison ran.
3. **The CLI exits 1 for a restricted receipt.** Exit 0 would read as an aggregate success; it is
   reserved for a run in which every stage completed and no receipt-wide restriction applies.

## Typed outcomes

Every refusal carries a stable code and the field it concerns. Families: `OBS_*` (parse),
`CORR_*` (correspondence), the pinned checker's own rule names plus `ENVELOPE_SCHEMA`,
`FIELD_SCHEMA` and `ADAPTER_*` (profile), `MAP_*` (mapping), `RECOMPUTE_*` and `COMPARISON_*`
(later stages), and `*_INTERNAL_ERROR` (an unexpected error is a refusal, never a pass).
A stage status is one of `completed`, `refused`, `not_evaluated`, `restricted` (comparison only), `not_run`; `completed` means
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

Exit 0 means every stage completed (a comparison was produced and the receipt was not restricted;
that says nothing about whether the sides match). Exit 1: a stage refused, was not evaluated, or
the comparison was restricted receipt-wide. Exit 2: usage or
source-integrity error. Without `--c2patool` or `ARCS_VERIFY_C2PATOOL` the recomputation is
`not_evaluated`; the verifier never falls back to an executable on `PATH`.

Tests: `python -m pytest tests/c2pa_srs`. The live pinned-validator tests are skipped (NOT
EXERCISED) unless `ARCS_VERIFY_C2PATOOL` names c2patool 0.27.15.

## Replay over a really produced observation (Phase B)

`tests/c2pa_srs/produced/` holds the unmodified output of the C2PA-EMIT0 producer (a provisional,
unsigned emitter in `dagr-ingest`) over a pinned asset and the machine report the pinned
c2patool 0.27.15 emitted: one positive, one tampered derivative (native `Invalid` with process
exit 0) and one missing remote manifest. `PROVENANCE.json` is the single place that records the
producing commit, command, validator, licence and every file digest; the tests read expected
digests only from it. Tampering negatives are created inside the tests from the vendored bytes
and are labelled `TEST MUTATION`.

The tests that need only bytes always run. The verifier's own recomputation over the frozen
inputs needs the pinned validator and is NOT_EXERCISED unless `ARCS_VERIFY_C2PATOOL` is set.
That replay is offline technical interoperability only: the observation is unsigned and
provisional under a test issuer identity, and `axes.operational_issuance_readiness` stays
`not_established`. It does not establish issuer trust, trust-list membership or content truth.

## What this does not establish

The Phase A fixtures are SYNTHETIC. They exercise ordering, refusals and typed outcomes;
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
