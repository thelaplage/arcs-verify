# ARCS Verify — SRS vNext External-Profile Failure Codes

This is the companion failure-code registry for
`arcs_verify.external_profile`. The repository-wide structural registry test
reads this file together with `docs/FAILURE_CODES.md`; every static or dynamic
code emitted by the module must appear in one of those two registries.

The split is deliberate for the candidate vNext lane: the established registry
remains byte-untouched while the new verifier surface is still DRAFT. Before a
future public release, these entries may be folded into the primary registry
without changing their stable code strings.

A failure code reports a verification axis that did not pass. No code here
implies truth, authorization, domain standing, evidence standing, or
certification.

## Candidate schema and input binding

| Code | Meaning |
|---|---|
| `schema_bytes_not_json` | Caller-supplied schema bytes are not JSON and cannot be used for validation. |
| `envelope_schema.digest_mismatch` | The supplied vNext envelope schema bytes do not match the independently pinned candidate SHA-256. |
| `profile_schema.digest_mismatch` | The supplied external-profile-declaration schema bytes do not match the independently pinned candidate SHA-256. |
| `receipt.not_json` | Receipt bytes are not JSON. |
| `profile.not_json` | External-profile declaration bytes are not JSON. |
| `input.not_object` | A parsed receipt or profile is not a JSON object. |
| `profile.schema_invalid` | The profile declaration does not validate against the pinned external-profile-declaration schema. |
| `profile.vnext_envelope_not_compatible` | The profile does not explicitly list the exact pinned vNext envelope version + SHA-256 as compatible. |
| `receipt.profile_id_mismatch` | Receipt `profile_id` differs from the supplied profile declaration. |
| `receipt.profile_version_mismatch` | Receipt `profile_version` differs from the supplied profile declaration. |
| `receipt.type_not_permitted` | Receipt type is not in the profile's permitted type set. |
| `receipt.profile_classification_missing_or_ambiguous` | The profile does not yield exactly one structural class for the receipt type/kind. |
| `receipt.contract_refs_mismatch` | Receipt contract refs do not bind the exact expected vNext envelope id/version/digest and profile id/version/digest. |

`envelope.schema_invalid`, `raw_content.prohibited_value`,
`attestation.missing_or_empty`, `signature_object_invalid`, `key_id_unresolved`,
`public_key_encoding_invalid`, `signature_encoding_invalid`, `signature_invalid`,
`preimage_canonicalization_failed`, and `key_untrusted` are shared with the
established signed-SRS verifier and remain documented in `FAILURE_CODES.md`.

## Profile cross-field conformance

| Code | Meaning |
|---|---|
| `profile.not_object` | Cross-field validation was asked to evaluate a non-object profile. |
| `profile.cross_field_inputs_invalid` | One or more profile arrays needed for cross-field validation are missing or not arrays. |
| `profile.classification_not_object` | A receipt-type classification entry is not an object. |
| `profile.classification_incomplete` | A classification entry lacks string receipt-type/class members. |
| `profile.classification_for_undeclared_type` | A classification is present for a receipt type not in the profile's permitted set. |
| `profile.conflicting_duplicate_classification` | The same receipt-type / receipt-kind key maps to more than one structural class. |
| `profile.permitted_type_unclassified` | At least one permitted receipt type has no structural classification. |
| `profile.v0_2_1_permits_non_frozen_type` | A profile claiming v0.2.1 compatibility permits a receipt type outside the frozen v0.2.1 enum. |
| `profile.kind_required_but_unqualified_classification` | A kind-sensitive type such as `sdk_enforcement` has a bare unqualified classification entry. |
| `profile.missing_kind_qualified_classification` | A kind-sensitive type is missing one or more required receipt-kind classifications. |

## Signing-required profile

| Code | Meaning |
|---|---|
| `profile.required_signature_invalid` | The profile declares `signing_required=true` and the receipt signature did not verify. |
