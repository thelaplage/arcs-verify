# ARCS Verify — Failure Code Registry

Every FAIL result is accompanied by one or more failure codes. Codes are
stable strings intended for scripting and alerting: match on the exact code
(or, for the dynamic families below, on the documented prefix), not on the
human-readable detail lines. This registry enumerates the code space emitted
by the current verifier bytes, and a repository test
(`tests/test_failure_code_registry.py`) sweeps the emitting modules and fails
if a code or code family is emitted that this document does not list. The
authoritative source is the code itself; the test exists so this document
cannot silently fall behind it.

Codes are grouped by the subcommand that emits them. A single run can emit
several codes: a tampered receipt typically fails both a profile constraint
and the signature at once.

Some families are **dynamic**: the code is a fixed prefix completed from a
field or key name at the emitting site. For each dynamic family this registry
gives the prefix, the completion rule, and the concrete completion set in the
current bytes. Alert on the prefix if you want forward compatibility with new
fields.

## Signed-SRS verification (default subcommand)

### Schema and envelope

| Code | Fails result | Meaning |
|---|---|---|
| `schema.digest_mismatch` | `schema_digest` | The loaded envelope schema file does not hash to the frozen SHA-256. |
| `envelope.schema_invalid` | `envelope` | The receipt does not validate against the pinned SRS envelope JSON Schema. One code per schema error; details carry the validator messages. |

### Signature and trust

| Code | Fails result | Meaning |
|---|---|---|
| `signature_object_invalid` | `signature_valid` | `receipt_signature` is missing or is not a well-formed signature object (algorithm, canonicalization, key_id, signature). |
| `signature_invalid` | `signature_valid` | The Ed25519 signature over the RFC8785-JCS canonical preimage does not verify under the resolved key. |
| `version_binding_mismatch` | `signature_valid` | The receipt's profile version binding does not match the selected profile. |
| `key_id_unresolved` | `issuer_key_resolved` | The signature `key_id` does not resolve to an entry in the supplied trust bundle. |
| `key_untrusted` | `issuer_key_trusted` | The resolved key is not marked trusted, its `issuer_id` does not match the receipt, or `issued_at` falls outside the key's validity window. |
| `legacy_unverified` | `signature_valid` | The receipt carries a legacy signature form the verifier does not verify. |
| `preimage_canonicalization_failed` | `signature_valid` | The receipt could not be serialized to its RFC 8785 canonical preimage. |
| `signature_encoding_invalid` | `signature_valid` | The signature value is not valid unpadded base64url encoding. |
| `public_key_encoding_invalid` | `signature_valid` | The resolved public key is not valid unpadded base64url encoding. |

### Raw-content exclusion and attestation limits

| Code | Fails result | Meaning |
|---|---|---|
| `raw_content.prohibited_value` | `raw_content_exclusion` | A prohibited raw-content or credential key carries a value. Receipts carry references and digests only. |
| `raw_content.forbidden_key:<key>` | `raw_content_exclusion` | Dynamic. A forbidden key name is present; the code names it. |
| `raw_content.invalid_digest_evidence:<key>` | `raw_content_exclusion` | Dynamic. A field required to be digest-shaped evidence is not. |
| `raw_content.invalid_identifier_evidence:<key>` | `raw_content_exclusion` | Dynamic. A field required to be identifier-shaped evidence is not. |
| `raw_content.invalid_reference_evidence:<key>` | `raw_content_exclusion` | Dynamic. A field required to be reference-shaped evidence is not. |
| `attestation.missing_or_empty` | `attestation_limits_present` | `attestation_limits` is absent, empty, or holds non-string or blank entries. |

### Profile: common

| Code | Meaning |
|---|---|
| `profile.unsupported_selection` | The selected profile name is not one this verifier evaluates. See `--list-profiles`. |
| `profile.memory_not_yet_ratified` | Emitted by `verify_memory_receipt` while the `srs.memory` profile family is not yet ratified by arcs-srs. This is a stub response; the code will be removed once the profile is published and pinned. `not_evaluated` discipline is preserved — no Boolean is promoted to `True`. |
| `profile.missing_required:<field,field,...>` | Dynamic. Required top-level fields are absent; the code carries the sorted, comma-joined missing set. The base required set is: `artifact_classes_covered`, `artifact_classes_excluded`, `attestation_limits`, `boundary_id`, `boundary_type`, `extensions`, `issued_at`, `issuer_id`, `profile_id`, `profile_version`, `protocol_binding`, `receipt_id`, `receipt_kind`, `receipt_signature`, `receipt_type`, `receipt_version`, `runtime_instance_id`, `subject_ref` (the MCP profile adds `logical_call_id`; the connection profile adds `tenant_id`, `actor_ref`, `source_record_refs`). |
| `profile.invalid_<key>` | Dynamic. A fixed-value field carries the wrong value. Completions in the current bytes: `receipt_version`, `profile_id`, `profile_version`, `receipt_type`, `boundary_type`, `protocol_binding` (MCP), and `receipt_version`, `profile_id`, `profile_version`, `receipt_type`, `boundary_type` (connection). The static codes `profile.invalid_disposition`, `profile.invalid_outcome`, `profile.invalid_protocol_binding`, `profile.invalid_receipt_kind`, `profile.invalid_retention_class`, `profile.invalid_source_record_refs` follow the same shape from explicit sites. |
| `profile.extensions_not_object` | `extensions` is present but is not a JSON object. |
| `profile.non_boolean_governance_field:<field>` | Dynamic. A registered binding-owned governance field is present but not strictly Boolean. Fields: `delivery_incomplete`, `request_cancelled`, `execution_state_unknown`. |

### Profile: `srs.mcp.sdk_enforcement.v0.1`

| Code | Meaning |
|---|---|
| `profile.admission_missing_<key>` | Dynamic. An admission receipt lacks a kind-required field. Completions: `requested_tool_name`, `tool_resolution_status`, `argument_digest`, `policy_pack_id`, `policy_pack_version`, `disposition`. |
| `profile.raw_artifact_exclusions_missing` | `artifact_classes_excluded` does not cover the exclusions the profile requires. |
| `profile.resolution_ref_for_not_observed` | A resolution reference is present although `tool_resolution_status` is `not_observed`. |
| `profile.result_missing_digest` | A result object lacks the digest the profile requires. |
| `profile.result_missing_attestation_limit` | A result object lacks its required attestation limit. |
| `profile.task_missing_attestation_limit` | A task object lacks its required attestation limit. |
| `profile.outcome_missing_admission_receipt_ref` | An outcome receipt does not reference its admission receipt. |
| `profile.forum_projection_binding_mismatch` | A forum projection binding does not match the profile's requirement. |
| `profile.deferred_invalid_retry_contract` | A deferred receipt carries an invalid retry contract. |
| `profile.deferred_missing_review_object_ref` | A deferred receipt lacks its review object reference. |

### Profile: `srs.connection.lifecycle.v0.1`

| Code | Meaning |
|---|---|
| `profile.connect_missing_provider_ref` | A connect receipt lacks its provider reference. |
| `profile.scope_grant_invalid_scope_refs` | A scope-grant receipt carries missing or malformed scope references. |
| `profile.retention_selection_invalid_retention_class` | A retention selection names a retention class outside the allowed set. |
| `profile.revoke_invalid_reason_code` | A revoke receipt carries a reason code outside the allowed set. |
| `profile.revoke_free_form_reason_forbidden:<key>` | Dynamic. A revoke receipt carries a forbidden free-form reason field; the code names it. Keys: `reason`, `reason_text`, `reason_message`. |
| `profile.<kind>_attestation_limit_missing` | Dynamic. The kind-specific attestation limit sentence is absent. Kinds: `connect`, `scope_grant`, `retention_selection`, `revoke`, `delete`. |
| `profile.connection_general_attestation_limit_missing` | The profile's general attestation limit is absent. |
| `profile.connection_governance_event_not_covered` | The receipt's governance event is not covered by the profile. |

### Profile: `srs.broadcast_control.v0.1`

| Code | Meaning |
|---|---|
| `broadcast_control.invalid_profile_id` | `profile_id` is not the broadcast-control profile. |
| `broadcast_control.invalid_profile_version` | `profile_version` is outside the allowed set. |
| `broadcast_control.invalid_receipt_type` | `receipt_type` is outside the allowed set. |
| `broadcast_control.invalid_receipt_kind` | `receipt_kind` is outside the allowed set. |
| `broadcast_control.invalid_boundary_type` | `boundary_type` is outside the allowed set. |
| `broadcast_control.invalid_capture_posture` | The capture posture is outside the allowed set. |
| `broadcast_control.invalid_assurance_claim` | The assurance claim is outside the allowed set. |
| `broadcast_control.forbidden_operation_type` | The operation type is forbidden for this receipt kind. |
| `broadcast_control.missing_target_state` | The required target-state field is absent. |
| `broadcast_control.missing_base_attestation_limit` | The profile's base attestation limit is absent. |
| `broadcast_control.missing_required_exclusions` | Required raw-artifact exclusions are not declared. |

### Profile: `srs.deferred_operation.v0.1`

| Code | Meaning |
|---|---|
| `deferred_operation.invalid_profile_id` | `profile_id` is not the deferred-operation profile. |
| `deferred_operation.invalid_profile_version` | `profile_version` is outside the allowed set. |
| `deferred_operation.invalid_receipt_type` | `receipt_type` is outside the allowed set. |
| `deferred_operation.invalid_receipt_kind` | `receipt_kind` is outside the allowed set. |
| `deferred_operation.missing_sequence_id` | The required sequence identifier is absent. |
| `deferred_operation.missing_base_attestation_limit` | The profile's base attestation limit is absent. |
| `deferred_operation.missing_required_exclusions` | Required raw-artifact exclusions are not declared. |
| `deferred_operation.defer_request_invalid_disposition` | A defer-request receipt carries a disposition outside the allowed set. |
| `deferred_operation.defer_request_invalid_argument_digest` | A defer-request receipt carries a malformed argument digest. |
| `deferred_operation.defer_request_invalid_operation_digest` | A defer-request receipt carries a malformed operation digest. |
| `deferred_operation.defer_request_invalid_retry_contract` | A defer-request receipt carries an invalid retry contract. |
| `deferred_operation.defer_request_missing_<field>` | Dynamic. Completions: `argument_digest`, `operation_digest`, `policy_pack_id`, `policy_pack_version`, `review_condition`. |
| `deferred_operation.condition_response_invalid_response_status` | A condition-response receipt carries a response status outside the allowed set. |
| `deferred_operation.condition_response_invalid_condition_digest` | A condition-response receipt carries a malformed condition digest. |
| `deferred_operation.condition_response_missing_<field>` | Dynamic. Completions: `condition_digest`, `predecessor_receipt_ref`, `responder_ref`, `response_status`. |
| `deferred_operation.reevaluation_invalid_operation_digest` | A reevaluation receipt carries a malformed operation digest. |
| `deferred_operation.reevaluation_missing_<field>` | Dynamic. Completions: `condition_receipt_ref`, `operation_digest`, `policy_pack_id`, `policy_pack_version`, `predecessor_receipt_ref`. |
| `deferred_operation.terminal_admission_invalid_disposition` | A terminal-admission receipt carries a disposition outside the allowed set. |
| `deferred_operation.terminal_admission_invalid_operation_digest` | A terminal-admission receipt carries a malformed operation digest. |
| `deferred_operation.terminal_admission_missing_<field>` | Dynamic. Completions: `condition_receipt_ref`, `defer_receipt_ref`, `disposition`, `operation_digest`, `policy_pack_id`, `policy_pack_version`, `predecessor_receipt_ref`. |
| `deferred_operation.execution_outcome_invalid_outcome` | An execution-outcome receipt carries an outcome outside the allowed set. |
| `deferred_operation.execution_outcome_invalid_operation_digest` | An execution-outcome receipt carries a malformed operation digest. |
| `deferred_operation.execution_outcome_missing_<field>` | Dynamic. Completions: `defer_receipt_ref`, `operation_digest`, `outcome`, `predecessor_receipt_ref`, `terminal_admission_ref`. |
| `deferred_operation.receipt_gap_missing_gap_reason` | A receipt-gap receipt does not state its gap reason. |

### Profile: `srs.editorial.publication_ingest.v0.1`

| Code | Meaning |
|---|---|
| `editorial_ingest.invalid_profile_id` | `profile_id` is not `srs.editorial.publication_ingest`. |
| `editorial_ingest.invalid_profile_version` | `profile_version` is not `v0.1`. |
| `editorial_ingest.invalid_receipt_type` | `receipt_type` is not `provenance`. |
| `editorial_ingest.invalid_boundary_type` | `boundary_type` is not `editorial_corpus_boundary`. |
| `editorial_ingest.invalid_receipt_kind` | `receipt_kind` is not `ingest`. |
| `editorial_ingest.subject_binding_mismatch` | `publication_artifact_id` and `subject_ref` are both present but not equal. |
| `editorial_ingest.invalid_publication_artifact_id` | `publication_artifact_id` is not a `sha256:`-prefixed string. |
| `editorial_ingest.invalid_occurrence_posture` | `occurrence_posture` is present but outside the allowed set (`unique_artifact`, `duplicate_location`). |
| `editorial_ingest.missing_required_covered_classes` | `artifact_classes_covered` omits a required class (`publication_artifact_digest`, `declared_reference_manifest_digest`). |
| `editorial_ingest.missing_required_excluded_classes` | `artifact_classes_excluded` omits a required exclusion (`raw_publication_bytes`, `raw_frontmatter_yaml`, `raw_body_text`). |
| `editorial_ingest.missing_base_attestation_limit` | `attestation_limits` does not carry the profile's base limitation statement. |
| `editorial_ingest.missing_ingest_attestation_limit` | `attestation_limits` does not carry the profile's ingest-kind limitation statement. |
| `editorial_ingest.missing_required:<field>` | Dynamic. A required top-level field is absent; the code carries the field name. Completions: `corpus_manifest_ref`, `corpus_scope`, `declaration_manifest_ref`, `occurrence_posture`, `parser_identity`, `publication_artifact_id`, `relative_path`, `root_id`. |
| `editorial_ingest.missing_required_limitation_code:<code>` | Dynamic. A required `machine_limitations` entry is absent; the code carries the missing limitation code. Completions: `ARTICLE_TRUTH_NOT_EVALUATED`, `EVIDENCE_COMPLETENESS_NOT_EVALUATED`. |

### Profile: `srs.editorial.source_capture.v0.1`

| Code | Meaning |
|---|---|
| `source_capture.invalid_profile_id` | `profile_id` is not `srs.editorial.source_capture`. |
| `source_capture.invalid_profile_version` | `profile_version` is not `v0.1`. |
| `source_capture.invalid_receipt_type` | `receipt_type` is not `provenance`. |
| `source_capture.invalid_boundary_type` | `boundary_type` is not `editorial_source_capture_boundary`. |
| `source_capture.invalid_receipt_kind` | `receipt_kind` is not `source_capture`. |
| `source_capture.missing_capture_block` | The `capture` object is absent or not an object. |
| `source_capture.invalid_captured_body_digest` | `capture.captured_body_sha256` is not a `sha256:`-prefixed string. |
| `source_capture.capture_url_not_external` | `capture.requested_url` is not an `http://` or `https://` URL. This profile is external/network capture only; an internal governed-record reference is a distinct class and must not ride it. |
| `source_capture.missing_reference_binding` | The `reference` object is absent or carries no `ref_id`. |
| `source_capture.subject_binding_mismatch` | `subject_ref` is present but not equal to `reference.ref_id`. |
| `source_capture.missing_required_covered_classes` | `artifact_classes_covered` omits a required class (`captured_response_digest`, `capture_transaction_metadata`). |
| `source_capture.missing_required_excluded_classes` | `artifact_classes_excluded` omits a required exclusion (`raw_network_response_body`, `raw_source_bytes`, `article_truth`). |
| `source_capture.invalid_retention_class` | `retention_class_applied` is not `hash_only`. |
| `source_capture.missing_required_limitation_code:<code>` | Dynamic. A required `machine_limitations` entry is absent; the code carries the missing limitation code. Completions: `ARTICLE_TRUTH_NOT_EVALUATED`, `CLAIM_SUPPORT_NOT_EVALUATED`, `SOURCE_IDENTITY_NOT_EVALUATED`. |

### Profile: `srs.editorial.source_capture.v0.1.1`

Provisional successor with a distinct receipt model: the capture disposition is a top-level `outcome` enum and `declared_url` / `captured_bytes_ref` are top-level fields bound to that outcome by enforced cross-field rules. It coexists with the byte-frozen v0.1 verifier under its own identity and reuses the shared code names (`invalid_profile_id`, `invalid_receipt_type`, `invalid_boundary_type`, `invalid_receipt_kind`, `missing_reference_binding`, `subject_binding_mismatch`, `missing_required_covered_classes`, `missing_required_excluded_classes`, `missing_required_limitation_code:<code>`) with v0.1.1-specific meanings, plus the following.

| Code | Meaning |
|---|---|
| `source_capture.invalid_profile_version` | `profile_version` is not `v0.1.1`. |
| `source_capture.invalid_outcome` | `outcome` is not one of `success`, `blocked`, `dns_error`, `http_error`, `connection_error`, `redirect_error`, `timeout`, `no_url_declared`. |
| `source_capture.missing_captured_bytes_on_success` | `outcome` is `success` but `captured_bytes_ref` is not a `sha256:`-prefixed digest. |
| `source_capture.captured_bytes_on_nonsuccess` | `outcome` is a known non-`success` value (including `no_url_declared`) but `captured_bytes_ref` is not JSON `null`. |
| `source_capture.declared_url_on_no_url_declared` | `outcome` is `no_url_declared` but `declared_url` is not JSON `null`. |
| `source_capture.missing_declared_url` | `outcome` is a known value other than `no_url_declared` but `declared_url` is not a non-empty string. |

The v0.1.1 required covered classes are `declared_reference_identity`, `capture_attempt_record`; the required exclusion is `raw_captured_bytes`; the required limitation completion is `CONTENT_NOT_VERIFIED`.

### Profile: `srs.editorial.source_capture.v0.2`

Provisional declaration-scoped successor (arcs-srs `1f8768d`). A **distinct profile identity** for a broader subject domain: it supersedes v0.1 for declaration-scoped capture but does not amend, deprecate, or coerce v0.1 / v0.1.1. A v0.2 receipt is verified as v0.2 or fails — there is no silent fallback. The verifier's expectation constants are transcribed from the byte-pinned manifest at `vendor/arcs-srs/vectors/editorial-source-capture-v0.2/profile.manifest.json` and cross-checked by `tests/test_editorial_source_capture_v02_ingest_pins.py`.

| Code | Meaning |
|---|---|
| `FIXED_VALUE_MISMATCH` | A manifest `fixed_values` field (`receipt_version`, `profile_id`, `receipt_type`, `boundary_type`) carries the wrong constant. |
| `PROFILE_VERSION_MISMATCH` | `profile_version` is not `v0.2`. Emitted (never a fallback to v0.1/v0.1.1) when a receipt selected under v0.2 declares another version. |
| `INVALID_RECEIPT_KIND` | `receipt_kind` is not `capture_attempt`. |
| `MISSING_PROFILE_FIELD` | A field the profile's `required_fields` requires is absent. |
| `SUBJECT_BINDING_MISMATCH` | `subject_ref` is present but not equal to `source_reference_id` (declaration identity, profile s2). |
| `INVALID_DECLARING_ARTIFACT_REF` | `declaring_artifact_ref` is present but not `sha256:` followed by 64 lowercase hex characters. |
| `SOURCE_REFERENCE_ID_NOT_DECLARATION_DERIVED` | `source_reference_id` does not incorporate both the `declaring_artifact_ref` hex and the `source_inventory_key` — its only two identity inputs (profile s4). Catches a wrong declaring artifact or inventory key folded into the reference identity. |
| `SOURCE_REFERENCE_ID_INCORPORATES_LOCATOR` | `source_reference_id` incorporates `declared_url`; URLs are locators, not identity (profile s4/s5). |
| `SOURCE_REFERENCE_ID_INCORPORATES_CAPTURER` | `source_reference_id` incorporates `capturer_identity`; the capturer belongs to the observation, not the declaration (profile s4/s6). |
| `INVALID_OUTCOME` | `outcome` is not one of the eight manifest `outcome_values`. |
| `CAPTURED_BYTES_REF_OUTCOME_MISMATCH` | `captured_bytes_ref` is not a `sha256:` digest when `outcome` is `success`, or is not JSON `null` for every other outcome (both directions, profile s8). |
| `DECLARED_URL_OUTCOME_MISMATCH` | `declared_url` is not JSON `null` exactly when `outcome` is `no_url_declared`, or is not a non-empty string otherwise (both directions, profile s5). |
| `MISSING_REQUIRED_ARTIFACT_CLASS` | `artifact_classes_covered` (`declared_reference_identity`, `capture_attempt_record`) or `artifact_classes_excluded` (`raw_captured_bytes`) omits a required class. |
| `MISSING_ATTESTATION_LIMIT` | `attestation_limits` does not carry the profile's verbatim base limitation statement. |
| `MISSING_LIMITATION_CODE:<code>` | Dynamic. A required `machine_limitations` entry is absent; the code carries the missing limitation code. Completion: `CONTENT_NOT_VERIFIED`. |

### Profile: `srs.editorial.source_ingest.v0.1`

Provisional source-ingest stage (arcs-srs `1f8768d`). Attests a deterministic derivation of exact captured source bytes under a pinned parser; it **references** a capture observation (`capture_observation_ref`) and never re-attests it. The verifier recomputes structure and the declared digests' internal consistency only — it does not re-run the parser and establishes no source truth, claim support, or admission. Expectation constants are transcribed from the byte-pinned manifest at `vendor/arcs-srs/vectors/editorial-source-ingest-v0.1/profile.manifest.json` and cross-checked by `tests/test_editorial_source_capture_v02_ingest_pins.py`. Reuses the shared uppercase codes `FIXED_VALUE_MISMATCH`, `PROFILE_VERSION_MISMATCH` (not `v0.1`), `INVALID_RECEIPT_KIND` (not `source_ingest`), `MISSING_PROFILE_FIELD`, `SUBJECT_BINDING_MISMATCH` (`subject_ref` != `source_artifact_id`, s3), `MISSING_REQUIRED_ARTIFACT_CLASS`, `MISSING_ATTESTATION_LIMIT`, and `MISSING_LIMITATION_CODE:<code>` (completions `SOURCE_TRUTH_NOT_EVALUATED`, `EVIDENCE_COMPLETENESS_NOT_EVALUATED`, `CLAIM_SUPPORT_NOT_EVALUATED`, `CONTENT_NOT_VERIFIED`), plus the following.

| Code | Meaning |
|---|---|
| `INVALID_SOURCE_ARTIFACT_ID` | `source_artifact_id` is present but not `sha256:` followed by 64 lowercase hex characters. |
| `PARSER_IDENTITY_INVALID` | `parser_identity` is absent or not a non-empty string. |
| `DERIVATION_INVALID` | `derivation` is absent or not an object. |
| `DERIVATION_INPUT_MISMATCH` | `derivation.input_hash` does not equal `source_artifact_id` (profile s7). |
| `PARSER_IDENTITY_MISMATCH` | `derivation.parser_id` does not equal `parser_identity` (profile s5/s7). |
| `EXTRACTION_REF_MISMATCH` | `extraction_ref` does not equal `derivation.output_hash` (profile s7). |
| `PDO_REF_DIGEST_INVALID` | `pdo_ref` is present but not a `sha256:`-followed-by-64-hex digest. |
| `PDO_MODULE_IDENTITY_INVALID` | `pdo_module_identity` is present but not an object carrying non-empty `module_id` and `module_version` strings. Historical identity is validated for shape only and never reconciled to the executing distribution (profile s5). |
| `INGEST_IMPLEMENTATION_INVALID` | The optional `ingest_implementation` is present but not an object carrying non-empty `distribution`, `version`, and `revision` strings. It is never derived from `pdo_module_identity` and MAY be omitted entirely (profile s6). |
| `CAPTURE_OBSERVATION_REF_INVALID` | `capture_observation_ref` is absent or not a non-empty reference string (profile s4). |
| `CAPTURE_OBSERVATION_RESTATED` | A capture-only field (`outcome`, `declared_url`, `captured_bytes_ref`, `capturer_identity`, `source_reference_id`) appears at top level, re-attesting capture, which s4 forbids. |

### Profile: `srs.activity.governed_read.v0.1`

Conformance is re-derived from the arcs-srs field schema (byte-pinned runtime
copy under `arcs_verify/data/`, provenance under `vendor/arcs-srs/`) plus the
subject-binding rule. Schema violations are mapped onto these named codes; the
four uppercase codes are the profile's frozen closed-set findings.

| Code | Meaning |
|---|---|
| `MISSING_PROFILE_FIELD` | A field the profile requires is absent (a top-level required field, or a disposition-required field such as `admitted_result_ref`/`refusal_class`). |
| `INVALID_VISIBILITY` | `visibility` is not in the mandatory C8 closed set (`LOCAL`, `PRIVATE_ORG`, `SHARED`, `PUBLIC_CANDIDATE`, `PUBLIC`). |
| `INVALID_DIGEST_FORMAT` | A `sha256:` reference field (`read_request_ref`, `basis_snapshot_digest`, `admitted_result_ref`, or a `produced_receipt_refs` element) is not `sha256:` followed by exactly 64 lowercase hex characters. |
| `AGGREGATE_FIELD_PRESENT` | A C6-forbidden aggregate/trust/reputation/standing field is present (e.g. `trust_score`, `reputation`, `activity_score`). |
| `governed_read.invalid_read_disposition` | `read_disposition` is not `admitted` or `refused`. |
| `governed_read.invalid_refusal_class` | `refusal_class` is present but not in the closed set (`POLICY_REFUSED`, `PRINCIPAL_NOT_PERMITTED`, `SCOPE_EXCEEDED`, `BASIS_UNAVAILABLE`, `DEFERRED_FOR_REVIEW`). |
| `governed_read.invalid_enum_value` | An enum-constrained field carries a value outside its closed set (fallback for enum fields other than visibility/refusal_class/read_disposition). |
| `governed_read.invalid_fixed_value` | A fixed-value field (`receipt_version`, `profile_id`, `profile_version`, `receipt_type`, `receipt_kind`, `boundary_type`, `identity_posture`) carries the wrong constant. |
| `governed_read.disposition_field_conflict` | The disposition-coherence rule is violated: an `admitted` receipt carries `refusal_class`, or a `refused` receipt carries `admitted_result_ref`. |
| `governed_read.missing_required_artifact_class` | `artifact_classes_covered` or `artifact_classes_excluded` omits a class the profile requires. |
| `governed_read.subject_binding_mismatch` | `subject_ref` is present but not equal to `basis_version_ref` (subject binding to the read basis). |
| `governed_read.field_schema_invalid` | The receipt fails the pinned field schema for a reason not covered by a more specific code above. |

### Profile: `srs.editorial.citation_pack.v0.1`

**PROVISIONAL** (arcs-srs `4d90b9c`, profile document `a78df524…`; `release_stage: provisional`, not ratified). A single `pack_assembly` provenance receipt for one editorial publication artifact. This is **single-receipt structural** verification only: it validates fixed identity, the FORM of the digest references, subject binding, required covered/excluded classes, required machine-limitation codes, and the base attestation limit. It does **not** recompute `publication_artifact_id` / `pack_integrity_ref` / `declaration_manifest_ref` from referenced bytes (the receipt is metadata-only and supplies no bytes or byte-count contract). **NON-ENFORCED** (no lexical rule / deterministic detector exists): the profile's cross-receipt consistency rule, its repository-snapshot-mixing rule, and the `protocol_binding` "MUST NOT embed file system paths or deployment credentials" rule — only non-empty/non-whitespace `protocol_binding` is checked. The checker is **fail-closed**: malformed field types yield deterministic failure codes, never exceptions. A structural PASS attests conformance to the provisional contract only — not admission, trust, truth, or correct citation mappings; the verifier records this in `details` as `provisional_profile: …`.

| Code | Meaning |
|---|---|
| `citation_pack.invalid_profile_id` | `profile_id` is not `srs.editorial.citation_pack`. |
| `citation_pack.invalid_profile_version` | `profile_version` is not `v0.1`. |
| `citation_pack.invalid_receipt_type` | `receipt_type` is not `provenance`. |
| `citation_pack.invalid_receipt_kind` | `receipt_kind` is not `pack_assembly`. |
| `citation_pack.invalid_boundary_type` | `boundary_type` is not `editorial_corpus_boundary`. |
| `citation_pack.invalid_protocol_binding` | `protocol_binding` is absent, not a string, or empty/whitespace. Only the non-empty rule is enforced; see the NON-ENFORCED note below for the path/credential prohibition. |
| `citation_pack.invalid_publication_artifact_id_digest` | `publication_artifact_id` is not a `sha256:<64 hex>` digest reference. |
| `citation_pack.invalid_pack_integrity_digest` | `pack_integrity_ref` is not a `sha256:<64 hex>` digest reference. |
| `citation_pack.invalid_declaration_manifest_digest` | `declaration_manifest_ref` is not a `sha256:<64 hex>` digest reference. |
| `citation_pack.invalid_capture_manifest_digest` | `capture_manifest_ref` is present and non-null but is not a `sha256:<64 hex>` digest reference. Presence itself is not required (SHOULD-level). |
| `citation_pack.subject_binding_mismatch` | `subject_ref` is not equal to `publication_artifact_id` (profile §2 binding). |
| `citation_pack.missing_required_covered_classes` | `artifact_classes_covered` omits a required class (`publication_artifact_identity`, `declaration_manifest_digest`, `pack_integrity_digest`). |
| `citation_pack.missing_required_excluded_classes` | `artifact_classes_excluded` omits a required exclusion (`raw_publication_bytes`, `raw_captured_bytes`). |
| `citation_pack.missing_required_limitation_code:<code>` | Dynamic. A required `machine_limitations` entry is absent; the code carries the missing limitation code. Completions: `ARTICLE_TRUTH_NOT_EVALUATED`, `EVIDENCE_COMPLETENESS_NOT_EVALUATED`, `CITATION_MAPPING_MACHINE_PROPOSED`. |
| `citation_pack.missing_base_attestation_limit` | `attestation_limits` does not carry the profile's required base limitation string. |

### Source-integrity errors (exit 2, not failure codes)

Unreadable or malformed inputs are reported before verification begins, as
`source_integrity_error: <kind>` on stderr (or a structured object under
`--json`) with exit 2. Kinds follow one Cartesian rule, `<role>_<condition>`,
over three roles (`receipt`, `keyring`, `schema`) and six conditions
(`not_found`, `not_a_file`, `not_utf8`, `unreadable`, `malformed_json`,
`not_an_object`), eighteen kinds in all. These are not verification verdicts
and never appear in `failure_codes`.

## `receipt-set` subcommand

Failures set the report's `manifest_integrity` Boolean false and surface as
findings with these codes (`manifest_integrity` is a report field, not a
code):

| Code | Meaning |
|---|---|
| `workflow_unreadable` | The workflow index file could not be read or parsed. |
| `workflow_shape_invalid` | The workflow index is not a well-formed refs/digests-only index. |
| `unsupported_workflow_schema` | The workflow index declares a schema this verifier does not support. |
| `trust_bundle_integrity_failed` | The enumerated trust bundle's bytes do not match the digest the index declares. |
| `receipt_entry_invalid` | An enumerated receipt entry is malformed or unreadable. |
| `receipt_integrity_failed` | An enumerated receipt's bytes do not match the digest the index declares. |
| `receipt_id_missing` | An enumerated receipt lacks its identifier. |
| `duplicate_receipt_id` | Two enumerated receipts carry the same identifier. |
| `admission_receipt_unresolved` | An outcome receipt references an admission receipt not present in the set. |
| `admission_outcome_linkage_mismatch` | The admission/outcome linkage does not hold across the set. |

## `deferred-sequence` subcommand

The sequence verifier reports conclusions (including a
`receipt_gap_disclosed` conclusion, which is a disclosure of whether any
receipt-gap receipt is present, not a failure code) and findings with these
codes:

| Code | Meaning |
|---|---|
| `sequence_empty_or_malformed` | The supplied sequence is empty or not a well-formed receipt sequence. |
| `individual_receipt_invalid` | A receipt in the sequence fails individual profile verification. |
| `receipt_missing_receipt_id` | A receipt in the sequence lacks its identifier. |
| `duplicate_receipt_id` | Two receipts in the sequence carry the same identifier. |
| `missing_operation_digest` | A receipt lacks the operation digest the sequence check requires. |
| `no_defer_request` | The sequence contains no defer-request receipt. |
| `sequence_id_discontinuity` | Receipts in the sequence do not share a continuous sequence identity. |
| `missing_predecessor_receipt_ref` | A receipt lacks its required predecessor reference. |
| `predecessor_ref_mismatch` | A predecessor reference does not match the actual predecessor. |
| `missing_defer_receipt_ref` | A receipt lacks its required reference to the defer-request receipt. |
| `defer_receipt_ref_mismatch` | A defer-request reference does not match the sequence's defer-request receipt. |
| `condition_response_absent` | A required condition response is absent from the sequence. |
| `missing_condition_receipt_ref` | A receipt lacks its required reference to the condition-response receipt. |
| `condition_receipt_ref_mismatch` | A condition-response reference does not match the sequence's condition-response receipt. |
| `expired_condition_followed_by_reevaluation` | A reevaluation follows an expired condition where the sequence rules forbid it. |
| `no_terminal_admission` | The sequence reaches no terminal admission. |
| `terminal_admission_invalid_disposition` | The terminal admission carries a disposition outside the allowed set. |
| `execution_outcome_missing_terminal_admission_ref` | An execution outcome lacks its reference to the terminal admission. |
| `execution_outcome_terminal_ref_unresolved` | An execution outcome references a terminal admission not present in the sequence. |
| `execution_outcome_after_refused_terminal` | An execution outcome follows a refused terminal admission. |

## `amnesiac-chain` subcommand

The chain profile reports conclusions rather than Boolean results. Failures
surface as findings whose codes name the artifact and property that failed to
recompute:

`malformed_bundle`, `malformed_artifact`, `missing_required_artifact`,
`unsupported_schema`, `unsupported_receipt_schema`,
`unsupported_operation_kind`, `substrate_hash_mismatch`,
`claim_node_hash_mismatch`, `claim_edge_hash_mismatch`,
`duplicate_claim_id`, `duplicate_edge_id`, `edge_endpoint_missing`,
`graph_node_order_mismatch`, `graph_edge_order_mismatch`,
`graph_drift_from_binding`, `binding_hash_mismatch`,
`binding_node_missing`, `binding_not_admitted`,
`packet_hash_mismatch`, `packet_duplicate_claim_id`,
`packet_binding_shape_mismatch`, `walk_hash_mismatch`,
`walk_packet_mismatch`, `select_claim_not_available`,
`quote_without_select`, `quote_without_binding`,
`quote_binding_hash_mismatch`, `quote_content_differs_from_binding`,
`quote_forbidden_by_permission`, `refuse_without_reason`,
`template_outside_lock`, `render_hash_mismatch`,
`render_reference_mismatch`, `render_replay_failed`,
`render_replay_mismatch`, `inspection_hash_mismatch`,
`inspection_reproduction_mismatch`, `unsupported_inspection_schema`,
`unsupported_inspection_mode`, `source_capture_hash_mismatch`,
`receipt_hash_mismatch`,
`receipt_artifact_hash_mismatch`, `receipt_subject_mismatch`,
`receipt_packet_ref_mismatch`, `receipt_walk_ref_mismatch`,
`manifest_source_refs_mismatch`, `manifest_anchor_refs_mismatch`.

The cross-stage public-proof lane of the same subcommand additionally emits:

`malformed_proof_bundle`, `unsupported_proof_bundle_schema`,
`missing_proofcase_id`, `missing_initial_stage`, `missing_revised_stage`,
`missing_reopening_block`, `missing_stale_inspection_block`,
`packet_id_proofcase_mismatch`, `query_ref_mismatch`,
`query_text_hash_mismatch`, `scope_mismatch`, `source_ref_mismatch`,
`source_identity_malformed`, `transition_malformed`,
`reopening_request_ref_mismatch`, `reopening_candidate_ref_mismatch`,
`candidate_not_in_initial_rejected_refs`,
`candidate_not_reconsiderable_in_initial`,
`candidate_not_admitted_in_revised`, `candidate_still_rejected_in_revised`,
`admitted_claim_absent_from_revised_graph`,
`admitted_claim_absent_from_revised_packet`,
`stale_inspection_mismatch`, `stale_inspection_not_genuinely_stale`,
`stale_inspection_reproduction_failed`, `cross_stage_unevaluable`.

The reserved conclusions `authenticity_verified` and `signature_verified` are
always `not_evaluated` and never produce failure codes; see the README's
Reserved conclusions section.

## `governed-memory-sequence` subcommand

Emitted by `arcs_verify/governed_memory_sequence.py` when recomputing a governed
memory-read sequence bundle. All codes are static; there are no dynamic families.

| Code | Meaning |
|---|---|
| `bundle_not_a_dict` | The bundle is not a JSON object. |
| `memory_read_request_absent` | `bundle.memory_read_request` is missing or not a JSON object. |
| `authorization_decision_absent` | `bundle.authorization_decision` is missing or not a JSON object. |
| `context_packet_absent` | `bundle.context_packet` is missing or not a JSON object. |
| `request_missing_request_id` | `memory_read_request.request_id` is absent or empty. |
| `request_missing_subject_ref` | `memory_read_request.subject_ref` is absent or empty. |
| `decision_missing_decision_id` | `authorization_decision.decision_id` is absent or empty. |
| `decision_missing_disposition` | `authorization_decision.disposition` is absent or empty. |
| `decision_missing_request_ref` | `authorization_decision` has no `request_ref` linking it to the request. |
| `decision_request_ref_mismatch` | `authorization_decision.request_ref` does not match `memory_read_request.request_id`. |
| `decision_packet_hash_malformed` | `authorization_decision.packet_hash` is present but not a non-empty string. |
| `packet_missing_packet_id` | `context_packet.packet_id` is absent or empty. |
| `packet_missing_packet_hash` | `context_packet.packet_hash` is absent or empty. |
| `packet_missing_decision_ref` | `context_packet` has no `decision_ref` linking it to the decision. |
| `packet_decision_ref_mismatch` | `context_packet.decision_ref` does not match `authorization_decision.decision_id`. |
| `packet_digest_mismatch` | `authorization_decision.packet_hash` does not match `context_packet.packet_hash`. |
| `subject_ref_absent` | No non-empty `subject_ref` is present across request, decision, or packet. |
| `subject_ref_discontinuity` | `subject_ref` is not consistent across request, decision, and packet. |
| `scope_ref_discontinuity` | `scope_ref` is not continuous across the sequence. |
| `reopening_ref_unresolved` | `context_packet.reopening_ref` does not resolve to a known `artifact_id` in the sequence. |
| `duplicate_artifact_id` | An `artifact_id` appears more than once in the sequence. |
| `source_descriptors_malformed` | `bundle.source_descriptors` is present but not a list. |
| `source_descriptor_refs_unresolved` | A source-descriptor reference does not resolve to a known artifact. |
| `exclusion_declarations_malformed` | `bundle.exclusion_declarations` is present but not a list. |
| `exclusion_declarations_incomplete` | Required raw-content exclusion declarations are absent or incomplete. |
| `raw_content_posture_violation` | A raw-content field appears where only hash references are permitted. |

## `ingest-run-sequence` subcommand

Emitted by `arcs_verify/ingest_run_sequence.py` when recomputing a
dagr.ingest_run.v0.1 editorial ingest sequence from serialized artifacts: the
neutral run document, the producer-owned receipt-set manifest
(`dagr-ingest.srs-receipt-set-manifest.v0.1`), and the individual SRS receipts.
Coverage is recomputed over `run_doc["file_occurrences"]` and the manifest's
`emitted_receipts` / `skipped_duplicate` / `skipped_no_parser` /
`profile_not_applicable` categories — the real producer contract, not a
verifier-invented shape. All codes are static; there are no dynamic families.

| Code | Meaning |
|---|---|
| `INGEST_RUN_SCHEMA_MISMATCH` | `run_doc["schema"]` is not `"dagr.ingest_run.v0.1"`, or the file is unreadable or malformed. |
| `INGEST_RUN_BOUNDARY_VIOLATION` | A required `run_doc["boundary"]` declaration (`no_arcs_srs`, `no_receipts_issued`, `no_network`) is absent or not `True`. |
| `RECEIPT_SET_MANIFEST_SCHEMA_MISMATCH` | `manifest["schema"]` is not `"dagr-ingest.srs-receipt-set-manifest.v0.1"`, the file is unreadable or malformed, or the required `emitted_receipts` array is absent. |
| `RUN_ID_MISMATCH` | `manifest["run_id"]` does not match `run_doc["run_id"]`. |
| `PROFILE_MANIFEST_PIN_MISMATCH` | The independently recomputed sha256 of the supplied profile manifest file does not match `manifest["profile_manifest_sha256"]` (pin integrity). |
| `PROFILE_MANIFEST_AUTHORITY_MISMATCH` | `manifest["profile_manifest_sha256"]` is not the pinned arcs-srs production `srs.editorial.publication_ingest.v0.1` profile-manifest digest. A self-consistent manifest that pins a non-production (e.g. test-only) profile manifest fails here. |
| `RECEIPT_FILE_MISSING` | No `<receipt_id>.json` file exists under the supplied receipts directory for an emitted manifest entry (`output_path` is never trusted as authority). |
| `RECEIPT_PARSE_ERROR` | A receipt file could not be read or is not valid JSON. |
| `PROTOCOL_BINDING_MISMATCH` | A receipt's `protocol_binding` is not `"dagr-ingest/v0.1"`. |
| `RECEIPT_ID_MISMATCH` | The resolved receipt's `receipt_id` does not match the manifest entry's `receipt_id`. |
| `SUBJECT_REF_MANIFEST_MISMATCH` | A receipt's `subject_ref` does not match the `subject_ref` in the manifest entry. |
| `SUBJECT_BINDING_MISMATCH` | A receipt's `subject_ref` is not equal to `publication_artifact_id`. |
| `REL_PATH_MISMATCH` | A receipt's `relative_path` does not match the manifest entry's `rel_path`. |
| `CORPUS_MANIFEST_REF_MISMATCH` | A receipt's `corpus_manifest_ref` is not `"sha256:" + run_doc["run_id"]`. |
| `RAW_CONTENT_PRESENT` | A receipt contains a forbidden raw-content field (`raw_publication_bytes`, `raw_frontmatter_yaml`, or `raw_body_text`). |
| `MISSING_REQUIRED_EXCLUSION` | A receipt's `artifact_classes_excluded` does not contain all three required exclusions (`raw_publication_bytes`, `raw_frontmatter_yaml`, `raw_body_text`). |
| `OCCURRENCE_NOT_ACCOUNTED` | A `run_doc["file_occurrences"]` entry (keyed by `rel_path`) appears in no manifest category, or lacks a usable `rel_path`. |
| `SKIP_CATEGORY_MALFORMED` | A manifest skip category (`skipped_duplicate`, `skipped_no_parser`, `profile_not_applicable`) is absent or not a list of strings, or a file occurrence appears in more than one category. |
| `DUPLICATE_POSTURE_VIOLATION` | A file occurrence with `is_duplicate_content == True` appears as emitted in the manifest. |
| `NULL_PARSER_POSTURE_VIOLATION` | A file occurrence with a null `parser_id` appears as emitted in the manifest. |

## Stability

Codes are append-only in intent: existing codes keep their meaning, and new
constraints add new codes. Alert on exact string match, or on the documented
prefix for dynamic families. The presence of a code in this registry does not
imply every profile can emit it; each code is scoped to the subcommand and
profile family under which it is listed. `tests/test_failure_code_registry.py`
enforces that every emitted code and family appears here.

## Analytics snapshot verification (analytics-snapshot subcommand)

Independent recount of DAGR Analytics C1 snapshots (`arcs_verify/analytics_snapshot.py`).
Upstream C1 (#2) and RET1 (#5) contracts are PROVISIONAL / unmerged. `NOT_EVALUATED`
is not PASS; retention conformance is reported as an axis independent of metric integrity.

- `analytics_snapshot.observation_profile_invalid` — a supplied observation does not validate the vendored C1_transport_read profile (wrong platform/privacy_class/action-transport pair/event_id grammar/context domain/extra fields); recount is not performed on invalid inputs.
- `analytics_snapshot.derivation_version_mismatch` — snapshot/definition derivation_version is not the pinned C1 expected derivation version (0.1.0).
- `analytics_snapshot.snapshot_shape_invalid` — snapshot is missing required body/identity fields.
- `analytics_snapshot.unsupported_metric_profile` — metric_id/metric_version is not a supported C1 v0.1 metric.
- `analytics_snapshot.metric_identity_mismatch` — supplied definition's metric_id/version disagrees with the snapshot.
- `analytics_snapshot.metric_definition_digest_mismatch` — recomputed metric definition digest != snapshot.metric_definition_digest.
- `analytics_snapshot.metric_definition_pin_mismatch` — definition digest is not the pinned C1 candidate definition for that metric/version (a self-consistent invented definition is not C1 conformance).
- `analytics_snapshot.partition_shape_invalid` — supplied partition lacks observations/window fields.
- `analytics_snapshot.duplicate_event_id` — a duplicate event_id makes the partition invalid; no value is recounted.
- `analytics_snapshot.window_mismatch` — partition window_start/window_end do not bind to the snapshot's.
- `analytics_snapshot.input_partition_digest_mismatch` — recomputed input_partition_digest != snapshot's.
- `analytics_snapshot.value_mismatch` — independently recounted value != snapshot.value.
- `analytics_snapshot.snapshot_digest_mismatch` — recomputed snapshot_digest != snapshot's.
- `analytics_snapshot.privacy_class_mismatch` — snapshot privacy_class is not ANONYMOUS_AGGREGATE.
- `analytics_snapshot.canonicalization_failed` — a value lies outside the C1 v0.1 canonical domain (non-integer number, non-ASCII key).
- `analytics_snapshot.retention_nonconforming` — supplied source is past its retention deadline (still recountable, but overdue).
- `analytics_snapshot.retention_schedule_invalid` — the supplied retention schedule is not a valid RET1 schedule shape.
- `analytics_snapshot.retention_schedule_pin_mismatch` — the supplied retention schedule is not the pinned RET1 candidate schedule.
- `analytics_snapshot.source_status_contradiction` — a declared source status is internally inconsistent (e.g. absent-expired before the retention deadline).

Missing/unreadable/malformed CLI input remains a source-integrity/usage posture (exit 2), not a verification verdict.

## Acquisition grounded-proposal verification (acquisition-grounding subcommand)

Independent verification of counterpedia-acquisition grounded content proposals
(`arcs_verify/acquisition_grounding.py`) against the exact captured source bytes.
Pinned to counterpedia-acquisition commit `d4b1127d84816cc8279fc2ea0b16358006b37745`
(grounded-proposal schema `acquisition.grounded_content_proposal.v0.1`, extraction
profile `acquisition.html-visible-text.v0.1`). The verifier recomputes from bytes
only and imports zero producer code. Three axes are reported SEPARATELY —
`artifact_integrity`, `grounding_integrity`, `proposal_posture` — with no master
trust score. A PASS attests binding of the proposal to its evidence, NOT that the
source is true or that the proposal is admitted. `NOT_EVALUATED` is not PASS.

Codes are grouped by the axis they trip.

### artifact_integrity

| Code | Meaning |
|---|---|
| `acquisition_grounding.artifact_digest_malformed` | `artifact_digest` is not a `sha256:<64 lowercase hex>` reference. |
| `acquisition_grounding.artifact_digest_mismatch` | The independently recomputed sha256 of the supplied source bytes does not equal the envelope's `artifact_digest`. |

### grounding_integrity

| Code | Meaning |
|---|---|
| `acquisition_grounding.schema_digest_mismatch` | The vendored grounded-proposal schema bytes do not hash to the pinned sha256 (verifier-integrity, fail-closed). |
| `acquisition_grounding.schema_version_mismatch` | `schema_version` is not `acquisition.grounded_content_proposal.v0.1`. |
| `acquisition_grounding.envelope_schema_invalid` | The envelope does not validate against the pinned grounded-proposal JSON schema. |
| `acquisition_grounding.extraction_profile_unknown` | The envelope's `extraction_profile` is not the pinned `acquisition.html-visible-text.v0.1`. |
| `acquisition_grounding.field_grounding_binding_invalid` | `field_grounding` does not bind one-to-one to `content_proposal.fields` (count mismatch, or `field_index` values are not exactly `0..n-1`). |
| `acquisition_grounding.grounding_kind_invalid` | A `field_grounding` entry's `grounding_kind` is outside the closed set (`extractive`, `abstractive`). |
| `acquisition_grounding.extractive_anchor_missing` | An extractive field grounding carries no `verified_anchor` object. |
| `acquisition_grounding.anchor_extraction_profile_unknown` | A `verified_anchor` names an `extraction_profile` other than the pinned profile. |
| `acquisition_grounding.anchor_artifact_digest_mismatch` | A `verified_anchor.artifact_digest` does not equal the envelope's captured-source `artifact_digest` (a model-supplied anchor may not re-point identity). |
| `acquisition_grounding.anchor_span_out_of_range` | An extractive anchor's `start`/`end` are not integers, are negative, are inverted, or fall outside the recomputed projection length. |
| `acquisition_grounding.anchor_span_text_mismatch` | The independently recomputed projection slice `[start:end]`, normalized, does not exactly equal the proposed field text, normalized. No fuzzy / semantic / substring rescue; text that is real elsewhere is not rescued. |
| `acquisition_grounding.abstractive_carries_anchor` | An abstractive (synthesis) field grounding carries a `verified_anchor`; synthesis is never treated as exact-span grounded. |
| `acquisition_grounding.dropped_disposition_malformed` | A `dropped_ungrounded` entry is malformed: bad `field_name`, `grounding_kind` outside the closed set, `reason` outside the closed drop-reason vocabulary, malformed `claimed_span`, or non-`sha256:` `proposed_value_sha256`; or `dropped_ungrounded` is present but not a list. |

### proposal_posture

| Code | Meaning |
|---|---|
| `acquisition_grounding.lifecycle_not_proposal` | The record is not proposal-only: `content_proposal.lifecycle_state` is not `proposal`, or an `is_proposal` flag (envelope or proposal) is not `true`. |
| `acquisition_grounding.authority_field_present` | A forbidden authority field (`admitted`, `refused`, `standing`, `canonical_id`, `trace_id`, `srs_verified`, `counterpedia_id`) is present anywhere in the envelope. Instruction-like text inside the captured source bytes has no authority effect and never trips this. |

Missing/unreadable/malformed CLI input (envelope or source) remains a source-integrity/usage posture (exit 2), not a verification verdict.

## C2PA native finding contract conformance (c2pa-native subcommand)

Contract-conformance findings emitted by `check_report()` in
`arcs_verify/c2pa_native.py` over a `arcs.c2pa_native_finding.report.v0.1`
report. Contract bundle: `arcs_verify/contracts/c2pa-native-finding/v0.1/`;
native validator pinned to `c2patool` 0.27.15 (crates.io,
`cargo install c2patool --version 0.27.15 --locked`).

These findings are about the **report's** conformance to the contract. They are
NOT C2PA validation verdicts, and they are NOT SRS receipt verification: native
C2PA validity, SRS envelope validity, and SRS signature validity are independent
axes, and a conformant report may describe a C2PA subject that failed every
native axis.

Per-axis native results (`satisfied` / `failed` / `indeterminate` /
`not_evaluated` / `not_applicable`) and per-axis comparison states are report
content, not failure codes. There is deliberately no aggregate match Boolean and
no master verdict.

### Structure

| Code | Meaning |
|---|---|
| `C2PA_SCHEMA` | The report does not validate against the pinned bundle schemas, or `jsonschema` was unavailable so structural validation was not performed (fail-closed). |
| `C2PA_RECOMPUTATION_REQUIRED` | `recomputed` is absent. An independent recomputation is mandatory; a report carrying only an observation is not a verification. |
| `C2PA_SIDE_LABEL` | A side is not labelled with its own role (`recomputed` / `observed`). |
| `C2PA_AGGREGATE_FORBIDDEN` | The report carries a prohibited aggregate key (for example `native_observation_matches_recomputation`). The contract reports separate axes; doctrine §13 prohibits `verified` without an axis. |

### Comparison presence

| Code | Meaning |
|---|---|
| `C2PA_COMPARISON_MISSING` | `observed` is present but `comparison` is absent. |
| `C2PA_COMPARISON_UNGROUNDED` | `comparison` is present without `observed`. A comparison with nothing to compare against must be ABSENT, never synthesized as an array of `not_evaluated` entries. |
| `C2PA_COMPARABILITY_COUPLING` | `comparability` is not present exactly when `observed` is present. |

### Axis coverage

| Code | Meaning |
|---|---|
| `C2PA_AXIS_DUPLICATE` | An axis appears more than once in a side or in the comparison array. |
| `C2PA_AXIS_COVERAGE` | A canonical axis is missing. Every axis is represented explicitly; omission is not a permitted way to say `not_evaluated`. |
| `C2PA_AXIS_UNKNOWN` | An axis outside the canonical set appears. |

### Comparison semantics

| Code | Meaning |
|---|---|
| `C2PA_COMPARISON_STATE` | The comparison state is not one of `match` / `mismatch` / `not_comparable` / `not_evaluated`. |
| `C2PA_REASON_ILLEGAL_FOR_STATE` | The `comparison_reason` is not legal for the declared state under the bundle's reason/posture matrix. |
| `C2PA_POSTURE_ILLEGAL_FOR_REASON` | The `integrity_posture` is not the one the matrix requires for that state and reason. Causal explanation and integrity inference are separate questions and the mapping between them is fixed. |
| `C2PA_STATUS_NOT_GROUNDED` | A comparison entry's declared `observed_status` or `recomputed_status` does not match the status actually recorded on that side. |
| `C2PA_MATCH_WITHOUT_EQUALITY` | State `match` declared while the two sides recorded different statuses. |
| `C2PA_MISMATCH_WITHOUT_DIFFERENCE` | State `mismatch` declared while the two sides recorded the same status. |
| `C2PA_COMPARABILITY_NOT_RECOMPUTED` | The declared comparability predicates do not match the values recomputed from the two sides' own recorded inputs. Comparability is a recomputed fact, not an emitter assertion. |

### Integrity-inference discipline

| Code | Meaning |
|---|---|
| `C2PA_INTEGRITY_ON_NONDETERMINISTIC_AXIS` | `possible_substantive_divergence` claimed on an axis that is not `byte_deterministic`. A divergence explainable by wall-clock passage, policy basis, or an unfreezable external resource is not an integrity inference. |
| `C2PA_INTEGRITY_WITHOUT_COMPARABLE_BASIS` | `possible_substantive_divergence` claimed while a comparability predicate is false. |

### Hermeticity and evaluation posture

| Code | Meaning |
|---|---|
| `C2PA_HERMETICITY` | A required hermetic setting was not applied: `remote_manifest_fetch` or `ocsp_fetch` not false, `allowed_network_hosts` not empty, or a hermeticity fact not false. |
| `C2PA_CLOCK_SOURCE` | `validation_clock.source` is not `wall_clock`. |
| `C2PA_CLOCK_PINNABLE` | `validation_clock.caller_pinnable` is not false. The pinned validator exposes no validation-clock control; hermetic execution bounds network access, not time. |
| `C2PA_REVOCATION_IMPLIED` | The revocation axis carries a status other than `not_evaluated`. Revocation is reachable only via network OCSP, captured responses cannot be injected for offline replay, and silence is not evidence of non-revocation. |
| `C2PA_UNAVAILABLE_AS_FAILURE` | The side reports an unavailable or errored evaluation while an axis reports something other than `not_evaluated` / `not_applicable`. An unavailable input is not a validation failure. |
| `C2PA_UNAVAILABLE_WITH_STATE` | A native `validation_state` is recorded although no evaluation occurred. |

Missing/unreadable/malformed CLI input, and an absent or version-mismatched
native validator, remain a usage posture (exit 2), not a verification verdict.

## Counterplayer study verification (`counterplayer-study` subcommand)

| Code | Meaning |
|---|---|
| `bundle_invalid` | The study bundle is absent or is not a well-formed JSON object. |
| `producer_pin_mismatch` | The counterplayer repository or commit pin in the bundle does not match the verifier's pinned value. |
| `manifest_invalid` | `StudyArtifactManifest` is missing or has a field-set mismatch. |
| `manifest_shape_invalid` | `StudyArtifactManifest` schema or digest field shape is invalid. |
| `manifest_identity_mismatch` | The manifest identity (schema + ref) does not match the declared identity. |
| `manifest_digest_mismatch` | The recomputed manifest digest does not match the declared value. |
| `manifest_canonicalization_failed` | Manifest canonicalization failed during digest recomputation. |
| `impact_invalid` | The study impact document is absent or is not a well-formed JSON object. |
| `impact_artifact_mismatch` | The impact artifact reference does not match the manifest. |
| `impact_digest_mismatch` | The recomputed impact digest does not match the declared value. |
| `impact_canonicalization_failed` | Impact document canonicalization failed during digest recomputation. |
| `recall_invalid` | The recall document is absent or is not a well-formed JSON object. |
| `recall_refs_invalid` | The recall document's reference set is invalid or inconsistent. |
| `recall_artifact_mismatch` | The recall artifact reference does not match the manifest. |
| `recall_digest_mismatch` | The recomputed recall digest does not match the declared value. |
| `recall_canonicalization_failed` | Recall document canonicalization failed during digest recomputation. |

## CG execution-packet digest-binding verification (`cg-replay` subcommand)

The `arcs_verify/cg_execution_replay.py` and `arcs_verify/cg_replay.py` modules
verify digest bindings in `countergraph.execution-packet/v0.1` packets.
Both modules use `_fail(code, detail)` with code at argument index 0; the
failure code registry structural sweep (HELPER_CODE_ARG = 1) does not extract
their codes via AST, so codes are listed here as a manual registry entry.

`arcs_verify/cg_execution_replay.py` (nested-schema packet form):

| Code | Meaning |
|---|---|
| `invalid_packet` | The packet is not a well-formed dict. |
| `wrong_packet_schema` | `schema` field is absent or does not match `countergraph.execution-packet/v0.1`. |
| `unsupported_packet_kind` | `packet_kind` is not `query_execution`; only query executions are supported. |
| `invalid_packet_digest` | `packet_digest` is absent or not a well-formed sha256 digest. |
| `packet_digest_error` | Packet digest recomputation raised an exception. |
| `missing_root_execution` | `root_execution` is absent or not a dict. |
| `wrong_execution_schema` | `root_execution.schema` does not match `countergraph.query-execution/v0.1`. |

`arcs_verify/cg_replay.py` (flat-schema packet form, CG-REPLAY0 Lane 4):

| Code | Meaning |
|---|---|
| `invalid_packet` | The packet is not a well-formed dict. |
| `wrong_packet_schema` | `schema` field is absent or does not match `countergraph.execution-packet/v0.1`. |
| `missing_query` | `query` field is absent or not a dict. |
| `invalid_query_digest` | `query_digest` is absent or not a well-formed sha256 digest. |
| `query_digest_error` | Query digest recomputation raised an exception. |
| `missing_result` | `result` field is absent or not a dict. |
| `invalid_result_digest` | `result_digest` is absent or not a well-formed sha256 digest. |
| `result_digest_error` | Result digest recomputation raised an exception. |
| `invalid_execution_digest` | `execution_digest` is absent or not a well-formed sha256 digest. |
| `execution_digest_error` | Execution digest recomputation raised an exception. |
| `invalid_execution_packet_digest` | `execution_packet_digest` is absent or not a well-formed sha256 digest. |
| `execution_packet_digest_error` | Execution packet digest recomputation raised an exception. |

## Profile: `srs.activity.admission_event.v0.1` (`arcs_verify/admission_event.py`)

| Code | Meaning |
|---|---|
| `envelope.schema_unreadable` | The pinned SRS envelope schema file could not be read from disk. |
| `admission_event.subject_binding_mismatch` | The receipt's subject reference and subject-edition reference are not the same logical subject as required by the profile. |
| `admission_event.extensions_not_object` | `extensions` is present but is not a JSON object. |
| `admission_event.aggregate_field_present` | An authority-shaped aggregate/verdict field is present at the root; the profile forbids it. |
| `admission_event.invalid_visibility` | The declared visibility value is not one the profile admits. |
| `admission_event.invalid_standing_act` | A declared standing-act entry is not a valid, known standing-act shape. |
| `admission_event.invalid_basis_refs` | The `basis_refs` collection is absent or malformed. |
| `admission_event.missing_content_not_verified` | A required `content_not_verified` disclosure is absent. |
| `admission_event.missing_required_covered_classes` | The receipt does not cover the artifact classes the profile requires as covered. |
| `admission_event.missing_required_excluded_classes` | The receipt does not exclude the artifact classes the profile requires as excluded. |
| `attestation.missing_required_limit` | A profile-required attestation limit string is absent from `attestation_limits`. |
| `admission_event.invalid_<field>` | Dynamic. A fixed-value field carries the wrong value; the code names the field. |
| `admission_event.invalid_digest:<field>` | Dynamic. A field required to be a `sha256:` digest is not well-formed; the code names the field. |
| `admission_event.invalid_text:<field>` | Dynamic. A field required to be a non-empty text value is not; the code names the field. |

Shared schema/signature/trust/raw-content codes (`schema.digest_mismatch`, `envelope.schema_invalid`, `signature_object_invalid`, `signature_invalid`, `key_id_unresolved`, `key_untrusted`, `preimage_canonicalization_failed`, `signature_encoding_invalid`, `public_key_encoding_invalid`, `raw_content.*`) are documented in the Signed-SRS verification tables above and emitted here with the same meaning.

## Profile: `srs.activity.admission_event.v0.2` (`arcs_verify/admission_event_v0_2.py`)

Independently verifies the v0.2 supersession bindings against the exact vendored `srs.activity.admission_event.v0.2` schema bytes (git-blob-SHA1 pinned) and the recursive authority membrane.

| Code | Meaning |
|---|---|
| `profile_schema.source_blob_mismatch` | The vendored v0.2 profile-schema file's git blob SHA-1 does not match the pinned `PROFILE_SOURCE_BLOB_SHA1`; the schema bytes are not the pinned #53 source. |
| `profile_schema.unreadable` | The vendored v0.2 profile-schema file could not be read from disk. |
| `profile_schema.invalid` | The vendored v0.2 profile-schema file is not well-formed JSON Schema. |
| `admission_event_v02.profile_schema_invalid` | The receipt does not validate against the vendored v0.2 profile schema. One code per schema error; details carry validator messages. |
| `admission_event_v02.subject_binding_mismatch` | The receipt's subject and subject-edition references are not the same logical subject. |
| `admission_event_v02.supersession_extension_missing` | The mandatory `extensions.supersession` block is absent. |
| `admission_event_v02.supersession_same_event` | Predecessor and successor name the same governed event; a supersession must replace a distinct event. |
| `admission_event_v02.supersession_same_edition` | Predecessor and successor name the same subject edition; a supersession must replace a distinct edition. |
| `admission_event_v02.supersession_cross_record` | `successor_subject_record_ref` does not equal `subject_record_ref`; a supersession must stay within the same logical record. |
| `admission_event_v02.predecessor_ref_not_in_basis` | The predecessor event reference is not present in the signed `basis_refs`. |
| `admission_event_v02.successor_ref_not_in_basis` | The successor event reference is not present in the signed `basis_refs`. |
| `admission_event_v02.semantic_owner_binding_ref_not_in_basis` | The Counterpedia semantic-owner binding reference is not present in the signed `basis_refs`. |
| `verified_receipt_canonicalization_failed` | The verified receipt could not be serialized to its RFC 8785 canonical form for identity capture. |
| `authority_field.forbidden:<key>` | Dynamic. An authority-shaped key (e.g. `truth`, `verified`, `authority_effect`, `standing_score`, `reliance_score`, `reputation_score`, `trust_score`) is present anywhere in the signed receipt — checked recursively at the root and inside any nested object or list. |

Shared schema/signature/trust codes (`schema.digest_mismatch`, `envelope.schema_invalid`, `envelope.schema_unreadable`, `signature_object_invalid`, `signature_invalid`, `key_id_unresolved`, `key_untrusted`, `preimage_canonicalization_failed`, `signature_encoding_invalid`, `public_key_encoding_invalid`, `attestation.missing_required_limit`) are documented above and emitted here with the same meaning.

## Profile: `srs.activity.admission_event.v0.3` (`arcs_verify/admission_event_v0_3.py`)

Additive successor to v0.2 (READMISSION-CONTENT-DIVERGENCE0 Lane 5). Independently verifies the vendored `srs.activity.admission_event.v0.3` schema bytes (git-blob-SHA1 pinned to the live arcs-srs PR #54 head) and reuses the v0.2 module's supersession-binding, authority-membrane, and signature/trust logic unchanged. It additionally computes `content_digest_comparison` (`DIVERGED` / `MATCH` / `NOT_EVALUATED`) and `content_digest_comparison_reason` (`CONTENT_DIGEST_ABSENT` / `CONTENT_DIGEST_MALFORMED` / `CONTENT_DIGEST_PROVENANCE_ABSENT` / `CONTENT_DIGEST_PROVENANCE_INVALID` / `null`) by independent literal-string comparison of the OPTIONAL, promoted `extensions.supersession.predecessor_captured_bytes_digest` / `successor_captured_bytes_digest` fields.

Structural-absence discipline: a digest (or `*_captured_bytes_digest_source`) key that is genuinely *missing* is `CONTENT_DIGEST_ABSENT` / `CONTENT_DIGEST_PROVENANCE_ABSENT`. A key that is *present* but wrong-typed, null, empty, or ill-shaped is never conflated with absence — it is `CONTENT_DIGEST_MALFORMED` (digest side; independent regex `^sha256:[0-9a-f]{64}$`) or `CONTENT_DIGEST_PROVENANCE_INVALID` (source side; independently recognizes only the literal enum values `HISTORICAL_CAPTURE_RECORD` / `LIVE_CAPTURE`). `DIVERGED`/`MATCH` are gated on all four of: both digests present + well-formed, both sources present + a recognized enum value — checked in priority order digest-absent → digest-malformed → source-absent → source-invalid → literal comparison. The gate is never affected by `*_bytes_currently_retrievable` — a digest pair whose bytes are no longer retrievable still resolves to `DIVERGED`/`MATCH` once both digests and both sources are present and valid. This comparison is a disclosed structural fact, never a verdict, and never participates in `passed`.

| Code | Meaning |
|---|---|
| `admission_event_v03.profile_schema_invalid` | The receipt does not validate against the vendored v0.3 profile schema. One code per schema error; details carry validator messages. |

Reused v0.2 supersession-binding codes (`admission_event_v02.subject_binding_mismatch`, `admission_event_v02.supersession_extension_missing`, `admission_event_v02.supersession_same_event`, `admission_event_v02.supersession_same_edition`, `admission_event_v02.supersession_cross_record`, `admission_event_v02.predecessor_ref_not_in_basis`, `admission_event_v02.successor_ref_not_in_basis`, `admission_event_v02.semantic_owner_binding_ref_not_in_basis`), the recursive authority-membrane code (`authority_field.forbidden:<key>`), and shared schema/signature/trust codes (`profile_schema.source_blob_mismatch`, `profile_schema.unreadable`, `profile_schema.invalid`, `schema.digest_mismatch`, `envelope.schema_invalid`, `envelope.schema_unreadable`, `signature_object_invalid`, `signature_invalid`, `key_id_unresolved`, `key_untrusted`, `preimage_canonicalization_failed`, `signature_encoding_invalid`, `public_key_encoding_invalid`, `attestation.missing_required_limit`) are documented above under v0.1/v0.2 and emitted here with the same meaning; the v0.3 module calls the v0.2 module's supersession/authority-error functions directly rather than redefining them.

`content_digest_comparison` and `content_digest_comparison_reason` are disclosed structural-fact outputs, not failure codes: an absent digest, a malformed digest, a missing per-side `digest_source`, or an unrecognized `digest_source` value never fails the receipt, it only leaves the comparison `NOT_EVALUATED`.
## OKF Attested Computation verifier-side bindings (`okf-attested-computation` subcommand)

`arcs_verify/okf_attested_computation.py` (OKF-ARCS-BRIDGE0) independently
binds an OKF v0.2 "Attested Computation" declaration to its referenced
executor/attester resources and to separately supplied run evidence. It never
executes any referenced resource and never fetches over the network. Static
codes plus dynamic families keyed by `role` (`executor` | `attester`) or by
the declared receipt field name.

| Code | Meaning |
|---|---|
| `okf_attested_computation.declaration_malformed` | The declaration could not be read, its frontmatter fence is absent/unclosed, the frontmatter violates the supported block-YAML subset, the parsed frontmatter is not a mapping, or `parameters` is present but not a mapping. |
| `okf_attested_computation.wrong_type` | The frontmatter `type` field is not `"Attested Computation"`. |
| `okf_attested_computation.missing_runtime` | The frontmatter `runtime` field is absent, empty, or not a string. |
| `okf_attested_computation.missing_executor_resource` | `executor` is not a mapping, or `executor.resource` is absent, empty, or not a string. |
| `okf_attested_computation.missing_executor_receipt` | `executor` is not a mapping, or `executor.receipt` is absent or not a list of non-empty strings. |
| `okf_attested_computation.missing_attester_resource` | `attester` is not a mapping, or `attester.resource` is absent, empty, or not a string. |
| `okf_attested_computation.unsafe_resource_reference:<role>` | Dynamic. The declared resource path for `<role>` (`executor` or `attester`) is absolute, contains a `..` segment, or resolves outside `--bundle-root` (including via symlink). |
| `okf_attested_computation.resource_missing:<role>` | Dynamic. The declared resource path for `<role>` resolves safely under the bundle root but no file exists there (or it became unreadable at read time). |
| `okf_attested_computation.resource_not_a_file:<role>` | Dynamic. The declared resource path for `<role>` resolves to something that is not a regular file (e.g. a directory). |
| `okf_attested_computation.resource_binding_mismatch:<role>` | Dynamic (concrete completions in current bytes: `okf_attested_computation.resource_binding_mismatch:executor`, `okf_attested_computation.resource_binding_mismatch:attester`). The supplied run evidence carries an `<role>_resource_digest` claim that is malformed or does not match the independently recomputed digest of the referenced resource bytes. |
| `okf_attested_computation.receipt_field_absent:<field>` | Dynamic. A field name listed in `executor.receipt` is absent from the supplied run evidence object. |
| `okf_attested_computation.run_evidence_malformed` | The run evidence could not be read, was not valid JSON, or its top-level JSON value is not an object. |
