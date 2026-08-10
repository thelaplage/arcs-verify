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
`inspection_reproduction_mismatch`, `receipt_hash_mismatch`,
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
