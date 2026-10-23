# Proposed handoff cases: executed evidence

All IDs are retained from the pinned SRS handoff. `EXECUTED_CONSTRUCTED` means
the listed assertions ran against the real adapter using constructed material;
it does not mean owner acceptance or real service conformance. **32 cases have
constructed coverage, two are partial, and T01 is unexecuted.** Test counts are
separate from case counts. See [actual run evidence](evidence/validation.json).

| Case | Status | Executed test selectors | Scope / limitation |
| --- | --- | --- | --- |
| T01 | NOT_EXECUTED | — | No authorized real-service specimen; reserved fixture remains unpopulated. |
| T02 | EXECUTED_CONSTRUCTED | `test_T02_T18_exact_bytes_and_occurrence` | Changed exact artifact leaves signature/inclusion intact and subject binding fails. |
| T03 | EXECUTED_CONSTRUCTED | `test_T03_T04_T05_srs_validity_remains_independent` | Two existing valid SRS goldens; wrong artifact fails binding. |
| T04 | EXECUTED_CONSTRUCTED | `test_T03_T04_T05_srs_validity_remains_independent` | Actual SRS verifier rejects signature; correctly constructed registration still succeeds. |
| T05 | EXECUTED_CONSTRUCTED | `test_T03_T04_T05_srs_validity_remains_independent`<br>`test_T05_absent_registration`<br>`test_cli_selection_and_unchanged_srs_dispatch` | Existing SRS report unchanged; absent registration is unevaluated. |
| T06 | EXECUTED_CONSTRUCTED | `test_T06_arbitrary_response_is_not_inclusion` | Empty/arbitrary body; no transport or real HTTP exchange is performed. |
| T07 | EXECUTED_CONSTRUCTED | `test_T07_T11_native_attached_wrong_root_requires_adapter_guard`<br>`test_selected_proof_and_malformed_unselected_proof` | Valid service signature cannot rescue wrong selected statement/root/proof. |
| T08 | EXECUTED_CONSTRUCTED | `test_T08_tampered_statement_signature_and_protected_header`<br>`test_B12_T08_duplicate_or_malformed_statement`<br>`test_unknown_critical_receipt_header_fails`<br>`test_receipt_cwt_header_validation`<br>`test_critical_receipt_cwt_requires_supported_semantics` | Tampering, duplicate/malformed maps, unknown critical semantics. |
| T09 | EXECUTED_CONSTRUCTED | `test_invalid_carrier_precedes_all_content_reading` | Missing Signed Statement prevents content evaluation; no regeneration. |
| T10 | EXECUTED_CONSTRUCTED | `test_T10_explicit_keys_do_not_establish_trust`<br>`test_private_key_is_not_a_public_selection` | Missing/wrong keys, wrong issuer, swapped roles, absent/reject policy. |
| T11 | EXECUTED_CONSTRUCTED | `test_T07_T11_native_attached_wrong_root_requires_adapter_guard` | Exact pinned native attached-payload false acceptance is reproduced and blocked by adapter. |
| T12 | EXECUTED_CONSTRUCTED | `test_B07_B19_T12_unsigned_time_is_an_observation`<br>`test_constructed_success_and_separate_axes` | Inclusion passes without time or consistency claim. |
| T13 | PARTIAL_CONSTRUCTED | `test_T13_signed_iat_does_not_supply_time_policy_or_authenticate_earlier_issuance` | Earlier artifact issuance is not authenticated by later signed iat; no trustworthy registration-time profile/policy is implemented, so the full premise is unexecuted. |
| T17 | EXECUTED_CONSTRUCTED | `test_B05_B06_T17_service_outcomes_remain_separate` | Two explicit service selections in both orders; valid/invalid receipts retained separately. |
| T18 | EXECUTED_CONSTRUCTED | `test_T02_T18_exact_bytes_and_occurrence` | Receipt-id occurrence and exact serialization changes fail old binding. |
| T19 | EXECUTED_CONSTRUCTED | `test_T19_original_submission_is_not_replaced_with_augmented_statement` | Adding outer unsigned proof preserves signature but changes selected statement bytes and invalidates old inclusion. |
| B01 | EXECUTED_CONSTRUCTED | `test_profile_cases[B01]` | Constructed handoff assertion; see named test. |
| B02 | EXECUTED_CONSTRUCTED | `test_B02_pairing_order_and_repeat_do_not_hide_failure`<br>`test_retained_constructed_replay_inputs_and_outputs` | Both signatures valid; S1/P pass, S2/P fail in both orders, repeated S1/P cannot suppress S2/P. |
| B03 | PARTIAL_CONSTRUCTED | `test_B03_exact_duplicate_entries_rejected`<br>`test_B03_context_and_three_digests_prevent_reuse`<br>`test_B03_missing_target_never_reuses_complete_findings`<br>`test_B03_same_relation_with_different_per_entry_policy_not_reused` | Three digests, selected proof, verifier and role-key/policy contexts exercised; proof profile is fixed and time policy absent. Alternate supported proof/time contexts await their implementations. |
| B04 | EXECUTED_CONSTRUCTED | `test_B04_service_and_target_hint_disagreement` | Constructed handoff assertion; see named test. |
| B05 | EXECUTED_CONSTRUCTED | `test_B05_B06_T17_service_outcomes_remain_separate` | Constructed handoff assertion; see named test. |
| B06 | EXECUTED_CONSTRUCTED | `test_B05_B06_T17_service_outcomes_remain_separate` | Constructed handoff assertion; see named test. |
| B07 | EXECUTED_CONSTRUCTED | `test_B07_B19_T12_unsigned_time_is_an_observation` | Constructed handoff assertion; see named test. |
| B08 | EXECUTED_CONSTRUCTED | `test_profile_cases[B08]` | Constructed handoff assertion; see named test. |
| B09 | EXECUTED_CONSTRUCTED | `test_profile_cases[B09]` | Constructed handoff assertion; see named test. |
| B10 | EXECUTED_CONSTRUCTED | `test_profile_cases[B10]` | Constructed handoff assertion; see named test. |
| B11 | EXECUTED_CONSTRUCTED | `test_profile_cases[B11-258]`<br>`test_profile_cases[B11-259]`<br>`test_profile_cases[B11-260]` | Constructed handoff assertion; see named test. |
| B12 | EXECUTED_CONSTRUCTED | `test_B12_T08_duplicate_or_malformed_statement` | Constructed handoff assertion; see named test. |
| B13 | EXECUTED_CONSTRUCTED | `test_profile_cases[B13]`<br>`test_malformed_statement_crit_does_not_crash` | Constructed handoff assertion; see named test. |
| B14 | EXECUTED_CONSTRUCTED | `test_profile_cases[B14]` | Constructed handoff assertion; see named test. |
| B15 | EXECUTED_CONSTRUCTED | `test_invalid_carrier_precedes_all_content_reading[B15]` | Constructed handoff assertion; see named test. |
| B16 | EXECUTED_CONSTRUCTED | `test_invalid_carrier_precedes_all_content_reading[B16]` | Constructed handoff assertion; see named test. |
| B17 | EXECUTED_CONSTRUCTED | `test_B17_receipt_id_is_not_digest_subject` | Constructed handoff assertion; see named test. |
| B18 | EXECUTED_CONSTRUCTED | `test_profile_cases[B18]` | Constructed handoff assertion; see named test. |
| B19 | EXECUTED_CONSTRUCTED | `test_B07_B19_T12_unsigned_time_is_an_observation` | Constructed handoff assertion; see named test. |

Tests live in [test_registration.py](../../tests/scitt/test_registration.py).
Additional tests cover independent tree sizes/leaf positions, EC signatures,
malformed proofs (including unselected ones), parser limits/encoding disclosure,
source pins, CLI behavior, and unsupported CCF/certificate references.
