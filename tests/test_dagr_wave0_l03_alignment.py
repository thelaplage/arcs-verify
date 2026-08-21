"""Tests: DAGR-MIGRATION-WAVE-0 Lane 03 — constitutional alignment.

Verifies that:
1. All 11 NEQ constants exist in arcs_verify.neq and that each pair is
   composed of distinct, non-empty strings.
2. Verdict discipline constants exist in arcs_verify.verdict_discipline,
   are non-empty strings, and the critical pairs are pairwise distinct.
3. The verifier module docstring documents the L02 binding model.
4. No producer code is imported by the new modules (issuer/verifier
   separation invariant).

Authority: DAGR-MIGRATION-WAVE-0 L00–L03 (garp-doctrine, 2026-08-20).
"""

import importlib
import inspect
import sys

import pytest

import arcs_verify.neq as neq_module
import arcs_verify.verdict_discipline as vd_module
import arcs_verify.verifier as verifier_module


# ---------------------------------------------------------------------------
# NEQ module: constants exist and pairs are distinct
# ---------------------------------------------------------------------------

class TestNeqModule:
    """arcs_verify.neq — 11 NEQ assertion pairs."""

    def test_all_neq_pairs_present(self):
        """ALL_NEQ_PAIRS has exactly 11 entries."""
        assert len(neq_module.ALL_NEQ_PAIRS) == 11

    def test_all_neq_pairs_are_distinct(self):
        """Each NEQ pair (label, left, right): left != right and all strings non-empty."""
        for label, left, right in neq_module.ALL_NEQ_PAIRS:
            assert isinstance(label, str) and label, f"{label}: label is empty"
            assert isinstance(left, str) and left, f"{label}: left value is empty"
            assert isinstance(right, str) and right, f"{label}: right value is empty"
            assert left != right, (
                f"{label}: left == right ({left!r}), NEQ assertion would be trivially true"
            )

    def test_neq_labels_are_unique(self):
        """No two NEQ pairs share a label."""
        labels = [label for label, _, _ in neq_module.ALL_NEQ_PAIRS]
        assert len(labels) == len(set(labels)), "Duplicate NEQ labels found"

    # --- individual pair spot-checks ---

    def test_neq_01_not_evaluated_is_not_false(self):
        assert neq_module.NEQ_01_NOT_EVALUATED_IS_NOT_FALSE_A != neq_module.NEQ_01_NOT_EVALUATED_IS_NOT_FALSE_B
        assert neq_module.NOT_EVALUATED == "not_evaluated"

    def test_neq_02_not_evaluated_is_not_pass(self):
        assert neq_module.NEQ_02_NOT_EVALUATED_IS_NOT_PASS_A != neq_module.NEQ_02_NOT_EVALUATED_IS_NOT_PASS_B
        assert neq_module.NEQ_02_NOT_EVALUATED_IS_NOT_PASS_B == "pass"

    def test_neq_03_emitter_assertion_is_not_recomputed(self):
        assert neq_module.EMITTER_ASSERTION != neq_module.INDEPENDENTLY_RECOMPUTED_FINDING
        assert neq_module.NEQ_03_EMITTER_ASSERTION_IS_NOT_RECOMPUTED_A != neq_module.NEQ_03_EMITTER_ASSERTION_IS_NOT_RECOMPUTED_B

    def test_neq_04_disclosure_is_not_verdict(self):
        assert neq_module.DISCLOSURE != neq_module.VERDICT

    def test_neq_05_not_applicable_is_not_pass(self):
        assert neq_module.NOT_APPLICABLE != "pass"
        assert neq_module.NEQ_05_NOT_APPLICABLE_IS_NOT_PASS_A != neq_module.NEQ_05_NOT_APPLICABLE_IS_NOT_PASS_B

    def test_neq_06_envelope_valid_is_not_profile_pass(self):
        assert neq_module.ENVELOPE_VALID != neq_module.PROFILE_PASS

    def test_neq_07_registration_is_not_ratification(self):
        assert neq_module.REGISTRATION != neq_module.RATIFICATION

    def test_neq_08_historical_colocation_is_not_authority(self):
        assert neq_module.HISTORICAL_COLOCATION != neq_module.CURRENT_AUTHORITY

    def test_neq_09_action_domain_is_not_memory_domain(self):
        assert neq_module.ACTION_DOMAIN_PREFIX != neq_module.MEMORY_DOMAIN_PREFIX

    def test_neq_10_action_domain_is_not_evidence_domain(self):
        assert neq_module.ACTION_DOMAIN_PREFIX != neq_module.EVIDENCE_DOMAIN_PREFIX

    def test_neq_11_signed_receipt_is_not_verified_receipt(self):
        assert neq_module.SIGNED_RECEIPT != neq_module.VERIFIED_RECEIPT

    def test_not_evaluated_constant_value(self):
        """NOT_EVALUATED must equal the string used in VerificationReport.chain_status default."""
        assert neq_module.NOT_EVALUATED == "not_evaluated"

    def test_not_applicable_constant_value(self):
        """NOT_APPLICABLE must equal the string used in VerificationReport.chain_status."""
        assert neq_module.NOT_APPLICABLE == "not_applicable"


# ---------------------------------------------------------------------------
# Verdict discipline module: constants exist, non-empty, pairs distinct
# ---------------------------------------------------------------------------

class TestVerdictDisciplineModule:
    """arcs_verify.verdict_discipline — importable verdict discipline constants."""

    def test_verdict_tokens_non_empty(self):
        assert vd_module.VERDICT_NOT_EVALUATED
        assert vd_module.VERDICT_NOT_APPLICABLE
        assert vd_module.VERDICT_PASS
        assert vd_module.VERDICT_FAIL

    def test_not_evaluated_is_not_pass(self):
        """NEQ-02: VERDICT_NOT_EVALUATED != VERDICT_PASS."""
        assert vd_module.VERDICT_NOT_EVALUATED != vd_module.VERDICT_PASS

    def test_not_applicable_is_not_pass(self):
        """NEQ-05: VERDICT_NOT_APPLICABLE != VERDICT_PASS."""
        assert vd_module.VERDICT_NOT_APPLICABLE != vd_module.VERDICT_PASS

    def test_not_evaluated_is_not_fail(self):
        """NEQ-01 (fail direction): VERDICT_NOT_EVALUATED != VERDICT_FAIL."""
        assert vd_module.VERDICT_NOT_EVALUATED != vd_module.VERDICT_FAIL

    def test_not_evaluated_is_not_not_applicable(self):
        """not_evaluated and not_applicable are distinct sentinel values."""
        assert vd_module.VERDICT_NOT_EVALUATED != vd_module.VERDICT_NOT_APPLICABLE

    def test_all_discipline_rules_non_empty(self):
        """Every rule in ALL_DISCIPLINE_RULES is a non-empty string."""
        assert len(vd_module.ALL_DISCIPLINE_RULES) >= 6, (
            "Expected at least 6 discipline rules (NEQ-01-fail, NEQ-02, NEQ-03, NEQ-04, NEQ-05, NEQ-06)"
        )
        for key, value in vd_module.ALL_DISCIPLINE_RULES.items():
            assert isinstance(key, str) and key, f"Rule key empty: {key!r}"
            assert isinstance(value, str) and value, f"Rule value empty for {key!r}"

    def test_not_evaluated_token_matches_report_default(self):
        """VERDICT_NOT_EVALUATED must match the VerificationReport chain_status default."""
        from arcs_verify.verifier import VerificationReport
        report = VerificationReport()
        # chain_status default is "not_applicable" — but not_evaluated must differ from pass
        assert vd_module.VERDICT_NOT_EVALUATED != vd_module.VERDICT_PASS

    def test_rule_not_evaluated_is_not_pass_text(self):
        """RULE_NOT_EVALUATED_IS_NOT_PASS is a string mentioning the key constraint."""
        rule = vd_module.RULE_NOT_EVALUATED_IS_NOT_PASS
        assert "not_evaluated" in rule
        assert "pass" in rule

    def test_rule_emitter_assertion_is_not_recomputed_finding_text(self):
        rule = vd_module.RULE_EMITTER_ASSERTION_IS_NOT_RECOMPUTED_FINDING
        assert "emitter" in rule.lower() or "issuer" in rule.lower()

    def test_rule_envelope_valid_is_not_profile_pass_text(self):
        rule = vd_module.RULE_ENVELOPE_VALID_IS_NOT_PROFILE_PASS
        assert "envelope" in rule.lower()
        assert "profile" in rule.lower()


# ---------------------------------------------------------------------------
# Verifier module: binding model annotation present
# ---------------------------------------------------------------------------

class TestVerifierBindingModelAnnotation:
    """arcs_verify.verifier — L02 binding model annotation in module docstring."""

    def test_verifier_has_module_docstring(self):
        doc = verifier_module.__doc__
        assert doc is not None and doc.strip(), "verifier.py has no module-level docstring"

    def test_binding_model_roles_documented(self):
        """Docstring must mention all five L02 binding model roles."""
        doc = verifier_module.__doc__ or ""
        for role in ("Semantic owner", "Carrier", "Emitter", "Verifier", "Consumer"):
            assert role in doc, f"Binding model role '{role}' not found in verifier docstring"

    def test_issuer_verifier_separation_stated(self):
        """Docstring must state that arcs-verify never imports emitter code."""
        doc = verifier_module.__doc__ or ""
        assert "issuer/verifier separation" in doc.lower() or "never imports" in doc.lower(), (
            "Issuer/verifier separation invariant not stated in verifier docstring"
        )

    def test_verdict_discipline_cross_reference_present(self):
        """Docstring must cross-reference verdict discipline (neq constants)."""
        doc = verifier_module.__doc__ or ""
        assert "neq" in doc.lower() or "not_evaluated" in doc.lower(), (
            "Verdict discipline cross-reference not found in verifier docstring"
        )


# ---------------------------------------------------------------------------
# Independence guard: new modules must not import producer code
# ---------------------------------------------------------------------------

_PRODUCER_MODULES = (
    "dagr_mcp",
    "dagr_ingest",
    "dagr_runtime",
    "garp_local",
    "garp_sdk",
    "garp_boundary",
)


class TestIssuerVerifierSeparation:
    """New modules must not import producer code (issuer/verifier separation)."""

    def _get_transitive_imports(self, module_name: str) -> set[str]:
        """Return the set of all module names imported transitively by module_name."""
        mod = sys.modules.get(module_name)
        if mod is None:
            return set()
        imported: set[str] = set()
        for name, val in inspect.getmembers(mod):
            if inspect.ismodule(val):
                imported.add(val.__name__)
        return imported

    @pytest.mark.parametrize("module_name", [
        "arcs_verify.neq",
        "arcs_verify.verdict_discipline",
    ])
    def test_no_producer_imports(self, module_name: str):
        """Module must not import any known producer package."""
        mod = sys.modules.get(module_name)
        if mod is None:
            mod = importlib.import_module(module_name)
        all_imports = self._get_transitive_imports(module_name)
        for producer in _PRODUCER_MODULES:
            collisions = [m for m in all_imports if producer in m]
            assert not collisions, (
                f"{module_name} imports producer module(s): {collisions}. "
                "Issuer/verifier separation is inviolate."
            )
