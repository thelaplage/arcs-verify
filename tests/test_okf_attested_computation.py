"""OKF-ARCS-BRIDGE0 — verifier-side bindings for OKF v0.2 "Attested
Computation" declarations.

Coverage:
  T01  valid declaration + resources + full run evidence -> all three
       Boolean conclusions True, passed=True
  T02  unknown extra frontmatter keys are inert (never flip a conclusion)
  T03  wrong `type` -> declaration_valid False, wrong_type code
  T04  missing runtime -> declaration_valid False, missing_runtime code
  T05  missing executor.resource -> missing_executor_resource code
  T06  missing executor.receipt -> missing_executor_receipt code,
       receipt_shape_satisfied False
  T07  missing attester.resource -> missing_attester_resource code
  T08  path traversal in executor.resource -> unsafe_resource_reference:executor
  T09  absolute path in executor.resource -> unsafe_resource_reference:executor
  T10  missing referenced resource file -> resource_missing:executor
  T11  resource path resolves to a directory -> resource_not_a_file:executor
  T12  MUTATION PROOF: valid bundle passes; mutate one executor byte and the
       independently recomputed digest changes; a run evidence claiming the
       original (now-stale) digest fails with resource_binding_mismatch
  T13  missing declared receipt field in run evidence -> receipt_field_absent:<field>
  T14  malformed run evidence (invalid JSON) -> run_evidence_malformed,
       never silently promoted to PASS
  T15  unclosed frontmatter fence -> declaration_malformed
  T16  no frontmatter fence at all -> declaration_malformed
  T17  declaration mutation changes the verdict (type flipped in-memory)
  T18  reserved conclusions (execution_verified, attester_verdict_verified,
       truth_verified, authority_conferred) are permanent constants on both
       the PASS and FAIL paths, and non_equivalences is always present
  T19  no producer/OpenKnowledge import in the module (AST sweep)
  T20  CLI smoke: exit 0 on valid input, exit 1 on structural failure,
       exit 2 on unreadable declaration (source-integrity, not a verdict)
  T21  safe resource resolution never reads outside bundle_root even when the
       file happens to exist there (belt-and-braces on the traversal fixture)
  T22  public-release guard: no forbidden producer import root introduced
"""

from __future__ import annotations

import ast
import copy
import hashlib
import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest

from arcs_verify import okf_attested_computation as okf

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "okf-attested-computation"
BUNDLE = FIXTURES / "bundle"
DECLARATIONS = FIXTURES / "declarations"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _run_evidence(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _verify(declaration_name: str, bundle_root: Path, run_evidence_name: str | None, *, run_evidence_error: str | None = None):
    declaration_text = _read(DECLARATIONS / declaration_name)
    run_evidence = _run_evidence(run_evidence_name) if run_evidence_name else None
    return okf.verify(declaration_text, None, bundle_root, run_evidence, run_evidence_error)


# --------------------------------------------------------------------------- #
# T01 — valid declaration, resources, and run evidence
# --------------------------------------------------------------------------- #
def test_valid_declaration_passes() -> None:
    finding = _verify("valid.md", BUNDLE, "run-valid.json")
    assert finding.declaration_valid is True
    assert finding.resource_bindings_valid is True
    assert finding.receipt_shape_satisfied is True
    assert finding.passed is True
    assert finding.failure_codes == ()
    assert finding.executor_resource_digest == (
        "sha256:7b0a83ee5045c56a3a6b7eb7c074ec08399754d19a1d8465d870d5914be3a2fe"
    )
    assert finding.attester_resource_digest == (
        "sha256:40730f603a81e80e1842762a29c73d440437bdf30fbc0d21349ce7d8e1a7c253"
    )


# --------------------------------------------------------------------------- #
# T02 — unknown frontmatter keys are inert
# --------------------------------------------------------------------------- #
def test_unknown_frontmatter_key_is_inert() -> None:
    baseline = _verify("valid.md", BUNDLE, "run-valid.json")
    extra = _verify("valid-extra-frontmatter.md", BUNDLE, "run-valid.json")
    assert extra.declaration_valid == baseline.declaration_valid == True  # noqa: E712
    assert extra.resource_bindings_valid == baseline.resource_bindings_valid == True  # noqa: E712
    assert extra.receipt_shape_satisfied == baseline.receipt_shape_satisfied == True  # noqa: E712
    assert extra.passed is True
    assert extra.failure_codes == ()
    # the forbidden-sounding keys never leak into the report
    assert "admitted" not in extra.to_dict()
    assert "standing" not in extra.to_dict()


# --------------------------------------------------------------------------- #
# T03-T07 — structural negative fixtures
# --------------------------------------------------------------------------- #
def test_wrong_type() -> None:
    finding = _verify("wrong-type.md", BUNDLE, "run-valid.json")
    assert finding.declaration_valid is False
    assert "okf_attested_computation.wrong_type" in finding.failure_codes
    assert finding.passed is False


def test_missing_runtime() -> None:
    finding = _verify("missing-runtime.md", BUNDLE, "run-valid.json")
    assert finding.declaration_valid is False
    assert "okf_attested_computation.missing_runtime" in finding.failure_codes


def test_missing_executor_resource() -> None:
    finding = _verify("missing-executor-resource.md", BUNDLE, "run-valid.json")
    assert finding.declaration_valid is False
    assert "okf_attested_computation.missing_executor_resource" in finding.failure_codes
    assert finding.resource_bindings_valid is False
    assert finding.executor_resource_digest is None


def test_missing_executor_receipt() -> None:
    finding = _verify("missing-executor-receipt.md", BUNDLE, "run-valid.json")
    assert finding.declaration_valid is False
    assert "okf_attested_computation.missing_executor_receipt" in finding.failure_codes
    assert finding.receipt_shape_satisfied is False


def test_missing_attester_resource() -> None:
    finding = _verify("missing-attester-resource.md", BUNDLE, "run-valid.json")
    assert finding.declaration_valid is False
    assert "okf_attested_computation.missing_attester_resource" in finding.failure_codes
    assert finding.resource_bindings_valid is False
    assert finding.attester_resource_digest is None


# --------------------------------------------------------------------------- #
# T08-T11 — resource safety
# --------------------------------------------------------------------------- #
def test_path_traversal_rejected() -> None:
    finding = _verify("path-traversal.md", BUNDLE, "run-valid.json")
    assert finding.resource_bindings_valid is False
    assert "okf_attested_computation.unsafe_resource_reference:executor" in finding.failure_codes
    assert finding.executor_resource_digest is None


def test_absolute_path_rejected() -> None:
    finding = _verify("absolute-path.md", BUNDLE, "run-valid.json")
    assert finding.resource_bindings_valid is False
    assert "okf_attested_computation.unsafe_resource_reference:executor" in finding.failure_codes


def test_missing_resource_file() -> None:
    finding = _verify("missing-resource-file.md", BUNDLE, "run-valid.json")
    assert finding.resource_bindings_valid is False
    assert "okf_attested_computation.resource_missing:executor" in finding.failure_codes


def test_resource_not_a_file() -> None:
    finding = _verify("resource-not-a-file.md", BUNDLE, "run-valid.json")
    assert finding.resource_bindings_valid is False
    assert "okf_attested_computation.resource_not_a_file:executor" in finding.failure_codes


def test_symlink_escape_rejected(tmp_path) -> None:
    """A resource path that resolves safely on paper but is a symlink
    pointing outside bundle_root must still be rejected (resolve() follows
    the symlink before the containment check runs)."""
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "secret.py"
    secret.write_text("SECRET = True\n", encoding="utf-8")

    bundle_root = tmp_path / "bundle"
    bundle_root.mkdir()
    shutil.copy(BUNDLE / "attester.py", bundle_root / "attester.py")
    link = bundle_root / "executor.py"
    try:
        link.symlink_to(secret)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported in this environment")

    declaration = bundle_root / "declaration.md"
    declaration.write_text(_read(DECLARATIONS / "valid.md"), encoding="utf-8")

    finding = _verify("valid.md", bundle_root, "run-valid.json")
    assert finding.resource_bindings_valid is False
    codes = finding.failure_codes
    assert any(
        c.startswith("okf_attested_computation.unsafe_resource_reference:executor")
        for c in codes
    )


# --------------------------------------------------------------------------- #
# T12 — MUTATION PROOF
# --------------------------------------------------------------------------- #
def test_mutation_proof_referenced_byte_change_breaks_binding(tmp_path) -> None:
    """(1) valid bundle -> structural PASS; (2) mutate one executor byte;
    (3) independent resource binding changes/fails; (4) no producer
    implementation is consulted anywhere in this process (the module imports
    none — see test_module_imports_no_producer_code)."""
    # (1) baseline PASS, and capture the true digest a real run would see.
    baseline = _verify("valid.md", BUNDLE, "run-claims-correct-digests.json")
    assert baseline.passed is True
    assert baseline.resource_bindings_valid is True
    original_digest = baseline.executor_resource_digest

    # (2) mutate one byte of the referenced executor resource in an isolated copy.
    mutated_bundle = tmp_path / "mutated-bundle"
    shutil.copytree(BUNDLE, mutated_bundle)
    executor_path = mutated_bundle / "executor.py"
    data = bytearray(executor_path.read_bytes())
    data[0] ^= 0xFF
    executor_path.write_bytes(bytes(data))

    # (3a) the independently recomputed digest changes.
    mutated = _verify("valid.md", mutated_bundle, "run-valid.json")
    assert mutated.executor_resource_digest is not None
    assert mutated.executor_resource_digest != original_digest

    # (3b) a run evidence claiming the ORIGINAL (now-stale) digest against the
    # mutated bytes produces a named binding-mismatch failure, not a silent PASS.
    stale_claim = _verify("valid.md", mutated_bundle, "run-claims-correct-digests.json")
    assert stale_claim.resource_bindings_valid is False
    assert "okf_attested_computation.resource_binding_mismatch:executor" in stale_claim.failure_codes
    assert stale_claim.passed is False


def test_resource_binding_mismatch_malformed_claim() -> None:
    finding = _verify("valid.md", BUNDLE, "run-claims-malformed-digest.json")
    assert finding.resource_bindings_valid is False
    assert "okf_attested_computation.resource_binding_mismatch:executor" in finding.failure_codes


def test_resource_binding_correct_claim_passes() -> None:
    finding = _verify("valid.md", BUNDLE, "run-claims-correct-digests.json")
    assert finding.resource_bindings_valid is True
    assert finding.passed is True


# --------------------------------------------------------------------------- #
# T13 — missing declared receipt field
# --------------------------------------------------------------------------- #
def test_missing_receipt_field() -> None:
    finding = _verify("valid.md", BUNDLE, "run-missing-field.json")
    assert finding.receipt_shape_satisfied is False
    assert "okf_attested_computation.receipt_field_absent:stdout_digest" in finding.failure_codes
    assert finding.passed is False


# --------------------------------------------------------------------------- #
# T14 — malformed run evidence
# --------------------------------------------------------------------------- #
def test_malformed_run_evidence() -> None:
    declaration_text = _read(DECLARATIONS / "valid.md")
    finding = okf.verify(
        declaration_text, None, BUNDLE, None, "run evidence is not valid JSON"
    )
    assert finding.receipt_shape_satisfied is False
    assert "okf_attested_computation.run_evidence_malformed" in finding.failure_codes
    assert finding.passed is False
    # never promoted to PASS despite a structurally valid declaration/resources
    assert finding.declaration_valid is True
    assert finding.resource_bindings_valid is True


def test_run_evidence_not_an_object() -> None:
    declaration_text = _read(DECLARATIONS / "valid.md")
    finding = okf.verify(declaration_text, None, BUNDLE, None, None)
    # run_evidence=None with no error string still must not silently pass
    assert finding.receipt_shape_satisfied is False


# --------------------------------------------------------------------------- #
# T15-T16 — malformed declaration framing
# --------------------------------------------------------------------------- #
def test_unclosed_frontmatter_fence() -> None:
    finding = _verify("unclosed-fence.md", BUNDLE, "run-valid.json")
    assert finding.declaration_valid is False
    assert "okf_attested_computation.declaration_malformed" in finding.failure_codes
    assert finding.passed is False


def test_no_frontmatter_fence() -> None:
    finding = _verify("no-fence.md", BUNDLE, "run-valid.json")
    assert finding.declaration_valid is False
    assert "okf_attested_computation.declaration_malformed" in finding.failure_codes


def test_parse_frontmatter_rejects_flow_collections() -> None:
    with pytest.raises(okf.OKFDeclarationError):
        okf.parse_frontmatter("---\nexecutor: {resource: x.py}\n---\n")


def test_parse_frontmatter_rejects_tabs() -> None:
    with pytest.raises(okf.OKFDeclarationError):
        okf.parse_frontmatter("---\ntype: Attested Computation\n\texecutor: x\n---\n")


# --------------------------------------------------------------------------- #
# T17 — declaration mutation changes the verdict
# --------------------------------------------------------------------------- #
def test_declaration_mutation_changes_verdict() -> None:
    original_text = _read(DECLARATIONS / "valid.md")
    baseline = okf.verify(original_text, None, BUNDLE, _run_evidence("run-valid.json"), None)
    assert baseline.declaration_valid is True

    mutated_text = original_text.replace("type: Attested Computation", "type: Not Attested")
    assert mutated_text != original_text
    mutated = okf.verify(mutated_text, None, BUNDLE, _run_evidence("run-valid.json"), None)
    assert mutated.declaration_valid is False
    assert "okf_attested_computation.wrong_type" in mutated.failure_codes


# --------------------------------------------------------------------------- #
# T18 — reserved conclusions are permanent constants
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("declaration_name", "run_evidence_name"),
    [
        ("valid.md", "run-valid.json"),
        ("wrong-type.md", "run-valid.json"),
        ("missing-runtime.md", "run-valid.json"),
        ("path-traversal.md", "run-valid.json"),
    ],
)
def test_reserved_conclusions_are_permanent(declaration_name, run_evidence_name) -> None:
    finding = _verify(declaration_name, BUNDLE, run_evidence_name)
    assert finding.execution_verified == "not_evaluated"
    assert finding.attester_verdict_verified == "not_evaluated"
    assert finding.truth_verified == "not_evaluated"
    assert finding.authority_conferred is False
    assert finding.non_equivalences == okf.NON_EQUIVALENCES
    assert len(finding.non_equivalences) >= 4


def test_receipt_shape_success_does_not_alter_reserved_conclusions() -> None:
    """A structural full-PASS receipt shape never promotes execution_verified,
    attester_verdict_verified, or truth_verified past not_evaluated, and never
    confers authority."""
    finding = _verify("valid.md", BUNDLE, "run-claims-correct-digests.json")
    assert finding.passed is True
    assert finding.execution_verified == "not_evaluated"
    assert finding.attester_verdict_verified == "not_evaluated"
    assert finding.truth_verified == "not_evaluated"
    assert finding.authority_conferred is False


# --------------------------------------------------------------------------- #
# T19 — independence: no producer / OpenKnowledge import
# --------------------------------------------------------------------------- #
def test_module_imports_no_producer_code() -> None:
    source = (ROOT / "arcs_verify" / "okf_attested_computation.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    forbidden_roots = {
        "openknowledge",
        "open_knowledge_format",
        "okf",
        "okf_runtime",
        "dagr_mcp",
        "dagr_ingest",
        "arcs_srs",
        "counterpedia_acquisition",
        "acquisition",
    }
    imported_roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots |= {alias.name.split(".", 1)[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported_roots.add(node.module.split(".", 1)[0])
    assert forbidden_roots.isdisjoint(imported_roots), (
        f"module imports producer code: {sorted(forbidden_roots & imported_roots)}"
    )
    # and, structurally: the module never executes anything it reads.
    assert "subprocess" not in imported_roots
    assert "exec(" not in source
    assert "eval(" not in source
    assert "importlib" not in imported_roots
    assert "urllib" not in imported_roots
    assert "requests" not in imported_roots
    assert "socket" not in imported_roots


# --------------------------------------------------------------------------- #
# T20 — CLI smoke
# --------------------------------------------------------------------------- #
def test_cli_valid_is_exit_0(capsys) -> None:
    rc = okf.main([
        str(DECLARATIONS / "valid.md"),
        "--bundle-root", str(BUNDLE),
        "--run", str(FIXTURES / "run-valid.json"),
        "--json",
    ])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["declaration_valid"] is True
    assert out["passed"] is True
    assert out["execution_verified"] == "not_evaluated"


def test_cli_structural_failure_is_exit_1() -> None:
    rc = okf.main([
        str(DECLARATIONS / "wrong-type.md"),
        "--bundle-root", str(BUNDLE),
        "--run", str(FIXTURES / "run-valid.json"),
    ])
    assert rc == 1


def test_cli_missing_declaration_is_exit_2(tmp_path) -> None:
    rc = okf.main([
        str(tmp_path / "nope.md"),
        "--bundle-root", str(BUNDLE),
        "--run", str(FIXTURES / "run-valid.json"),
    ])
    assert rc == 2


def test_cli_missing_bundle_root_is_exit_2(tmp_path) -> None:
    rc = okf.main([
        str(DECLARATIONS / "valid.md"),
        "--bundle-root", str(tmp_path / "nope"),
        "--run", str(FIXTURES / "run-valid.json"),
    ])
    assert rc == 2


def test_cli_malformed_run_evidence_is_exit_1_not_exit_2() -> None:
    """A readable-but-invalid-JSON run evidence file is a verification FAIL
    (a named code), not a usage/source-integrity exit 2 — the CLI could read
    the bytes; they just don't parse into the expected shape."""
    rc = okf.main([
        str(DECLARATIONS / "valid.md"),
        "--bundle-root", str(BUNDLE),
        "--run", str(FIXTURES / "run-malformed.json"),
    ])
    assert rc == 1


def test_cli_dispatch_from_top_level() -> None:
    from arcs_verify.cli import main as top_level_main

    rc = top_level_main([
        "okf-attested-computation",
        str(DECLARATIONS / "valid.md"),
        "--bundle-root", str(BUNDLE),
        "--run", str(FIXTURES / "run-valid.json"),
    ])
    assert rc == 0


# --------------------------------------------------------------------------- #
# T22 — public-release producer-import guard passes on the repo tree
# --------------------------------------------------------------------------- #
def test_public_release_guard_passes() -> None:
    spec = importlib.util.spec_from_file_location(
        "check_public_release", ROOT / "tools" / "check_public_release.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_public_release"] = module  # required so @dataclass resolves under 3.14
    spec.loader.exec_module(module)
    findings = module.check(ROOT)
    producer_import = [f for f in findings if f.rule_id == "PR010"]
    assert not producer_import, producer_import
