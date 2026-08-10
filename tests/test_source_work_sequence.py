"""ARCSV-SOURCESEQ0 — independent verification of the one-source work sequence.

Independence is the core invariant: this suite (and the module under test) imports
ZERO producer code. Every artifact in the coherent sequence is LITERAL producer
output threaded through the SAME source session (the TIT-S02 golden: declaration
digest a272eb55…cdcfc3, inventory key TIT-S02), vendored byte-for-byte at pinned
commits and pinned here so a silent regeneration fails:

  * governed declaration bytes  counterpedia-acquisition @ d4b1127d
      docs/demo-corpus-capture-wave1/CAPTURE_WAVE1_P0_MANIFEST.json
  * source_declaration_binding / session.manifest / capture_receipt
      dagr-ingest @ dbe880dc  tests/fixtures/acquisition_session/tit_s02_bound/
  * source_capture.v0.2 receipt  arcs-srs @ 4d90b9c
      conformance/profiles/srs.editorial.source_capture.v0.2/fixtures/valid/
      source-capture-success.json
  * unbound (SRS-source-capture-ineligible) session  dagr-ingest @ dbe880dc
      tests/fixtures/acquisition_session/unbound/

The adversarial corpus mutates one lineage fact at a time and asserts the SPECIFIC
axis it trips. 'Linked' is never allowed to mean 'true' or 'admitted'; there is no
aggregate verdict; NOT_EVALUATED is never PASS.
"""
from __future__ import annotations

import ast
import copy
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

from arcs_verify import source_work_sequence as sws

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "source-work-sequence"
TIT_S02 = FIXTURES / "tit-s02"
UNBOUND = FIXTURES / "unbound"
# The foreign (cross-source) grounded proposal: a DIFFERENT source than TIT-S02.
FOREIGN_GROUNDING = ROOT / "tests" / "fixtures" / "acquisition-grounding"
FOREIGN_PROPOSAL = FOREIGN_GROUNDING / "grounded-valid.json"
FOREIGN_SOURCE = FOREIGN_GROUNDING / "grounded-valid.source.html"

# Pins (byte provenance of the literal producer artifacts).
ACQ_PIN = "d4b1127d84816cc8279fc2ea0b16358006b37745"
DAGR_INGEST_PIN = "dbe880dc"
ARCS_SRS_PIN = "4d90b9c"

DECLARING_REF = "sha256:a272eb55b983b97fe10320b49051e62e042ced0d3f9d06aa7ffba61136cdcfc3"
INVENTORY_KEY = "TIT-S02"
CAPTURED_REF = "sha256:ffdbd3dfde2d776b07783ebeacef5183fa3b7c5e13ca7cd06f90c70bb937f84b"
EXPECTED_R1A = (
    "urn:counterpedia.source-reference:"
    "sha256:a272eb55b983b97fe10320b49051e62e042ced0d3f9d06aa7ffba61136cdcfc3:TIT-S02"
)

# Exact byte digests of the vendored fixtures (silent regeneration guard).
FIXTURE_DIGESTS = {
    TIT_S02 / "declaration.CAPTURE_WAVE1_P0_MANIFEST.json":
        "a272eb55b983b97fe10320b49051e62e042ced0d3f9d06aa7ffba61136cdcfc3",
    TIT_S02 / "source_declaration_binding.json":
        "7f9d72455b16c2f38c794c8a5eb096919665e863df5b77e9c48d83204945b927",
    TIT_S02 / "session.manifest.json":
        "f0e0b9164b1dd8867258192ea86337325a838bd90d0f4fdffaebf2ccbd3f66a3",
    TIT_S02 / "capture_receipt.json":
        "957d99eb80d641fbc652bb47e260590a9adcfc3cb5aa2f152af0dd6e60996ad3",
    TIT_S02 / "source_capture.v0_2.receipt.json":
        "49a6d14ff2447e1c41cbc42925875db5a6302bb1ddc3f215efbbe3433a096054",
    UNBOUND / "session.manifest.json":
        "dc940777c2084d0a8ee6445fe2533f71a52cc934f5ac18dba2ed1e0e51e4292b",
    UNBOUND / "capture_receipt.json":
        "7885ab54e4242edd0549f5a5c4c267c0a9ec8f11a6c3936f7841ecf2514e1b89",
}

# --------------------------------------------------------------------------- #
# one-source-grounded (OSG-01) — the END-TO-END single-source witness.
#
# Unlike TIT-S02 (whose captured object is an out-of-evidence PDF and which bound
# no proposal), this fixture is ONE governed source whose exact bytes ARE vendored
# and which threads capture -> grounded proposal -> declaration binding ->
# source_capture.v0.2. So on the SAME source both capture_linkage=PASS (raw bytes
# recompute) and proposal_grounding=PASS (same-lineage proposal whose grounding
# recomputes). It was produced ONCE by the real producers and vendored byte-for-
# byte (see one-source-grounded/PROVENANCE.md for the generation recipe + pins):
#
#   * governed declaration + binding + session.manifest + capture_receipt +
#     grounded_content_proposal + captured_source.html (the raw captured bytes)
#       counterpedia-acquisition @ d4b1127d, scripts/gen_osg01_sourceseq_fixture.py
#       (generator sha256:e457df2bf92c81d1794618ce66fca585bb82c16e7adcfb6e717d543cc8589245)
#   * source_capture.v0.2 receipt
#       dagr-ingest @ dbe880dc, adapters/acquisition_source_capture.py
#       (emit_source_capture_from_session over the untouched export)
# --------------------------------------------------------------------------- #
ONE_SOURCE = FIXTURES / "one-source-grounded"
OSG_DECLARATION_FILE = "declaration.OSG_01_MANIFEST.json"
OSG_SOURCE_FILE = "captured_source.html"

OSG_DECLARING_REF = "sha256:bfc8d023c092468d359c6a515599fb3b6c3c94504e1bcb535ce44bd167d272d6"
OSG_INVENTORY_KEY = "OSG-01"
OSG_CAPTURED_REF = "sha256:5b7fa4b9559750e1b5dd0aa9fd396d3291569054f6cbb0a441b9aebf1785eb33"
OSG_EXPECTED_R1A = (
    "urn:counterpedia.source-reference:"
    "sha256:bfc8d023c092468d359c6a515599fb3b6c3c94504e1bcb535ce44bd167d272d6:OSG-01"
)

# Exact byte digests of every vendored OSG-01 artifact (silent-regeneration guard).
ONE_SOURCE_FIXTURE_DIGESTS = {
    ONE_SOURCE / "declaration.OSG_01_MANIFEST.json":
        "bfc8d023c092468d359c6a515599fb3b6c3c94504e1bcb535ce44bd167d272d6",
    ONE_SOURCE / "source_declaration_binding.json":
        "48570a29b59f8151d6bfabbe149e3a9cae31fe5b3012c1a22223fc71f2035d20",
    ONE_SOURCE / "session.manifest.json":
        "39d85aefd36d1ff4e099f5828cb5c190c8dfbc21a2368ec5886b1b54a378a8ae",
    ONE_SOURCE / "capture_receipt.json":
        "7855ec9d7eaa32885031f2a7fb45dea276a1346251390790faf391a827bd548f",
    ONE_SOURCE / "grounded_content_proposal.json":
        "81e33407e2d736b18f68b429ddffb8455a85ddd761ddf2141f656e851bc69a6e",
    ONE_SOURCE / "source_capture.v0_2.receipt.json":
        "1296ea1bbd6e1608ea919c6b20b5f72020ae5bf15d32490729f9f027c5ce435f",
    ONE_SOURCE / "captured_source.html":
        "5b7fa4b9559750e1b5dd0aa9fd396d3291569054f6cbb0a441b9aebf1785eb33",
}

AXES = (
    "artifact_integrity",
    "capture_linkage",
    "declaration_binding_linkage",
    "proposal_grounding",
    "ingest_linkage",
    "citation_pack_linkage",
    "external_source_truth",
)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _evidence() -> sws.SourceWorkEvidence:
    return sws.load_sequence(TIT_S02)


# --------------------------------------------------------------------------- #
# Independence acceptance gates
# --------------------------------------------------------------------------- #
def test_producer_packages_absent() -> None:
    # The producer packages whose serialized bytes this lane consumes must be
    # absent from the verifier environment. (dagr_mcp is a separate, repo-wide
    # pre-existing env leak unrelated to this lane and not consumed here; the
    # source-level ban on importing it is covered by
    # test_module_imports_no_producer_code below.)
    for pkg in ("acquisition", "counterpedia_acquisition", "dagr_ingest", "arcs_srs"):
        assert importlib.util.find_spec(pkg) is None, (
            f"Producer package {pkg!r} present; producer/verifier independence violated."
        )


def test_module_imports_no_producer_code() -> None:
    source = (ROOT / "arcs_verify" / "source_work_sequence.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    forbidden = {"counterpedia_acquisition", "acquisition", "dagr_ingest", "dagr_mcp", "arcs_srs"}
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".", 1)[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module.split(".", 1)[0])
    assert forbidden.isdisjoint(imported), (
        f"module imports producer code: {sorted(forbidden & imported)}"
    )


# --------------------------------------------------------------------------- #
# Fixture byte provenance
# --------------------------------------------------------------------------- #
def test_vendored_fixture_digests_pinned() -> None:
    for path, expected in FIXTURE_DIGESTS.items():
        assert path.is_file(), f"missing vendored fixture: {path}"
        assert _sha(path.read_bytes()) == expected, f"fixture bytes changed: {path}"


def test_declaration_bytes_recompute_to_declaring_ref() -> None:
    raw = (TIT_S02 / "declaration.CAPTURE_WAVE1_P0_MANIFEST.json").read_bytes()
    assert "sha256:" + _sha(raw) == DECLARING_REF


def test_r1a_reference_recomputes_to_arcs_srs_fixture_identity() -> None:
    assert sws.derive_source_reference_id(DECLARING_REF, INVENTORY_KEY) == EXPECTED_R1A
    sc = json.loads((TIT_S02 / "source_capture.v0_2.receipt.json").read_text())
    assert sc["source_reference_id"] == EXPECTED_R1A
    assert sc["subject_ref"] == EXPECTED_R1A
    assert sc["captured_bytes_ref"] == CAPTURED_REF


# --------------------------------------------------------------------------- #
# Happy path — coherent same-source sequence
# --------------------------------------------------------------------------- #
def test_coherent_sequence_axis_shapes() -> None:
    report = sws.verify(_evidence())
    assert report["artifact_integrity"] == "PASS"
    # captured raw bytes are out of evidence -> PARTIAL (digest agreement PASS,
    # raw-byte recompute NOT_EVALUATED). This must never silently be PASS.
    assert report["capture_linkage"] == "PARTIAL"
    assert report["conclusions"]["captured_object_digest_agreement"] == "PASS"
    assert report["conclusions"]["raw_captured_bytes_recompute"] == "NOT_EVALUATED"
    assert report["declaration_binding_linkage"] == "PASS"
    assert report["conclusions"]["r1a_reference_recomputes"] == "PASS"
    # No proposal was emitted for this one-source session (grounding_summary=0).
    assert report["proposal_grounding"] == "NOT_EVALUATED"
    assert report["ingest_linkage"] == "NOT_EVALUATED"
    assert report["recomputed"]["source_ingest_absent"] is True
    assert report["citation_pack_linkage"] == "NOT_EVALUATED"
    assert report["external_source_truth"] == "NOT_EVALUATED"
    assert report["failure_codes"] == []


def test_no_aggregate_verdict_or_trust_score() -> None:
    report = sws.verify(_evidence())
    for banned in ("passed", "verdict", "trust", "trust_score", "ok", "valid", "verified"):
        assert banned not in report, f"report carries an aggregate field: {banned!r}"


def test_axes_reported_separately() -> None:
    report = sws.verify(_evidence())
    for axis in AXES:
        assert axis in report


# --------------------------------------------------------------------------- #
# one-source-grounded (OSG-01) — one source proven END-TO-END
# --------------------------------------------------------------------------- #
def _osg_evidence() -> sws.SourceWorkEvidence:
    # The raw captured HTML is BOTH the proposal source and the captured-object
    # bytes — a single source threads every leg.
    return sws.load_sequence(
        ONE_SOURCE,
        declaration_file=OSG_DECLARATION_FILE,
        grounded_proposal_file="grounded_content_proposal.json",
        proposal_source_file=OSG_SOURCE_FILE,
        captured_source_file=OSG_SOURCE_FILE,
    )


def test_one_source_fixture_digests_pinned() -> None:
    for path, expected in ONE_SOURCE_FIXTURE_DIGESTS.items():
        assert path.is_file(), f"missing vendored fixture: {path}"
        assert _sha(path.read_bytes()) == expected, f"fixture bytes changed: {path}"


def test_one_source_declaration_and_r1a_recompute() -> None:
    raw = (ONE_SOURCE / OSG_DECLARATION_FILE).read_bytes()
    assert "sha256:" + _sha(raw) == OSG_DECLARING_REF
    assert (
        sws.derive_source_reference_id(OSG_DECLARING_REF, OSG_INVENTORY_KEY)
        == OSG_EXPECTED_R1A
    )
    # The raw captured bytes recompute to the captured-object ref every artifact
    # cites, and the source_capture receipt binds THIS declaration's identity.
    html = (ONE_SOURCE / OSG_SOURCE_FILE).read_bytes()
    assert "sha256:" + _sha(html) == OSG_CAPTURED_REF
    sc = json.loads((ONE_SOURCE / "source_capture.v0_2.receipt.json").read_text())
    assert sc["source_reference_id"] == OSG_EXPECTED_R1A
    assert sc["subject_ref"] == OSG_EXPECTED_R1A
    assert sc["captured_bytes_ref"] == OSG_CAPTURED_REF


def test_one_source_end_to_end_all_producer_axes_pass() -> None:
    """The corpus-of-one, proven end-to-end on a SINGLE source: every
    producer-half axis recomputes to PASS at once, while the genuinely-absent
    axes stay NOT_EVALUATED (never silently upgraded)."""
    report = sws.verify(_osg_evidence())

    # Top-level positive matrix.
    assert report["artifact_integrity"] == "PASS"
    assert report["capture_linkage"] == "PASS"
    assert report["declaration_binding_linkage"] == "PASS"
    assert report["proposal_grounding"] == "PASS"

    # Honest NOT_EVALUATED discipline preserved (nothing to evaluate is present).
    assert report["ingest_linkage"] == "NOT_EVALUATED"
    assert report["citation_pack_linkage"] == "NOT_EVALUATED"
    assert report["external_source_truth"] == "NOT_EVALUATED"

    assert report["failure_codes"] == []

    # Granular conclusions underneath the axes: the two upgrades vs. TIT-S02 are
    # (a) the raw captured bytes now recompute, and (b) the same-lineage grounded
    # proposal's grounding recomputes.
    c = report["conclusions"]
    assert c["raw_captured_bytes_recompute"] == "PASS"      # was NOT_EVALUATED for TIT-S02
    assert c["captured_object_digest_agreement"] == "PASS"
    assert c["captured_role_is_raw_source"] == "PASS"
    assert c["r1a_reference_recomputes"] == "PASS"
    assert c["session_is_bound"] == "PASS"
    assert c["proposal_lineage_same_source"] == "PASS"
    assert c["proposal_grounding_recomputes"] == "PASS"     # was NOT_EVALUATED for TIT-S02
    # The absence axes are verified-absent, not assumed.
    assert report["recomputed"]["source_ingest_absent"] is True
    assert report["recomputed"]["citation_pack_present"] is False
    # The composed ACQGROUND0 sub-report itself passed all three of its axes.
    pg = report["recomputed"]["proposal_grounding_report"]
    assert pg["artifact_integrity"] == "PASS"
    assert pg["grounding_integrity"] == "PASS"
    assert pg["proposal_posture"] == "PASS"


def test_one_source_no_aggregate_verdict() -> None:
    report = sws.verify(_osg_evidence())
    for banned in ("passed", "verdict", "trust", "trust_score", "ok", "valid", "verified"):
        assert banned not in report, f"report carries an aggregate field: {banned!r}"


def test_one_source_cli_all_axes_pass_exit_zero(capsys) -> None:
    rc = sws.main(
        [
            str(ONE_SOURCE),
            "--declaration-file", OSG_DECLARATION_FILE,
            "--grounded-proposal-file", "grounded_content_proposal.json",
            "--proposal-source-file", OSG_SOURCE_FILE,
            "--captured-source-file", OSG_SOURCE_FILE,
            "--json",
        ]
    )
    out = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert out["capture_linkage"] == "PASS"
    assert out["proposal_grounding"] == "PASS"
    assert out["declaration_binding_linkage"] == "PASS"
    assert out["ingest_linkage"] == "NOT_EVALUATED"


# --------------------------------------------------------------------------- #
# Adversarial mutation corpus — each trips the RIGHT axis
# --------------------------------------------------------------------------- #
def test_cross_source_substitution_foreign_captured_receipt() -> None:
    """Foreign captured bytes: source_capture points at a different object."""
    ev = _evidence()
    ev.source_capture = copy.deepcopy(ev.source_capture)
    ev.source_capture["captured_bytes_ref"] = "sha256:" + "0" * 64
    report = sws.verify(ev)
    assert report["capture_linkage"] == "FAIL"
    assert "source_work_sequence.captured_object_digest_disagreement" in report["failure_codes"]


def test_cross_source_substitution_foreign_grounded_proposal() -> None:
    """A foreign grounded proposal (different source) fails proposal lineage."""
    ev = _evidence()
    ev.grounded_proposal = json.loads(FOREIGN_PROPOSAL.read_text(encoding="utf-8"))
    ev.proposal_source_bytes = FOREIGN_SOURCE.read_bytes()
    report = sws.verify(ev)
    assert report["proposal_grounding"] == "FAIL"
    assert "source_work_sequence.proposal_cross_source" in report["failure_codes"]
    # The foreign proposal is itself well-grounded to ITS own source — proving
    # the failure is lineage (cross-source), not a broken proposal.
    assert report["recomputed"]["proposal_grounding_report"]["grounding_integrity"] == "PASS"
    assert report["conclusions"]["proposal_grounding_recomputes"] == "PASS"


def test_altered_source_bytes_declaration() -> None:
    """Altered governed declaration bytes: digest no longer binds."""
    ev = _evidence()
    ev.declaration_bytes = ev.declaration_bytes + b"\x00tamper"
    report = sws.verify(ev)
    assert report["artifact_integrity"] == "FAIL"
    assert "source_work_sequence.declaration_digest_mismatch" in report["failure_codes"]


def test_altered_captured_digest_capture_receipt() -> None:
    """Altered captured-object digest in the capture receipt breaks agreement."""
    ev = _evidence()
    ev.capture_receipt = copy.deepcopy(ev.capture_receipt)
    ev.capture_receipt["exact_bytes_sha256"] = "sha256:" + "a" * 64
    report = sws.verify(ev)
    assert report["capture_linkage"] == "FAIL"
    assert "source_work_sequence.captured_object_digest_disagreement" in report["failure_codes"]


def test_altered_declaration_inventory_key() -> None:
    """Altered inventory key: the R1a identity no longer recomputes."""
    ev = _evidence()
    ev.binding = copy.deepcopy(ev.binding)
    ev.binding["source_inventory_key"] = "TIT-S99"
    report = sws.verify(ev)
    assert report["declaration_binding_linkage"] == "FAIL"
    assert "source_work_sequence.r1a_reference_mismatch" in report["failure_codes"]


def test_altered_declaring_artifact_ref() -> None:
    """Altered declaring_artifact_ref: declaration no longer recomputes/binds."""
    ev = _evidence()
    ev.binding = copy.deepcopy(ev.binding)
    ev.binding["declaring_artifact_ref"] = "sha256:" + "b" * 64
    report = sws.verify(ev)
    assert report["artifact_integrity"] == "FAIL"
    assert report["declaration_binding_linkage"] == "FAIL"


def test_spliced_sessions_foreign_source_capture_identity() -> None:
    """Two individually-valid sessions stitched: the source_capture receipt
    carries a DIFFERENT declaration identity than the session lineage."""
    ev = _evidence()
    ev.source_capture = copy.deepcopy(ev.source_capture)
    foreign_ref = "sha256:" + "c" * 64
    foreign_id = f"urn:counterpedia.source-reference:{foreign_ref}:TIT-S02"
    ev.source_capture["declaring_artifact_ref"] = foreign_ref
    ev.source_capture["source_reference_id"] = foreign_id
    ev.source_capture["subject_ref"] = foreign_id
    report = sws.verify(ev)
    assert report["declaration_binding_linkage"] == "FAIL"
    codes = report["failure_codes"]
    assert "source_work_sequence.source_capture_identity_mismatch" in codes
    assert "source_work_sequence.r1a_reference_mismatch" in codes


def test_unbound_session_cannot_masquerade_as_bound() -> None:
    """An unbound (SRS-source-capture-ineligible) session presented with a
    source_capture receipt must not be accepted as an SRS-bound sequence."""
    ev = _evidence()
    ev.manifest = json.loads((UNBOUND / "session.manifest.json").read_text(encoding="utf-8"))
    ev.capture_receipt = json.loads((UNBOUND / "capture_receipt.json").read_text(encoding="utf-8"))
    report = sws.verify(ev)
    assert report["declaration_binding_linkage"] == "FAIL"
    assert "source_work_sequence.session_not_bound" in report["failure_codes"]


def test_identity_override_cannot_replace_lineage() -> None:
    """A model/prompt-injected derived_source_reference_id (here, the
    acquisition-local URL-derived source_id) cannot override the recomputed R1a
    identity."""
    ev = _evidence()
    ev.binding = copy.deepcopy(ev.binding)
    ev.binding["derived_source_reference_id"] = ev.manifest["source_id"]
    report = sws.verify(ev)
    assert report["declaration_binding_linkage"] == "FAIL"
    assert "source_work_sequence.r1a_reference_mismatch" in report["failure_codes"]


# --------------------------------------------------------------------------- #
# NOT_EVALUATED discipline for the out-of-scope / absent axes
# --------------------------------------------------------------------------- #
def test_unexpected_source_ingest_is_a_finding_not_a_pass() -> None:
    """source_ingest was never emitted; an unexpectedly present source_ingest
    claim is a FAIL finding, not a silent pass, and never NOT_EVALUATED."""
    ev = _evidence()
    ev.extra_receipts = [{"profile_id": "srs.editorial.source_ingest", "profile_version": "v0.1"}]
    report = sws.verify(ev)
    assert report["ingest_linkage"] == "FAIL"
    assert report["recomputed"]["source_ingest_absent"] is False
    assert "source_work_sequence.unexpected_source_ingest_present" in report["failure_codes"]


def test_source_ingest_absence_is_verified_not_assumed() -> None:
    report = sws.verify(_evidence())
    assert report["ingest_linkage"] == "NOT_EVALUATED"
    assert report["recomputed"]["source_ingest_absent"] is True


def test_citation_pack_linkage_not_evaluated_when_absent() -> None:
    report = sws.verify(_evidence())
    assert report["citation_pack_linkage"] == "NOT_EVALUATED"
    assert report["recomputed"]["citation_pack_present"] is False


def test_citation_pack_linkage_reflects_present_pack() -> None:
    ev = _evidence()
    ev.extra_receipts = [{"profile_id": "srs.editorial.citation_pack.v0.1"}]
    report = sws.verify(ev)
    assert report["citation_pack_linkage"] != "NOT_EVALUATED"
    assert report["recomputed"]["citation_pack_present"] is True


def test_external_source_truth_permanently_not_evaluated() -> None:
    report = sws.verify(_evidence())
    assert report["external_source_truth"] == "NOT_EVALUATED"


def test_grounding_summary_claiming_absent_proposal_fails() -> None:
    """If the session claims proposal fields but no proposal is supplied, the
    inconsistency is surfaced rather than passed."""
    ev = _evidence()
    ev.manifest = copy.deepcopy(ev.manifest)
    ev.manifest["grounding_summary"]["proposal_fields"] = 3
    report = sws.verify(ev)
    assert report["proposal_grounding"] == "FAIL"
    assert (
        "source_work_sequence.grounding_summary_claims_unpresented_proposal"
        in report["failure_codes"]
    )


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def test_cli_json_happy_path_exit_zero(capsys) -> None:
    rc = sws.main([str(TIT_S02), "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert out["declaration_binding_linkage"] == "PASS"
    assert out["capture_linkage"] == "PARTIAL"


def test_cli_exit_one_on_fail(tmp_path, capsys) -> None:
    # Materialize a tampered capture receipt to force a FAIL axis via the CLI.
    import shutil
    dst = tmp_path / "tit-s02"
    shutil.copytree(TIT_S02, dst)
    cr = json.loads((dst / "capture_receipt.json").read_text())
    cr["exact_bytes_sha256"] = "sha256:" + "d" * 64
    (dst / "capture_receipt.json").write_text(json.dumps(cr, indent=2))
    rc = sws.main([str(dst), "--json"])
    capsys.readouterr()
    assert rc == 1
