"""TIT-S02 source_ingest witness coverage for ARCSV-SOURCESEQ0."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from arcs_verify import source_work_sequence as sws

ROOT = Path(__file__).resolve().parents[1]
TIT_S02 = ROOT / "tests" / "fixtures" / "source-work-sequence" / "tit-s02"

SOURCE_INGEST_RECEIPT = "source_ingest.v0_1.receipt.json"
SOURCE_INGEST_EXTRACTED = "source_ingest.extracted.txt"
SOURCE_INGEST_PROVENANCE = "source_ingest.provenance.json"

EXPECTED_SOURCE_ARTIFACT_ID = (
    "sha256:ffdbd3dfde2d776b07783ebeacef5183fa3b7c5e13ca7cd06f90c70bb937f84b"
)
EXPECTED_EXTRACTION_REF = (
    "sha256:c95bf3ff650312c66246c5208ff31ac39ae58636c2574ca783570275347488e8"
)
EXPECTED_PDO_REF = "sha256:0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9"
EXPECTED_CAPTURE_OBSERVATION_REF = "editorial-source-capture-v02-success-TIT-S02-0001"
EXPECTED_PARSER_IDENTITY = "dagr-ingest.pdf"
EXPECTED_PDO_MODULE_IDENTITY = {"module_id": "garp-ingest", "module_version": "0.1.0"}


def _sha256_ref(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _load_evidence(
    *,
    source_ingest: bool = True,
    source_ingest_extraction_bytes: bytes | None = None,
) -> sws.SourceWorkEvidence:
    kwargs = {}
    if source_ingest:
        kwargs["source_ingest_file"] = SOURCE_INGEST_RECEIPT
        kwargs["source_ingest_extraction_file"] = SOURCE_INGEST_EXTRACTED
    evidence = sws.load_sequence(TIT_S02, **kwargs)
    if source_ingest and source_ingest_extraction_bytes is not None:
        evidence.source_ingest_extraction_bytes = source_ingest_extraction_bytes
    if not source_ingest:
        evidence.source_ingest = None
        evidence.source_ingest_extraction_bytes = None
    return evidence


def test_tit_s02_ingest_fixture_bytes_are_pinned() -> None:
    extracted = (TIT_S02 / SOURCE_INGEST_EXTRACTED).read_bytes()
    receipt = (TIT_S02 / SOURCE_INGEST_RECEIPT).read_bytes()
    provenance = (TIT_S02 / SOURCE_INGEST_PROVENANCE).read_bytes()

    assert _sha256_ref(extracted) == EXPECTED_EXTRACTION_REF
    assert _sha256_ref(receipt) == "sha256:0f3bf01285133c0c3ba48de6c437fa5b93542560a1e8e845403b12a126e06ec6"
    assert _sha256_ref(provenance) == "sha256:eb58cd4e4af4152d593e88f2fb0abad6c40c25576e72697a6269f004a270b24c"


def test_tit_s02_source_ingest_linkage_passes() -> None:
    report = sws.verify(_load_evidence())
    assert report["capture_linkage"] == "PARTIAL"
    assert report["ingest_linkage"] == "PASS"
    assert report["recomputed"]["source_ingest_absent"] is False
    assert report["recomputed"]["source_ingest_present"] is True
    assert report["recomputed"]["source_ingest_extraction_ref"] == EXPECTED_EXTRACTION_REF
    assert report["failure_codes"] == []


def test_tit_s02_source_ingest_requires_extraction_bytes() -> None:
    evidence = _load_evidence()
    evidence.source_ingest_extraction_bytes = None
    report = sws.verify(evidence)
    assert report["ingest_linkage"] == "FAIL"
    assert "source_work_sequence.source_ingest_extraction_missing" in report["failure_codes"]


@pytest.mark.parametrize(
    ("mutator", "expected_code"),
    [
        (lambda r: r.__setitem__("source_artifact_id", "sha256:" + "0" * 64), "source_work_sequence.source_ingest_identity_mismatch"),
        (lambda r: r["derivation"].__setitem__("input_hash", "sha256:" + "1" * 64), "source_work_sequence.source_ingest_identity_mismatch"),
        (lambda r: r["derivation"].__setitem__("output_hash", "sha256:" + "2" * 64), "source_work_sequence.source_ingest_identity_mismatch"),
        (lambda r: r.__setitem__("parser_identity", "other.parser"), "source_work_sequence.source_ingest_identity_mismatch"),
        (lambda r: r.__setitem__("capture_observation_ref", "wrong-observation"), "source_work_sequence.source_ingest_identity_mismatch"),
        (lambda r: r.__setitem__("profile_version", "v9.9"), "source_work_sequence.source_ingest_identity_mismatch"),
    ],
)
def test_tit_s02_source_ingest_tamper_vectors_fail(mutator, expected_code) -> None:
    evidence = _load_evidence()
    evidence.source_ingest = copy.deepcopy(evidence.source_ingest)
    mutator(evidence.source_ingest)
    report = sws.verify(evidence)
    assert report["ingest_linkage"] == "FAIL"
    assert expected_code in report["failure_codes"]


def test_tit_s02_source_ingest_with_wrong_extraction_bytes_fails() -> None:
    evidence = _load_evidence()
    evidence.source_ingest_extraction_bytes = b"wrong extraction bytes"
    report = sws.verify(evidence)
    assert report["ingest_linkage"] == "FAIL"
    assert "source_work_sequence.source_ingest_extraction_mismatch" in report["failure_codes"]
