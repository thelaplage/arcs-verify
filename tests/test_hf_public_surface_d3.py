from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
SPEC_PATH = (
    REPO_ROOT
    / "public_artifacts"
    / "hf-public-surface"
    / "d3-v0.1"
    / "input-spec.json"
)
MATERIALIZER_PATH = REPO_ROOT / "tools" / "materialize_hf_d3_v0_1.py"
SOURCE_COMMIT = "87ee2d7f223a645a54acda805a22361036102eb4"
DOCTRINE_COMMIT = "48b08000feeeb5ce5f6f7e46d14dd534c99fea0a"


def _load_materializer():
    spec = importlib.util.spec_from_file_location(
        "materialize_hf_d3_v0_1", MATERIALIZER_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _source_pin_available() -> bool:
    proc = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "cat-file", "-e", f"{SOURCE_COMMIT}^{{commit}}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return proc.returncode == 0


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_d3_input_spec_is_bounded_and_nonpublishing():
    spec = json.loads(SPEC_PATH.read_text(encoding="utf-8"))

    assert spec["schema"] == "arcs.hf_public_surface.d3_input.v0.1"
    assert spec["status"] == "candidate_not_published"
    assert spec["source"]["commit"] == SOURCE_COMMIT
    assert spec["doctrine"]["ratification_commit"] == DOCTRINE_COMMIT
    assert spec["doctrine"]["candidate"] == "D3"

    assert spec["case_set"]["valid_count"] == 5
    assert spec["case_set"]["mutation_count"] == 7
    assert spec["case_set"]["total_count"] == 12

    boundary = spec["publication_boundary"]
    assert boundary == {
        "hf_publication_authorized": False,
        "hf_jobs_authorized": False,
        "hf_namespace_assumed": False,
        "webmcp_included": False,
        "synthetic_cases_included": False,
    }

    assert spec["license"]["spdx"] == "Apache-2.0"
    assert len(spec["authority_inputs"]["profile_documents"]) == 2
    assert "no epistemic truth, no authority, and no trust policy" in spec[
        "bounded_statement"
    ]


@pytest.mark.skipif(
    not _source_pin_available(),
    reason="historical D3 source pin unavailable in shallow checkout",
)
def test_materializes_exact_twelve_case_candidate_from_historical_pin(tmp_path):
    module = _load_materializer()
    out = tmp_path / "d3"

    result = module.materialize(repo_root=REPO_ROOT, out_dir=out)

    assert result["source_commit"] == SOURCE_COMMIT
    assert result["case_count"] == 12
    assert result["valid_count"] == 5
    assert result["mutation_count"] == 7

    manifest_path = out / "DATASET_MANIFEST.json"
    sums_path = out / "SHA256SUMS.txt"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    assert manifest["schema"] == "arcs.hf_public_surface.d3_dataset.v0.1"
    assert manifest["status"] == "release_candidate_not_published"
    assert manifest["source"]["commit"] == SOURCE_COMMIT
    assert manifest["doctrine"]["ratification_commit"] == DOCTRINE_COMMIT
    assert manifest["counts"] == {"valid": 5, "mutations": 7, "total": 12}
    assert manifest["publication_boundary"]["hf_publication_authorized"] is False
    assert manifest["publication_boundary"]["hf_jobs_authorized"] is False
    assert manifest["publication_boundary"]["webmcp_included"] is False
    assert manifest["publication_boundary"]["synthetic_cases_included"] is False

    case_paths = [row["path"] for row in manifest["cases"]]
    assert len(case_paths) == 12
    assert len(set(case_paths)) == 12
    assert sum(path.startswith("cases/valid/") for path in case_paths) == 5
    assert sum(path.startswith("cases/mutations/") for path in case_paths) == 7
    assert all("webmcp" not in path.lower() for path in case_paths)

    # Every copied source payload is independently digest-checkable from the
    # generated manifest, and the checksum file binds exactly the same set.
    file_rows = manifest["files"]
    assert len(file_rows) == 19  # 12 cases + 7 authority/support files
    for row in file_rows:
        assert _sha256(out / row["path"]) == row["sha256"]
        assert (out / row["path"]).stat().st_size == row["byte_length"]

    sums = sums_path.read_text(encoding="utf-8").splitlines()
    expected_sums = {
        f"{row['sha256']}  {row['path']}" for row in manifest["files"]
    }
    assert set(sums) == expected_sums
    assert hashlib.sha256(sums_path.read_bytes()).hexdigest() == manifest[
        "sha256sums_sha256"
    ]

    assert (out / "authority" / "srs-envelope-v0.2.0.schema.json").is_file()
    assert (
        out
        / "authority"
        / "profiles"
        / "SRS_SIGNED_RECEIPT_PROFILE_v0_1.md"
    ).is_file()
    assert (
        out
        / "authority"
        / "profiles"
        / "SRS_MCP_SDK_ENFORCEMENT_PROFILE_v0_1.md"
    ).is_file()
    assert (out / "trust" / "issuer-keys.json").is_file()
    assert (out / "expected" / "expectations.json").is_file()
    assert (out / "LICENSE").is_file()


@pytest.mark.skipif(
    not _source_pin_available(),
    reason="historical D3 source pin unavailable in shallow checkout",
)
def test_materializer_refuses_overwrite(tmp_path):
    module = _load_materializer()
    out = tmp_path / "d3"
    out.mkdir()

    with pytest.raises(module.MaterializationError, match="already exists"):
        module.materialize(repo_root=REPO_ROOT, out_dir=out)


def test_materializer_contains_no_hf_network_or_jobs_client():
    source = MATERIALIZER_PATH.read_text(encoding="utf-8")

    forbidden = (
        "huggingface_hub",
        "HfApi",
        "requests.",
        "httpx.",
        "hf jobs",
        "run_job",
    )
    for token in forbidden:
        assert token not in source
