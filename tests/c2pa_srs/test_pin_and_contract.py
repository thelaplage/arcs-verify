"""The vendored arcs-srs profile bytes are pinned in code and re-hashed on load."""
import hashlib
import json
import shutil

import pytest

from arcs_verify import c2pa_srs_observed as adapter
from arcs_verify.schema import ENVELOPE_SCHEMA_PINS

CONTRACT = adapter.CONTRACT_DIR


def _copy_contract(tmp_path):
    dest = tmp_path / "contract"
    shutil.copytree(CONTRACT, dest)
    return dest


def test_vendored_files_match_the_code_held_pin():
    for name, (sha, blob) in adapter.PINNED_CONTRACT_FILES.items():
        data = (CONTRACT / name).read_bytes()
        assert hashlib.sha256(data).hexdigest() == sha, name
        assert adapter._git_blob_sha1(data) == blob, name


def test_contract_directory_holds_exactly_the_pinned_files_and_the_provenance_record():
    assert {p.name for p in CONTRACT.iterdir()} == set(adapter.PINNED_CONTRACT_FILES) | {"source-pin.json"}


def test_source_pin_record_agrees_with_the_code_held_pin():
    record = json.loads((CONTRACT / "source-pin.json").read_text())
    assert record["source_commit"] == adapter.SOURCE_COMMIT == "3219ff83eb47f46582eefbd53dc46a9d78ef5d4b"
    assert record["profile_slug"] == adapter.PROFILE_SLUG
    assert record["release_stage"] == "provisional" and record["requires_signing"] is False
    for name, (sha, blob) in adapter.PINNED_CONTRACT_FILES.items():
        assert record["files"][name]["sha256"] == sha
        assert record["files"][name]["git_blob"] == blob
    assert record["binding_manifest"]["semantic_digest"] == adapter.BINDING_SEMANTIC_DIGEST
    assert record["profile_manifest_projection_sha256"] == adapter.PROFILE_MANIFEST_PROJECTION_SHA256


def test_profile_manifest_projection_digest_is_the_value_arcs_srs_records():
    manifest = json.loads((CONTRACT / "profile.manifest.json").read_text())
    projection = {k: v for k, v in manifest.items() if k not in ("document_sha256", "notes")}
    canonical = json.dumps(projection, sort_keys=True, separators=(",", ":")).encode("utf-8")
    assert hashlib.sha256(canonical).hexdigest() == adapter.PROFILE_MANIFEST_PROJECTION_SHA256


def test_envelope_identity_is_the_pinned_v0_2_1_schema():
    data = adapter.ENVELOPE_SCHEMA_PATH.read_bytes()
    assert hashlib.sha256(data).hexdigest() == ENVELOPE_SCHEMA_PINS["v0.2.1"]
    manifest = json.loads((CONTRACT / "profile.manifest.json").read_text())
    identities = [i["identity"] for i in manifest["compatible_envelope_identities"]]
    assert identities == ["srs-envelope@0.2.1+sha256:" + ENVELOPE_SCHEMA_PINS["v0.2.1"]]


def test_profile_is_provisional_and_unsigned_in_the_pinned_manifest():
    manifest = json.loads((CONTRACT / "profile.manifest.json").read_text())
    assert manifest["release_stage"] == "provisional"
    assert manifest["requires_signing"] is False


@pytest.mark.parametrize("name", sorted(adapter.PINNED_CONTRACT_FILES))
def test_tampered_vendored_file_is_refused_loudly(tmp_path, name):
    root = _copy_contract(tmp_path)
    (root / name).write_bytes((root / name).read_bytes() + b" ")
    with pytest.raises(adapter.ContractPinError):
        adapter._load_contract_cached(str(root))


@pytest.mark.parametrize("name", sorted(adapter.PINNED_CONTRACT_FILES))
def test_sha256_pin_is_enforced_on_its_own(monkeypatch, name):
    _, blob = adapter.PINNED_CONTRACT_FILES[name]
    monkeypatch.setitem(adapter.PINNED_CONTRACT_FILES, name, ("0" * 64, blob))
    with pytest.raises(adapter.ContractPinError, match="pinned sha256"):
        adapter._load_contract_cached(str(CONTRACT) + "/.")


@pytest.mark.parametrize("name", sorted(adapter.PINNED_CONTRACT_FILES))
def test_git_blob_pin_is_enforced_on_its_own(monkeypatch, name):
    sha, _ = adapter.PINNED_CONTRACT_FILES[name]
    monkeypatch.setitem(adapter.PINNED_CONTRACT_FILES, name, (sha, "0" * 40))
    with pytest.raises(adapter.ContractPinError, match="pinned git blob"):
        adapter._load_contract_cached(str(CONTRACT) + "/./")


def test_provenance_record_cannot_move_the_pin(tmp_path):
    root = _copy_contract(tmp_path)
    record = json.loads((root / "source-pin.json").read_text())
    record["source_commit"] = "0" * 40
    (root / "source-pin.json").write_text(json.dumps(record))
    with pytest.raises(adapter.ContractPinError, match="source_commit"):
        adapter._load_contract_cached(str(root))


def test_provenance_record_disagreeing_on_a_file_digest_is_refused(tmp_path):
    root = _copy_contract(tmp_path)
    record = json.loads((root / "source-pin.json").read_text())
    record["files"]["field.schema.json"]["sha256"] = "0" * 64
    (root / "source-pin.json").write_text(json.dumps(record))
    with pytest.raises(adapter.ContractPinError, match="disagrees"):
        adapter._load_contract_cached(str(root))


def test_envelope_schema_substitution_is_refused(tmp_path, monkeypatch):
    altered = tmp_path / "envelope.json"
    altered.write_bytes(adapter.ENVELOPE_SCHEMA_PATH.read_bytes() + b" ")
    monkeypatch.setattr(adapter, "ENVELOPE_SCHEMA_PATH", altered)
    with pytest.raises(adapter.ContractPinError, match="envelope"):
        adapter._load_contract_cached(str(CONTRACT) + "/././")


def test_intact_contract_loads_and_exposes_the_pinned_profile():
    contract = adapter._load_contract()
    assert contract.manifest["profile_slug"] == adapter.PROFILE_SLUG
    assert contract.rules["profile_slug"] == adapter.PROFILE_SLUG
    assert contract.registry["version"] == "0.1"
