from __future__ import annotations

import hashlib
import json
import shutil
import socket
import zipfile
from pathlib import Path

import pytest

from arcs_verify.portable_pack import (
    PortablePackError,
    TRUST_CONTEXT_SCHEMA,
    create_portable_package,
    verify_portable_package,
)


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "packs" / "srs.mcp.sdk_enforcement" / "v0.1" / "normative" / "valid" / "admission-admitted.json"
KEYRING = ROOT / "packs" / "srs.mcp.sdk_enforcement" / "v0.1" / "normative" / "trust" / "issuer-keys.json"
SCHEMA = ROOT / "arcs_verify" / "data" / "srs-envelope-v0.2.0.schema.json"
PROFILE = "srs.mcp.sdk_enforcement.v0.1"


def _sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _trust_context(tmp_path: Path) -> Path:
    path = tmp_path / "operator-selected-trust-context.json"
    path.write_text(
        json.dumps(
            {
                "schema": TRUST_CONTEXT_SCHEMA,
                "context_id": "test:operator-selected:2026-08-01",
                "issued_at": "2026-08-01T00:00:00Z",
                "keyring_sha256": _sha(KEYRING.read_bytes()),
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return path


def _package(tmp_path: Path, name: str = "receipt.arcs-verify.zip") -> Path:
    path = tmp_path / name
    create_portable_package(
        receipt_path=RECEIPT,
        schema_path=SCHEMA,
        selected_profile=PROFILE,
        output_path=path,
    )
    return path


def test_package_bytes_are_deterministic_and_contain_no_trust_root(tmp_path):
    first = _package(tmp_path, "first.zip")
    second = _package(tmp_path, "second.zip")
    assert first.read_bytes() == second.read_bytes()
    with zipfile.ZipFile(first, "r") as archive:
        assert archive.namelist() == ["manifest.json", "receipt.json", "schema.json"]
        all_names = "\n".join(archive.namelist()).lower()
        assert "keyring" not in all_names
        assert "trust" not in all_names


def test_offline_verification_passes_with_socket_connect_physically_blocked(tmp_path, monkeypatch):
    package = _package(tmp_path)
    context = _trust_context(tmp_path)

    def forbidden_connect(*args, **kwargs):
        raise AssertionError("outbound socket connect attempted during offline verification")

    monkeypatch.setattr(socket.socket, "connect", forbidden_connect)
    result = verify_portable_package(
        package_path=package,
        keyring_path=KEYRING,
        trust_context_path=context,
    )
    assert result.passed is True
    assert result.report["package_integrity"] == "pass"
    assert result.report["freshness_limitations"] == {
        "key_status_after_context_issued_at": "not_evaluated",
        "post_context_revocation_or_compromise": "not_evaluated",
        "current_standing": "not_evaluated",
        "continued_validity": "not_evaluated",
        "real_world_truth": "not_evaluated",
    }


def test_wrong_external_keyring_is_rejected_by_independent_context_pin(tmp_path):
    package = _package(tmp_path)
    context = _trust_context(tmp_path)
    hostile_keyring = tmp_path / "hostile-keyring.json"
    hostile_keyring.write_text('{"trust_bundle_version":"hostile","issuers":[]}', encoding="utf-8")
    with pytest.raises(PortablePackError, match="trust_context_keyring_digest_mismatch"):
        verify_portable_package(
            package_path=package,
            keyring_path=hostile_keyring,
            trust_context_path=context,
        )


def test_package_cannot_self_authorize_by_embedding_trust_material(tmp_path):
    package = _package(tmp_path)
    hostile = tmp_path / "self-authorizing.zip"
    with zipfile.ZipFile(package, "r") as source, zipfile.ZipFile(hostile, "w") as target:
        for info in source.infolist():
            target.writestr(info, source.read(info.filename))
        target.writestr("trust-context.json", _trust_context(tmp_path).read_bytes())
        target.writestr("keyring.json", KEYRING.read_bytes())
    with pytest.raises(PortablePackError, match="package_entry_set_or_order_mismatch"):
        verify_portable_package(
            package_path=hostile,
            keyring_path=KEYRING,
            trust_context_path=_trust_context(tmp_path),
        )


def test_one_byte_semantic_mutation_of_receipt_fails_package_integrity(tmp_path):
    package = _package(tmp_path)
    hostile = tmp_path / "mutated.zip"
    with zipfile.ZipFile(package, "r") as source, zipfile.ZipFile(hostile, "w") as target:
        for info in source.infolist():
            data = source.read(info.filename)
            if info.filename == "receipt.json":
                text = data.decode("utf-8")
                data = text.replace('"decision": "admitted"', '"decision": "refused"', 1).encode("utf-8")
                if data == source.read(info.filename):
                    data = data.replace(b"admitted", b"refused", 1)
            target.writestr(info, data)
    with pytest.raises(PortablePackError, match="package_entry_(digest|size)_mismatch"):
        verify_portable_package(
            package_path=hostile,
            keyring_path=KEYRING,
            trust_context_path=_trust_context(tmp_path),
        )


def test_copying_byte_identical_package_does_not_change_verification(tmp_path):
    package = _package(tmp_path)
    mirror = tmp_path / "mirror.zip"
    shutil.copyfile(package, mirror)
    context = _trust_context(tmp_path)
    first = verify_portable_package(
        package_path=package,
        keyring_path=KEYRING,
        trust_context_path=context,
    )
    second = verify_portable_package(
        package_path=mirror,
        keyring_path=KEYRING,
        trust_context_path=context,
    )
    assert package.read_bytes() == mirror.read_bytes()
    assert first.report == second.report


def test_post_context_revocation_is_never_forced_pass(tmp_path):
    result = verify_portable_package(
        package_path=_package(tmp_path),
        keyring_path=KEYRING,
        trust_context_path=_trust_context(tmp_path),
    )
    assert result.report["freshness_limitations"]["post_context_revocation_or_compromise"] == "not_evaluated"
    assert "pass" not in result.report["freshness_limitations"].values()
