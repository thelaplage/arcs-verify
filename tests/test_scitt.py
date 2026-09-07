from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from scitt_cose import build_receipt, build_signed_statement

from arcs_verify.scitt import NOT_EVALUATED, verify_scitt


def _pem_pair() -> tuple[bytes, bytes]:
    private = ed25519.Ed25519PrivateKey.generate()
    private_pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def _statement(private_pem: bytes, payload: bytes = b'{"event":"refused"}') -> bytes:
    return build_signed_statement(
        payload,
        alg="EdDSA",
        private_key_pem=private_pem,
        issuer="https://issuer.example",
        subject="urn:example:governed-event:1",
        content_type="application/json",
    )


def test_valid_statement_without_receipt_keeps_receipt_not_evaluated() -> None:
    issuer_private, issuer_public = _pem_pair()
    statement = _statement(issuer_private)

    report = verify_scitt(statement, statement_public_key_pem=issuer_public)

    assert report.statement_signature_valid is True
    assert report.statement_required_headers_valid is True
    assert report.receipt_evaluated is False
    assert report.receipt_verification_valid == NOT_EVALUATED
    assert report.passed is True


def test_valid_statement_and_receipt_pass_the_in_scope_checks() -> None:
    issuer_private, issuer_public = _pem_pair()
    log_private, log_public = _pem_pair()
    statement = _statement(issuer_private)
    receipt = build_receipt(
        leaf_entry_hex=statement.hex(),
        leaf_index=0,
        tree_entries_hex=[statement.hex()],
        alg="EdDSA",
        log_private_key_pem=log_private,
    )

    report = verify_scitt(
        statement,
        statement_public_key_pem=issuer_public,
        receipt_bytes=receipt,
        transparency_service_public_key_pem=log_public,
    )

    assert report.statement_signature_valid is True
    assert report.receipt_evaluated is True
    assert report.receipt_verification_valid is True
    assert report.passed is True


def test_wrong_statement_key_fails_without_authenticating_identity() -> None:
    issuer_private, _issuer_public = _pem_pair()
    _wrong_private, wrong_public = _pem_pair()
    statement = _statement(issuer_private)

    report = verify_scitt(statement, statement_public_key_pem=wrong_public)

    assert report.statement_signature_valid is False
    assert report.statement_issuer is None
    assert report.statement_subject is None
    assert "statement.signature_invalid" in report.failure_codes
    assert report.passed is False


def test_receipt_for_other_statement_does_not_bind() -> None:
    issuer_private, issuer_public = _pem_pair()
    log_private, log_public = _pem_pair()
    statement_a = _statement(issuer_private, b"A")
    statement_b = _statement(issuer_private, b"B")
    receipt_for_a = build_receipt(
        leaf_entry_hex=statement_a.hex(),
        leaf_index=0,
        tree_entries_hex=[statement_a.hex()],
        alg="EdDSA",
        log_private_key_pem=log_private,
    )

    report = verify_scitt(
        statement_b,
        statement_public_key_pem=issuer_public,
        receipt_bytes=receipt_for_a,
        transparency_service_public_key_pem=log_public,
    )

    assert report.statement_signature_valid is True
    assert report.receipt_verification_valid is False
    assert report.passed is False


def test_receipt_without_transparency_service_key_fails_explicitly() -> None:
    issuer_private, issuer_public = _pem_pair()
    log_private, _log_public = _pem_pair()
    statement = _statement(issuer_private)
    receipt = build_receipt(
        leaf_entry_hex=statement.hex(),
        leaf_index=0,
        tree_entries_hex=[statement.hex()],
        alg="EdDSA",
        log_private_key_pem=log_private,
    )

    report = verify_scitt(
        statement,
        statement_public_key_pem=issuer_public,
        receipt_bytes=receipt,
    )

    assert report.receipt_verification_valid is False
    assert "receipt.transparency_service_key_missing" in report.failure_codes


def test_reserved_conclusions_never_promote_from_valid_transparency() -> None:
    issuer_private, issuer_public = _pem_pair()
    log_private, log_public = _pem_pair()
    statement = _statement(issuer_private)
    receipt = build_receipt(
        leaf_entry_hex=statement.hex(),
        leaf_index=0,
        tree_entries_hex=[statement.hex()],
        alg="EdDSA",
        log_private_key_pem=log_private,
    )

    data = verify_scitt(
        statement,
        statement_public_key_pem=issuer_public,
        receipt_bytes=receipt,
        transparency_service_public_key_pem=log_public,
    ).to_dict()

    assert data["passed"] is True
    assert set(data["reserved_conclusions"].values()) == {"not_evaluated"}
    assert "verified" not in data
