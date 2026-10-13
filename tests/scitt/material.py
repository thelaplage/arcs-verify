"""CONSTRUCTED TEST MATERIAL ONLY. No service registration or production keys.

Independent COSE producer and recursive Merkle proof generator: never imports
scitt_cose or production adapter helpers. Standard cryptography/CBOR primitives
are shared dependencies; these are not independent implementations of Ed25519.
"""
import base64
import hashlib
import json

import cbor2
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

ARTIFACT = b'{"receipt_id":"constructed:receipt:1","issued_at":"2000-01-01T00:00:00Z"}'
ISSUER = 'https://issuer.constructed.invalid'
SERVICE = 'https://service.constructed.invalid'
# Public, deterministic TEST seeds. Never suitable for any production use.
ISSUER_KEY = ed25519.Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b'CONSTRUCTED TEST issuer').digest())
SERVICE_KEY = ed25519.Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b'CONSTRUCTED TEST service').digest())
OTHER_KEY = ed25519.Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b'CONSTRUCTED TEST other').digest())


def public(key):
    return key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def b64(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip('=')


def sign(header, payload, *, key=ISSUER_KEY, unprotected=None, detached=False, protected_raw=None):
    protected = cbor2.dumps(header) if protected_raw is None else protected_raw
    to_sign = cbor2.dumps(['Signature1', protected, b'', payload])
    if isinstance(key, ed25519.Ed25519PrivateKey):
        signature = key.sign(to_sign)
    else:
        size = 48 if header[1] == -35 else 32
        algorithm = hashes.SHA384() if size == 48 else hashes.SHA256()
        r, s = decode_dss_signature(key.sign(to_sign, ec.ECDSA(algorithm)))
        signature = r.to_bytes(size, 'big') + s.to_bytes(size, 'big')
    return cbor2.dumps(cbor2.CBORTag(18, [protected, unprotected or {}, None if detached else payload, signature]))


def headers(target=ARTIFACT):
    return {1: -8, 4: b'constructed-issuer', 15: {1: ISSUER, 2: 'ni:///sha-256;' + b64(hashlib.sha256(target).digest())}, 258: -16, 259: 'application/json'}


def statement(target=ARTIFACT, *, header=None, **kw):
    return sign(headers(target) if header is None else header, hashlib.sha256(target).digest(), **kw)


def root(leaves):
    if not leaves:
        return hashlib.sha256(b'').digest()
    if len(leaves) == 1:
        return hashlib.sha256(b'\x00' + leaves[0]).digest()
    split = 1 << ((len(leaves) - 1).bit_length() - 1)
    return hashlib.sha256(b'\x01' + root(leaves[:split]) + root(leaves[split:])).digest()


def path(leaves, index):
    if len(leaves) == 1:
        return []
    split = 1 << ((len(leaves) - 1).bit_length() - 1)
    if index < split:
        return path(leaves[:split], index) + [root(leaves[split:])]
    return path(leaves[split:], index - split) + [root(leaves[:split])]


def receipt(s, *, leaves=None, index=0, key=SERVICE_KEY, header=None, unprotected=None, attached=False, signed_root=None):
    leaves = [s] if leaves is None else leaves
    unsigned = {396: {-1: [cbor2.dumps([len(leaves), index, path(leaves, index)])]}}
    unsigned.update(unprotected or {})
    return sign({1: -8, 395: 1} if header is None else header,
                root(leaves) if signed_root is None else signed_root,
                key=key, unprotected=unsigned, detached=not attached)


def plain(value):
    if hasattr(value, 'items'):
        return {k: plain(v) for k, v in value.items()}
    if isinstance(value, (tuple, list)):
        return [plain(v) for v in value]
    return value


def parts(raw):
    return plain(cbor2.loads(raw).value)


def mutate(raw, slot, value):
    p = parts(raw)
    p[slot] = value
    return cbor2.dumps(cbor2.CBORTag(18, p))


def carried(raw, kind):
    return {'media_type': 'application/scitt-' + kind + '+cose', 'encoding': 'base64url', 'bytes': b64(raw), 'digest': 'sha256:' + hashlib.sha256(raw).hexdigest()}


def entry(s, p, **hints):
    return {'signed_statement': carried(s, 'statement'), 'receipt': carried(p, 'receipt'), **hints}


def sidecar(entries, target=ARTIFACT):
    return {'sidecar_version': 'srs.scitt.registration_sidecar.v0.1', 'binding_id': 'srs.scitt.registration.v0.1',
            'srs_receipt': {'receipt_id': json.loads(target).get('receipt_id', 'constructed'), 'exact_artifact_digest': 'sha256:' + hashlib.sha256(target).hexdigest()},
            'registrations': entries, 'attestation_limits': [
                'SCITT_REGISTRATION_PROVES_ISSUER_STATEMENT_ONLY', 'SCITT_REGISTRATION_NOT_EVENT_TRUTH',
                'SCITT_REGISTRATION_TIME_TS_RECORDED', 'SCITT_REGISTRATION_NOT_REQUIRED_FOR_VALIDITY']}
