"""Experimental offline adapter for the pinned SRS SCITT handoff.

No service requests, certificate discovery, SRS validity verdict, time policy,
or portable trust-bundle format. Native COSE/Merkle operations are delegated to
an exact source-pinned scitt-cose backend. Owner acceptance remains outstanding.
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import io
import json
import math
import re
import sys
from dataclasses import dataclass
from importlib.metadata import version
from pathlib import Path

from jsonschema import Draft202012Validator

CONTRACT = Path(__file__).parent / "contracts/scitt-registration/v0.1"
MAX_BYTES = 10 * 1024 * 1024
MAX_ENTRIES = 128
VERIFIER = "arcs-verify.scitt-registration/experimental-2"


class InputError(ValueError):
    """Input/invocation error; not a verification verdict."""


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _json_digest(value) -> str:
    return digest(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def _contracts():
    pin = json.loads((CONTRACT / "source-pin.json").read_bytes())
    loaded = {}
    for name, source in pin["files"].items():
        data = (CONTRACT / name).read_bytes()
        if digest(data) != "sha256:" + source["sha256"]:
            raise InputError("SCITT contract source digest mismatch")
        loaded[name] = json.loads(data)
    return pin, loaded


def _backend(pin):
    try:
        import cbor2
        import scitt_cose
    except ImportError as exc:
        raise InputError("install the scitt optional dependency group") from exc
    for package, expected in (("cbor2", "6.1.4"), ("cryptography", "46.0.7"), ("jsonschema", "4.26.0")):
        if version(package) != expected:
            raise InputError(f"unexpected {package} version for this experimental adapter")
    root = Path(scitt_cose.__file__).parent
    for name, expected in pin["backend"]["files"].items():
        if digest((root / name).read_bytes()) != "sha256:" + expected:
            raise InputError("SCITT native backend source digest mismatch")
    return cbor2, scitt_cose

@dataclass(frozen=True)
class SelectedKey:
    """Caller-selected local public key and identity, never carrier-selected.

    policy=None means no trust appraisal was requested. A named local policy
    records the caller decision; it is never inferred from a valid signature.
    This API input is not a new portable trust-bundle contract.
    """
    identity: str
    public_key_pem: bytes
    policy: dict | None = None

    def context(self):
        if not isinstance(self.identity, str) or not self.identity:
            raise InputError("selected key identity must be nonempty")
        if self.policy is not None and (
            not isinstance(self.policy, dict) or set(self.policy) != {"id", "decision"}
            or not isinstance(self.policy["id"], str) or not self.policy["id"]
            or self.policy["decision"] not in ("accept", "reject")
        ):
            raise InputError("policy requires a nonempty id and accept/reject decision")
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519
        try:
            key = serialization.load_pem_public_key(self.public_key_pem)
        except (ValueError, TypeError) as exc:
            raise InputError("selected key must be a local public PEM key") from exc
        if not isinstance(key, (ed25519.Ed25519PublicKey, ec.EllipticCurvePublicKey)):
            raise InputError("selected public key type is unsupported")
        der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        return {"identity": self.identity, "public_key_digest": digest(der), "policy": copy.deepcopy(self.policy)}


@dataclass(frozen=True)
class Selection:
    """Explicit per-entry selection. Carrier hints never choose keys/policies."""
    statement_key: SelectedKey | None = None
    service_key: SelectedKey | None = None
    proof_index: int = 0

    def context(self, pin):
        if type(self.proof_index) is not int or self.proof_index < 0:
            raise InputError("proof_index must be a nonnegative integer")
        return {
            "selected_proof": {"header": 396, "type": -1, "index": self.proof_index},
            "proof_profile": "RFC9942/RFC9162_SHA256",
            "verifier": VERIFIER, "backend_commit": pin["backend"]["commit"],
            "cbor2": "6.1.4", "cryptography": version("cryptography"),
            "trust_policy": {
                "statement_issuer": self.statement_key.context() if self.statement_key else None,
                "transparency_service": self.service_key.context() if self.service_key else None,
            },
            "time_policy": None, "binding_semantic_digest": pin["semantic_digest"],
        }

def _decode(raw, cbor):
    if not isinstance(raw, bytes) or len(raw) > MAX_BYTES:
        raise ValueError("CBOR byte limit")
    stream = io.BytesIO(raw)
    value = cbor.CBORDecoder(stream, read_size=1, max_depth=48, allow_duplicate_keys=False).decode()
    if stream.read(1):
        raise ValueError("trailing CBOR bytes")
    return value


def _plain(value):
    if hasattr(value, "items"):
        return {k: _plain(v) for k, v in value.items()}
    if isinstance(value, (tuple, list)):
        return [_plain(v) for v in value]
    return value


def _envelope(raw, cbor):
    tagged = _decode(raw, cbor)
    if not isinstance(tagged, cbor.CBORTag) or tagged.tag != 18:
        raise ValueError("tagged COSE_Sign1 required by this adapter")
    parts = _plain(tagged.value)
    if not isinstance(parts, list) or len(parts) != 4:
        raise ValueError("COSE_Sign1 shape")
    protected_raw, unprotected, payload, signature = parts
    if not isinstance(protected_raw, bytes) or not isinstance(unprotected, dict):
        raise ValueError("COSE header shape")
    protected = _plain(_decode(protected_raw, cbor)) if protected_raw else {}
    if not isinstance(protected, dict) or not isinstance(signature, bytes):
        raise ValueError("COSE protected header/signature shape")
    if payload is not None and not isinstance(payload, bytes):
        raise ValueError("COSE payload shape")
    if any(type(k) not in (int, str) for k in (*protected, *unprotected)):
        raise ValueError("COSE label type")
    if set(protected) & set(unprotected):
        raise ValueError("COSE header buckets overlap")
    return protected, parts


def _carried(obj):
    if not isinstance(obj, dict) or obj.get("encoding") != "base64url":
        raise ValueError("byte carrier shape")
    text = obj.get("bytes")
    if not isinstance(text, str) or len(text) > (MAX_BYTES * 4 // 3 + 4):
        raise ValueError("byte carrier limit")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", text):
        raise ValueError("base64url syntax")
    raw = base64.b64decode(text + "=" * (-len(text) % 4), altchars=b"-_", validate=True)
    if base64.urlsafe_b64encode(raw).decode().rstrip("=") != text or digest(raw) != obj.get("digest"):
        raise ValueError("byte carrier digest/encoding")
    return raw



def _critical_shape(header):
    if 2 in header:
        value = header[2]
        if not isinstance(value, list) or not value or any(type(k) not in (int, str) for k in value):
            raise ValueError("invalid critical header labels")
        if len(set(value)) != len(value):
            raise ValueError("duplicate critical header labels")

def _algorithm_supported(alg, selected):
    if type(alg) is not int or alg not in (-8, -7, -35):
        return False
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519
    key = serialization.load_pem_public_key(selected.public_key_pem)
    return ((alg == -8 and isinstance(key, ed25519.Ed25519PublicKey))
            or (alg == -7 and isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP256R1))
            or (alg == -35 and isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP384R1)))


def verify_registration(sidecar, *, target: bytes | None, selection: Selection | None = None,
                        entry_selections: dict[int, Selection] | None = None):
    """Evaluate carried relationships offline, with no cache across calls.

    Each entry uses its explicitly supplied selection or the default selection.
    The caller must associate service keys with entry indexes, never with hints.
    CCF, key discovery and registration-time policy evaluation are unsupported.
    """
    pin, contracts = _contracts()
    cbor, native = _backend(pin)
    if target is not None and not isinstance(target, bytes):
        raise InputError("target must be exact bytes or absent")
    selection = selection or Selection()
    default_context = selection.context(pin)
    entry_selections = entry_selections or {}
    if not isinstance(entry_selections, dict) or any(type(i) is not int or i < 0 for i in entry_selections):
        raise InputError("entry selections require nonnegative integer indexes")
    contexts = {i: value.context(pin) for i, value in entry_selections.items()}
    findings = [f["id"] for f in contracts["verifier-handoff.json"]["findings"]]
    blank = {name: "not_evaluated" for name in findings}
    report = {"status": "EXPERIMENTAL_NOT_OWNER_ACCEPTED", "default_context": default_context, "relationships": [], "entry_observations": [],
              "limitations": ["No SRS validity, event truth, custody, consistency or submission authorization finding.",
                              "No portable trust bundle, certificate discovery, CCF or registration-time profile support.",
                              "Tagged COSE with native-backend encoding support only; not full binding acceptance."]}
    if sidecar is None:
        report["relationships"].append({"evaluation_identity": None, "findings": blank,
                                        "reason_codes": ["SCITT_REGISTRATION_NOT_SUPPLIED"]})
        return report
    if not isinstance(sidecar, dict) or not isinstance(sidecar.get("registrations"), list):
        raise InputError("sidecar must contain a registrations array")
    entries = sidecar["registrations"]
    if any(i >= len(entries) for i in entry_selections):
        raise InputError("entry selection index outside registrations")
    if not 1 <= len(entries) <= MAX_ENTRIES:
        raise InputError("sidecar registration count outside adapter limits")
    if len({_json_digest(e) for e in entries}) != len(entries):
        raise InputError("exact duplicate registration entries violate schema uniqueItems")
    # Invalid carried byte fields route via R02; other schema failures are input
    # errors. Validate a sanitized copy only for entries whose bytes failed,
    # preserving the original object for R02 and never parsing those COSE bytes.
    schema_copy = copy.deepcopy(sidecar)
    decoded = []
    for i, entry in enumerate(entries):
        try:
            s = _carried(entry.get("signed_statement"))
            p = _carried(entry.get("receipt"))
            decoded.append((s, p))
        except (ValueError, TypeError, AttributeError):
            decoded.append(None)
            if isinstance(entry, dict):
                for name, media in (("signed_statement", "application/scitt-statement+cose"), ("receipt", "application/scitt-receipt+cose")):
                    schema_copy["registrations"][i][name] = {"media_type": media, "encoding": "base64url", "bytes": base64.urlsafe_b64encode(str(i).encode()).decode().rstrip("="), "digest": digest(str(i).encode())}
    schema = copy.deepcopy(contracts["sidecar.schema.json"])
    # Original uniqueItems was checked above; sanitized placeholders must not
    # introduce false duplicates with another entry.
    schema["properties"]["registrations"]["uniqueItems"] = False
    if list(Draft202012Validator(schema).iter_errors(schema_copy)):
        raise InputError("sidecar schema validation failed")
    results = {}
    for index, pair in enumerate(decoded):
        observation = {"entry_index": index, "reason_codes": []}
        report["entry_observations"].append(observation)
        if pair is None:
            report["relationships"].append({"evaluation_identity": None, "entry_index": index,
                                            "findings": dict(blank), "reason_codes": ["SCITT_CARRIER_BYTES_INVALID"]})
            continue
        statement, receipt = pair
        chosen = entry_selections.get(index, selection)
        context = contexts.get(index, default_context)
        identity = {"target_artifact_digest": digest(target) if target is not None else None,
                    "signed_statement_digest": digest(statement), "receipt_digest": digest(receipt),
                    "context_digest": _json_digest(context)}
        key = _json_digest(identity)
        observation["evaluation_key"] = key
        if target is not None and key in results:
            observation["reason_codes"].append("SCITT_DUPLICATE_ENTRY")
            result = results[key]
        else:
            result = {"evaluation_identity": identity, "evaluation_key": key, "context": context, "findings": dict(blank), "reason_codes": []}
            _evaluate(result, target, statement, receipt, chosen.statement_key, chosen.service_key, chosen.proof_index, cbor, native, contracts)
            results[key] = result
            report["relationships"].append(result)
        observation["registration_time_reported"] = {
            "provenance": "unauthenticated" if "registration_time_hint" in entries[index] else "absent",
            "source": "sidecar", "value": entries[index].get("registration_time_hint"),
        }
        authenticated = result.get("authenticated_service_identity")
        hint = entries[index].get("transparency_service", {}).get("service_id")
        if authenticated and hint and hint != authenticated:
            observation["reason_codes"].append("SCITT_SERVICE_HINT_DISAGREEMENT")
        if target is not None and sidecar["srs_receipt"]["exact_artifact_digest"] != digest(target):
            observation["reason_codes"].append("SCITT_TARGET_HINT_DISAGREEMENT")
        if target is not None:
            if "byte_size" in sidecar["srs_receipt"] and sidecar["srs_receipt"]["byte_size"] != len(target):
                observation["reason_codes"].append("SCITT_TARGET_SIZE_HINT_DISAGREEMENT")
            try:
                receipt_id = json.loads(target).get("receipt_id")
            except (ValueError, AttributeError):
                receipt_id = None
            if receipt_id is not None and receipt_id != sidecar["srs_receipt"]["receipt_id"]:
                observation["reason_codes"].append("SCITT_RECEIPT_ID_HINT_DISAGREEMENT")
    # No independent-source count: unique relationships are not unique sources.
    report["relationships"].sort(key=lambda r: r.get("evaluation_key", "") + str(r.get("entry_index", "")))
    return report


def _evaluate(result, target, statement, receipt, statement_key, service_key, proof_index, cbor, native, contracts):
    f, reasons = result["findings"], result["reason_codes"]
    try:
        header, parts = _envelope(statement, cbor)
    except (ValueError, TypeError, RecursionError, cbor.CBORDecodeError):
        for name in ("registration_statement_profile", "registration_subject_binding", "registration_statement_signature", "registration_receipt_inclusion"):
            f[name] = "fail"
        reasons.append("SCITT_STATEMENT_MALFORMED")
        return
    claims = header.get(15)
    profile = contracts["binding-rules.json"]["signed_statement"]
    labels = {h["label"] for h in profile["protected_header_allowlist"]}
    valid = (set(header) <= labels and {1, 15, 258, 259} <= set(header) and not parts[1] and type(header.get(1)) is int
             and bool(set(header) & {4, 33, 34}) and isinstance(parts[2], bytes)
             and isinstance(claims, dict) and set(claims) == {1, 2}
             and all(type(k) is int for k in claims)
             and all(isinstance(claims[k], str) and claims[k] for k in (1, 2)))
    if 4 in header and not isinstance(header[4], bytes):
        valid = False
    if 33 in header and not (isinstance(header[33], bytes) or
                             isinstance(header[33], list) and header[33] and all(isinstance(v, bytes) for v in header[33])):
        valid = False
    if 34 in header and not (isinstance(header[34], list) and len(header[34]) == 2
                             and type(header[34][0]) in (str, int) and isinstance(header[34][1], bytes)):
        valid = False
    if 260 in header and not isinstance(header[260], str):
        valid = False
    f["registration_statement_profile"] = "pass" if valid else "fail"
    if valid and set(header) & {33, 34}:
        f["registration_statement_profile"] = "not_evaluated"
        reasons.append("SCITT_CERTIFICATE_REFERENCE_PROFILE_UNSUPPORTED")
    if target is not None:
        expected = hashlib.sha256(target).digest()
        subject = "ni:///sha-256;" + base64.urlsafe_b64encode(expected).decode().rstrip("=")
        bound = (type(header.get(258)) is int and header[258] == -16 and header.get(259) == "application/json"
                 and parts[2] == expected and isinstance(claims, dict) and claims.get(2) == subject)
        f["registration_subject_binding"] = "pass" if bound else "fail"
    issuer = claims.get(1) if isinstance(claims, dict) else None
    if statement_key and statement_key.identity == issuer:
        try:
            native.cose_sign1.strict_decode(statement)
            encoding_supported = True
        except native.CoseError:
            encoding_supported = False
            reasons.append("SCITT_STATEMENT_ENCODING_UNSUPPORTED_BY_BACKEND")
        if encoding_supported and _algorithm_supported(header.get(1), statement_key):
            try:
                _critical_shape(header)
                native.verify_sign1(statement, public_key_pem=statement_key.public_key_pem)
                f["registration_statement_signature"] = "pass"
            except (native.CoseError, ValueError, TypeError):
                f["registration_statement_signature"] = "fail"
        elif encoding_supported:
            reasons.append("SCITT_STATEMENT_ALGORITHM_UNSUPPORTED_OR_KEY_MISMATCH")
        if statement_key.policy is not None:
            f["statement_issuer_trusted"] = "pass" if statement_key.policy["decision"] == "accept" else "fail"
    try:
        proof_header, proof_parts = _envelope(receipt, cbor)
        if type(proof_header.get(1)) is not int or type(proof_header.get(395)) is not int:
            raise ValueError("missing Receipt headers")
        if proof_header[395] != 1:
            reasons.append("SCITT_PROOF_PROFILE_UNSUPPORTED")
            return
        proofs = proof_parts[1].get(396, {}).get(-1)
        if not isinstance(proofs, list) or not proofs or len(proofs) > 16 or proof_index >= len(proofs):
            raise ValueError("proof selection")
        for proof in proofs:
            _decode(proof, cbor)  # Duplicate keys/trailing bytes checked before native interpretation.
            native.receipt._decode_inclusion_proof(proof)
        # RFC9597 requires CWT Claims to be a map with int/text labels in
        # either header bucket. The native backend otherwise ignores malformed
        # values, which could turn a malformed Receipt into inclusion PASS.
        for bucket in (proof_header, proof_parts[1]):
            if 15 in bucket:
                claims = bucket[15]
                if not isinstance(claims, dict) or any(type(k) not in (int, str) for k in claims):
                    raise ValueError("malformed Receipt CWT Claims")
        _critical_shape(proof_header)
        # This profile implements alg and vds processing, but no application
        # semantics for critical CWT Claims. A map shape check is not enough to
        # claim understanding of arbitrary claims or a registration-time policy.
        native.cose_sign1._check_critical_headers(proof_header, {1, 2, 395})
        if 2 in proof_parts[1]:
            raise ValueError("crit must be protected")
        selected_proof = proofs[proof_index]
    except (ValueError, TypeError, AttributeError, RecursionError, cbor.CBORDecodeError, native.CoseError):
        f["registration_receipt_inclusion"] = "fail"
        reasons.append("SCITT_RECEIPT_MALFORMED_OR_PROOF_SELECTION_INVALID")
        return
    unprotected_claims = proof_parts[1].get(15)
    unprotected_time = unprotected_claims.get(6) if isinstance(unprotected_claims, dict) else None
    if type(unprotected_time) is float and not math.isfinite(unprotected_time):
        unprotected_time = None
    result["registration_time_reported"] = {
        "provenance": "unauthenticated" if unprotected_time is not None else "absent",
        "source": "receipt_unprotected_cwt_iat", "value": unprotected_time if type(unprotected_time) in (str, int, float) else None,
    }
    try:
        native.cose_sign1.strict_decode(receipt)
    except native.CoseError:
        reasons.append("SCITT_RECEIPT_ENCODING_UNSUPPORTED_BY_BACKEND")
        return
    if service_key is None:
        return
    if service_key.policy is not None:
        f["transparency_service_trusted"] = "pass" if service_key.policy["decision"] == "accept" else "fail"
    if not _algorithm_supported(proof_header.get(1), service_key):
        reasons.append("SCITT_RECEIPT_ALGORITHM_UNSUPPORTED_OR_KEY_MISMATCH")
        return
    # Pin one proof explicitly. This derived native invocation changes only the
    # unsigned proof collection; protected bytes, signature and payload remain
    # exact. The finding identity always retains the ORIGINAL Receipt digest.
    selected_parts = copy.deepcopy(proof_parts)
    selected_parts[1][396][-1] = [selected_proof]
    selected_receipt = cbor.dumps(cbor.CBORTag(18, selected_parts))
    # RFC9942 applies the proof to candidate entry bytes. Do NOT substitute a
    # statement digest merely because a substrate example uses digest leaves.
    outcome = native.verify_receipt(selected_receipt, leaf_entry_hex=statement.hex(), log_public_key_pem=service_key.public_key_pem)
    # The pinned backend verifies an attached payload directly. Independently
    # require equality to its reconstructed root: a signature over a different
    # attached root must never yield inclusion PASS (R09/R10).
    attached_matches = proof_parts[2] is None or (outcome.root is not None and proof_parts[2] == bytes.fromhex(outcome.root))
    f["registration_receipt_inclusion"] = "pass" if outcome.ok and attached_matches else "fail"
    if f["registration_receipt_inclusion"] == "pass":
        result["authenticated_service_identity"] = service_key.identity
        result["selected_proof_digest"] = digest(selected_proof)
    # Neither signed iat nor sidecar/unprotected times define a registration
    # time policy. This prototype deliberately leaves that finding unevaluated.


def _unique_json(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InputError("duplicate JSON key")
        result[key] = value
    return result


def read_selection(path: Path):
    """Experimental local JSON input; no URLs, private keys or implicit trust."""
    raw = path.read_bytes()
    if len(raw) > MAX_BYTES:
        raise InputError("selection input exceeds adapter limit")
    value = json.loads(raw, object_pairs_hook=_unique_json)
    schema = json.loads((CONTRACT / "local-selection.schema.json").read_bytes())
    if list(Draft202012Validator(schema).iter_errors(value)):
        raise InputError("local selection schema validation failed")
    def parse(obj):
        def key(role):
            k = obj.get(role)
            return SelectedKey(k["identity"], k["public_key_pem"].encode(), k.get("policy")) if k else None
        return Selection(key("statement_issuer"), key("transparency_service"), obj.get("proof_index", 0))
    return parse(value.get("default", {})), {int(i): parse(v) for i, v in value.get("entries", {}).items()}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Experimental offline SRS SCITT adapter; separate findings, no aggregate verdict.")
    parser.add_argument("sidecar", type=Path)
    parser.add_argument("--artifact", type=Path)
    parser.add_argument("--selection", type=Path, help="explicit local role-separated public keys and named policies")
    args = parser.parse_args(argv)
    try:
        raw = args.sidecar.read_bytes()
        if len(raw) > MAX_BYTES * 3:
            raise InputError("sidecar exceeds adapter byte limit")
        selection, entries = read_selection(args.selection) if args.selection else (Selection(), {})
        report = verify_registration(json.loads(raw, object_pairs_hook=_unique_json),
                                     target=args.artifact.read_bytes() if args.artifact else None,
                                     selection=selection, entry_selections=entries)
        print(json.dumps(report, indent=2, allow_nan=False))
        # Zero means a report was produced, never an aggregate verification pass.
        return 0
    except (InputError, OSError, ValueError) as exc:
        print(f"scitt-registration input error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
