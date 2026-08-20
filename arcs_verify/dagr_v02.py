"""
DAGR v0.1 independent receipt verifier.

INDEPENDENCE CONTRACT: this module imports nothing from dagr-spec,
dagr-runtime, counterpedia, countervail, or amnesiac. It works from
the byte-level contract only.

not_evaluated != PASS
None is not PASS — callers must check `is True`, not just truthiness.
"""

import hashlib
import re

# ── contract constants ────────────────────────────────────────────────────────

SCHEMA_V01 = "dagr.receipt/v0.1"

RESERVED_DOMAINS = frozenset({"evidence", "memory", "action", "organization"})

# vocabulary: ^[a-z][a-z0-9_.-]*/v[0-9]+\.[0-9]+$
_VOCABULARY_RE = re.compile(r"^[a-z][a-z0-9_.-]*/v[0-9]+\.[0-9]+$")

# digest: sha256: + exactly 64 lowercase hex chars
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

# preimage field order (exact)
_PREIMAGE_FIELDS = [
    "schema",
    "receipt_id",
    "domain",
    "producer_id",
    "producer_version",
    "issued_at",
    "subject_digest",
    "input_digest",
    "decision_domain",
    "decision_vocabulary",
    "decision_digest",
    "contract_id",
    "contract_digest",
]


# ── helpers ───────────────────────────────────────────────────────────────────

def _is_digest(value: object) -> bool:
    return isinstance(value, str) and bool(_DIGEST_RE.match(value))


def _safe_str(receipt: dict, *keys: str) -> str | None:
    """
    Walk a chain of keys into nested dicts, return the string leaf or None.
    Never raises.
    """
    node: object = receipt
    for key in keys:
        if not isinstance(node, dict):
            return None
        node = node.get(key)
    return node if isinstance(node, str) else None


def _build_preimage(receipt: dict) -> str | None:
    """
    Build the canonical preimage string from the receipt.
    Returns None if any required field is absent or not a string.
    """
    decision_ref = receipt.get("decision_ref")
    if not isinstance(decision_ref, dict):
        return None
    contract_ref = receipt.get("contract_ref")
    if not isinstance(contract_ref, dict):
        return None

    fields: dict[str, str | None] = {
        "schema":              _safe_str(receipt, "schema"),
        "receipt_id":          _safe_str(receipt, "receipt_id"),
        "domain":              _safe_str(receipt, "domain"),
        "producer_id":         _safe_str(receipt, "producer_id"),
        "producer_version":    _safe_str(receipt, "producer_version"),
        "issued_at":           _safe_str(receipt, "issued_at"),
        "subject_digest":      _safe_str(receipt, "subject_digest"),
        "input_digest":        _safe_str(receipt, "input_digest"),
        "decision_domain":     _safe_str(decision_ref, "domain"),
        "decision_vocabulary": _safe_str(decision_ref, "vocabulary"),
        "decision_digest":     _safe_str(decision_ref, "digest"),
        "contract_id":         _safe_str(contract_ref, "contract_id"),
        "contract_digest":     _safe_str(contract_ref, "digest"),
    }

    if any(v is None for v in fields.values()):
        return None

    lines = ["DAGR-RECEIPT-V0.1"]
    for name in _PREIMAGE_FIELDS:
        lines.append(f"{name}={fields[name]}")

    return "\n".join(lines) + "\n"


# ── public API ────────────────────────────────────────────────────────────────

def verify_dagr_receipt(receipt: dict) -> dict:
    """
    Verify a DAGR v0.1 receipt against the byte-level contract.

    Returns seven separate findings. None is returned for action_vocabulary_closed
    because membership in the decision vocabulary requires the decision preimage,
    which is NOT present in the receipt bytes — only the decision_digest is.
    Returning None for this finding is NOT PASS; it means not_evaluated.

    NOTE on action_vocabulary_closed: The decision record's actual state is
    opaque from the receipt alone. Only its digest is carried. Membership cannot
    be verified from receipt bytes alone. This finding is always None
    (not_evaluated) for ALL domains, including "action". Do NOT check
    decision_ref for a state field — no such field exists in the spec.

    Parameters
    ----------
    receipt : dict
        Parsed receipt object (caller is responsible for JSON decode).

    Returns
    -------
    dict with keys:
        schema_valid            : bool
        domain_qualified        : bool
        vocabulary_declared     : bool
        decision_domain_aligned : bool
        digests_well_formed     : bool
        receipt_digest_match    : bool
        action_vocabulary_closed: None  (always not_evaluated — see note above)
    """

    # ── schema_valid ──────────────────────────────────────────────────────────
    schema = receipt.get("schema") if isinstance(receipt, dict) else None
    schema_valid: bool = schema == SCHEMA_V01

    # ── domain_qualified ─────────────────────────────────────────────────────
    domain = receipt.get("domain") if isinstance(receipt, dict) else None
    domain_qualified: bool = isinstance(domain, str) and domain in RESERVED_DOMAINS

    # ── vocabulary_declared ───────────────────────────────────────────────────
    # vocabulary lives in decision_ref, not at the top level of the receipt
    decision_ref = receipt.get("decision_ref") if isinstance(receipt, dict) else None
    vocabulary = decision_ref.get("vocabulary") if isinstance(decision_ref, dict) else None
    vocabulary_declared: bool = (
        isinstance(vocabulary, str) and bool(_VOCABULARY_RE.match(vocabulary))
    )

    # ── decision_domain_aligned ───────────────────────────────────────────────
    if isinstance(decision_ref, dict):
        decision_domain = decision_ref.get("domain")
        decision_domain_aligned: bool = (
            isinstance(decision_domain, str)
            and isinstance(domain, str)
            and decision_domain == domain
        )
    else:
        decision_domain_aligned = False

    # ── action_vocabulary_closed ──────────────────────────────────────────────
    # INVARIANT: membership in the decision vocabulary requires the decision
    # preimage, not available in receipt bytes. Always not_evaluated (None).
    # None is NOT PASS.
    action_vocabulary_closed: None = None

    # ── digests_well_formed ───────────────────────────────────────────────────
    digest_fields: list[bool] = []

    for top_key in ("subject_digest", "input_digest", "receipt_digest"):
        val = receipt.get(top_key) if isinstance(receipt, dict) else None
        digest_fields.append(_is_digest(val))

    if isinstance(decision_ref, dict):
        digest_fields.append(_is_digest(decision_ref.get("digest")))
    else:
        digest_fields.append(False)

    contract_ref = receipt.get("contract_ref") if isinstance(receipt, dict) else None
    if isinstance(contract_ref, dict):
        digest_fields.append(_is_digest(contract_ref.get("digest")))
    else:
        digest_fields.append(False)

    digests_well_formed: bool = all(digest_fields)

    # ── receipt_digest_match ──────────────────────────────────────────────────
    claimed_digest = receipt.get("receipt_digest") if isinstance(receipt, dict) else None
    preimage = _build_preimage(receipt) if isinstance(receipt, dict) else None

    if preimage is not None and isinstance(claimed_digest, str):
        raw = hashlib.sha256(preimage.encode("utf-8")).hexdigest()
        recomputed = f"sha256:{raw}"
        receipt_digest_match: bool = recomputed == claimed_digest
    else:
        receipt_digest_match = False

    return {
        "schema_valid":             schema_valid,
        "domain_qualified":         domain_qualified,
        "vocabulary_declared":      vocabulary_declared,
        "decision_domain_aligned":  decision_domain_aligned,
        "digests_well_formed":      digests_well_formed,
        "receipt_digest_match":     receipt_digest_match,
        "action_vocabulary_closed": action_vocabulary_closed,
    }
