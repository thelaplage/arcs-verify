"""
DAGR v0.2 independent receipt verifier.

INDEPENDENCE CONTRACT: this module imports nothing from dagr-spec,
dagr-runtime, counterpedia, countervail, or amnesiac. It works from
the byte-level contract only.

Five findings are returned. not_evaluated is never a valid return value.

Receipt validity does not establish:
- producer authentication
- trusted time
- truth
- authorization
- action vocabulary membership (requires the referenced decision record,
  not just the receipt — that is a separate verification surface)
"""

import hashlib
import re

from arcs_verify.dagr_constitutional_consumer import DAGR_CONSTITUTIONAL_CONTRACT_ID

# ── contract constants ────────────────────────────────────────────────────────

RECEIPT_SCHEMA_V01 = "dagr.receipt/v0.1"

RESERVED_DOMAINS = frozenset({"evidence", "memory", "action", "organization"})

# digest: sha256: + exactly 64 lowercase hex chars
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

# preimage field order (exact — must match DAGR_RECEIPT_v0_1.md §4)
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
    return isinstance(value, str) and bool(_DIGEST_RE.fullmatch(value))


def _safe_str(node: object, *keys: str) -> str | None:
    """Walk a chain of keys into nested dicts; return string leaf or None."""
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
    Verify a DAGR v0.2 receipt against the byte-level contract.

    Returns five independent Boolean findings:

        schema_matches          : receipt["schema"] == "dagr.receipt/v0.1"
        domain_qualified        : receipt["domain"] is a reserved DAGR domain
        decision_domain_matches : decision_ref.domain == receipt.domain
        digest_algorithm_valid  : all five digest fields match sha256:<64 hex>
        receipt_digest_match    : recomputed preimage digest == receipt_digest

    What a True result does NOT establish:
        producer_id is authenticated
        issued_at is trusted time
        subject or input bytes exist
        decision bytes are valid or currently authorized
        action vocabulary membership (requires the referenced decision record)
        independent verification by ARCS Verify
        truth of any claim in the receipt

    Parameters
    ----------
    receipt : dict
        Parsed receipt object (caller is responsible for JSON decode).
    """

    if not isinstance(receipt, dict):
        return {
            "schema_matches": False,
            "domain_qualified": False,
            "decision_domain_matches": False,
            "digest_algorithm_valid": False,
            "receipt_digest_match": False,
        }

    # ── schema_matches ────────────────────────────────────────────────────────
    schema_matches: bool = receipt.get("schema") == RECEIPT_SCHEMA_V01

    # ── domain_qualified ─────────────────────────────────────────────────────
    domain = receipt.get("domain")
    domain_qualified: bool = isinstance(domain, str) and domain in RESERVED_DOMAINS

    # ── decision_domain_matches ───────────────────────────────────────────────
    decision_ref = receipt.get("decision_ref")
    if isinstance(decision_ref, dict):
        decision_domain = decision_ref.get("domain")
        decision_domain_matches: bool = (
            isinstance(decision_domain, str)
            and isinstance(domain, str)
            and decision_domain == domain
        )
    else:
        decision_domain_matches = False

    # ── digest_algorithm_valid ────────────────────────────────────────────────
    digest_checks: list[bool] = [
        _is_digest(receipt.get("subject_digest")),
        _is_digest(receipt.get("input_digest")),
        _is_digest(receipt.get("receipt_digest")),
        _is_digest(_safe_str(decision_ref, "digest")) if isinstance(decision_ref, dict) else False,
    ]
    contract_ref = receipt.get("contract_ref")
    digest_checks.append(
        _is_digest(_safe_str(contract_ref, "digest")) if isinstance(contract_ref, dict) else False
    )
    digest_algorithm_valid: bool = all(digest_checks)

    # ── receipt_digest_match ──────────────────────────────────────────────────
    claimed_digest = receipt.get("receipt_digest")
    preimage = _build_preimage(receipt)

    if preimage is not None and isinstance(claimed_digest, str):
        recomputed = "sha256:" + hashlib.sha256(preimage.encode("utf-8")).hexdigest()
        receipt_digest_match: bool = recomputed == claimed_digest
    else:
        receipt_digest_match = False

    return {
        "schema_matches": schema_matches,
        "domain_qualified": domain_qualified,
        "decision_domain_matches": decision_domain_matches,
        "digest_algorithm_valid": digest_algorithm_valid,
        "receipt_digest_match": receipt_digest_match,
        "dagr_constitution_id": DAGR_CONSTITUTIONAL_CONTRACT_ID,
    }
