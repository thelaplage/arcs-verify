from __future__ import annotations

import arcs_verify
from arcs_verify.dagr_authority_context_producer_landed import (
    verify_dagr_authority_context_producer_receipt,
)


def test_package_exports_landed_authority_context_producer_verifier() -> None:
    assert (
        arcs_verify.verify_dagr_authority_context_producer_receipt
        is verify_dagr_authority_context_producer_receipt
    )
