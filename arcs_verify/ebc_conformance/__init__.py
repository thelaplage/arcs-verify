"""Provisional conformance harness for candidate EBC artifacts.

NON-NORMATIVE. This package prototypes conformance checking for
``dagr.candidates.epistemic-boundary-commitment.v0.1`` -- a proposed and
UNRATIFIED doctrine candidate. It has no bearing on any ratified profile,
schema, or verdict elsewhere in this repository, and it is not wired into any
other module in this repository. See ``README.md`` in this directory for the
full scope statement and the list of open normative questions this harness
does not resolve.
"""

from __future__ import annotations

from arcs_verify.ebc_conformance.harness import (
    EBCConclusion,
    EBCConformanceReport,
    EBCFinding,
    verify_ebc_vector,
)

__all__ = [
    "EBCConclusion",
    "EBCConformanceReport",
    "EBCFinding",
    "verify_ebc_vector",
]
