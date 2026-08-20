"""
Amnesiac Adapter
================
Wraps the Amnesiac memory-accountability system for epistemic benchmark
evaluation.

Amnesiac context
----------------
Amnesiac is the memory-accountability wedge in the GARP/ARCS ecosystem.
Its core invariant: ``memory accountability != AI memory``.  It tracks *what
the system believed and when*, not a general-purpose memory store.

For the epistemic benchmark, Amnesiac is particularly relevant for:
  - ``memory_poisoning``    — can Amnesiac detect injected / stale beliefs?
  - ``temporal_invalidity`` — does Amnesiac surface the belief timestamp?
  - ``false_certainty``     — does memory confidence propagate to conclusion
                              confidence, or is it decoupled?

Configuration
-------------
Set ``AMNESIAC_BASE_URL`` (default: ``http://localhost:8001``) and optionally
``AMNESIAC_API_KEY`` in the environment, or pass them to the constructor.

This adapter is a SKELETON — ``_query_amnesiac`` must be wired to the real
Amnesiac HTTP API once the epistemic-query surface stabilizes.
"""

from __future__ import annotations

import json
import os
from typing import Any, Optional

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from runner import BenchmarkCase, EpistemicSUTAdapter, SUTResponse


class AmnesiacAdapter(EpistemicSUTAdapter):
    """
    Adapter for the Amnesiac memory-accountability system.

    Targets the ``POST /v1/epistemic/query`` endpoint (planned).
    Falls back to a structured not-wired response when unavailable.
    """

    DEFAULT_BASE_URL = "http://localhost:8001"

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout_seconds: int = 30,
    ) -> None:
        self._base_url = (
            base_url
            or os.environ.get("AMNESIAC_BASE_URL", self.DEFAULT_BASE_URL)
        ).rstrip("/")
        self._api_key = api_key or os.environ.get("AMNESIAC_API_KEY")
        self._timeout = timeout_seconds

    @property
    def name(self) -> str:
        return "Amnesiac"

    @property
    def version(self) -> str:
        try:
            import importlib.metadata
            return importlib.metadata.version("amnesiac")
        except Exception:
            return "unknown"

    def respond(self, case: BenchmarkCase) -> SUTResponse:
        payload = self._build_payload(case)
        raw = self._query_amnesiac(payload)
        return self._parse_response(case.id, raw)

    # ------------------------------------------------------------------
    # Payload construction
    # ------------------------------------------------------------------

    def _build_payload(self, case: BenchmarkCase) -> dict[str, Any]:
        """
        Build the Amnesiac epistemic query payload.

        The ``memory_context`` field signals Amnesiac to surface any
        stored beliefs related to the evidence sources, enabling the
        adapter to detect memory_poisoning and temporal_invalidity cases.
        """
        return {
            "mode": "epistemic_query",
            "evidence": case.input.evidence,
            "source_metadata": case.input.source_metadata,
            "candidate_claim": case.input.candidate_claim,
            "benchmark_case_id": case.id,
            # Amnesiac-specific: request belief provenance and timestamps
            "memory_context": {
                "include_belief_timestamps": True,
                "include_belief_confidence": True,
                "include_staleness_indicators": True,
            },
            "response_format": "json",
        }

    # ------------------------------------------------------------------
    # Transport
    # ------------------------------------------------------------------

    def _query_amnesiac(self, payload: dict[str, Any]) -> dict[str, Any]:
        """
        POST to the Amnesiac epistemic-query endpoint.

        TODO: implement once POST /v1/epistemic/query is stable.
        Currently returns a not-wired stub response.
        """
        # Attempt HTTP call; fall back gracefully
        try:
            import urllib.request
            import urllib.error

            url = f"{self._base_url}/v1/epistemic/query"
            headers = {"Content-Type": "application/json"}
            if self._api_key:
                headers["Authorization"] = f"Bearer {self._api_key}"

            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode(),
                headers=headers,
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                return json.loads(resp.read().decode())

        except Exception as exc:
            return self._not_available_response(str(exc))

    def _not_available_response(self, error: str) -> dict[str, Any]:
        return {
            "stated_conclusion": (
                "ADAPTER_NOT_WIRED: Amnesiac endpoint not reachable. "
                f"Error: {error}. Set AMNESIAC_BASE_URL or start the Amnesiac server."
            ),
            "disposition": "deferred_for_review",
            "uncertainty_declared": True,
            "adapter_error": "not_wired",
            "belief_timestamps": None,
            "staleness_indicators": None,
        }

    # ------------------------------------------------------------------
    # Response parsing
    # ------------------------------------------------------------------

    def _parse_response(self, case_id: str, raw: dict[str, Any]) -> SUTResponse:
        """
        Map the Amnesiac response to SUTResponse.

        Amnesiac-specific response keys:
          - stated_conclusion (str)
          - disposition (str)
          - uncertainty_declared (bool)
          - belief_timestamps (dict | null): when each piece of evidence was
            first believed; used to flag temporal_invalidity
          - staleness_indicators (list | null): beliefs flagged as stale
          - memory_receipt (dict | null): Amnesiac's SRS receipt for this query
        """
        stated = raw.get("stated_conclusion", "")
        disposition = raw.get("disposition", "admitted")
        if disposition not in ("admitted", "refused", "deferred_for_review"):
            disposition = "admitted"
        uncertainty = raw.get("uncertainty_declared", False)

        # Amnesiac-specific: if staleness detected, force uncertainty
        staleness = raw.get("staleness_indicators") or []
        if staleness:
            uncertainty = True

        trace_parts = []
        if raw.get("belief_timestamps"):
            trace_parts.append(f"belief_timestamps: {json.dumps(raw['belief_timestamps'])}")
        if staleness:
            trace_parts.append(f"staleness_indicators: {staleness}")
        trace = "; ".join(trace_parts) if trace_parts else raw.get("reasoning_trace")

        return SUTResponse(
            case_id=case_id,
            stated_conclusion=stated,
            disposition=disposition,
            uncertainty_declared=uncertainty,
            reasoning_trace=trace,
            raw_output=raw,
        )
