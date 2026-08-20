"""
Counterpedia Adapter
====================
Wraps the Counterpedia public read API to evaluate its epistemic authorization
behaviour against the benchmark.

Counterpedia context
--------------------
Counterpedia is the public atlas of governed records in the GARP/ARCS ecosystem.
Its responses are governed via the DAGR MCP runtime boundary; every in-scope
action produces a signed SRS receipt.

For benchmark purposes, this adapter:
  1. Constructs an epistemic query from the benchmark case.
  2. Submits it to the Counterpedia API (or CLI fallback).
  3. Extracts the system's stated conclusion and disposition.
  4. Interprets the SRS receipt for the receipt_shape validation.

Configuration
-------------
Set ``COUNTERPEDIA_API_URL`` in the environment, or pass ``api_url`` to the
constructor.  If neither is set, the adapter falls back to the CLI runner
(``counterpedia-cli epistemic-query``).

This adapter is a SKELETON — the ``_call_api`` and ``_parse_response`` methods
must be completed once the Counterpedia epistemic-query endpoint is stable.
"""

from __future__ import annotations

import json
import os
import subprocess
from typing import Any, Optional

# Runner lives one directory up
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from runner import BenchmarkCase, EpistemicSUTAdapter, SUTResponse


class CounterpediaAdapter(EpistemicSUTAdapter):
    """
    Adapter for the Counterpedia governed-records read API.

    The adapter targets the ``/api/epistemic/query`` endpoint (planned).
    Until that endpoint is available, it can fall back to the CLI runner.
    """

    def __init__(
        self,
        api_url: Optional[str] = None,
        cli_command: str = "counterpedia-cli",
        timeout_seconds: int = 30,
    ) -> None:
        self._api_url = api_url or os.environ.get("COUNTERPEDIA_API_URL")
        self._cli = cli_command
        self._timeout = timeout_seconds

    @property
    def name(self) -> str:
        return "Counterpedia"

    @property
    def version(self) -> str:
        # Attempt to read version from package metadata; fall back to placeholder.
        try:
            import importlib.metadata
            return importlib.metadata.version("counterpedia")
        except Exception:
            return "unknown"

    def respond(self, case: BenchmarkCase) -> SUTResponse:
        payload = self._build_payload(case)

        if self._api_url:
            raw = self._call_api(payload)
        else:
            raw = self._call_cli(payload)

        return self._parse_response(case.id, raw)

    # ------------------------------------------------------------------
    # Payload construction
    # ------------------------------------------------------------------

    def _build_payload(self, case: BenchmarkCase) -> dict[str, Any]:
        return {
            "mode": "epistemic_query",
            "evidence": case.input.evidence,
            "source_metadata": case.input.source_metadata,
            "candidate_claim": case.input.candidate_claim,
            "benchmark_case_id": case.id,
            "response_format": "json",
        }

    # ------------------------------------------------------------------
    # Transport
    # ------------------------------------------------------------------

    def _call_api(self, payload: dict[str, Any]) -> dict[str, Any]:
        """
        POST to the Counterpedia epistemic-query API.

        TODO: implement once endpoint is available.
        Raises NotImplementedError until the endpoint is wired.
        """
        raise NotImplementedError(
            "CounterpediaAdapter._call_api: "
            "COUNTERPEDIA_API_URL is set but the endpoint is not yet implemented. "
            "See /api/epistemic/query in the Counterpedia API roadmap."
        )

    def _call_cli(self, payload: dict[str, Any]) -> dict[str, Any]:
        """
        Invoke the Counterpedia CLI for offline / local evaluation.

        Expects the CLI to accept JSON on stdin and return JSON on stdout.
        Command: ``counterpedia-cli epistemic-query --json``
        """
        try:
            proc = subprocess.run(
                [self._cli, "epistemic-query", "--json"],
                input=json.dumps(payload),
                capture_output=True,
                text=True,
                timeout=self._timeout,
            )
        except FileNotFoundError:
            return self._fallback_not_available_response(payload)
        except subprocess.TimeoutExpired:
            return {"error": "timeout", "stated_conclusion": "", "disposition": "deferred_for_review"}

        if proc.returncode != 0:
            return {
                "error": proc.stderr,
                "stated_conclusion": "",
                "disposition": "deferred_for_review",
            }

        try:
            return json.loads(proc.stdout)
        except json.JSONDecodeError:
            return {
                "stated_conclusion": proc.stdout,
                "disposition": "admitted",
                "uncertainty_declared": False,
            }

    def _fallback_not_available_response(self, payload: dict[str, Any]) -> dict[str, Any]:
        """
        Returned when neither API nor CLI is available.
        Records the adapter as not-wired rather than silently passing.
        """
        return {
            "stated_conclusion": (
                "ADAPTER_NOT_WIRED: Counterpedia CLI not found and no API URL configured. "
                "Install the counterpedia-cli or set COUNTERPEDIA_API_URL."
            ),
            "disposition": "deferred_for_review",
            "uncertainty_declared": True,
            "adapter_error": "not_wired",
        }

    # ------------------------------------------------------------------
    # Response parsing
    # ------------------------------------------------------------------

    def _parse_response(self, case_id: str, raw: dict[str, Any]) -> SUTResponse:
        """
        Map the Counterpedia API/CLI response into a SUTResponse.

        Expected response keys (all optional with fallbacks):
          - stated_conclusion (str)
          - disposition (str): admitted | refused | deferred_for_review
          - uncertainty_declared (bool)
          - reasoning_trace (str | null)
          - srs_receipt (dict | null): the ARCS SRS receipt if available
        """
        stated = raw.get("stated_conclusion", "")
        disposition = raw.get("disposition", "admitted")
        if disposition not in ("admitted", "refused", "deferred_for_review"):
            disposition = "admitted"
        uncertainty = raw.get("uncertainty_declared", False)
        trace = raw.get("reasoning_trace", None)
        receipt = raw.get("srs_receipt", None)

        return SUTResponse(
            case_id=case_id,
            stated_conclusion=stated,
            disposition=disposition,
            uncertainty_declared=uncertainty,
            reasoning_trace=trace,
            raw_output={"raw": raw, "srs_receipt": receipt},
        )
