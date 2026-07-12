from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from arcs_verify.verifier import verify_receipt

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "arcs_verify/data/srs-envelope-v0.2.0.schema.json"

TOP_LEVEL_KEYS = {"profile", "keyring", "receipts"}
RECEIPT_ENTRY_KEYS = {"path", "verdicts", "expected_failure_codes"}
BOOLEAN_VERDICT_KEYS = {
    "schema_digest",
    "envelope",
    "profile",
    "raw_content_exclusion",
    "signature_valid",
    "issuer_key_resolved",
    "issuer_key_trusted",
    "attestation_limits_present",
}
VERDICT_KEYS = BOOLEAN_VERDICT_KEYS | {"chain_status"}

EXPECTATION_PATHS = tuple(
    sorted(
        ROOT.glob(
            "packs/*/*/implementation/*/expectations.json"
        )
    )
)


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return value


def _contained_file(directory: Path, relative: str, *, label: str) -> Path:
    if not isinstance(relative, str) or not relative:
        raise ValueError(f"{label} must be a non-empty string")

    base = directory.resolve()
    candidate = (directory / relative).resolve()

    if candidate.parent != base:
        raise ValueError(f"{label} must name a file in {directory}")
    if not candidate.is_file():
        raise ValueError(f"{label} does not exist: {candidate}")

    return candidate


def _validate_expectations(
    document: dict[str, Any],
    expectations_path: Path,
) -> None:
    if set(document) != TOP_LEVEL_KEYS:
        raise ValueError(
            f"{expectations_path}: top-level keys must be exactly "
            f"{sorted(TOP_LEVEL_KEYS)}"
        )

    profile = document["profile"]
    keyring = document["keyring"]
    receipts = document["receipts"]

    if not isinstance(profile, str) or not profile:
        raise ValueError(f"{expectations_path}: profile must be non-empty")

    _contained_file(
        expectations_path.parent,
        keyring,
        label="keyring",
    )

    if not isinstance(receipts, list) or not receipts:
        raise ValueError(
            f"{expectations_path}: receipts must be a non-empty list"
        )

    seen_paths: set[str] = set()

    for index, entry in enumerate(receipts):
        prefix = f"{expectations_path}: receipts[{index}]"

        if not isinstance(entry, dict):
            raise ValueError(f"{prefix} must be an object")

        if set(entry) != RECEIPT_ENTRY_KEYS:
            raise ValueError(
                f"{prefix} keys must be exactly "
                f"{sorted(RECEIPT_ENTRY_KEYS)}"
            )

        receipt_path = entry["path"]
        _contained_file(
            expectations_path.parent,
            receipt_path,
            label=f"{prefix}.path",
        )

        if receipt_path in seen_paths:
            raise ValueError(f"{prefix}.path is duplicated")
        seen_paths.add(receipt_path)

        verdicts = entry["verdicts"]
        if not isinstance(verdicts, dict):
            raise ValueError(f"{prefix}.verdicts must be an object")

        if set(verdicts) != VERDICT_KEYS:
            missing = sorted(VERDICT_KEYS - set(verdicts))
            extra = sorted(set(verdicts) - VERDICT_KEYS)
            raise ValueError(
                f"{prefix}.verdicts must contain exactly the nine "
                f"verdict keys; missing={missing}; extra={extra}"
            )

        for key in BOOLEAN_VERDICT_KEYS:
            if not isinstance(verdicts[key], bool):
                raise ValueError(
                    f"{prefix}.verdicts.{key} must be boolean"
                )

        if not isinstance(verdicts["chain_status"], str):
            raise ValueError(
                f"{prefix}.verdicts.chain_status must be a string"
            )

        failure_codes = entry["expected_failure_codes"]
        if (
            not isinstance(failure_codes, list)
            or not all(isinstance(code, str) for code in failure_codes)
        ):
            raise ValueError(
                f"{prefix}.expected_failure_codes must be a string list"
            )


def _discover_cases() -> tuple[tuple[Path, int, str], ...]:
    cases: list[tuple[Path, int, str]] = []

    for expectations_path in EXPECTATION_PATHS:
        document = _load_json(expectations_path)
        _validate_expectations(document, expectations_path)

        for index, entry in enumerate(document["receipts"]):
            cases.append(
                (
                    expectations_path,
                    index,
                    f"{expectations_path.parent.name}:{entry['path']}",
                )
            )

    return tuple(cases)


IMPLEMENTATION_CASES = _discover_cases()


def _evaluate_case(
    expectations_path: Path,
    entry_index: int,
    *,
    entry_override: dict[str, Any] | None = None,
) -> list[str]:
    document = _load_json(expectations_path)
    _validate_expectations(document, expectations_path)

    entry = (
        copy.deepcopy(entry_override)
        if entry_override is not None
        else document["receipts"][entry_index]
    )

    receipt_path = _contained_file(
        expectations_path.parent,
        entry["path"],
        label="receipt path",
    )
    keyring_path = _contained_file(
        expectations_path.parent,
        document["keyring"],
        label="keyring",
    )

    receipt = _load_json(receipt_path)
    keyring = _load_json(keyring_path)

    report = verify_receipt(
        receipt,
        keyring,
        schema_path=SCHEMA_PATH,
        selected_profile=document["profile"],
    )
    actual = report.to_dict()
    expected = entry["verdicts"]

    mismatches: list[str] = []

    for key in sorted(VERDICT_KEYS):
        if actual[key] != expected[key]:
            mismatches.append(
                f"{entry['path']} {key}: "
                f"expected {expected[key]!r}, got {actual[key]!r}"
            )

    if actual["failure_codes"] != entry["expected_failure_codes"]:
        mismatches.append(
            f"{entry['path']} failure_codes: expected "
            f"{entry['expected_failure_codes']!r}, got "
            f"{actual['failure_codes']!r}"
        )

    return mismatches


def test_implementation_expectations_are_discovered() -> None:
    assert EXPECTATION_PATHS, (
        "no implementation expectations discovered under "
        "packs/*/*/implementation/*/expectations.json"
    )
    assert IMPLEMENTATION_CASES, (
        "implementation expectations contain no receipt cases"
    )


@pytest.mark.parametrize(
    ("expectations_path", "entry_index", "_case_name"),
    IMPLEMENTATION_CASES,
    ids=[case[2] for case in IMPLEMENTATION_CASES],
)
def test_implementation_fixture_full_verdict_vector(
    expectations_path: Path,
    entry_index: int,
    _case_name: str,
) -> None:
    mismatches = _evaluate_case(expectations_path, entry_index)
    assert not mismatches, "\n".join(mismatches)


def test_negative_control_detects_flipped_verdict() -> None:
    if not IMPLEMENTATION_CASES:
        pytest.fail("no implementation case available for negative control")

    expectations_path, entry_index, _ = IMPLEMENTATION_CASES[0]
    document = _load_json(expectations_path)
    mutated = copy.deepcopy(document["receipts"][entry_index])

    original = mutated["verdicts"]["signature_valid"]
    mutated["verdicts"]["signature_valid"] = not original

    mismatches = _evaluate_case(
        expectations_path,
        entry_index,
        entry_override=mutated,
    )

    assert mismatches
    assert any("signature_valid" in mismatch for mismatch in mismatches)


@pytest.mark.parametrize("mutation", ["missing", "extra"])
def test_expectations_reject_missing_or_extra_verdict_keys(
    mutation: str,
) -> None:
    if not EXPECTATION_PATHS:
        pytest.fail("no implementation expectations available")

    expectations_path = EXPECTATION_PATHS[0]
    document = _load_json(expectations_path)
    mutated = copy.deepcopy(document)
    verdicts = mutated["receipts"][0]["verdicts"]

    if mutation == "missing":
        del verdicts["schema_digest"]
    else:
        verdicts["unknown_verdict"] = True

    with pytest.raises(
        ValueError,
        match="exactly the nine verdict keys",
    ):
        _validate_expectations(mutated, expectations_path)
