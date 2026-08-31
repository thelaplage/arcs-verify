"""Independent DAGR ResolvedAuthorityContext same-genesis verifier.

This module consumes serialized bytes only. It deliberately imports no
``dagr_runtime`` or ``dagr_sdk`` producer implementation. The candidate contract
is pinned by exact bytes and the producer algorithms needed for independent
recomputation are reimplemented here from reviewed public contract/source bytes.

A PASS means only that the supplied candidate context is structurally/integrity
valid and is independently shown to bind the same exact governed operator-
authority genesis bytes. It does not establish producer authorship, DAGR
ratification, action permission, Countervail authorization, execution, policy
correctness, or truth.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from importlib.resources import files
from typing import Any, Mapping

from jsonschema import Draft202012Validator, FormatChecker


CONTEXT_SCHEMA_ID = "dagr.resolved-authority-context-candidate/v0.1"
CONTEXT_SCHEMA_SOURCE_HEAD = "3af8c8231ff1135bb9837eb5ccf24cbc55ac65b5"
CONTEXT_SCHEMA_SHA256 = (
    "sha256:0467b3bef718fb386b0d30cce871f8b0c1e71342c012b688e9de0f6f04874892"
)
RUNTIME_SOURCE_HEAD = "6d5f16e3fa3ac32cf4ecaa7856b9df46966e65d8"
DAGR_SDK_PIN = "90594775489645a08f6061ad066c761b75572235"
GENESIS_SCHEMA = "dagr.operator-authority-genesis/v0.1"
GENESIS_ID = "dagr-merit-operator-authority-v0.1"
GENESIS_PRINCIPAL_CLASS = "human_principal"
PINNED_GENESIS_DIGEST = (
    "sha256:46b453d61d15946163b7b58336bbeceed4092e867910b6ff56fe1129338b9dc8"
)
AUTHORITY_SOURCE = "operator_authority_profile"

_PROFILE_REVIEW_ROLES: dict[str, list[str]] = {
    "approver": ["approver", "auditor"],
    "editor": ["auditor"],
    "viewer": [],
}

_GENESIS_KEYS = {
    "schema",
    "genesis_id",
    "operator_identity_ref",
    "authority_profile_ref",
    "principal_class",
    "status",
    "effective_from",
    "authority_source_ref",
    "supporting_review_ref",
    "non_equivalences",
    "genesis_digest",
}

_REQUIRED_GENESIS_NON_EQUIVALENCES = {
    "operator authority != merit outcome",
    "resolver success != approve",
    "review eligibility != approve",
    "operator identity != requested_actor_label",
    "merit approval != institutional admission",
    "merit approval != factual truth",
}


@dataclass
class DagrAuthorityContextVerificationReport:
    context_schema_digest: bool = False
    context_schema: bool = False
    context_digest: bool = False
    genesis_shape: bool = False
    genesis_digest: bool = False
    genesis_pin: bool = False
    operator_identity_match: bool = False
    authority_profile_match: bool = False
    review_roles_match: bool = False
    authority_source_match: bool = False
    provenance_match: bool = False
    same_genesis_binding: bool = False
    failure_codes: list[str] = field(default_factory=list)
    details: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.same_genesis_binding

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result.update(
            {
                "passed": self.passed,
                "context_schema_identity": CONTEXT_SCHEMA_ID,
                "context_schema_source_head": CONTEXT_SCHEMA_SOURCE_HEAD,
                "runtime_source_head": RUNTIME_SOURCE_HEAD,
                "dagr_sdk_pin": DAGR_SDK_PIN,
                "pinned_genesis_digest": PINNED_GENESIS_DIGEST,
                "ratification_status": "not_evaluated",
                "producer_authorship": "not_evaluated",
                "action_permission": "not_evaluated",
                "countervail_authorization": "not_evaluated",
                "execution": "not_evaluated",
            }
        )
        return result


def _dedupe(report: DagrAuthorityContextVerificationReport) -> DagrAuthorityContextVerificationReport:
    report.failure_codes = list(dict.fromkeys(report.failure_codes))
    report.details = list(dict.fromkeys(report.details))
    return report


def _sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _strict_json_loads(value: bytes, *, label: str) -> Any:
    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        output: dict[str, Any] = {}
        for key, item in pairs:
            if key in output:
                raise ValueError(f"{label}.duplicate_key:{key}")
            output[key] = item
        return output

    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label}.invalid_utf8") from exc
    try:
        return json.loads(text, object_pairs_hook=no_duplicates)
    except (json.JSONDecodeError, ValueError) as exc:
        if isinstance(exc, ValueError) and str(exc).startswith(f"{label}.duplicate_key:"):
            raise
        raise ValueError(f"{label}.invalid_json") from exc


def _stable_payload_hash(payload: Any) -> str:
    """Independent reimplementation of dagr-sdk stable_payload_hash for JSON data.

    The reviewed runtime pin uses sorted keys, compact separators, UTF-8, and
    ensure_ascii=False before SHA-256. Inputs here are parsed JSON values, so the
    producer helper's non-JSON fallback path is intentionally irrelevant.
    """

    payload_bytes = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return _sha256_bytes(payload_bytes)


def _compute_context_digest(context: Mapping[str, Any]) -> str:
    provenance = context["authority_provenance"]
    preimage = (
        "DAGR-RESOLVED-AUTHORITY-CONTEXT-CANDIDATE-V0.1\n"
        f"schema={context['schema']}\n"
        f"domain={context['domain']}\n"
        f"transaction_id={context['transaction_id']}\n"
        f"transaction_digest={context['transaction_digest']}\n"
        f"operator_identity_ref={context['operator_identity_ref']}\n"
        f"authority_profile_ref={context['authority_profile_ref']}\n"
        f"review_role_count={len(context['review_roles'])}\n"
    )
    for index, role in enumerate(context["review_roles"]):
        preimage += f"review_role_{index}={role}\n"
    preimage += (
        f"authority_source={context['authority_source']}\n"
        f"authority_genesis_id={provenance['genesis_id']}\n"
        f"authority_genesis_digest={provenance['genesis_digest']}\n"
        f"authority_genesis_status={provenance['status']}\n"
        f"authority_effective_from={provenance['effective_from']}\n"
        f"authority_source_ref={provenance['authority_source_ref']}\n"
        f"supporting_review_ref={provenance['supporting_review_ref']}\n"
    )
    return _sha256_bytes(preimage.encode("utf-8"))


def _validate_genesis_shape(genesis: Any) -> list[str]:
    failures: list[str] = []
    if not isinstance(genesis, dict):
        return ["genesis.not_object"]
    if set(genesis) != _GENESIS_KEYS:
        failures.append("genesis.closed_shape_mismatch")
    if genesis.get("schema") != GENESIS_SCHEMA:
        failures.append("genesis.schema_mismatch")
    if genesis.get("genesis_id") != GENESIS_ID:
        failures.append("genesis.id_mismatch")
    if genesis.get("principal_class") != GENESIS_PRINCIPAL_CLASS:
        failures.append("genesis.principal_class_mismatch")
    if genesis.get("status") != "active":
        failures.append("genesis.not_active")
    if genesis.get("authority_profile_ref") not in _PROFILE_REVIEW_ROLES:
        failures.append("genesis.authority_profile_invalid")
    for key in (
        "operator_identity_ref",
        "authority_profile_ref",
        "effective_from",
        "authority_source_ref",
        "supporting_review_ref",
    ):
        value = genesis.get(key)
        if not isinstance(value, str) or not value:
            failures.append(f"genesis.invalid_text:{key}")
    non_equivalences = genesis.get("non_equivalences")
    if not isinstance(non_equivalences, list) or not all(
        isinstance(item, str) for item in non_equivalences
    ):
        failures.append("genesis.non_equivalences_invalid")
    elif set(non_equivalences) != _REQUIRED_GENESIS_NON_EQUIVALENCES:
        failures.append("genesis.non_equivalences_mismatch")
    digest = genesis.get("genesis_digest")
    if (
        not isinstance(digest, str)
        or not digest.startswith("sha256:")
        or len(digest) != 71
        or any(ch not in "0123456789abcdef" for ch in digest[7:])
    ):
        failures.append("genesis.digest_format_invalid")
    return failures


def verify_dagr_authority_context_same_genesis(
    *,
    context_bytes: bytes,
    genesis_bytes: bytes,
    context_schema_bytes: bytes | None = None,
) -> DagrAuthorityContextVerificationReport:
    """Verify candidate context integrity and same-genesis binding from bytes.

    ``producer_authorship`` is deliberately outside this function's claim surface.
    A signed SRS/trust path is a separate verification axis.
    """

    report = DagrAuthorityContextVerificationReport()

    if context_schema_bytes is None:
        context_schema_bytes = files("arcs_verify").joinpath(
            "data/dagr-resolved-authority-context-candidate-3af8c823.schema.json"
        ).read_bytes()

    report.context_schema_digest = _sha256_bytes(context_schema_bytes) == CONTEXT_SCHEMA_SHA256
    if not report.context_schema_digest:
        report.failure_codes.append("context_schema.digest_mismatch")
        return _dedupe(report)

    try:
        schema = _strict_json_loads(context_schema_bytes, label="context_schema")
    except ValueError as exc:
        report.failure_codes.append(str(exc))
        return _dedupe(report)

    try:
        context = _strict_json_loads(context_bytes, label="context")
    except ValueError as exc:
        report.failure_codes.append(str(exc))
        return _dedupe(report)

    try:
        genesis = _strict_json_loads(genesis_bytes, label="genesis")
    except ValueError as exc:
        report.failure_codes.append(str(exc))
        return _dedupe(report)

    try:
        context_errors = sorted(
            Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(context),
            key=lambda error: list(error.absolute_path),
        )
    except Exception as exc:  # invalid pinned schema is a verifier failure, never PASS
        report.failure_codes.append("context_schema.validator_error")
        report.details.append(type(exc).__name__)
        return _dedupe(report)

    if context_errors:
        report.failure_codes.extend("context.schema_invalid" for _ in context_errors)
        report.details.extend(error.message for error in context_errors)
    else:
        report.context_schema = True

    genesis_failures = _validate_genesis_shape(genesis)
    if genesis_failures:
        report.failure_codes.extend(genesis_failures)
    else:
        report.genesis_shape = True

    if report.context_schema:
        recomputed_context_digest = _compute_context_digest(context)
        report.context_digest = recomputed_context_digest == context["authority_context_digest"]
        if not report.context_digest:
            report.failure_codes.append("context.digest_mismatch")

    if report.genesis_shape:
        payload = {key: value for key, value in genesis.items() if key != "genesis_digest"}
        recomputed_genesis_digest = _stable_payload_hash(payload)
        report.genesis_digest = recomputed_genesis_digest == genesis["genesis_digest"]
        if not report.genesis_digest:
            report.failure_codes.append("genesis.digest_mismatch")
        report.genesis_pin = (
            report.genesis_digest
            and recomputed_genesis_digest == PINNED_GENESIS_DIGEST
            and genesis["genesis_digest"] == PINNED_GENESIS_DIGEST
        )
        if not report.genesis_pin:
            report.failure_codes.append("genesis.independent_pin_mismatch")

    if report.context_schema and report.genesis_shape:
        provenance = context["authority_provenance"]
        report.operator_identity_match = (
            context["operator_identity_ref"] == genesis["operator_identity_ref"]
        )
        report.authority_profile_match = (
            context["authority_profile_ref"] == genesis["authority_profile_ref"]
        )
        expected_roles = _PROFILE_REVIEW_ROLES.get(genesis["authority_profile_ref"])
        report.review_roles_match = expected_roles is not None and context["review_roles"] == expected_roles
        report.authority_source_match = context["authority_source"] == AUTHORITY_SOURCE
        report.provenance_match = all(
            (
                provenance["genesis_id"] == genesis["genesis_id"],
                provenance["genesis_digest"] == genesis["genesis_digest"],
                provenance["status"] == genesis["status"],
                provenance["effective_from"] == genesis["effective_from"],
                provenance["authority_source_ref"] == genesis["authority_source_ref"],
                provenance["supporting_review_ref"] == genesis["supporting_review_ref"],
            )
        )

        for ok, code in (
            (report.operator_identity_match, "relation.operator_identity_mismatch"),
            (report.authority_profile_match, "relation.authority_profile_mismatch"),
            (report.review_roles_match, "relation.review_roles_mismatch"),
            (report.authority_source_match, "relation.authority_source_mismatch"),
            (report.provenance_match, "relation.provenance_mismatch"),
        ):
            if not ok:
                report.failure_codes.append(code)

    report.same_genesis_binding = all(
        (
            report.context_schema_digest,
            report.context_schema,
            report.context_digest,
            report.genesis_shape,
            report.genesis_digest,
            report.genesis_pin,
            report.operator_identity_match,
            report.authority_profile_match,
            report.review_roles_match,
            report.authority_source_match,
            report.provenance_match,
        )
    )
    return _dedupe(report)
