"""OKF-ARCS-BRIDGE0 — verifier-side bindings for OKF v0.2 "Attested Computation"
declarations.

INDEPENDENCE CONTRACT
  This module imports NOTHING from OpenKnowledge, any OKF reference
  implementation, or any producer/runtime/emitter repository. It consumes
  three serialized inputs supplied by the caller:

    declaration.md   — an OKF "Attested Computation" declaration: a Markdown
                        file whose top-of-file YAML frontmatter carries the
                        declaration fields (see SUPPORTED SURFACE below).
    bundle_root/      — a local directory under which the declaration's
                        `executor.resource` and `attester.resource` paths are
                        resolved. Resolution is safe-path-only: no network
                        fetch, no traversal outside the root, no symlink
                        escape.
    run.json          — separately supplied, serialized run evidence (a JSON
                        object) that a caller asserts came from running the
                        declared executor.

THIS IS NOT AN EXECUTION ENGINE.
  Despite the name "Attested Computation", this module never executes the
  referenced executor or attester resource. It treats both as opaque bytes
  and independently recomputes their content digests. Whether the supplied
  run evidence actually resulted from running the named executor is outside
  what static, serialized bytes can prove; that gap is preserved as
  `not_evaluated`, not quietly assumed away.

SUPPORTED SURFACE (OKF v0.2 "Attested Computation", minimum interoperable
subset — see docs/OKF_ARCS_BRIDGE0.md for the full interoperability note)
  type                 — must equal "Attested Computation"
  runtime              — free-form declared runtime identifier (opaque string)
  parameters           — optional flat mapping (opaque; never a source of
                          authority, never interpreted for control flow)
  executor.resource    — path (relative to bundle_root) to the executor
                          resource
  executor.receipt     — list of field names the OKF declaration says a run
                          of the executor should return
  attester.resource    — path (relative to bundle_root) to the attester
                          resource

  Any other frontmatter key is read and ignored. An unrecognized key can
  never grant authority, flip a conclusion, or otherwise change a finding —
  see test_unknown_frontmatter_key_is_inert in the accompanying test suite.

  The upstream OKF format deliberately leaves the runtime receipt/verdict
  protocol (i.e. what it *means* for an executor to have "passed", or how an
  attester's opinion is structurally encoded) outside the static bundle.
  Bridge0 treats that absence as a boundary, not as an invitation to invent a
  universal OKF receipt protocol. `executor.receipt` is verified only for
  field-name *presence* in the supplied run evidence; no value semantics are
  assumed.

PARSING / DEPENDENCY DECISION
  No YAML dependency exists anywhere in this repository's dependency graph
  (see pyproject.toml: cryptography, rfc8785, jsonschema only), and this
  lane's surface is a narrow, block-style, single-document subset: scalar
  key: value pairs, one level of nested mapping (executor / attester), and
  flat lists of scalars (executor.receipt). Rather than casually widen the
  dependency footprint with a general-purpose YAML engine (arbitrary tags,
  anchors, multi-document streams, flow collections — none of which this
  surface needs and all of which enlarge the reviewed attack surface for a
  verifier that reads untrusted bytes), this module ships a small,
  intentionally-restricted block-YAML-subset frontmatter parser scoped to
  exactly the constructs the supported surface requires. It is not a general
  YAML parser and rejects (via OKFDeclarationError, surfaced as the
  `okf_attested_computation.declaration_malformed` failure code) anything
  outside that subset — tabs, flow collections (`{...}` / `[...]`), anchors,
  multi-line scalars, and unterminated frontmatter fences all fail closed
  rather than being silently approximated. If a future lane needs the full
  OKF surface (multi-document bundles, richer scalar folding, etc.), that is
  the point to reconsider a real YAML dependency — not before.

NON-EQUIVALENCES (always present in every report — see NON_EQUIVALENCES)
  "okf_declaration != execution"
  "declared_receipt_shape != verified_event"
  "resource_digest_match != truth"
  "arcs_finding != dagr_authority"
  "verifier != producer"
  "receipt_field_present != executor_ran_correctly"

RESERVED CONCLUSIONS (permanent constants — never promoted by any finding)
  execution_verified          = "not_evaluated"
  attester_verdict_verified   = "not_evaluated"
  truth_verified               = "not_evaluated"
  authority_conferred          = False
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Literal

# ── contract constants ─────────────────────────────────────────────────────

DECLARATION_TYPE = "Attested Computation"

_SHA256_PREFIX = "sha256:"

NON_EQUIVALENCES: tuple[str, ...] = (
    "okf_declaration != execution",
    "declared_receipt_shape != verified_event",
    "resource_digest_match != truth",
    "arcs_finding != dagr_authority",
    "verifier != producer",
    "receipt_field_present != executor_ran_correctly",
)


class OKFDeclarationError(ValueError):
    """The declaration text is not a well-formed instance of the narrow
    block-YAML-subset frontmatter this module supports."""


# ── narrow block-YAML-subset frontmatter parser ────────────────────────────
#
# Supports exactly: `---`-fenced frontmatter, blank lines, `#` full-line
# comments, `key: value` scalar pairs, one level (or more, symmetrically) of
# nested mapping via indentation, and `- item` lists of scalars. Scalars are
# unquoted strings, single/double-quoted strings, `true`/`false`, `null`/`~`,
# and plain integers/floats. No flow collections, no anchors/aliases, no
# multi-line scalars, no tabs.

_INT_RE = re.compile(r"-?\d+")
_FLOAT_RE = re.compile(r"-?\d+\.\d+")


def _parse_scalar(raw: str) -> Any:
    raw = raw.strip()
    if raw == "":
        return None
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "\"'":
        return raw[1:-1]
    if raw == "true":
        return True
    if raw == "false":
        return False
    if raw in ("null", "~"):
        return None
    if _INT_RE.fullmatch(raw):
        return int(raw)
    if _FLOAT_RE.fullmatch(raw):
        return float(raw)
    return raw


def _tokenize(text: str) -> list[tuple[int, str]]:
    tokens: list[tuple[int, str]] = []
    for raw_line in text.split("\n"):
        if "\t" in raw_line:
            raise OKFDeclarationError(
                "tab characters are not supported in frontmatter indentation"
            )
        if not raw_line.strip():
            continue
        stripped = raw_line.lstrip(" ")
        indent = len(raw_line) - len(stripped)
        content = stripped.rstrip()
        if content.startswith("#"):
            continue
        tokens.append((indent, content))
    return tokens


def _parse_list(tokens: list[tuple[int, str]], i: int, indent: int) -> tuple[list[Any], int]:
    result: list[Any] = []
    n = len(tokens)
    while i < n:
        tok_indent, content = tokens[i]
        if tok_indent < indent:
            break
        if tok_indent > indent:
            raise OKFDeclarationError(f"unexpected indentation in list item: {content!r}")
        if not content.startswith("- "):
            break
        result.append(_parse_scalar(content[2:]))
        i += 1
    return result, i


def _parse_mapping(tokens: list[tuple[int, str]], i: int, indent: int) -> tuple[dict[str, Any], int]:
    result: dict[str, Any] = {}
    n = len(tokens)
    while i < n:
        tok_indent, content = tokens[i]
        if tok_indent < indent:
            break
        if tok_indent > indent:
            raise OKFDeclarationError(f"unexpected indentation: {content!r}")
        if content.startswith("- "):
            raise OKFDeclarationError(f"unexpected list item outside a list context: {content!r}")
        if "{" in content or "[" in content:
            raise OKFDeclarationError(f"flow collections are not supported: {content!r}")
        if ":" not in content:
            raise OKFDeclarationError(f"expected 'key: value': {content!r}")
        key, _, rest = content.partition(":")
        key = key.strip()
        if not key:
            raise OKFDeclarationError(f"empty key: {content!r}")
        rest = rest.strip()
        i += 1
        if rest == "":
            if i < n and tokens[i][0] > indent:
                next_indent, next_content = tokens[i]
                if next_content.startswith("- "):
                    value: Any
                    value, i = _parse_list(tokens, i, next_indent)
                else:
                    value, i = _parse_mapping(tokens, i, next_indent)
            else:
                value = None
        else:
            value = _parse_scalar(rest)
        result[key] = value
    return result, i


def parse_frontmatter(text: str) -> dict[str, Any]:
    """Parse the leading `---`-fenced YAML-subset frontmatter block.

    Raises OKFDeclarationError if the file does not open with a `---` fence,
    the fence is never closed, or the block violates the narrow supported
    grammar. The Markdown body after the closing fence is not read; this
    bridge binds declared fields and resources, not document prose.
    """
    lines = text.split("\n")
    if not lines or lines[0].strip() != "---":
        raise OKFDeclarationError("declaration does not open with a '---' frontmatter fence")
    end_idx = None
    for idx in range(1, len(lines)):
        if lines[idx].strip() == "---":
            end_idx = idx
            break
    if end_idx is None:
        raise OKFDeclarationError("frontmatter fence is never closed")
    fm_text = "\n".join(lines[1:end_idx])
    tokens = _tokenize(fm_text)
    if not tokens:
        return {}
    mapping, consumed = _parse_mapping(tokens, 0, tokens[0][0])
    if consumed != len(tokens):
        raise OKFDeclarationError("trailing content in frontmatter block could not be parsed")
    return mapping


# ── safe resource resolution under bundle_root ─────────────────────────────


def _safe_resource_path(bundle_root: Path, raw: Any) -> Path:
    """Resolve a declared resource path safely under bundle_root.

    Rejects (raises ValueError): non-string / empty values, absolute paths,
    `..` segments, and any resolved path that escapes bundle_root (including
    via a symlink, since resolution follows symlinks before the containment
    check runs).
    """
    if not isinstance(raw, str) or not raw:
        raise ValueError("resource path must be a non-empty string")
    if raw.startswith("./") or "/./" in raw or raw.endswith("/."):
        raise ValueError(f"unsafe resource path: {raw!r}")
    posix = PurePosixPath(raw)
    if posix.is_absolute() or ".." in posix.parts:
        raise ValueError(f"unsafe resource path: {raw!r}")
    base_resolved = bundle_root.resolve()
    resolved = (bundle_root / Path(*posix.parts)).resolve()
    try:
        resolved.relative_to(base_resolved)
    except ValueError as exc:
        raise ValueError(f"resource path escapes bundle root: {raw!r}") from exc
    return resolved


def _sha256_bytes(data: bytes) -> str:
    return _SHA256_PREFIX + hashlib.sha256(data).hexdigest()


def _is_sha256_ref(value: Any) -> bool:
    if not isinstance(value, str) or not value.startswith(_SHA256_PREFIX):
        return False
    hex_part = value[len(_SHA256_PREFIX):]
    return len(hex_part) == 64 and all(c in "0123456789abcdef" for c in hex_part.lower()) and hex_part == hex_part.lower()


# ── report shape ────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class OKFBridgeFinding:
    """Verifier-side findings for one OKF Attested Computation declaration.

    declaration_valid / resource_bindings_valid / receipt_shape_satisfied are
    Booleans: this bridge always reaches a concrete verdict for them from the
    supplied bytes (they are False, not not_evaluated, when a precondition —
    e.g. a resource file being unreachable — prevents a positive finding).

    execution_verified, attester_verdict_verified, and truth_verified are
    permanent reserved conclusions: always "not_evaluated". authority_conferred
    is a permanent reserved constant: always False. None of the three
    Booleans above can promote any of these four.
    """

    declaration_valid: bool
    resource_bindings_valid: bool
    receipt_shape_satisfied: bool
    executor_resource_digest: str | None
    attester_resource_digest: str | None
    execution_verified: Literal["not_evaluated"]
    attester_verdict_verified: Literal["not_evaluated"]
    truth_verified: Literal["not_evaluated"]
    authority_conferred: Literal[False]
    non_equivalences: tuple[str, ...]
    failure_codes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def passed(self) -> bool:
        return (
            self.declaration_valid
            and self.resource_bindings_valid
            and self.receipt_shape_satisfied
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "declaration_valid": self.declaration_valid,
            "resource_bindings_valid": self.resource_bindings_valid,
            "receipt_shape_satisfied": self.receipt_shape_satisfied,
            "executor_resource_digest": self.executor_resource_digest,
            "attester_resource_digest": self.attester_resource_digest,
            "execution_verified": self.execution_verified,
            "attester_verdict_verified": self.attester_verdict_verified,
            "truth_verified": self.truth_verified,
            "authority_conferred": self.authority_conferred,
            "non_equivalences": list(self.non_equivalences),
            "failure_codes": list(self.failure_codes),
            "passed": self.passed,
        }


def _reserved(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "declaration_valid": False,
        "resource_bindings_valid": False,
        "receipt_shape_satisfied": False,
        "executor_resource_digest": None,
        "attester_resource_digest": None,
        "execution_verified": "not_evaluated",
        "attester_verdict_verified": "not_evaluated",
        "truth_verified": "not_evaluated",
        "authority_conferred": False,
        "non_equivalences": NON_EQUIVALENCES,
    }
    base.update(overrides)
    return base


# ── verification core ───────────────────────────────────────────────────────


def verify(
    declaration_text: str | None,
    declaration_error: str | None,
    bundle_root: Path,
    run_evidence: dict[str, Any] | None,
    run_evidence_error: str | None,
) -> OKFBridgeFinding:
    """Independently verify an OKF Attested Computation declaration.

    Args:
        declaration_text: raw bytes (decoded) of declaration.md, or None if
            declaration_error is set (the caller already found it unreadable
            at the I/O level — a source-integrity condition, not this
            function's concern).
        declaration_error: non-None means declaration_text could not even be
            obtained (usage/source-integrity concern, handled by the CLI at
            exit 2, not surfaced through this function's failure_codes).
        bundle_root: directory resources are safely resolved under.
        run_evidence: parsed run-evidence JSON object, or None if
            run_evidence_error is set.
        run_evidence_error: non-None means the run evidence file could not be
            read (source-integrity; handled by the CLI).

    Never executes any referenced resource. Never fetches over the network.
    """
    findings: list[str] = []

    if declaration_error is not None or declaration_text is None:
        # Source-integrity condition: the CLI is expected to have already
        # exited 2 in this case. verify() still returns a coherent all-false
        # report rather than raising, so library callers get a report object.
        findings.append("okf_attested_computation.declaration_malformed")
        return OKFBridgeFinding(**_reserved(failure_codes=tuple(findings)))

    try:
        frontmatter = parse_frontmatter(declaration_text)
    except OKFDeclarationError:
        findings.append("okf_attested_computation.declaration_malformed")
        return OKFBridgeFinding(**_reserved(failure_codes=tuple(findings)))

    if not isinstance(frontmatter, dict):
        findings.append("okf_attested_computation.declaration_malformed")
        return OKFBridgeFinding(**_reserved(failure_codes=tuple(findings)))

    declared_type = frontmatter.get("type")
    if declared_type != DECLARATION_TYPE:
        findings.append("okf_attested_computation.wrong_type")

    runtime = frontmatter.get("runtime")
    if not isinstance(runtime, str) or not runtime:
        findings.append("okf_attested_computation.missing_runtime")

    executor = frontmatter.get("executor")
    executor_resource_raw: Any = None
    executor_receipt_fields: list[str] | None = None
    if not isinstance(executor, dict):
        findings.append("okf_attested_computation.missing_executor_resource")
        findings.append("okf_attested_computation.missing_executor_receipt")
    else:
        executor_resource_raw = executor.get("resource")
        if not isinstance(executor_resource_raw, str) or not executor_resource_raw:
            findings.append("okf_attested_computation.missing_executor_resource")
            executor_resource_raw = None
        receipt_raw = executor.get("receipt")
        if not isinstance(receipt_raw, list) or not all(isinstance(f, str) and f for f in receipt_raw):
            findings.append("okf_attested_computation.missing_executor_receipt")
        else:
            executor_receipt_fields = list(receipt_raw)

    attester = frontmatter.get("attester")
    attester_resource_raw: Any = None
    if not isinstance(attester, dict):
        findings.append("okf_attested_computation.missing_attester_resource")
    else:
        attester_resource_raw = attester.get("resource")
        if not isinstance(attester_resource_raw, str) or not attester_resource_raw:
            findings.append("okf_attested_computation.missing_attester_resource")
            attester_resource_raw = None

    # parameters, if present, must be a mapping — but its content is never
    # interpreted for control flow (unknown-key inertness). A present
    # non-mapping is a structural declaration defect.
    parameters = frontmatter.get("parameters")
    if parameters is not None and not isinstance(parameters, dict):
        findings.append("okf_attested_computation.declaration_malformed")

    declaration_valid = not any(
        code in findings
        for code in (
            "okf_attested_computation.wrong_type",
            "okf_attested_computation.missing_runtime",
            "okf_attested_computation.missing_executor_resource",
            "okf_attested_computation.missing_executor_receipt",
            "okf_attested_computation.missing_attester_resource",
            "okf_attested_computation.declaration_malformed",
        )
    )

    # ── resource resolution + digest binding (executor, attester) ──────────
    executor_digest: str | None = None
    attester_digest: str | None = None
    resource_bindings_valid = True

    def _bind_resource(raw: Any, role: str) -> str | None:
        nonlocal resource_bindings_valid
        if raw is None:
            resource_bindings_valid = False
            return None
        try:
            resolved = _safe_resource_path(bundle_root, raw)
        except ValueError:
            findings.append(f"okf_attested_computation.unsafe_resource_reference:{role}")
            resource_bindings_valid = False
            return None
        if not resolved.exists():
            findings.append(f"okf_attested_computation.resource_missing:{role}")
            resource_bindings_valid = False
            return None
        if not resolved.is_file():
            findings.append(f"okf_attested_computation.resource_not_a_file:{role}")
            resource_bindings_valid = False
            return None
        try:
            data = resolved.read_bytes()
        except OSError:
            findings.append(f"okf_attested_computation.resource_missing:{role}")
            resource_bindings_valid = False
            return None
        return _sha256_bytes(data)

    executor_digest = _bind_resource(executor_resource_raw, "executor")
    attester_digest = _bind_resource(attester_resource_raw, "attester")

    # ── run evidence: receipt-field presence + optional digest-claim check ──
    receipt_shape_satisfied = True
    if run_evidence_error is not None or run_evidence is None:
        findings.append("okf_attested_computation.run_evidence_malformed")
        receipt_shape_satisfied = False
    elif not isinstance(run_evidence, dict):
        findings.append("okf_attested_computation.run_evidence_malformed")
        receipt_shape_satisfied = False
    else:
        if executor_receipt_fields is None:
            receipt_shape_satisfied = False
        else:
            for field_name in executor_receipt_fields:
                if field_name not in run_evidence:
                    findings.append(f"okf_attested_computation.receipt_field_absent:{field_name}")
                    receipt_shape_satisfied = False

        # Optional digest claims: run evidence MAY assert what it believes
        # the executor/attester resource digests are. If it does, a conflict
        # with the independently recomputed digest is a named failure. Making
        # no claim is not itself a failure — the resource binding above
        # already stands on its own from the declaration + bundle alone.
        claimed_executor_digest = run_evidence.get("executor_resource_digest")
        if claimed_executor_digest is not None:
            if not _is_sha256_ref(claimed_executor_digest) or claimed_executor_digest != executor_digest:
                findings.append("okf_attested_computation.resource_binding_mismatch:executor")
                resource_bindings_valid = False

        claimed_attester_digest = run_evidence.get("attester_resource_digest")
        if claimed_attester_digest is not None:
            if not _is_sha256_ref(claimed_attester_digest) or claimed_attester_digest != attester_digest:
                findings.append("okf_attested_computation.resource_binding_mismatch:attester")
                resource_bindings_valid = False

    return OKFBridgeFinding(
        declaration_valid=declaration_valid,
        resource_bindings_valid=resource_bindings_valid,
        receipt_shape_satisfied=receipt_shape_satisfied,
        executor_resource_digest=executor_digest,
        attester_resource_digest=attester_digest,
        execution_verified="not_evaluated",
        attester_verdict_verified="not_evaluated",
        truth_verified="not_evaluated",
        authority_conferred=False,
        non_equivalences=NON_EQUIVALENCES,
        failure_codes=tuple(sorted(set(findings))),
    )


# ── CLI ──────────────────────────────────────────────────────────────────────


def _human(report: dict[str, Any]) -> None:
    print(f"declaration_valid: {'PASS' if report['declaration_valid'] else 'FAIL'}")
    print(f"resource_bindings_valid: {'PASS' if report['resource_bindings_valid'] else 'FAIL'}")
    print(f"receipt_shape_satisfied: {'PASS' if report['receipt_shape_satisfied'] else 'FAIL'}")
    print(f"executor_resource_digest: {report['executor_resource_digest']}")
    print(f"attester_resource_digest: {report['attester_resource_digest']}")
    print(f"execution_verified: {report['execution_verified']}")
    print(f"attester_verdict_verified: {report['attester_verdict_verified']}")
    print(f"truth_verified: {report['truth_verified']}")
    print(f"authority_conferred: {report['authority_conferred']}")
    for code in report["failure_codes"]:
        print(f"failure_code: {code}")
    for neq in report["non_equivalences"]:
        print(f"non_equivalence: {neq}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="arcs-verify okf-attested-computation",
        description=(
            "Independently verify an OKF v0.2 'Attested Computation' "
            "declaration: recompute resource digest bindings for the "
            "declared executor and attester resources under a bundle root, "
            "and check declared receipt-field presence in separately "
            "supplied run evidence. Never executes any referenced resource, "
            "never fetches over the network, and never confers DAGR "
            "authority or verifies truth/execution correctness."
        ),
    )
    parser.add_argument("declaration", type=Path, help="path to the OKF declaration.md")
    parser.add_argument(
        "--bundle-root",
        required=True,
        type=Path,
        dest="bundle_root",
        help="directory the declaration's executor/attester resource paths resolve under",
    )
    parser.add_argument(
        "--run",
        required=True,
        type=Path,
        dest="run_evidence_path",
        help="path to the serialized run evidence JSON",
    )
    parser.add_argument("--json", action="store_true", dest="as_json")
    return parser


def _read_text(path: Path) -> tuple[str | None, str | None]:
    try:
        return path.read_text(encoding="utf-8"), None
    except FileNotFoundError:
        return None, f"no such file: {path}"
    except IsADirectoryError:
        return None, f"path is a directory: {path}"
    except UnicodeDecodeError as exc:
        return None, f"not valid utf-8: {path}: {exc}"
    except OSError as exc:
        return None, f"unreadable: {path}: {exc}"


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code) if exc.code is not None else 2

    if not args.bundle_root.is_dir():
        print(f"source-integrity/usage error: bundle root is not a directory: {args.bundle_root}", file=sys.stderr)
        return 2

    declaration_text, declaration_io_error = _read_text(args.declaration)
    if declaration_io_error is not None:
        print(f"source-integrity/usage error: cannot read declaration: {declaration_io_error}", file=sys.stderr)
        return 2

    run_text, run_io_error = _read_text(args.run_evidence_path)
    if run_io_error is not None:
        print(f"source-integrity/usage error: cannot read run evidence: {run_io_error}", file=sys.stderr)
        return 2

    run_evidence: dict[str, Any] | None
    run_evidence_error: str | None
    try:
        parsed = json.loads(run_text) if run_text is not None else None
    except json.JSONDecodeError as exc:
        parsed = None
        run_evidence_error = f"run evidence is not valid JSON: {exc}"
    else:
        run_evidence_error = None
    if run_evidence_error is None and not isinstance(parsed, dict):
        run_evidence_error = "run evidence top-level JSON is not an object"
        parsed = None
    run_evidence = parsed if run_evidence_error is None else None

    finding = verify(
        declaration_text,
        None,
        args.bundle_root,
        run_evidence,
        run_evidence_error,
    )
    report = finding.to_dict()

    if args.as_json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        _human(report)

    return 0 if finding.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
