#!/usr/bin/env python3
"""Dependency-free public release gate."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Iterator

TEXT_SUFFIXES = {
    ".c", ".cc", ".css", ".go", ".h", ".html", ".java", ".js", ".json",
    ".jsx", ".md", ".mjs", ".py", ".rs", ".sh", ".toml", ".ts", ".tsx",
    ".txt", ".yaml", ".yml",
}
MARKDOWN_SUFFIXES = {".md", ".markdown", ".mdx"}
RECEIPT_DIR_NAMES = {"fixtures", "vectors", "packs"}
RAW_CONTENT_KEYS = {
    "prompt_text", "transcript", "raw_payload", "tool_arguments", "arguments",
    "result_body", "headers",
}
PRIVATE_PATH_MARKERS = (
    "/" + "Users" + "/",
    "/" + "home" + "/",
    "/" + "private" + "/" + "var",
    "C:" + "\\" + "\\",
    "~" + "/" + "garp-",
    "~" + "/" + "arcs-anchor",
)
INTERNAL_REVIEWER = "Stein" + "er"
PRIVATE_IMPORT_ROOTS = (
    "garp" + "_sdk",
    "garp" + "_core",
    "garp" + "_local",
    # countergraph is a producer; arcs-verify must never import producer code
    "counter" + "graph",
)
WITHDRAWN_LANGUAGE = (
    "none is externally verifiable",
    "the record-governance layer is empty",
    "empty layer",
    "has no peer",
    "payload" + "-free",
    "tool" + "_executed",
    "any byte change",
    "bytes on the wire",
)
DATestamp_RE = re.compile(r"_[A-Z]{3}[0-9]{2}(?:\.[^.]+)?$")
IMPORT_RE = re.compile(r"^\s*(?:from|import)\s+([A-Za-z_][A-Za-z0-9_\.]*)", re.MULTILINE)

_BRAND_EXCEPTION_CONTROL = "brand_historical_exceptions.json"
_BRAND_EXCEPTION_SCHEMA = "arcs-verify.brand-historical-exceptions/v0.1"
_BRAND_EXCEPTION_POLICY_ID = "garp.doctrine.brand-deny0.historical-immutable-exception.v0.1"
_BRAND_EXCEPTION_POLICY_BLOB = "20bdf1236d159ce57e793a1843d778cd4d64f3e2"
_BRAND_EXCEPTION_RATIFICATION = "5007b1f92acd260e8553b7cec76f67c785f98628"
_BRAND_EXCEPTION_REPOSITORY = "thelaplage/arcs-verify"
_HISTORICAL_RESERVED_TOKEN = "Counter" + "vail"
_EXPECTED_BRAND_HISTORICAL_EXCEPTIONS = frozenset({
    (
        "arcs_verify/contracts/dagr-srs-verification-report-v0-1/README.md",
        _HISTORICAL_RESERVED_TOKEN,
        "19a20bcde49fbfad699a40e8dceb060668a9ac3f",
    ),
    (
        "arcs_verify/data/dagr-resolved-authority-context-1a12726f.schema.json",
        _HISTORICAL_RESERVED_TOKEN,
        "1d1efd510f5d5786e260d9f95872b01220e622ca",
    ),
})


@dataclass(frozen=True)
class Finding:
    rule_id: str
    path: str
    message: str


def _git_files(root: Path) -> list[Path] | None:
    if not (root / ".git").exists():
        return None
    proc = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if proc.returncode != 0:
        return None
    return [root / item.decode("utf-8", "surrogateescape") for item in proc.stdout.split(b"\0") if item]


def tracked_files(root: Path) -> list[Path]:
    git_files = _git_files(root)
    if git_files is not None:
        return [path for path in git_files if path.is_file()]
    return [
        path for path in root.rglob("*")
        if path.is_file() and ".git" not in path.parts and "__pycache__" not in path.parts
    ]


def relative(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def is_internal_doc(rel: str) -> bool:
    return rel == "docs/internal" or rel.startswith("docs/internal/")


def read_text(path: Path) -> str | None:
    if path.suffix.lower() not in TEXT_SUFFIXES and path.name not in {"README", "LICENSE", "SECURITY"}:
        return None
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def iter_json_keys(value: object) -> Iterator[str]:
    if isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            yield from iter_json_keys(item)
    elif isinstance(value, list):
        for item in value:
            yield from iter_json_keys(item)


def is_receipt_fixture(rel: str) -> bool:
    path = Path(rel)
    return path.suffix.lower() == ".json" and any(part in RECEIPT_DIR_NAMES for part in path.parts)


_ACKNOWLEDGED_EMPTY_SENTINEL = "# BRAND_GATE: acknowledged-empty"


def load_brand_denylist(script_dir: Path) -> list[str]:
    """Return brand tokens from brand_denylist.txt, or a sentinel list when
    the file has no real tokens but carries the explicit waiver.

    Real tokens take precedence: if the file contains any real brand token,
    that list is returned even when the acknowledged-empty waiver line is also
    present (a stale waiver). The singleton ``["__acknowledged_empty__"]`` is
    returned only when there are no real tokens and the waiver line is present,
    so the caller can distinguish a deliberately-waived-empty from an
    unanticipated empty. The stale-waiver case (tokens present *and* waiver
    declared) is surfaced loudly as PR014 by ``check`` rather than silently
    overridden here; use ``brand_waiver_declared`` to detect it.
    """
    path = script_dir / "brand_denylist.txt"
    if not path.exists():
        return []
    raw_text = path.read_text(encoding="utf-8")
    values: list[str] = []
    for raw in raw_text.splitlines():
        value = raw.strip()
        if value and not value.startswith("#"):
            values.append(value)
    if values:
        return values
    if _ACKNOWLEDGED_EMPTY_SENTINEL in raw_text:
        return ["__acknowledged_empty__"]
    return []


def brand_waiver_declared(script_dir: Path) -> bool:
    """Whether brand_denylist.txt carries the acknowledged-empty waiver line,
    independent of whether real tokens are also present. Real tokens win in
    load_brand_denylist; this lets check() still detect a stale waiver line
    left behind alongside real tokens and fail loudly (PR014)."""
    path = script_dir / "brand_denylist.txt"
    if not path.exists():
        return False
    return _ACKNOWLEDGED_EMPTY_SENTINEL in path.read_text(encoding="utf-8")


def _git_blob_sha1_bytes(data: bytes) -> str:
    preimage = f"blob {len(data)}\0".encode("ascii") + data
    return hashlib.sha1(preimage).hexdigest()


def _git_blob_sha1_path(path: Path) -> str | None:
    try:
        return _git_blob_sha1_bytes(path.read_bytes())
    except OSError:
        return None


def load_brand_historical_exceptions(
    script_dir: Path,
) -> tuple[frozenset[tuple[str, str, str]], str | None]:
    """Load the exact ratified historical-brand exception control.

    The control is not an open-ended allowlist. Its governance source metadata
    and complete exception set must equal the exact ratified policy encoded by
    this checker version. Missing, malformed, stale, or widened control fails
    closed and yields no usable exceptions.
    """
    path = script_dir / _BRAND_EXCEPTION_CONTROL
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return frozenset(), "historical brand exception control is missing"
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return frozenset(), "historical brand exception control is malformed JSON"
    if not isinstance(payload, dict):
        return frozenset(), "historical brand exception control must be a JSON object"

    expected_top = {
        "schema",
        "source_policy_id",
        "source_policy_blob_sha1",
        "source_ratification_merge",
        "repository",
        "exceptions",
    }
    if set(payload) != expected_top:
        return frozenset(), "historical brand exception control has unexpected top-level fields"
    if payload.get("schema") != _BRAND_EXCEPTION_SCHEMA:
        return frozenset(), "historical brand exception control schema mismatch"
    if payload.get("source_policy_id") != _BRAND_EXCEPTION_POLICY_ID:
        return frozenset(), "historical brand exception policy id mismatch"
    if payload.get("source_policy_blob_sha1") != _BRAND_EXCEPTION_POLICY_BLOB:
        return frozenset(), "historical brand exception policy blob mismatch"
    if payload.get("source_ratification_merge") != _BRAND_EXCEPTION_RATIFICATION:
        return frozenset(), "historical brand exception ratification mismatch"
    if payload.get("repository") != _BRAND_EXCEPTION_REPOSITORY:
        return frozenset(), "historical brand exception repository mismatch"

    records = payload.get("exceptions")
    if not isinstance(records, list):
        return frozenset(), "historical brand exception records must be a list"
    parsed: set[tuple[str, str, str]] = set()
    for item in records:
        if not isinstance(item, dict) or set(item) != {"path", "token", "git_blob_sha1"}:
            return frozenset(), "historical brand exception record has invalid shape"
        rel = item.get("path")
        token = item.get("token")
        blob = item.get("git_blob_sha1")
        if not all(isinstance(value, str) and value for value in (rel, token, blob)):
            return frozenset(), "historical brand exception record has invalid values"
        if not re.fullmatch(r"[a-f0-9]{40}", blob):
            return frozenset(), "historical brand exception record has invalid git blob id"
        parsed.add((rel, token, blob))

    frozen = frozenset(parsed)
    if frozen != _EXPECTED_BRAND_HISTORICAL_EXCEPTIONS:
        return frozenset(), "historical brand exception set differs from ratified policy"
    return frozen, None


def check(
    root: Path,
    *,
    script_dir: Path | None = None,
    require_real_denylist: bool = False,
) -> list[Finding]:
    findings: list[Finding] = []
    files = tracked_files(root)
    text_by_rel: dict[str, str] = {}
    for path in files:
        rel = relative(root, path)
        text = read_text(path)
        if text is not None:
            text_by_rel[rel] = text

        name = path.name
        if not is_internal_doc(rel) and (name.startswith("IN___") or name.startswith("ARCS_-_IN___")):
            findings.append(Finding("PR001", rel, "internal-prefixed filename outside docs/internal"))
        if not is_internal_doc(rel) and DATestamp_RE.search(name):
            findings.append(Finding("PR002", rel, "internal datestamp filename outside docs/internal"))

    for rel, text in text_by_rel.items():
        for marker in PRIVATE_PATH_MARKERS:
            if marker in text:
                findings.append(Finding("PR003", rel, f"absolute or private path marker found: {marker}"))
        if INTERNAL_REVIEWER in text:
            findings.append(Finding("PR004", rel, "internal reviewer reference found"))

    if not (root / "LICENSE").is_file():
        findings.append(Finding("PR005", "LICENSE", "missing root LICENSE"))
    if not (root / "SECURITY.md").is_file():
        findings.append(Finding("PR006", "SECURITY.md", "missing root SECURITY.md"))

    readme_path = next((root / name for name in ("README.md", "README.rst", "README") if (root / name).is_file()), None)
    readme_text = read_text(readme_path) if readme_path else None
    if not readme_text or not (
        "<!-- layer-map -->" in readme_text
        or "Standard (ARCS)" in readme_text
        or "Receipt protocol and profiles" in readme_text
    ):
        findings.append(Finding("PR007", readme_path.name if readme_path else "README.md", "README missing layer-map marker or six-role surface map"))
    if readme_text and "DAGR" in readme_text and "MCP" in readme_text and "first supported binding" not in readme_text:
        findings.append(Finding("PR008", readme_path.name if readme_path else "README.md", "README lacks required first-binding language"))

    for rel, text in text_by_rel.items():
        if is_receipt_fixture(rel):
            try:
                payload = json.loads(text)
            except json.JSONDecodeError:
                continue
            keys = set(iter_json_keys(payload))
            for key in sorted(keys.intersection(RAW_CONTENT_KEYS)):
                findings.append(Finding("PR009", rel, f"receipt fixture carries forbidden raw-content key: {key}"))
            if isinstance(payload, dict) and {"receipt_type", "boundary_type", "extensions"}.issubset(payload) and "receipt_version" not in payload:
                findings.append(Finding("PR009", rel, "SRS receipt candidate lacks receipt_version"))

        if Path(rel).suffix.lower() == ".py":
            for match in IMPORT_RE.finditer(text):
                root_name = match.group(1).split(".", 1)[0]
                if root_name in PRIVATE_IMPORT_ROOTS:
                    findings.append(Finding("PR010", rel, f"private import root found: {root_name}"))

        if Path(rel).suffix.lower() in MARKDOWN_SUFFIXES:
            lower = text.lower()
            for phrase in WITHDRAWN_LANGUAGE:
                if phrase.lower() in lower:
                    findings.append(Finding("PR011", rel, f"withdrawn language found: {phrase}"))

    script_root = script_dir or Path(__file__).resolve().parent
    denylist = load_brand_denylist(script_root)
    waiver_declared = brand_waiver_declared(script_root)
    historical_exceptions, historical_exception_error = (
        load_brand_historical_exceptions(script_root)
    )
    if historical_exception_error is not None:
        findings.append(Finding(
            "PR015",
            f"tools/{_BRAND_EXCEPTION_CONTROL}",
            historical_exception_error,
        ))
    naming_path = "docs/NAMING.md"
    brand_control_paths = {
        naming_path,
        "tools/brand_denylist.txt",
        f"tools/{_BRAND_EXCEPTION_CONTROL}",
    }
    waived = denylist == ["__acknowledged_empty__"]
    if not denylist:
        # Fail closed: an empty denylist means brand governance is not enforced.
        # Populate brand_denylist.txt (or add '# BRAND_GATE: acknowledged-empty')
        # before this gate will pass.
        findings.append(Finding(
            "PR013",
            "tools/brand_denylist.txt",
            "brand denylist is empty; brand governance is not enforced — "
            "populate brand_denylist.txt or add '# BRAND_GATE: acknowledged-empty' "
            "to explicitly waive this check",
        ))
    elif waived and require_real_denylist:
        # The caller insists on real brand tokens; the acknowledged-empty
        # waiver is not accepted under --require-denylist.
        findings.append(Finding(
            "PR013",
            "tools/brand_denylist.txt",
            "brand denylist is waived (acknowledged-empty) but --require-denylist "
            "was set; populate brand_denylist.txt with real brand tokens",
        ))
    elif not waived:
        if waiver_declared:
            # Real tokens win over the waiver (see load_brand_denylist), but a
            # waiver line left behind alongside real tokens is a stale waiver
            # that has silently outlived its justification. Fail loudly rather
            # than override quietly, so the dead line is removed.
            findings.append(Finding(
                "PR014",
                "tools/brand_denylist.txt",
                "stale brand-gate waiver: '# BRAND_GATE: acknowledged-empty' is "
                "present alongside real brand tokens; the tokens are enforced and "
                "the waiver line must be removed",
            ))
        for brand in denylist:
            for rel, text in text_by_rel.items():
                if rel in brand_control_paths:
                    continue
                if brand.lower() not in text.lower():
                    continue
                blob_sha1 = _git_blob_sha1_path(root / rel)
                if (
                    blob_sha1 is not None
                    and (rel, brand, blob_sha1) in historical_exceptions
                ):
                    continue
                findings.append(Finding(
                    "PR012",
                    rel,
                    f"candidate brand outside {naming_path}: {brand}",
                ))

    return sorted(findings, key=lambda item: (item.rule_id, item.path, item.message))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument(
        "--require-denylist",
        action="store_true",
        dest="require_denylist",
        help="require real brand tokens: reject even the acknowledged-empty "
             "waiver (PR013). The gate is already fail-closed on a genuinely "
             "empty denylist regardless of this flag.",
    )
    parser.add_argument("repo_root", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code)
    root = args.repo_root.expanduser().resolve()
    if not root.is_dir():
        print(f"usage error: repository root is not a directory: {root}", file=sys.stderr)
        return 2
    findings = check(root, require_real_denylist=args.require_denylist)
    denylist = load_brand_denylist(Path(__file__).resolve().parent)
    waived = denylist == ["__acknowledged_empty__"]
    # The brand scan (PR012) only actually runs when real tokens are present;
    # a genuinely empty denylist now fails closed (PR013), and the
    # acknowledged-empty waiver passes without covering brand exposure.
    brand_check_performed = bool(denylist) and not waived
    if args.as_json:
        print(json.dumps({"brand_check_performed": brand_check_performed, "repo_root": str(root), "finding_count": len(findings), "findings": [asdict(item) for item in findings]}, indent=2, sort_keys=True))
    else:
        for item in findings:
            print(f"{item.rule_id} {item.path}: {item.message}")
        if waived and not findings:
            print(
                "WARNING: brand denylist is explicitly waived (acknowledged-empty); "
                "this PASS does not cover brand exposure"
            )
        print(f"{'PASS' if not findings else 'FAIL'}: {len(findings)} finding(s)")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
