"""The failure-code registry must cover every code the verifier can emit.

Extracts codes structurally from the emitting call sites themselves: string
arguments to the ``_fail``/``_finding`` helpers, string arguments to any
``.append(...)`` call, list-literal returns, bare string and f-string
returns, ``code=`` keyword arguments, and ``ValueError(...)`` constant
arguments. There is no recognition allowlist: a newly emitted code is
collected because of where it is emitted, not because a regex already knows
its shape. The single structural filter is that codes never contain spaces,
which excludes detail-message strings by shape rather than by name. Each static code and
each dynamic-family prefix must appear verbatim in docs/FAILURE_CODES.md, so
the registry is an interface that cannot silently fall behind the code.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = (ROOT / "docs" / "FAILURE_CODES.md").read_text(encoding="utf-8")

MODULES = [
    "arcs_verify/verifier.py",
    "arcs_verify/receipt_set.py",
    "arcs_verify/deferred_sequence.py",
    "arcs_verify/governed_memory_sequence.py",
    "arcs_verify/ingest_run_sequence.py",
    "arcs_verify/amnesiac/verifier.py",
    "arcs_verify/amnesiac/public_proof.py",
]

# Signatures that mark a module as one that emits verifier failure codes. The
# fixed MODULES list above is itself a recognition-level allowlist at the module
# granularity: a newly added emitting module escapes it silently (as
# governed_memory_sequence.py once did). test_no_emitting_module_is_unregistered
# discovers emitting modules structurally and fails if one is missing from
# MODULES, so module-level drift cannot reopen the gap that code-level
# extraction closes.
EMISSION_SIGNATURES = (
    "_fail(",
    "_finding(",
    "failure_codes.append(",
    ".findings.append(",
    "SequenceFinding(",
)

HELPER_NAMES = {"_fail", "_finding"}
HELPER_CODE_ARG = 1

# Strings collected by the structural sweep that are not failure codes:
# detail text fragments never reach these sites as bare constants in the
# current bytes, so the exclusion set stays empty. Add entries here only with
# a comment naming the emitting site and why the string is not a code.
NOT_CODES: set[str] = set()


def _harvest(node: ast.expr, static: set[str], templates: set[str]) -> None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        if " " not in node.value:
            static.add(node.value)
    elif isinstance(node, ast.JoinedStr):
        parts = []
        for piece in node.values:
            parts.append(str(piece.value) if isinstance(piece, ast.Constant) else "{VAR}")
        joined = "".join(parts)
        prefix = joined.split("{VAR}", 1)[0]
        if prefix and " " not in prefix:
            templates.add(prefix)


def _extract(module: str) -> tuple[set[str], set[str]]:
    tree = ast.parse((ROOT / module).read_text(encoding="utf-8"))
    static: set[str] = set()
    templates: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fname = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
            if fname in HELPER_NAMES and len(node.args) > HELPER_CODE_ARG:
                _harvest(node.args[HELPER_CODE_ARG], static, templates)
            if getattr(node.func, "attr", None) == "append" and node.args:
                _harvest(node.args[0], static, templates)
        if isinstance(node, ast.Call):
            fname = getattr(node.func, "id", None)
            if fname == "ValueError" and node.args:
                _harvest(node.args[0], static, templates)
            for keyword in getattr(node, "keywords", []):
                if keyword.arg == "code":
                    _harvest(keyword.value, static, templates)
        if isinstance(node, ast.Return) and node.value is not None:
            if isinstance(node.value, ast.List):
                for element in node.value.elts:
                    _harvest(element, static, templates)
            else:
                _harvest(node.value, static, templates)
    return static - NOT_CODES, templates


def test_every_emitted_code_is_in_the_registry() -> None:
    missing: list[str] = []
    for module in MODULES:
        static, _ = _extract(module)
        for code in sorted(static):
            if f"`{code}`" not in REGISTRY:
                missing.append(f"{module}: {code}")
    assert not missing, (
        "codes emitted but absent from docs/FAILURE_CODES.md:\n" + "\n".join(missing)
    )


def test_every_dynamic_family_prefix_is_in_the_registry() -> None:
    missing: list[str] = []
    for module in MODULES:
        _, templates = _extract(module)
        for prefix in sorted(templates):
            if prefix not in REGISTRY:
                missing.append(f"{module}: {prefix}<...>")
    assert not missing, (
        "dynamic code families emitted but absent from docs/FAILURE_CODES.md:\n"
        + "\n".join(missing)
    )


def test_registry_lists_no_phantom_static_codes() -> None:
    """Bare-identifier codes documented in the receipt-set and
    deferred-sequence tables must actually be emitted by those modules.
    Guards against the registry inventing codes."""
    import re

    emitted: set[str] = set()
    for module in ("arcs_verify/receipt_set.py", "arcs_verify/deferred_sequence.py"):
        static, _ = _extract(module)
        emitted |= static

    section = REGISTRY[
        REGISTRY.index("## `receipt-set` subcommand") : REGISTRY.index(
            "## `amnesiac-chain` subcommand"
        )
    ]
    documented = {
        match.group(1)
        for match in re.finditer(r"^\| `([a-z][a-z0-9_]+)` \|", section, re.M)
    }
    phantoms = sorted(documented - emitted)
    assert not phantoms, (
        "registry documents codes the receipt-set/deferred-sequence modules "
        "do not emit:\n" + "\n".join(phantoms)
    )


def test_no_emitting_module_is_unregistered() -> None:
    """Every module under arcs_verify/ that carries a code-emission signature
    must appear in MODULES. This is the module-level analogue of the code-level
    coverage test: it prevents a new emitting module (e.g. a future subcommand)
    from silently escaping the structural sweep, the failure mode that left
    governed_memory_sequence.py's codes undocumented after a merge."""
    registered = set(MODULES)
    discovered: list[str] = []
    for path in sorted((ROOT / "arcs_verify").rglob("*.py")):
        rel = path.relative_to(ROOT).as_posix()
        source = path.read_text(encoding="utf-8")
        if any(sig in source for sig in EMISSION_SIGNATURES):
            discovered.append(rel)
    missing = sorted(set(discovered) - registered)
    assert not missing, (
        "modules emit failure codes but are absent from MODULES in this test, "
        "so their codes are never checked against docs/FAILURE_CODES.md:\n"
        + "\n".join(missing)
    )


def test_every_signature_failure_code_is_in_the_registry() -> None:
    """Direct membership assertion over the verifier's own constant, so the
    signature-path code set is documented even if a future emission shape
    escapes the structural sweep."""
    from arcs_verify.verifier import SIGNATURE_FAILURE_CODES

    missing = sorted(
        code for code in SIGNATURE_FAILURE_CODES if f"`{code}`" not in REGISTRY
    )
    assert not missing, (
        "SIGNATURE_FAILURE_CODES members absent from docs/FAILURE_CODES.md:\n"
        + "\n".join(missing)
    )
