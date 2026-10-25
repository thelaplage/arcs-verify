"""The failure-code registry must cover every code the verifier can emit.

Extracts codes structurally from the emitting call sites themselves: string
arguments to the ``_fail``/``_finding`` helpers, string arguments to any
``.append(...)`` call, list-literal returns, bare string and f-string
returns, ``code=`` keyword arguments, and ``ValueError(...)`` constant
arguments. There is no recognition allowlist: a newly emitted code is
collected because of where it is emitted, not because a regex already knows
its shape. The single structural filter is that codes never contain spaces,
which excludes detail-message strings by shape rather than by name. Each static
code and each dynamic-family prefix must appear verbatim in the combined
failure-code registry text, so the registry is an interface that cannot
silently fall behind the code.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REGISTRY_FILES = (
    ROOT / "docs" / "FAILURE_CODES.md",
    ROOT / "docs" / "FAILURE_CODES_EXTERNAL_PROFILE.md",
)
REGISTRY = "\n".join(path.read_text(encoding="utf-8") for path in REGISTRY_FILES)

MODULES = [
    "arcs_verify/verifier.py",
    "arcs_verify/public_publication_candidate.py",
    "arcs_verify/public_publication_profile.py",
    "arcs_verify/receipt_set.py",
    "arcs_verify/deferred_sequence.py",
    "arcs_verify/governed_memory_sequence.py",
    "arcs_verify/ingest_run_sequence.py",
    "arcs_verify/analytics_snapshot.py",
    "arcs_verify/acquisition_grounding.py",
    "arcs_verify/c2pa_native.py",
    "arcs_verify/amnesiac/verifier.py",
    "arcs_verify/amnesiac/public_proof.py",
    "arcs_verify/universal.py",
    # CG-REPLAY0 Lane 4 — execution-packet digest-binding verifiers
    "arcs_verify/cg_execution_replay.py",
    "arcs_verify/cg_replay.py",
    # Counterplayer study verifier
    "arcs_verify/counterplayer_study.py",
    # ADMISSION-EVENT-VERIFY1 — admission-event supersession verifiers
    "arcs_verify/admission_event.py",
    "arcs_verify/admission_event_v0_2.py",
    # READMISSION-CONTENT-DIVERGENCE0 Lane 5 — tri-state content-digest
    # comparison verifier
    "arcs_verify/admission_event_v0_3.py",
    # OKF-ARCS-BRIDGE0 — OKF Attested Computation verifier-side bindings
    "arcs_verify/okf_attested_computation.py",
    # SRS-VNEXT-VERIFY0 — independent vNext external-profile verification
    "arcs_verify/external_profile.py",
    # DAGR-AUTHORITY-CONTEXT0 — independent same-genesis authority-context verifier
    "arcs_verify/dagr_authority_context.py",
    # DAGR-AUTHORSHIP-VERIFY0 — trust-relative producer-authorship receipt verifier
    "arcs_verify/dagr_authority_context_producer.py",
    # VERIFY-FINDINGS0 — read-only findings projection carries verifier failure codes
    "arcs_verify/findings.py",
    # ARCS-VERIFY-EXIT-O0 — EXIT-O semantic-issuer origin-authentication verifier
    "arcs_verify/exit_o_origin_authentication.py",
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
        "codes emitted but absent from the failure-code registries:\n"
        + "\n".join(missing)
    )


def test_every_dynamic_family_prefix_is_in_the_registry() -> None:
    missing: list[str] = []
    for module in MODULES:
        _, templates = _extract(module)
        for prefix in sorted(templates):
            if prefix not in REGISTRY:
                missing.append(f"{module}: {prefix}<...>")
    assert not missing, (
        "dynamic code families emitted but absent from the failure-code registries:\n"
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


def test_registry_documents_no_code_unknown_to_the_verifier() -> None:
    """Whole-registry phantom check, dotted identifiers included.

    test_registry_lists_no_phantom_static_codes above is deliberately strict and
    deliberately narrow: two modules, one section, bare identifiers, and
    membership in the precise structural extraction. This one trades that
    precision for reach -- every table row in both registry documents.

    The two directions need different predicates. "Is every emitted code
    documented?" must extract conservatively, or it demands documentation for
    strings that are not codes. "Is every documented code real?" must accept
    any evidence that the verifier knows the string, because the sweep has
    known blind spots that are not registry inventions: cg_replay.py and
    cg_execution_replay.py pass the code at helper argument 0 while the sweep
    reads argument 1, relation.* codes live in a tuple literal inside a for
    loop, and ACPS_B1_PRINCIPAL_BINDING_DIGEST_FAILED is a module constant.
    Treating those as phantoms would be wrong.

    So a documented code is accepted when it appears as a string literal in an
    emitting module, or matches a dynamic family prefix, or ends with the
    literal tail of a variable-first f-string. A code satisfying none of those
    appears nowhere in the verifier and is an invention.

    Weaker than the narrow check in one way, and stated rather than hidden: a
    code mentioned only in a comment or docstring would pass here. The narrow
    check is kept precisely so that nothing is given up.
    """
    import re

    sources = {module: (ROOT / module).read_text(encoding="utf-8") for module in MODULES}
    blob = "\n".join(sources.values())

    prefixes = set()
    for module in MODULES:
        prefixes |= _extract(module)[1]
    prefixes.discard("")

    tails: set[str] = set()
    for text in sources.values():
        tails |= {tail for tail in re.findall(r'f"\{[a-z_]+\}([a-z0-9_.]+)"', text) if tail}

    documented = sorted(set(re.findall(r"^\| `([a-z][A-Za-z0-9_.]*)` \|", REGISTRY, re.M)))

    def known(code: str) -> bool:
        if f'"{code}"' in blob or f"'{code}'" in blob:
            return True
        if any(code.startswith(prefix) for prefix in prefixes):
            return True
        return any(code.endswith(tail) for tail in tails)

    invented = sorted(code for code in documented if not known(code))
    assert not invented, (
        "the registries document codes that appear nowhere in the verifier:\n"
        + "\n".join(invented)
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
        "so their codes are never checked against the failure-code registries:\n"
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
        "SIGNATURE_FAILURE_CODES members absent from the failure-code registries:\n"
        + "\n".join(missing)
    )
