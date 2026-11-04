"""SCITT-RATCHET0-CORR2: the sealed judge. Runs ONLY from base-commit bytes.

This file computes, from the candidate checkout treated purely as DATA, the set
of code-shaped emissions that are not documented in the failure-code registry.
It is staged by ``failure_code_ratchet.py`` from the pinned base commit
(``git show <base>:...``) into a fresh directory together with the base's
``failure_code_census.py`` and executed in an isolated interpreter
(``-I -S -B``, cleared environment, clean bytecode-cache prefix, working
directory = that fresh directory). Nothing from the candidate is imported or
executed: candidate ``.py`` files are read as bytes and ``ast.parse``d; the
registry is read as text. The candidate therefore cannot alter the code that
decides its own acceptance, through source, bytecode, ``sys.path`` shadowing,
``.pth``/``sitecustomize`` or environment.

READ-AS-PYTHON-RUNS (CORR3). Candidate source is parsed from BYTES (``ast.parse``
of ``bytes`` honours a PEP 263 coding cookie and a BOM exactly as the interpreter
does; decoding to ``str`` first ignores the cookie and let ``# coding: utf-7``
hide a code). The package is enumerated here, not with ``rglob``: directory and
file symlinks, and source-less importable files (``.pyc``, extension modules),
are reported (fail closed) because the interpreter can import what a source scan
would never see. The census library is used only for per-module analysis and is
handed the already-parsed tree and the sinks derived from the same trees.

stdlib only. Prints one JSON object on stdout.

``NOT_CODES`` mirrors the table in ``test_failure_code_census.py``; a parity
test in ``test_failure_code_ratchet.py`` fails if the two diverge.
"""

from __future__ import annotations

import ast
import json
import os
import sys
from pathlib import Path

# The directory this file was staged into: the ONLY import location.
HERE = os.path.dirname(os.path.abspath(__file__))

_TAXONOMY_TOKENS = (
    "input_delta",
    "insufficient_evidence",
    "policy_delta",
    "revocation_basis_delta",
    "same_inputs_same_semantics",
    "unsupported_native_feature",
    "validation_clock_delta",
    "validator_implementation_delta",
    "validator_version_delta",
)
NOT_CODES = {("arcs_verify/c2pa_native.py", token) for token in _TAXONOMY_TOKENS}
NOT_CODES.add(("arcs_verify/okf_attested_computation.py", "unreadable:"))
NOT_CODE_PREFIXES = frozenset({"sha256:"})
REGISTRY_FILES = ("docs/FAILURE_CODES.md", "docs/FAILURE_CODES_EXTERNAL_PROFILE.md")


_UNSCANNED_SUFFIXES = (".pyc", ".pyo", ".so", ".pyd", ".dylib", ".dll")


def enumerate_package(root: Path) -> tuple[list[str], list[str], list[str]]:
    """(scannable module paths, symlinks, unscanned importable files), no symlink followed."""
    package = root / "arcs_verify"
    modules: list[str] = []
    symlinks: list[str] = []
    unscanned: list[str] = []
    if package.is_symlink():
        symlinks.append("arcs_verify")
        return modules, symlinks, unscanned
    if not package.is_dir():
        return modules, symlinks, unscanned
    for current, dirs, files in os.walk(package, followlinks=False):
        here = Path(current)
        for name in list(dirs):
            if (here / name).is_symlink():
                symlinks.append((here / name).relative_to(root).as_posix())
                dirs.remove(name)  # never follow
        if here.name == "__pycache__":
            dirs[:] = []
            continue
        for name in files:
            path = here / name
            rel = path.relative_to(root).as_posix()
            if path.is_symlink():
                symlinks.append(rel)
            elif name.endswith(".py"):
                modules.append(rel)
            elif name.endswith(_UNSCANNED_SUFFIXES) or ".cpython-" in name or ".abi3." in name:
                unscanned.append(rel)
    return sorted(modules), sorted(symlinks), sorted(unscanned)


def undocumented_sets(root: Path, census_lib) -> dict:
    registry = "\n".join((root / rel).read_text(encoding="utf-8") for rel in REGISTRY_FILES)
    modules, symlinks, unscanned = enumerate_package(root)
    # BYTES -> ast: the coding cookie and BOM are honoured as the interpreter honours them.
    trees = {module: ast.parse((root / module).read_bytes(), filename=module) for module in modules}
    sinks: dict[str, set] = {}
    for tree in trees.values():
        for name, spec in census_lib._defined_sinks(tree).items():
            sinks.setdefault(name, set()).update(spec)
    out: dict[str, dict[str, list[str]]] = {}
    for module in modules:
        found = census_lib.extract(module, sinks=sinks, tree=trees[module])
        codes = {c for c in found.static if (module, c) not in NOT_CODES and f"`{c}`" not in registry}
        prefixes = {
            p for p in found.families
            if (module, p) not in NOT_CODES and p not in NOT_CODE_PREFIXES and p not in registry
        }
        if codes or prefixes:
            out[module] = {"codes": sorted(codes), "families": sorted(prefixes)}
    return {
        "modules": out,
        "package_modules": len(modules),
        "symlinks": symlinks,
        "unscanned_importable": unscanned,
    }


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[0] != "--root":
        print(json.dumps({"error": "usage: failure_code_judge.py --root <candidate checkout>"}))
        return 3
    sys.path.insert(0, HERE)  # staged directory only; the candidate is never on sys.path
    try:
        import failure_code_census as census_lib  # staged sibling

        result = undocumented_sets(Path(argv[1]).resolve(), census_lib)
    except BaseException as exc:  # fail closed: any problem is an error verdict, never an empty set
        print(json.dumps({"error": f"{type(exc).__name__}: {exc}"}))
        return 3
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
