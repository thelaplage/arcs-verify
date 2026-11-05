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

IMPORTABLE-SET SUPERSET (CORR4). Python imports a ``.py`` placed anywhere under
the package, including inside a ``__pycache__`` directory (an ordinary namespace
package). The walk therefore never prunes ``__pycache__``: compiled ``.pyc``
caches inside it are ignored, but a ``.py`` there is scanned AND reported
(``IMPORTABLE_IN_PYCACHE``), and symlinks / extension modules there are refused
like anywhere else. CONSTANT FOLDING (CORR4): ``"a" + "b"``, ``"%s_x" % "a"``,
``"ab" * 2`` and f-strings of constants are folded before the code-shape check,
so a statically-apparent folded code is the value that is judged.

Known limits, recorded rather than chased: an ALIASED sink
(``from x import _sink as emit``) is matched by callee name only; codes emitted
from modules OUTSIDE ``arcs_verify/`` are out of scope; runtime construction
(``exec``/``eval``/``getattr``/``.format``/data files) is invisible to any static
census. See ``docs/FAILURE_CODE_RATCHET.md``.

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


def enumerate_package(root: Path) -> tuple[list[str], list[str], list[str], list[str]]:
    """(module paths to scan, symlinks, unscanned importable files, .py under __pycache__).

    No symlink is followed and NOTHING is pruned: the scanned set must be a
    superset of what the interpreter can import from the package."""
    package = root / "arcs_verify"
    modules: list[str] = []
    symlinks: list[str] = []
    unscanned: list[str] = []
    in_cache_py: list[str] = []
    if package.is_symlink():
        symlinks.append("arcs_verify")
        return modules, symlinks, unscanned, in_cache_py
    if not package.is_dir():
        return modules, symlinks, unscanned, in_cache_py
    for current, dirs, files in os.walk(package, followlinks=False):
        here = Path(current)
        for name in list(dirs):
            if (here / name).is_symlink():
                symlinks.append((here / name).relative_to(root).as_posix())
                dirs.remove(name)  # never follow
        in_cache = "__pycache__" in here.relative_to(package).parts
        for name in files:
            path = here / name
            rel = path.relative_to(root).as_posix()
            if path.is_symlink():
                symlinks.append(rel)
            elif name.endswith(".py"):
                modules.append(rel)
                if in_cache:
                    in_cache_py.append(rel)
            elif in_cache and name.endswith((".pyc", ".pyo")):
                continue  # an ordinary compiled cache; the source it came from is scanned
            elif name.endswith(_UNSCANNED_SUFFIXES) or ".cpython-" in name or ".abi3." in name:
                unscanned.append(rel)
    return sorted(modules), sorted(symlinks), sorted(unscanned), sorted(in_cache_py)


_MAX_FOLDED = 10_000


def _constant(node: ast.AST):
    """The compile-time value of a literal string/int node, else a sentinel."""
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, int)) and not isinstance(node.value, bool):
        return node.value
    if isinstance(node, ast.Tuple) and all(isinstance(e, ast.Constant) for e in node.elts):
        return tuple(e.value for e in node.elts)
    return _NOT_CONSTANT


_NOT_CONSTANT = object()


class _FoldConstants(ast.NodeTransformer):
    """Replace compile-time-constant string expressions by their value, so what is
    judged is what the interpreter computes (``"a" + "b"`` -> ``"ab"``)."""

    def visit_BinOp(self, node: ast.BinOp):
        self.generic_visit(node)
        left, right = _constant(node.left), _constant(node.right)
        if left is _NOT_CONSTANT or right is _NOT_CONSTANT:
            return node
        try:
            if isinstance(node.op, ast.Add) and isinstance(left, str) and isinstance(right, str):
                value = left + right
            elif isinstance(node.op, ast.Mult) and isinstance(left, str) and isinstance(right, int) and 0 <= right <= 1000:
                value = left * right
            elif isinstance(node.op, ast.Mod) and isinstance(left, str):
                value = left % right
            else:
                return node
        except Exception:  # not foldable: leave the expression to the census as written
            return node
        if not isinstance(value, str) or len(value) > _MAX_FOLDED:
            return node
        return ast.copy_location(ast.Constant(value=value), node)

    def visit_JoinedStr(self, node: ast.JoinedStr):
        self.generic_visit(node)
        parts: list[str] = []
        for piece in node.values:
            if isinstance(piece, ast.Constant) and isinstance(piece.value, str):
                parts.append(piece.value)
            elif (
                isinstance(piece, ast.FormattedValue)
                and piece.conversion == -1
                and piece.format_spec is None
                and isinstance(piece.value, ast.Constant)
                and isinstance(piece.value.value, str)
            ):
                parts.append(piece.value.value)
            else:
                return node
        value = "".join(parts)
        if len(value) > _MAX_FOLDED:
            return node
        return ast.copy_location(ast.Constant(value=value), node)


def undocumented_sets(root: Path, census_lib) -> dict:
    registry = "\n".join((root / rel).read_text(encoding="utf-8") for rel in REGISTRY_FILES)
    modules, symlinks, unscanned, in_cache_py = enumerate_package(root)
    # BYTES -> ast: the coding cookie and BOM are honoured as the interpreter honours them.
    # Then constant expressions are folded to the value the interpreter computes.
    trees = {
        module: ast.fix_missing_locations(_FoldConstants().visit(ast.parse((root / module).read_bytes(), filename=module)))
        for module in modules
    }
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
        "importable_in_pycache": in_cache_py,
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
