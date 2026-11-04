"""Form-agnostic failure-code census (SCITT-HARDEN0-P3).

``tests/test_failure_code_registry.py`` extracts codes from a fixed list of
call-site *spellings* (``_fail``/``_finding`` argument 1, ``.append``, list
returns, ``code=``). A code emitted through any other spelling is invisible to
it, and the registry check that depends on it passes vacuously for that code.
At the P2 head 10 of the 20 codes of ``c2pa_test_signature0.py`` were invisible:
tuple returns, codes passed to a helper whose parameter is a list, an
if/else assignment, ``list.insert`` and an ``identity_codes=`` keyword.

This module discovers emit sites by what they DO, not by how they are spelled.

* SINKS ARE DISCOVERED, NOT LISTED. Every ``def`` whose parameter name contains
  ``code`` (``code``, ``codes``, ``failure_codes``, ``identity_codes`` ...) is a
  sink; the argument bound to that parameter at every call of that function in
  the module is an emitted-code position. ``self.fail(code, ...)``,
  ``_reject(code)``, ``_finding(..., codes, ...)`` and a helper added tomorrow
  are therefore found without editing this file.
* Any keyword argument whose name contains ``code`` is a sink.
* ``.append/.add/.extend/.insert`` arguments, ``raise ValueError(<const>)``,
  ``return`` values, assignments / augmented assignments to a name or attribute
  containing ``code``, and ``{"code": ...}`` dict values are sinks.
* A harvested expression is descended structurally: tuple/list/set elements,
  both arms of an if/else, ``or``/``and`` operands, ``frozenset({...})`` /
  ``tuple(...)`` / ``sorted(...)`` wrappers, and string concatenation. An
  f-string or ``"prefix" + x`` yields a FAMILY PREFIX, not a static code.
* A ``for name in (<literal strings>)`` loop whose variable reaches a sink in
  its body contributes the iterated literals (so a tuple of codes inside a loop
  is not hidden).

Every site is recorded as ``(module, line, form)`` so the census can be
enumerated and counted mechanically, and each form can be mutated separately.
The only content filter is SHAPE: a code is one identifier-like token
(``[A-Za-z][A-Za-z0-9_.:]*``; ``:`` appears in family prefixes and in
``family:detail`` literals), and is not a bare hex digest. Detail text contains spaces and is
excluded by shape, never by name.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "arcs_verify"

_CODE_SHAPE = re.compile(r"^[A-Za-z][A-Za-z0-9_.:]*$")
_DIGEST_SHAPE = re.compile(r"^[0-9a-fA-F]{32,}$")

# Forms, as recorded on every site. Mutation tests enumerate these.
FORMS = (
    "sink-call",
    "keyword",
    "append",
    "raise",
    "return",
    "assign",
    "dict-value",
    "for-literal",
)


def is_code_shaped(value: str) -> bool:
    return bool(_CODE_SHAPE.match(value)) and not _DIGEST_SHAPE.match(value)


@dataclass
class Census:
    """Codes and family prefixes found in one module, with every site."""

    module: str
    static: dict[str, list[tuple[int, str]]] = field(default_factory=dict)
    families: dict[str, list[tuple[int, str]]] = field(default_factory=dict)

    def site_count(self) -> int:
        return sum(len(v) for v in self.static.values()) + sum(len(v) for v in self.families.values())

    def codes(self) -> set[str]:
        return set(self.static)

    def prefixes(self) -> set[str]:
        return set(self.families)


def _callee(func: ast.expr) -> str | None:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _defined_sinks(tree: ast.AST) -> dict[str, set[tuple[int | None, str]]]:
    """name -> {(positional index excluding self/cls | None for kw-only, param name)}."""
    sinks: dict[str, set[tuple[int | None, str]]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        positional = [a.arg for a in node.args.posonlyargs + node.args.args]
        offset = 1 if positional and positional[0] in ("self", "cls") else 0
        for index, name in enumerate(positional[offset:]):
            if "code" in name.lower():
                sinks.setdefault(node.name, set()).add((index, name))
        for arg in node.args.kwonlyargs:
            if "code" in arg.arg.lower():
                sinks.setdefault(node.name, set()).add((None, arg.arg))
    return sinks


def package_sinks() -> dict[str, set[tuple[int | None, str]]]:
    """Sinks defined anywhere in the package, for names a module only imports."""
    merged: dict[str, set[tuple[int | None, str]]] = {}
    for path in sorted(PACKAGE.rglob("*.py")):
        for name, spec in _defined_sinks(ast.parse(path.read_text(encoding="utf-8"))).items():
            merged.setdefault(name, set()).update(spec)
    return merged


class _Collector:
    def __init__(self, module: str) -> None:
        self.census = Census(module)

    def _add_static(self, value: str, line: int, form: str) -> None:
        if value and " " not in value and is_code_shaped(value):
            self.census.static.setdefault(value, []).append((line, form))

    def _add_family(self, prefix: str, line: int, form: str) -> None:
        prefix = prefix.rstrip()  # "code: {detail}" -> the family is "code:"
        if prefix and " " not in prefix and is_code_shaped(prefix.rstrip(":") or "x"):
            self.census.families.setdefault(prefix, []).append((line, form))

    def harvest(self, node: ast.expr | None, line: int, form: str) -> None:
        if node is None:
            return
        # A site is the line of the LITERAL, not of the statement around it: a
        # multi-line call or literal puts its codes on later lines.
        line = getattr(node, "lineno", line)
        if isinstance(node, ast.Constant):
            if isinstance(node.value, str):
                self._add_static(node.value, line, form)
        elif isinstance(node, ast.JoinedStr):
            pieces = [str(p.value) if isinstance(p, ast.Constant) else "{VAR}" for p in node.values]
            joined = "".join(pieces)
            if "{VAR}" in joined:
                self._add_family(joined.split("{VAR}", 1)[0], line, form)
            else:
                self._add_static(joined, line, form)
        elif isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            for element in node.elts:
                self.harvest(element, line, form)
        elif isinstance(node, ast.IfExp):
            self.harvest(node.body, line, form)
            self.harvest(node.orelse, line, form)
        elif isinstance(node, ast.BoolOp):
            for value in node.values:
                self.harvest(value, line, form)
        elif isinstance(node, ast.Starred):
            self.harvest(node.value, line, form)
        elif isinstance(node, ast.Call):
            if _callee(node.func) in ("frozenset", "set", "tuple", "list", "sorted") and node.args:
                self.harvest(node.args[0], line, form)
        elif isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            left = node.left
            if isinstance(left, ast.Constant) and isinstance(left.value, str) and not isinstance(node.right, ast.Constant):
                self._add_family(left.value, line, form)
            else:
                self.harvest(node.left, line, form)
                self.harvest(node.right, line, form)

    @staticmethod
    def _names(node: ast.expr | None) -> set[str]:
        """Bare names that ARE a harvested value (for loop variables)."""
        found: set[str] = set()
        if node is None:
            return found
        if isinstance(node, ast.Name):
            found.add(node.id)
        elif isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            for element in node.elts:
                found |= _Collector._names(element)
        elif isinstance(node, ast.IfExp):
            found |= _Collector._names(node.body) | _Collector._names(node.orelse)
        # A name interpolated into an f-string or concatenation is PART of a code
        # (the family prefix is already harvested); only a name that IS the whole
        # emitted value stands for the literals a loop iterates.
        return found


_SINKS_CACHE: dict[str, set[tuple[int | None, str]]] | None = None


def cached_package_sinks() -> dict[str, set[tuple[int | None, str]]]:
    global _SINKS_CACHE
    if _SINKS_CACHE is None:
        _SINKS_CACHE = package_sinks()
    return _SINKS_CACHE


def parse_module(module: str) -> ast.Module:
    return ast.parse((ROOT / module).read_text(encoding="utf-8"))


def extract(
    module: str,
    source: str | None = None,
    sinks: dict | None = None,
    tree: ast.AST | None = None,
) -> Census:
    """Census one module.

    ``source`` or ``tree`` override the file bytes (for mutation tests). Sinks
    for names a module only imports default to the package-wide discovery.
    """
    if tree is None:
        text = source if source is not None else (ROOT / module).read_text(encoding="utf-8")
        tree = ast.parse(text)
    local = _defined_sinks(tree)
    shared = sinks if sinks is not None else cached_package_sinks()
    collector = _Collector(module)
    flowing: set[str] = set()  # names that reached a sink, for for-literal resolution

    def note_names(node: ast.expr | None) -> None:
        flowing.update(_Collector._names(node))

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _callee(node.func)
            specs = local.get(name) or (shared.get(name) if name not in local else None) or set()
            for index, param in specs:
                if index is not None and index < len(node.args):
                    collector.harvest(node.args[index], node.lineno, "sink-call")
                    note_names(node.args[index])
                for keyword in node.keywords:
                    if keyword.arg == param:
                        collector.harvest(keyword.value, node.lineno, "sink-call")
                        note_names(keyword.value)
            for keyword in node.keywords:
                if keyword.arg and "code" in keyword.arg.lower():
                    collector.harvest(keyword.value, node.lineno, "keyword")
                    note_names(keyword.value)
            if isinstance(node.func, ast.Attribute) and node.func.attr in ("append", "add", "extend") and node.args:
                collector.harvest(node.args[0], node.lineno, "append")
                note_names(node.args[0])
            if isinstance(node.func, ast.Attribute) and node.func.attr == "insert" and len(node.args) > 1:
                collector.harvest(node.args[1], node.lineno, "append")
                note_names(node.args[1])
            if name == "ValueError" and node.args:
                collector.harvest(node.args[0], node.lineno, "raise")
        elif isinstance(node, ast.Return):
            collector.harvest(node.value, node.lineno, "return")
            note_names(node.value)
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                label = target.id if isinstance(target, ast.Name) else getattr(target, "attr", None)
                if label and "code" in label.lower() and node.value is not None:
                    collector.harvest(node.value, node.lineno, "assign")
                    note_names(node.value)
        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if isinstance(key, ast.Constant) and isinstance(key.value, str) and "code" in key.value.lower():
                    collector.harvest(value, node.lineno, "dict-value")
                    note_names(value)

    for node in ast.walk(tree):
        if (
            isinstance(node, ast.For)
            and isinstance(node.target, ast.Name)
            and node.target.id in flowing
            and isinstance(node.iter, (ast.Tuple, ast.List, ast.Set))
        ):
            collector.harvest(node.iter, node.lineno, "for-literal")

    return collector.census


def emit_site_inventory(module: str, source: str | None = None) -> list[tuple[str, int, str]]:
    """Every (code-or-prefix, line, form) site, sorted: the mechanical enumeration."""
    census = extract(module, source)
    rows = [(code, line, form) for code, sites in census.static.items() for line, form in sites]
    rows += [(prefix + "<...>", line, form) for prefix, sites in census.families.items() for line, form in sites]
    return sorted(rows, key=lambda row: (row[1], row[0], row[2]))


def package_modules() -> list[str]:
    return sorted(p.relative_to(ROOT).as_posix() for p in PACKAGE.rglob("*.py"))
