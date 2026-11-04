"""SCITT-HARDEN0-P3: failure-code registry completeness, in both directions.

``test_failure_code_registry.py`` is kept unchanged. It extracts codes from a
fixed list of call-site spellings, and a code emitted through any other spelling
was silently skipped: at the P2 head it discovered 10 of the 20 codes of
``c2pa_test_signature0.py`` while the registry check read as green. This file
adds the form-agnostic census in ``failure_code_census.py`` and proves it
complete rather than asserting it:

1. DISCOVERY IS A SUPERSET. Everything the legacy extractor found, the census
   still finds, in every legacy module.
2. THE INVENTORY IS COMPLETE. Every module under ``arcs_verify/`` is scanned.
   A module that emits codes is either registered (its codes are checked
   against the registry) or listed in ``failure_code_known_gaps.json`` with the
   exact codes still undocumented. The list is two-sided: a new emitting module,
   a new undocumented code, or a gap that has been closed but not removed all
   fail, so the list can only shrink.
3. EVERY EMITTED CODE IS DOCUMENTED, per module, so a failure names the module.
4. EVERY DOCUMENTED CODE IN A MODULE-BOUND SECTION IS EMITTED (the C2PA-SIGNED0
   section is bound to ``c2pa_test_signature0.py`` row for row).
5. ADVERSARIAL DELETION, one code or one site at a time, each a named test:
   * deleting any one emitted code from the registry is detected;
   * deleting the last emission of any documented signed-lane code is detected;
   * mutating ANY ONE emit site of ANY inventory module removes exactly that
     site from the census, so no site is covered only because a sibling is;
   * each emission FORM, planted in a synthetic module, is discovered and, being
     undocumented, flagged.
"""

from __future__ import annotations

import ast
import json
import re
from collections.abc import Iterator
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path

import pytest

import failure_code_census as census_lib
import test_failure_code_registry as legacy

ROOT = census_lib.ROOT
REGISTRY = legacy.REGISTRY
KNOWN_GAPS_PATH = Path(__file__).with_name("failure_code_known_gaps.json")

# Emitting modules the legacy MODULES list does not carry. dagr_authority_context_producer_landed.py
# overlays the producer verifier's codes and every one is already documented.
EXTRA_REGISTERED = ("arcs_verify/dagr_authority_context_producer_landed.py",)
REGISTERED = tuple(legacy.MODULES) + EXTRA_REGISTERED

# A string the census harvests that is not a verifier failure code. Each entry
# names the module, the string, why it is not a code, and where its vocabulary
# is recorded. The table is two-sided: an entry the census no longer harvests is
# stale and fails, so it cannot quietly outlive its reason.
#   key: (module, token)  value: (reason, evidence_file or None)
_TAXONOMY = "arcs_verify/contracts/c2pa-native-finding/v0.1/comparison-taxonomy.json"
NOT_CODES: dict[tuple[str, str], tuple[str, str | None]] = {
    (
        "arcs_verify/c2pa_native.py",
        token,
    ): ("comparison-taxonomy reason/delta value returned by a classifier, not a failure code", _TAXONOMY)
    for token in (
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
}
NOT_CODES[("arcs_verify/okf_attested_computation.py", "unreadable:")] = (
    "detail text 'unreadable: <path>: <error>' returned beside None by a file reader; "
    "the failure code for it is okf_attested_computation.resource_not_a_file/resource_missing",
    None,
)

# A prefix every digest helper returns ("sha256:" + hexdigest). It names a value
# format, never a failure code, and appears in modules that emit no codes at all.
NOT_CODE_PREFIXES = frozenset({"sha256:"})

# Verdict-state words returned next to codes. Documented once for the whole
# registry; excluded only from the row-for-row section binding below.
STATUS_WORDS = frozenset({"pass", "fail", "not_evaluated", "not_applicable"})

# Documentation sections whose rows are bound to exactly one module: the set of
# codes the module emits (less status words) must equal the set of rows.
BOUND_SECTIONS = {
    "## C2PA-SIGNED0 test-only receipt signature lane": "arcs_verify/c2pa_test_signature0.py",
}

MUTATED = "zz_mutated_for_p3"


@lru_cache(maxsize=None)
def _tree(module: str) -> ast.Module:
    return census_lib.parse_module(module)


@lru_cache(maxsize=None)
def _census(module: str) -> census_lib.Census:
    return census_lib.extract(module, tree=_tree(module))


def _known_gaps() -> dict[str, dict]:
    return json.loads(KNOWN_GAPS_PATH.read_text(encoding="utf-8"))["modules"]


def _effective(module: str, found: census_lib.Census) -> tuple[set[str], set[str]]:
    """(codes, family prefixes) after removing entries the NOT_CODES table explains."""
    codes = {c for c in found.static if (module, c) not in NOT_CODES}
    prefixes = {
        p for p in found.families if (module, p) not in NOT_CODES and p not in NOT_CODE_PREFIXES
    }
    return codes, prefixes


def _undocumented(module: str, found: census_lib.Census, registry: str) -> tuple[set[str], set[str]]:
    codes, prefixes = _effective(module, found)
    return (
        {c for c in codes if f"`{c}`" not in registry},
        {p for p in prefixes if p not in registry},
    )


def _assert_documented(module: str, found: census_lib.Census, registry: str) -> None:
    codes, prefixes = _undocumented(module, found, registry)
    problems = [f"{module}: {c}" for c in sorted(codes)] + [f"{module}: {p}<...>" for p in sorted(prefixes)]
    assert not problems, "codes emitted but absent from the failure-code registries:\n" + "\n".join(problems)


@contextmanager
def _mutated(module: str, predicate) -> Iterator[int]:
    """Rename matching string Constants in the cached tree, then restore them."""
    touched: list[tuple[ast.Constant, str]] = []
    for node in ast.walk(_tree(module)):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and predicate(node):
            touched.append((node, node.value))
            node.value = MUTATED
    try:
        yield len(touched)
    finally:
        for node, original in touched:
            node.value = original


def _section(heading: str) -> str:
    start = REGISTRY.index(heading)
    nxt = REGISTRY.find("\n## ", start + 1)
    return REGISTRY[start : nxt if nxt != -1 else len(REGISTRY)]


def _section_rows(heading: str) -> set[str]:
    return set(re.findall(r"^\| `([A-Za-z][A-Za-z0-9_.]*)` \|", _section(heading), re.M))


# ---------------------------------------------------------------------------
# 1. discovery is a superset of the legacy extractor
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("module", legacy.MODULES)
def test_census_is_a_superset_of_the_legacy_extractor(module: str) -> None:
    legacy_static, legacy_families = legacy._extract(module)
    found = _census(module)
    lost_static = sorted(legacy_static - set(found.static))
    lost_families = sorted(legacy_families - set(found.families))
    assert not lost_static and not lost_families, (
        f"{module}: the census lost what the legacy extractor found: "
        f"codes={lost_static} families={lost_families}"
    )


def test_census_reaches_every_signed_lane_code_the_legacy_extractor_missed() -> None:
    """Positive control for the reported gap: the legacy extractor saw 10 of the
    20 signed-lane codes. The census must see all 20 (plus the status words)."""
    module = "arcs_verify/c2pa_test_signature0.py"
    legacy_seen = legacy._extract(module)[0]
    documented = _section_rows(next(iter(BOUND_SECTIONS)))
    census_seen = set(_census(module).static) - STATUS_WORDS
    assert len(documented) == 20
    assert len(legacy_seen & documented) == 10, "the legacy extractor's blind spot changed; re-baseline deliberately"
    assert census_seen == documented


# ---------------------------------------------------------------------------
# 2. the inventory is complete and its exceptions are two-sided
# ---------------------------------------------------------------------------


def test_inventory_scans_every_module_and_classifies_every_emitter() -> None:
    gaps = _known_gaps()
    modules = census_lib.package_modules()
    assert len(modules) >= 50, "the package inventory is implausibly small; the scan is not reaching arcs_verify/"
    emitting = {m for m in modules if _effective(m, _census(m))[0] | _effective(m, _census(m))[1]}
    unclassified = sorted(emitting - set(REGISTERED) - set(gaps))
    assert not unclassified, (
        "modules emit failure-code-shaped values but are neither registered nor listed in "
        "failure_code_known_gaps.json:\n" + "\n".join(unclassified)
    )
    stale = sorted(set(gaps) - emitting)
    assert not stale, "known-gap modules no longer emit anything; remove them:\n" + "\n".join(stale)
    overlap = sorted(set(gaps) & set(REGISTERED))
    assert not overlap, "a module is both registered and a known gap:\n" + "\n".join(overlap)
    for module in REGISTERED:
        assert module in modules, f"registered module {module} does not exist"


def test_not_codes_entries_are_live_and_evidenced() -> None:
    for (module, token), (reason, evidence) in sorted(NOT_CODES.items()):
        found = _census(module)
        assert token in found.static or token in found.families, (
            f"NOT_CODES entry ({module}, {token}) is stale: the census no longer harvests it"
        )
        assert reason.strip()
        if evidence is not None:
            assert f'"{token}"' in (ROOT / evidence).read_text(encoding="utf-8"), (
                f"NOT_CODES entry ({module}, {token}) names {evidence}, which does not record it"
            )


@pytest.mark.parametrize("module", sorted(_known_gaps()))
def test_known_gap_is_exactly_the_undocumented_set(module: str) -> None:
    pinned = _known_gaps()[module]
    codes, prefixes = _undocumented(module, _census(module), REGISTRY)
    assert sorted(codes) == sorted(pinned["codes"]) and sorted(prefixes) == sorted(pinned["families"]), (
        f"{module}: the undocumented set moved. If codes were documented, shrink the pin; if a new "
        f"undocumented code appeared, document it.\n  now codes={sorted(codes)} families={sorted(prefixes)}\n"
        f"  pinned codes={sorted(pinned['codes'])} families={sorted(pinned['families'])}"
    )
    assert pinned["reason"].strip()


# ---------------------------------------------------------------------------
# 3. every emitted code is documented, one test per module
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("module", REGISTERED)
def test_every_emitted_code_is_documented(module: str) -> None:
    _assert_documented(module, _census(module), REGISTRY)


# ---------------------------------------------------------------------------
# 4. module-bound sections list exactly what the module emits
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("heading", sorted(BOUND_SECTIONS))
def test_bound_section_rows_equal_emitted_codes(heading: str) -> None:
    module = BOUND_SECTIONS[heading]
    documented = _section_rows(heading)
    emitted = set(_census(module).static) - STATUS_WORDS
    assert emitted == documented, (
        f"{module} vs '{heading}': emitted-not-documented={sorted(emitted - documented)} "
        f"documented-not-emitted={sorted(documented - emitted)}"
    )


# ---------------------------------------------------------------------------
# 5. adversarial deletion
# ---------------------------------------------------------------------------


def _all_codes() -> list[tuple[str, str]]:
    return [(m, c) for m in REGISTERED for c in sorted(_effective(m, _census(m))[0])]


@pytest.mark.parametrize("module,code", _all_codes(), ids=lambda v: v.rsplit("/", 1)[-1] if "/" in v else v)
def test_deleting_one_emitted_code_from_the_registry_is_detected(module: str, code: str) -> None:
    """Remove ONE emitted code from the registry text; the documented-code test
    must refuse and name it. Every (module, code) of every registered module."""
    mutated = REGISTRY.replace(f"`{code}`", "`__deleted__`")
    assert mutated != REGISTRY, f"{code} is not documented in backticks at all"
    with pytest.raises(AssertionError) as raised:
        _assert_documented(module, _census(module), mutated)
    assert f"{module}: {code}" in str(raised.value)


def _site_params() -> list[tuple[str, str, int, str]]:
    rows = []
    modules = sorted(set(REGISTERED) | set(_known_gaps()))
    for module in modules:
        found = _census(module)
        for code, sites in sorted(found.static.items()):
            rows += [(module, code, line, form) for line, form in sorted(set(sites))]
        for prefix, sites in sorted(found.families.items()):
            rows += [(module, prefix, line, form) for line, form in sorted(set(sites))]
    return rows


def _site_id(row: tuple[str, str, int, str]) -> str:
    module, token, line, form = row
    return f"{module.rsplit('/', 1)[-1]}:{line}:{form}:{token}"


@pytest.mark.parametrize("row", _site_params(), ids=_site_id)
def test_mutating_one_emit_site_removes_exactly_that_site(row: tuple[str, str, int, str]) -> None:
    """A mutation covers only the site it touches: rename the literal at ONE
    (line, form) site and require the census to lose that site. Passing for the
    representative site of a code says nothing about its siblings, so every site
    of every inventory module is mutated separately."""
    module, token, line, form = row
    is_prefix = token not in _census(module).static

    def hits(node: ast.Constant) -> bool:
        if node.lineno != line:
            return False
        return node.value.startswith(token.rstrip()) if is_prefix else node.value == token

    before = _census(module)
    pool = before.families if is_prefix else before.static
    assert (line, form) in pool[token]
    with _mutated(module, hits) as touched:
        assert touched >= 1, f"no string literal for {token!r} on line {line}"
        after = census_lib.extract(module, tree=_tree(module))
    pool_after = after.families if is_prefix else after.static
    assert (line, form) not in pool_after.get(token, []), (
        f"{module}:{line} {form}: mutating the literal {token!r} did not remove the site, "
        "so the census was reaching it through some other path"
    )
    assert after.site_count() <= before.site_count()


def _signed_lane_rows() -> list[str]:
    return sorted(_section_rows(next(iter(BOUND_SECTIONS))))


@pytest.mark.parametrize("code", _signed_lane_rows())
def test_deleting_the_last_emission_of_a_documented_signed_lane_code_is_detected(code: str) -> None:
    """The converse direction: a documented code that the module stops emitting
    must fail the section binding, by name."""
    heading = next(iter(BOUND_SECTIONS))
    module = BOUND_SECTIONS[heading]
    with _mutated(module, lambda node: node.value == code) as touched:
        assert touched >= 1
        after = census_lib.extract(module, tree=_tree(module))
    emitted = set(after.static) - STATUS_WORDS
    documented = _section_rows(heading)
    assert code in documented - emitted, f"{code} still looks emitted after every literal was renamed"


# One synthetic emission per FORM, planted in a throw-away module. If a form is
# not discovered it would be invisible in the real tree too.
_FORM_SNIPPETS = {
    "sink-call": "def _sink(report, code):\n    report.append(code)\n\n\ndef f(report):\n    _sink(report, 'zz_new_code')\n",
    "keyword": "def f(make):\n    return make(identity_codes=('zz_new_code',))\n",
    "append": "def f(out):\n    out.insert(0, 'zz_new_code')\n",
    "raise": "def f():\n    raise ValueError('zz_new_code')\n",
    "return": "def f():\n    return None, ('zz_new_code',)\n",
    "assign": "def f(trusted):\n    codes = [] if trusted else ['zz_new_code']\n    return codes\n",
    "dict-value": "def f():\n    return {'code': 'zz_new_code'}\n",
    "for-literal": "def f(report):\n    for name in ('zz_new_code', 'zz_other'):\n        report.append(name)\n",
}


def test_form_snippets_cover_every_declared_form() -> None:
    assert set(_FORM_SNIPPETS) == set(census_lib.FORMS)


@pytest.mark.parametrize("form", census_lib.FORMS)
def test_each_emission_form_is_discovered_and_flagged_when_undocumented(form: str) -> None:
    found = census_lib.extract("synthetic.py", source=_FORM_SNIPPETS[form], sinks={})
    assert "zz_new_code" in found.static, f"form {form!r} was not discovered"
    codes, _ = _undocumented("synthetic.py", found, REGISTRY)
    assert "zz_new_code" in codes
    with pytest.raises(AssertionError):
        _assert_documented("synthetic.py", found, REGISTRY)
    _assert_documented("synthetic.py", found, REGISTRY + "\n| `zz_new_code` | planted |\n| `zz_other` | planted |")


def test_f_string_and_concatenation_families_are_discovered_not_dropped() -> None:
    source = "def f(out, x):\n    out.append(f'zz_family.{x}')\n    out.append('zz_concat:' + x)\n    raise ValueError(f'zz_decode: {x}')\n"
    found = census_lib.extract("synthetic.py", source=source, sinks={})
    assert {"zz_family.", "zz_concat:", "zz_decode:"} <= set(found.families)


# ---------------------------------------------------------------------------
# mechanical enumeration, printed for the record
# ---------------------------------------------------------------------------


def test_inventory_counts_are_reported(capsys: pytest.CaptureFixture[str]) -> None:
    with capsys.disabled():
        modules = sorted(set(REGISTERED) | set(_known_gaps()))
        total_codes = total_sites = 0
        for module in modules:
            found = _census(module)
            total_codes += len(found.static)
            total_sites += found.site_count()
        print(
            f"\nfailure-code census: {len(census_lib.package_modules())} package modules scanned, "
            f"{len(modules)} emitting ({len(REGISTERED)} registered, {len(_known_gaps())} known-gap), "
            f"{total_codes} distinct codes, {total_sites} emit sites"
        )
    assert total_codes > 0
