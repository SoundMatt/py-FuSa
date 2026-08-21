"""Regression test for a duplicated-logic finding from a follow-up
authenticity/quality audit: rules/lint.py (LINT004) and rules/comp.py
(COMP001, and the standalone `pyfusa comp` command) independently
reimplemented near-identical McCabe cyclomatic-complexity math with
slightly different AST node coverage, which could silently drift further
apart over time. Both now share one function."""

from __future__ import annotations

import ast

from pyfusa.rules.comp import cyclomatic_complexity


def test_lint004_no_longer_has_its_own_copy():
    from pyfusa.rules import lint

    assert not hasattr(lint, "_cyclomatic_complexity")
    assert lint.cyclomatic_complexity is cyclomatic_complexity


def test_pyfusa_comp_module_uses_the_shared_function():
    from pyfusa import comp

    assert comp.cyclomatic_complexity is cyclomatic_complexity


def test_union_of_previously_uncovered_node_types_all_count():
    """Constructs each of the two prior implementations independently
    missed (async for/with, assert, ternary) must all now count as
    decision points."""
    code = (
        "async def f(x):\n"
        "    async for i in x:\n"
        "        pass\n"
        "    async with x as y:\n"
        "        pass\n"
        "    assert x\n"
        "    z = 1 if x else 2\n"
        "    return z\n"
    )
    tree = ast.parse(code)
    fn = tree.body[0]
    # base 1 + AsyncFor + AsyncWith + Assert + IfExp
    assert cyclomatic_complexity(fn) == 5


def test_match_case_and_comprehension_ifs_still_count():
    """rules/comp.py's own pre-existing coverage (match statements,
    per-clause comprehension ifs) must survive the merge unchanged."""
    code = (
        "def f(x):\n"
        "    y = [i for i in x if i > 0 if i < 10]\n"
        "    match x:\n"
        "        case 1:\n"
        "            pass\n"
        "        case _:\n"
        "            pass\n"
        "    return y\n"
    )
    tree = ast.parse(code)
    fn = tree.body[0]
    # base 1 + comprehension(1) + 2 ifs + 2 match_case clauses (each
    # match_case.pattern is always non-None in valid AST, including "case _")
    assert cyclomatic_complexity(fn) == 6
