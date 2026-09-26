"""Sigma-like matching engine.

Supports: field maps (AND), lists of maps (OR), value lists (OR), keyword
lists, modifiers contains/startswith/endswith/re/all/exists/cased, glob
wildcards, case-insensitive equality, and conditions with and/or/not/
parentheses, `1 of sel*`, `all of sel*`, `1 of them`, `all of them`.
"""
from __future__ import annotations

import fnmatch
import re
from functools import lru_cache
from typing import Any

from .models import Rule

MODIFIERS = {"contains", "startswith", "endswith", "re", "all", "exists", "cased"}


class ConditionError(ValueError):
    pass


def get_field(event: dict[str, Any], field: str) -> Any:
    if field in event:
        return event[field]
    cur: Any = event
    for part in field.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


@lru_cache(maxsize=4096)
def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


def _match_value(actual: Any, expected: Any, mods: list[str]) -> bool:
    if "exists" in mods:
        return (actual is not None) == bool(expected)
    if actual is None or expected is None:
        return actual is None and expected is None
    if "re" in mods:
        return _rx(str(expected)).search(str(actual)) is not None
    a, e = str(actual), str(expected)
    if "cased" not in mods:
        a, e = a.lower(), e.lower()
    if "contains" in mods:
        return e in a
    if "startswith" in mods:
        return a.startswith(e)
    if "endswith" in mods:
        return a.endswith(e)
    if isinstance(actual, (int, float)) and isinstance(expected, (int, float)) \
            and not isinstance(actual, bool):
        return actual == expected
    if "*" in e or "?" in e:
        return fnmatch.fnmatchcase(a, e)
    return a == e


def match_field(event: dict[str, Any], key: str, expected: Any) -> bool:
    field, *mods = key.split("|")
    unknown = set(mods) - MODIFIERS
    if unknown:
        raise ValueError(f"unknown modifier(s): {sorted(unknown)}")
    actual = get_field(event, field)
    values = expected if isinstance(expected, list) else [expected]
    actuals = actual if isinstance(actual, list) else [actual]

    def test(v: Any) -> bool:
        return any(_match_value(x, v, mods) for x in actuals)

    return all(test(v) for v in values) if "all" in mods else any(test(v) for v in values)


def match_selection(event: dict[str, Any], selection: Any) -> bool:
    if isinstance(selection, list):
        if selection and all(isinstance(s, dict) for s in selection):
            return any(match_selection(event, s) for s in selection)
        blob = " ".join(str(v) for v in event.values()).lower()
        return any(str(k).lower() in blob for k in selection)
    if isinstance(selection, dict):
        return all(match_field(event, k, v) for k, v in selection.items())
    raise ValueError(f"unsupported selection type {type(selection).__name__}")


_TOKEN = re.compile(r"\(|\)|[A-Za-z0-9_*]+")


def tokenize(cond: str) -> list[str]:
    out, pos = [], 0
    while pos < len(cond):
        if cond[pos].isspace():
            pos += 1
            continue
        m = _TOKEN.match(cond, pos)
        if not m:
            raise ConditionError(f"bad character at {pos}: {cond[pos:]!r}")
        out.append(m.group(0))
        pos = m.end()
    return out


class _Parser:
    """or := and ('or' and)* ; and := not ('and' not)* ; not := 'not' not | atom."""

    def __init__(self, tokens: list[str], names: list[str]):
        self.t, self.i, self.names = tokens, 0, names

    def peek(self) -> str:
        return self.t[self.i] if self.i < len(self.t) else ""

    def take(self) -> str:
        if self.i >= len(self.t):
            raise ConditionError("unexpected end of condition")
        self.i += 1
        return self.t[self.i - 1]

    def parse(self):
        if not self.t:
            raise ConditionError("empty condition")
        node = self.or_expr()
        if self.peek():
            raise ConditionError(f"unexpected token {self.peek()!r}")
        return node

    def or_expr(self):
        node = self.and_expr()
        while self.peek().lower() == "or":
            self.take()
            node = ("or", node, self.and_expr())
        return node

    def and_expr(self):
        node = self.not_expr()
        while self.peek().lower() == "and":
            self.take()
            node = ("and", node, self.not_expr())
        return node

    def not_expr(self):
        if self.peek().lower() == "not":
            self.take()
            return ("not", self.not_expr())
        return self.atom()

    def _expand(self, pat: str) -> list[str]:
        if pat == "them":
            return list(self.names)
        found = [n for n in self.names if fnmatch.fnmatchcase(n, pat)]
        if not found:
            raise ConditionError(f"pattern {pat!r} matches no selection")
        return found

    def atom(self):
        tok = self.take()
        if tok == "(":
            node = self.or_expr()
            if self.take() != ")":
                raise ConditionError("expected ')'")
            return node
        if tok in ("1", "all") and self.peek().lower() == "of":
            self.take()
            return ("any" if tok == "1" else "all", self._expand(self.take()))
        if tok not in self.names:
            raise ConditionError(f"unknown selection {tok!r}")
        return ("sel", tok)


def parse_condition(cond: str, names: list[str]):
    return _Parser(tokenize(cond), names).parse()


def referenced_selections(node) -> set[str]:
    op = node[0]
    if op == "sel":
        return {node[1]}
    if op in ("any", "all"):
        return set(node[1])
    return set().union(*(referenced_selections(c) for c in node[1:]))


def _eval(node, ev) -> bool:
    op = node[0]
    if op == "sel":
        return ev(node[1])
    if op == "not":
        return not _eval(node[1], ev)
    if op == "and":
        return _eval(node[1], ev) and _eval(node[2], ev)
    if op == "or":
        return _eval(node[1], ev) or _eval(node[2], ev)
    if op == "any":
        return any(ev(n) for n in node[1])
    return all(ev(n) for n in node[1])


class CompiledRule:
    def __init__(self, rule: Rule):
        self.rule = rule
        self.sels = rule.selections
        self.ast = parse_condition(rule.condition, list(self.sels))

    def matches(self, event: dict[str, Any]) -> bool:
        cache: dict[str, bool] = {}

        def ev(name: str) -> bool:
            if name not in cache:
                cache[name] = match_selection(event, self.sels[name])
            return cache[name]

        return _eval(self.ast, ev)


def compile_rule(rule: Rule) -> CompiledRule:
    return CompiledRule(rule)


def run(rule: Rule, events: list[dict[str, Any]]) -> list[int]:
    cr = compile_rule(rule)
    return [i for i, e in enumerate(events) if cr.matches(e)]


def rule_fields(rule: Rule) -> set[str]:
    """All event field names a rule references (for schema-drift checks)."""
    out: set[str] = set()

    def walk(sel: Any) -> None:
        if isinstance(sel, dict):
            out.update(k.split("|")[0] for k in sel)
        elif isinstance(sel, list):
            for s in sel:
                if isinstance(s, dict):
                    walk(s)

    for s in rule.selections.values():
        walk(s)
    return out
