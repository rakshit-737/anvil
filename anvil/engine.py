"""Sigma matching engine.

Rules are compiled once into a tree of small predicate closures, then applied to
many events. Supported (covers >95% of the SigmaHQ Windows/Linux rule corpus):

* selections: field maps (AND), lists of maps (OR), value lists (OR), keyword
  lists (full-text search over all event values), ``null`` values
* wildcards ``*``/``?`` with Sigma escaping (``\\*``, ``\\?``, ``\\\\``)
* modifiers: contains, startswith, endswith, all, exists, cased, re (+ i/m/s),
  windash, base64, base64offset, wide/utf16le/utf16be/utf16, cidr,
  lt/lte/gt/gte, fieldref, neq
* conditions: and/or/not, parentheses, ``1 of x*``, ``all of x*``, ``them``

Anything else (aggregations ``| count()``, ``expand`` placeholders, unknown
modifiers) raises :class:`UnsupportedRule` at compile time, so callers can
report coverage honestly instead of silently mis-evaluating a rule.
"""
from __future__ import annotations

import base64
import fnmatch
import ipaddress
import re
from functools import lru_cache
from typing import Any, Callable

from .models import Rule

try:  # optional: Aho-Corasick makes large OR-lists of substrings O(len(text))
    import ahocorasick as _ac  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - exercised when the extra is not installed
    _ac = None
AC_MIN_LITERALS = 8

Event = dict[str, Any]
Pred = Callable[[Event], bool]

STRING_MODS = {"contains", "startswith", "endswith"}
ENCODING_MODS = {"base64", "base64offset", "wide", "utf16le", "utf16be", "utf16", "windash"}
COMPARE_MODS = {"lt", "lte", "gt", "gte"}
MODIFIERS = (STRING_MODS | ENCODING_MODS | COMPARE_MODS
             | {"re", "i", "m", "s", "all", "exists", "cased", "cidr", "fieldref", "neq"})
UNSUPPORTED_MODS = {"expand"}
DASHES = ["-", "/", "–", "—", "―"]  # windash: -, /, en dash, em dash, horizontal bar


class ConditionError(ValueError):
    pass


class UnsupportedRule(ValueError):
    """The rule uses a Sigma feature this engine deliberately does not evaluate."""


# --------------------------------------------------------------------------- fields

def get_field(event: Event, field: str) -> Any:
    if field in event:
        return event[field]
    if "." in field:
        cur: Any = event
        for part in field.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                break
        else:
            return cur
    return None


# --------------------------------------------------------------------------- values

def _sigma_glob_to_regex(value: str) -> tuple[str, bool]:
    """Translate a Sigma string to a regex body. Returns (regex, has_wildcards)."""
    out, wild, i = [], False, 0
    while i < len(value):
        c = value[i]
        if c == "\\" and i + 1 < len(value) and value[i + 1] in "*?\\":
            out.append(re.escape(value[i + 1]))
            i += 2
            continue
        if c == "*":
            out.append(".*")
            wild = True
        elif c == "?":
            out.append(".")
            wild = True
        else:
            out.append(re.escape(c))
        i += 1
    return "".join(out), wild


def _unescape(value: str) -> str:
    return re.sub(r"\\([*?\\])", r"\1", value)


def _b64_variants(raw: bytes) -> list[str]:
    """The three shifted base64 encodings used by Sigma's ``base64offset``."""
    out = []
    starts, ends = (0, 2, 3), (None, -3, -2)
    for i in range(3):
        enc = base64.b64encode(b" " * i + raw).decode()
        tail = (len(raw) + i) % 3
        enc = enc[starts[i]:ends[tail] if tail else None]
        out.append(enc)
    return out


def _encode(value: str, mods: list[str]) -> list[str]:
    """Apply encoding modifiers left-to-right (Sigma semantics), returning variants."""
    vals = [value]
    for m in mods:
        if m == "windash":
            nxt = []
            for v in vals:
                variants = {v}
                for d in DASHES:
                    variants |= {re.sub(r"(?:(?<=\s)|^)[-/]", d, v)}
                nxt.extend(sorted(variants))
            vals = nxt
        elif m in ("wide", "utf16le"):
            vals = [v.encode("utf-16-le").decode("latin-1") for v in vals]
        elif m == "utf16be":
            vals = [v.encode("utf-16-be").decode("latin-1") for v in vals]
        elif m == "utf16":
            vals = [v.encode("utf-16").decode("latin-1") for v in vals]
        elif m == "base64":
            vals = [base64.b64encode(v.encode("latin-1")).decode() for v in vals]
        elif m == "base64offset":
            vals = [e for v in vals for e in _b64_variants(v.encode("latin-1"))]
    return vals


def _to_number(x: Any) -> float | None:
    if isinstance(x, bool):
        return None
    if isinstance(x, (int, float)):
        return float(x)
    try:
        return float(str(x).strip()) if str(x).strip() else None
    except ValueError:
        try:
            return float(int(str(x), 0))
        except ValueError:
            return None


def _generic_pred(expected: Any, mods: list[str]) -> Callable[[Any], bool] | None:
    """Predicates that are not plain string literals (``actual -> bool``), else None."""
    if expected is None:
        return lambda a: a is None or a == ""
    if "cidr" in mods:
        net = ipaddress.ip_network(str(expected), strict=False)

        def cidr(a: Any) -> bool:
            try:
                return ipaddress.ip_address(str(a).strip()) in net
            except ValueError:
                return False
        return cidr
    cmp = [m for m in mods if m in COMPARE_MODS]
    if cmp:
        e = _to_number(expected)
        op = cmp[0]

        def compare(a: Any) -> bool:
            n = _to_number(a)
            if n is None or e is None:
                return False
            return {"lt": n < e, "lte": n <= e, "gt": n > e, "gte": n >= e}[op]
        return compare
    if "re" in mods:
        flags = (re.I if "i" in mods else 0) | (re.M if "m" in mods else 0) | (re.S if "s" in mods else 0)
        rx = _rx(str(expected), flags)
        return lambda a: a is not None and rx.search(str(a)) is not None
    if isinstance(expected, bool):
        return lambda a: a == expected or str(a).lower() == str(expected).lower()
    if isinstance(expected, (int, float)) and not any(m in mods for m in STRING_MODS | ENCODING_MODS):
        s_e = str(expected)
        return lambda a: a is not None and (a == expected or str(a).strip() == s_e)
    return None


@lru_cache(maxsize=65536)
def _rx(pattern: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(pattern, flags)


class _Literals:
    """OR-set of string literals for one field, matched with fast C string ops."""

    __slots__ = ("eq", "sw", "ew", "ct", "ct_rx", "ac")

    def __init__(self) -> None:
        self.eq: set[str] = set()
        self.sw: list[str] = []
        self.ew: list[str] = []
        self.ct: list[str] = []
        self.ct_rx: re.Pattern[str] | None = None
        self.ac: Any = None

    def __bool__(self) -> bool:
        return bool(self.eq or self.sw or self.ew or self.ct)

    def freeze(self) -> "_Literals":
        # NB: a regex alternation over hundreds of literals is ~50x slower than a loop of
        # C-level substring searches in CPython (no Aho-Corasick in ``re``), so keep the loop.
        self.sw, self.ew = tuple(self.sw), tuple(self.ew)  # type: ignore[assignment]
        self.ct = list(dict.fromkeys(self.ct))
        if _ac is not None and len(self.ct) >= AC_MIN_LITERALS:
            self.ac = _ac.Automaton()
            for c in self.ct:
                self.ac.add_word(c, c)
            self.ac.make_automaton()
        return self

    def test(self, s: str) -> bool:
        if s in self.eq:
            return True
        if self.sw and s.startswith(self.sw):  # type: ignore[arg-type]
            return True
        if self.ew and s.endswith(self.ew):  # type: ignore[arg-type]
            return True
        if self.ac is not None:
            for _ in self.ac.iter(s):
                return True
            return False
        for c in self.ct:
            if c in s:
                return True
        return False


def _lower(e: Event, field: str, a: Any) -> str:
    """Lower-cased string value of ``field``, cached on the event (values can be 100 KB scripts)."""
    lc = e.get("__lc__")
    if lc is None:
        lc = e["__lc__"] = {}
    s = lc.get(field)
    if s is None:
        s = lc[field] = str(a).lower()
    return s


def _value_checker(field: str, values: list[Any], mods: list[str]) -> Callable[[Event, Any], bool]:
    """OR over ``values`` for one field -> ``check(event, actual_scalar)``."""
    cased = "cased" in mods
    enc = [m for m in mods if m in ENCODING_MODS]
    op = "ct" if "contains" in mods else "sw" if "startswith" in mods else "ew" if "endswith" in mods else "eq"
    lits, generic = _Literals(), []
    for v in values:
        g = _generic_pred(v, mods)
        if g is not None:
            generic.append(g)
            continue
        for var in _encode(str(v), enc):
            body, wild = _sigma_glob_to_regex(var)
            if wild:
                pat = {"ct": body, "sw": "^" + body, "ew": body + r"\Z", "eq": "^" + body + r"\Z"}[op]
                rx = _rx(pat, (0 if cased else re.I) | re.S)
                generic.append(lambda a, rx=rx: a is not None and rx.search(str(a)) is not None)
                continue
            lit = _unescape(var) if cased else _unescape(var).lower()
            if op == "eq":
                lits.eq.add(lit)
            else:
                getattr(lits, op).append(lit)
    lits.freeze()
    has_lits = bool(lits)

    if cased:
        def check(e: Event, a: Any) -> bool:
            if a is None:
                return any(g(a) for g in generic)
            if has_lits and lits.test(str(a)):
                return True
            return any(g(a) for g in generic)
    elif not generic:
        def check(e: Event, a: Any) -> bool:
            return a is not None and lits.test(_lower(e, field, a))
    else:
        def check(e: Event, a: Any) -> bool:
            if a is not None and has_lits and lits.test(_lower(e, field, a)):
                return True
            return any(g(a) for g in generic)
    return check


# kept for tests / external callers: single value, no event cache
def _value_pred(expected: Any, mods: list[str]) -> Callable[[Any], bool]:
    chk = _value_checker("_", [expected], mods)
    return lambda a: chk({}, a)


def _field_pred(key: str, expected: Any) -> Pred:
    field, *mods = str(key).split("|")
    mods = [m.lower() for m in mods]
    bad = set(mods) & UNSUPPORTED_MODS
    if bad:
        raise UnsupportedRule(f"modifier {sorted(bad)} not supported")
    unknown = set(mods) - MODIFIERS
    if unknown:
        raise UnsupportedRule(f"unknown modifier(s): {sorted(unknown)}")
    values = expected if isinstance(expected, list) else [expected]
    if not values:
        values = [None]

    if "exists" in mods:
        want = bool(values[0]) if values else True
        return lambda e: (get_field(e, field) is not None) == want

    if "fieldref" in mods:
        refs = [str(v) for v in values]

        def fieldref(e: Event) -> bool:
            a = get_field(e, field)
            hits = [a is not None and str(a).lower() == str(get_field(e, r)).lower() for r in refs]
            return all(hits) if "all" in mods else any(hits)
        return fieldref

    neg = "neq" in mods
    checkers = ([_value_checker(field, [v], mods) for v in values] if "all" in mods
                else [_value_checker(field, values, mods)])

    def f(e: Event) -> bool:
        a = get_field(e, field)
        if isinstance(a, list):  # multi-valued field: any element may satisfy each value
            items = a or [None]
            r = all(any(c({}, x) for x in items) for c in checkers)
        elif len(checkers) == 1:
            r = checkers[0](e, a)
        else:
            r = all(c(e, a) for c in checkers)
        return not r if neg else r
    return f


def _event_blob(e: Event) -> str:
    blob = e.get("__blob__")
    if blob is None:
        parts: list[str] = []

        def walk(v: Any) -> None:
            if isinstance(v, dict):
                for x in v.values():
                    walk(x)
            elif isinstance(v, list):
                for x in v:
                    walk(x)
            elif v is not None:
                parts.append(str(v))
        walk({k: v for k, v in e.items() if not k.startswith("__")})
        blob = "\n".join(parts).lower()
        e["__blob__"] = blob
    return blob


def _keyword_pred(values: list[Any], mods: list[str] | None = None) -> Pred:
    mods = mods or []
    pats = []
    for v in values:
        for enc in _encode(str(v), [m for m in mods if m in ENCODING_MODS]):
            body, wild = _sigma_glob_to_regex(enc)
            pats.append(_rx(body, re.I | re.S).search if wild else
                        (lambda lit: lambda b: lit in b)(_unescape(enc).lower()))
    if "all" in mods:
        return lambda e: all(p(_event_blob(e)) for p in pats)
    return lambda e: any(p(_event_blob(e)) for p in pats)


def compile_selection(sel: Any) -> Pred:
    if isinstance(sel, dict):
        if not sel:
            raise UnsupportedRule("empty selection")
        preds = []
        for k, v in sel.items():
            if k is None or str(k).startswith("|"):
                # keyless modifier map, e.g. '|all': [...] (keywords with modifiers)
                preds.append(_keyword_pred(v if isinstance(v, list) else [v], str(k or "").split("|")[1:]))
            else:
                preds.append(_field_pred(str(k), v))
        if len(preds) == 1:
            return preds[0]
        return lambda e: all(p(e) for p in preds)
    if isinstance(sel, list):
        if not sel:
            raise UnsupportedRule("empty selection")
        if all(isinstance(s, dict) for s in sel):
            subs = [compile_selection(s) for s in sel]
            return lambda e: any(p(e) for p in subs)
        if any(isinstance(s, dict) for s in sel):
            subs = [compile_selection(s) if isinstance(s, dict) else _keyword_pred([s]) for s in sel]
            return lambda e: any(p(e) for p in subs)
        return _keyword_pred(sel)
    if isinstance(sel, (str, int, float)):
        return _keyword_pred([sel])
    raise UnsupportedRule(f"unsupported selection type {type(sel).__name__}")


# kept for backwards compatibility with 0.1 callers
def match_selection(event: Event, selection: Any) -> bool:
    return compile_selection(selection)(event)


def match_field(event: Event, key: str, expected: Any) -> bool:
    return _field_pred(key, expected)(event)


# --------------------------------------------------------------------------- conditions

_TOKEN = re.compile(r"\(|\)|[A-Za-z0-9_*\-.]+")


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
        if pat.lower() == "them":
            return [n for n in self.names if not n.startswith("_")]
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
        if tok.lower() in ("1", "all", "any") and self.peek().lower() == "of":
            self.take()
            return ("all" if tok.lower() == "all" else "any", self._expand(self.take()))
        if tok not in self.names:
            raise ConditionError(f"unknown selection {tok!r}")
        return ("sel", tok)


def parse_condition(cond: str, names: list[str]):
    if "|" in cond:
        raise UnsupportedRule("aggregation conditions (| count() ...) are not supported")
    return _Parser(tokenize(cond), names).parse()


def referenced_selections(node) -> set[str]:
    op = node[0]
    if op == "sel":
        return {node[1]}
    if op in ("any", "all"):
        return set(node[1])
    return set().union(*(referenced_selections(c) for c in node[1:]))


def _build(node, sels: dict[str, Pred]) -> Pred:
    op = node[0]
    if op == "sel":
        return sels[node[1]]
    if op == "not":
        inner = _build(node[1], sels)
        return lambda e: not inner(e)
    if op in ("and", "or"):
        a, b = _build(node[1], sels), _build(node[2], sels)
        return (lambda e: a(e) and b(e)) if op == "and" else (lambda e: a(e) or b(e))
    subs = [sels[n] for n in node[1]]
    return (lambda e: any(p(e) for p in subs)) if op == "any" else (lambda e: all(p(e) for p in subs))


def _conditions(rule: Rule) -> list[str]:
    raw = rule.detection.get("condition", "")
    return [str(c) for c in raw] if isinstance(raw, list) else [str(raw)]


def _sel_event_ids(sel: Any) -> frozenset[int] | None:
    """EventIDs a selection requires, or None if it does not constrain EventID."""
    if isinstance(sel, dict):
        for k, v in sel.items():
            if k is not None and str(k).split("|")[0] == "EventID" and "|" not in str(k):
                vals = v if isinstance(v, list) else [v]
                try:
                    return frozenset(int(x) for x in vals)
                except (TypeError, ValueError):
                    return None
        return None
    if isinstance(sel, list) and sel and all(isinstance(x, dict) for x in sel):
        parts = [_sel_event_ids(x) for x in sel]
        if any(p is None for p in parts):
            return None
        return frozenset().union(*parts)  # type: ignore[arg-type]
    return None


def required_event_ids(node, sels_raw: dict[str, Any]) -> frozenset[int] | None:
    """Static analysis: the EventIDs an event must have to possibly match (None = any).

    Used by the runner to index rules by (channel, EventID) instead of testing
    every rule for a channel against every event of that channel.
    """
    op = node[0]
    if op == "sel":
        return _sel_event_ids(sels_raw[node[1]])
    if op == "not":
        return None
    if op in ("and", "all"):
        kids = [required_event_ids(c, sels_raw) for c in node[1:]] if op == "and" else             [_sel_event_ids(sels_raw[n]) for n in node[1]]
        known = [k for k in kids if k is not None]
        if not known:
            return None
        out = known[0]
        for k in known[1:]:
            out = out & k
        return out
    kids = [required_event_ids(c, sels_raw) for c in node[1:]] if op == "or" else         [_sel_event_ids(sels_raw[n]) for n in node[1]]
    if any(k is None for k in kids):
        return None
    return frozenset().union(*kids)  # type: ignore[arg-type]


class CompiledRule:
    def __init__(self, rule: Rule):
        self.rule = rule
        self.sels_raw = rule.selections
        sels = {name: compile_selection(sel) for name, sel in self.sels_raw.items()}
        conds = _conditions(rule)
        self.asts = [parse_condition(c, list(sels)) for c in conds]
        preds = [_build(a, sels) for a in self.asts]
        self._pred = preds[0] if len(preds) == 1 else (lambda e: any(p(e) for p in preds))
        self.ast = self.asts[0]
        ids = [required_event_ids(a, self.sels_raw) for a in self.asts]
        self.event_ids: frozenset[int] | None = (
            None if any(i is None for i in ids) else frozenset().union(*ids))  # type: ignore[arg-type]

    guard: Pred | None = None  # optional logsource pre-condition set by the runner

    def matches(self, event: Event) -> bool:
        if self.guard is not None and not self.guard(event):
            return False
        return self._pred(event)


def compile_rule(rule: Rule) -> CompiledRule:
    return CompiledRule(rule)


def run(rule: Rule, events: list[Event]) -> list[int]:
    cr = compile_rule(rule)
    return [i for i, e in enumerate(events) if cr.matches(e)]


def rule_fields(rule: Rule) -> set[str]:
    """All event field names a rule references (for schema-drift checks)."""
    out: set[str] = set()

    def walk(sel: Any) -> None:
        if isinstance(sel, dict):
            for k, v in sel.items():
                if k is None or str(k).startswith("|"):
                    continue
                name, *mods = str(k).split("|")
                out.add(name)
                if "fieldref" in mods:
                    out.update(str(x) for x in (v if isinstance(v, list) else [v]))
        elif isinstance(sel, list):
            for s in sel:
                walk(s)

    for s in rule.selections.values():
        walk(s)
    return out
