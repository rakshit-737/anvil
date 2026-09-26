"""Evaluate a whole rule library against a telemetry stream.

The runner compiles every rule once, resolves its ``logsource`` to
(channel, event id) routes and builds an index so that each event is only
tested against the rules that apply to it. On the SigmaHQ corpus this cuts
the work per event from ~3,000 rule evaluations to a few hundred at most.
"""
from __future__ import annotations

import time
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .engine import CompiledRule, ConditionError, UnsupportedRule, compile_rule
from .logsource import Route, event_key, route, where_ok
from .models import Rule

_Loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)  # libyaml is ~20x faster on 3k rules

Event = dict[str, Any]


@dataclass
class LoadReport:
    loaded: int = 0
    parse_errors: dict[str, str] = field(default_factory=dict)
    skipped_non_detection: int = 0  # correlation / filter documents


def load_rule_dir(paths: Iterable[str | Path]) -> tuple[list[Rule], LoadReport]:
    """Load Sigma YAML rules from one or more directories (recursive)."""
    rules, rep = [], LoadReport()
    for base in paths:
        base = Path(base)
        files = [base] if base.is_file() else sorted(list(base.rglob("*.yml")) + list(base.rglob("*.yaml")))
        for f in files:
            try:
                docs = [d for d in yaml.load_all(f.read_text(encoding="utf-8"), Loader=_Loader) if d]
            except (yaml.YAMLError, UnicodeDecodeError, OSError) as exc:
                rep.parse_errors[str(f)] = str(exc).splitlines()[0]
                continue
            for d in docs:
                if not isinstance(d, dict) or "detection" not in d:
                    rep.skipped_non_detection += 1
                    continue
                rules.append(Rule.from_dict(d, str(f)))
                rep.loaded += 1
    return rules, rep


@dataclass
class Library:
    """A compiled, routed rule library."""
    compiled: dict[str, CompiledRule] = field(default_factory=dict)
    routes: dict[str, Route] = field(default_factory=dict)
    unsupported: dict[str, str] = field(default_factory=dict)   # rule id -> reason
    unroutable: dict[str, str] = field(default_factory=dict)    # rule id -> reason
    rules: dict[str, Rule] = field(default_factory=dict)
    _index: dict[tuple[str, int], list[str]] = field(default_factory=dict)
    _chan_any: dict[str, list[str]] = field(default_factory=dict)
    _global: list[str] = field(default_factory=list)

    @classmethod
    def build(cls, rules: Iterable[Rule], include_deprecated: bool = False) -> Library:
        lib = cls()
        chan_any: dict[str, list[str]] = defaultdict(list)
        index: dict[tuple[str, int], list[str]] = defaultdict(list)
        for r in rules:
            if r.status == "deprecated" and not include_deprecated:
                continue
            rid = r.id or r.path
            lib.rules[rid] = r
            try:
                lib.compiled[rid] = compile_rule(r)
            except (UnsupportedRule, ConditionError, ValueError, TypeError) as exc:
                lib.unsupported[rid] = f"{type(exc).__name__}: {exc}"
                continue
            rt = route(r.logsource)
            lib.routes[rid] = rt
            if rt.where is not None:
                lib.compiled[rid].guard = (lambda rt: lambda e: where_ok(rt, e))(rt)
            if not rt.routable:
                lib.unroutable[rid] = rt.reason
                continue
            req = lib.compiled[rid].event_ids  # EventIDs the detection itself requires
            for chan, ids in rt.channels:
                if ids and req is not None:
                    ids = tuple(i for i in ids if i in req)
                    if not ids:
                        continue
                elif not ids and req is not None and chan != "*":
                    ids = tuple(sorted(req))
                if chan == "*":
                    lib._global.append(rid)
                elif not ids:
                    chan_any[chan].append(rid)
                else:
                    for i in ids:
                        index[(chan, i)].append(rid)
        lib._index, lib._chan_any = dict(index), dict(chan_any)
        return lib

    @property
    def active_ids(self) -> list[str]:
        return [r for r in self.compiled if r not in self.unroutable]

    def candidates(self, ev: Event) -> list[str]:
        chan, eid = event_key(ev)
        out = self._index.get((chan, eid), [])
        extra = self._chan_any.get(chan)
        if extra or self._global:
            out = out + (extra or []) + self._global
        return out

    def match_event(self, ev: Event) -> list[str]:
        hits = []
        for rid in self.candidates(ev):
            try:
                if self.compiled[rid].matches(ev):
                    hits.append(rid)
            except (TypeError, ValueError, AttributeError):
                continue
        return hits


@dataclass
class ScanResult:
    events: int = 0
    evaluations: int = 0
    seconds: float = 0.0
    hits: Counter = field(default_factory=Counter)             # rule id -> matched events
    first_hit: dict[str, int] = field(default_factory=dict)    # rule id -> event index
    by_key: Counter = field(default_factory=Counter)            # (channel, eid) -> events

    @property
    def events_per_second(self) -> float:
        return self.events / self.seconds if self.seconds else 0.0


def scan(lib: Library, events: Iterable[Event], keep_keys: bool = True,
         on_hit: Callable[[str, Event], None] | None = None) -> ScanResult:
    res = ScanResult()
    t0 = time.perf_counter()
    for i, ev in enumerate(events):
        res.events += 1
        if keep_keys:
            res.by_key[event_key(ev)] += 1
        cands = lib.candidates(ev)
        res.evaluations += len(cands)
        for rid in cands:
            try:
                ok = lib.compiled[rid].matches(ev)
            except (TypeError, ValueError, AttributeError):
                ok = False
            if ok:
                res.hits[rid] += 1
                res.first_hit.setdefault(rid, i)
                if on_hit is not None:
                    on_hit(rid, ev)
    res.seconds = time.perf_counter() - t0
    return res
