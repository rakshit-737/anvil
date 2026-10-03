#!/usr/bin/env python3
"""ANVIL benchmark suite on real public data.

    python scripts/download_data.py all          # SigmaHQ, ATT&CK, OTRF, evtx-baseline
    python -m anvil ingest --benign              # EVTX -> sharded JSONL corpus
    python benchmarks/bench.py all               # writes results/*.json + results/SUMMARY.md

Each stage writes ``results/<stage>.json``; ``report`` renders the tables in
``results/SUMMARY.md``, figures in ``docs/img`` and the static dashboard.
Stages: lint engine fp otrf coverage decay convert fpmodel draft report.
``python benchmarks/bench.py verify`` compares results/*.json with the committed files,
ignoring provenance and timings.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import gzip
import json
import statistics
import sys
import tempfile
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from anvil.attack import load_stix  # noqa: E402
from anvil.coverage import coverage, navigator_layer  # noqa: E402
from anvil.decay import META_FIELDS, SCHEMA_CHANGES, FieldInventory, analyse, apply_change  # noqa: E402
from anvil.engine import rule_fields  # noqa: E402
from anvil.lint import ERROR, lint_rules  # noqa: E402
from anvil.logsource import SYSMON, applies, event_key  # noqa: E402
from anvil.models import Rule  # noqa: E402
from anvil.otrf import load_catalog  # noqa: E402
from anvil.parallel import scan_files  # noqa: E402
from anvil.regression import discover, run_case  # noqa: E402
from anvil.runner import Library, load_rule_dir  # noqa: E402
from anvil.telemetry import iter_json_file, iter_path  # noqa: E402
from benchmarks.common import RESULTS, benign_shards, data_dir, load, provenance, save, sigma_root  # noqa: E402
from benchmarks.stats import paired_mcnemar, wilson  # noqa: E402

CAPACITY, SHARE = 200.0, 0.10          # SOC triage capacity/day and max share for one rule
BUDGET = CAPACITY * SHARE              # -> 20 alerts/day per rule


def _rule_dirs() -> list[str]:
    base = sigma_root()
    return [str(base / d) for d in ("rules", "rules-emerging-threats", "rules-threat-hunting")
            if (base / d).exists()]


def _rules() -> tuple[list[Rule], Any]:
    return load_rule_dir(_rule_dirs())


def _is_windows(r: Rule) -> bool:
    return r.logsource.product.lower() == "windows"


def _folder(r: Rule) -> str:
    p = r.path.replace("\\", "/")
    for f in ("rules-emerging-threats", "rules-threat-hunting"):
        if f"/{f}/" in p:
            return f.removeprefix("rules-")
    return "core"


def _catalog():
    p = data_dir() / "attack" / "enterprise-attack-19.2.json"
    return load_stix(p) if p.exists() else None


# ------------------------------------------------------------------------------- lint
def stage_lint() -> dict[str, Any]:
    rules, rep = _rules()
    cat = _catalog()
    t0 = time.perf_counter()
    findings = lint_rules(rules, profile="sigma", catalog=cat)
    secs = time.perf_counter() - t0
    by_rule: dict[str, list[Any]] = defaultdict(list)
    for f in findings:
        by_rule[f.rule_id].append(f)
    lib = Library.build(rules)
    codes = Counter(f.code for f in findings)
    status = Counter(r.status for r in rules)
    res = {
        "rules": len(rules), "parse_errors": len(rep.parse_errors), "lint_seconds": round(secs, 2),
        "rules_with_errors": sum(any(f.severity == ERROR for f in v) for v in by_rule.values()),
        "rules_with_warnings": sum(any(f.severity != ERROR for f in v) for v in by_rule.values()),
        "findings_by_code": dict(codes.most_common()),
        "status": dict(status), "level": dict(Counter(r.level for r in rules)),
        "product": dict(Counter(r.logsource.product or "(none)" for r in rules).most_common(15)),
        "windows_rules": sum(_is_windows(r) for r in rules),
        "compiled": len(lib.compiled), "unsupported": len(lib.unsupported),
        "unsupported_reasons": dict(Counter(v.split(":")[1].strip()[:60] for v in lib.unsupported.values())),
        "routable_windows": sum(1 for rid in lib.active_ids if _is_windows(lib.rules[rid])),
        "unroutable_windows": dict(Counter(v for k, v in lib.unroutable.items() if _is_windows(lib.rules[k]))),
        "with_regression_test": sum(bool(r.regression_tests_path) for r in rules),
        "test_or_stable_without_regression": codes.get("W209", 0),
        "attack_version": cat.version if cat else None,
        "aggregation_census": _aggregation_census(),
    }
    save("lint.json", res)
    return res


def _aggregation_census() -> dict[str, Any]:
    """Legacy aggregation conditions and correlation documents in the pinned SigmaHQ checkout."""
    import re
    base = sigma_root()
    agg = re.compile(r"^\s*condition:.*\|\s*(count|min|max|avg|sum|near)\b", re.M)
    out: dict[str, Any] = {}
    for folder in ("unsupported", "deprecated", "rules", "rules-emerging-threats", "rules-threat-hunting"):
        texts = [f.read_text(encoding="utf-8", errors="replace") for f in sorted((base / folder).rglob("*.yml"))]
        out[folder] = {"files": len(texts), "with_count_call": sum("count(" in t for t in texts),
                       "with_aggregation_condition": sum(bool(agg.search(t)) for t in texts),
                       "correlation_documents": sum(len(re.findall(r"^correlation:", t, re.M)) for t in texts)}
    return out


# ------------------------------------------------------------------------------- engine
def _benign_sample(per_group: int = 1500, stride: int = 37) -> list[dict[str, Any]]:
    """Deterministic benign sample: every ``stride``-th event of the first shard of each corpus."""
    out: list[dict[str, Any]] = []
    firsts: dict[str, Path] = {}
    for s in benign_shards():
        firsts.setdefault(s.parent.name, s)
    for s in firsts.values():
        n = 0
        for i, e in enumerate(iter_path(s)):
            if i % stride == 0:
                out.append(e)
                n += 1
                if n >= per_group:
                    break
    return out


def stage_engine() -> dict[str, Any]:
    """Regression replay: ANVIL 0.2 vs the ANVIL 0.1 engine vs pySigma->SQLite."""
    from benchmarks.baselines import engine_v01
    rules, _ = _rules()
    lib = Library.build(rules)
    root = sigma_root()
    cases = discover(root)

    t0 = time.perf_counter()
    ours = [run_case(lib, c) for c in cases]
    t_ours = time.perf_counter() - t0
    n_events = sum(r.events for r in ours)

    # baseline 1: ANVIL 0.1 engine (no logsource routing, subset of modifiers)
    by_id = {r.id: r for r in rules}
    v01 = Counter()
    t0 = time.perf_counter()
    for c in cases:
        r = by_id.get(c["rule_id"])
        if r is None:
            v01["missing-rule"] += 1
            continue
        try:
            cr = engine_v01.compile_rule(r)
            evs = list(iter_json_file(c["sample"]))
        except OSError:
            v01["unreadable"] += 1
            continue
        except Exception:  # noqa: BLE001 - old engine raises assorted errors on unknown syntax
            v01["unsupported"] += 1
            continue
        try:
            n = sum(bool(cr.matches(e)) for e in evs)
        except Exception:  # noqa: BLE001
            v01["error"] += 1
            continue
        v01["pass" if n >= (c["expected"] or 1) else "fail"] += 1
    t_v01 = time.perf_counter() - t0

    # baseline 2: pySigma -> SQLite, executed on the same routed events
    oracle: dict[str, Any] = {"available": False}
    try:
        from anvil.convert import SqliteOracle
        o = SqliteOracle()
        oc, disagree = Counter(), []
        t0 = time.perf_counter()
        for c, mine in zip(cases, ours):
            rid = c["rule_id"]
            if mine.status in ("unreadable", "missing-rule", "unsupported", "unroutable"):
                oc["skipped"] += 1
                continue
            conv = o.compile(Path(lib.rules[rid].path).read_text(encoding="utf-8"), rid)
            if not conv.ok:
                oc["convert-error"] += 1
                continue
            evs = [e for e in iter_json_file(c["sample"]) if applies(lib.routes[rid], e)]
            try:
                n = sum(o.count(q, evs) for q in conv.queries)
            except Exception as exc:  # noqa: BLE001
                oc["exec-error"] += 1
                disagree.append({"rule": rid, "title": lib.rules[rid].title, "why": f"oracle error: {exc}"[:120]})
                continue
            oc["pass" if n >= (c["expected"] or 1) else "fail"] += 1
            if n != mine.matched:
                oc["disagree"] += 1
                disagree.append({"rule": rid, "title": lib.rules[rid].title, "anvil": mine.matched, "oracle": n,
                                 "expected": c["expected"]})
            else:
                oc["agree"] += 1
        oracle = {"available": True, "seconds": round(time.perf_counter() - t0, 1), **dict(oc),
                  "disagreements": disagree}
    except ImportError:
        pass

    # benign sample: the 0.1 engine has no logsource routing, so every rule sees every event
    sample = _benign_sample(per_group=600)
    benign = {}
    if sample:
        from anvil.runner import scan as lib_scan
        r02 = lib_scan(lib, sample)
        compiled01 = []
        for r in rules:
            if not _is_windows(r) or r.status == "deprecated":
                continue
            try:
                compiled01.append(engine_v01.compile_rule(r))
            except Exception:  # noqa: BLE001
                continue
        t0 = time.perf_counter()
        hits01: Counter = Counter()
        for e in sample:
            for cr in compiled01:
                try:
                    if cr.matches(e):
                        hits01[cr.rule.id] += 1
                except Exception:  # noqa: BLE001
                    continue
        # ablation: the same 1.x engine with log-source routing switched off (every Windows rule
        # sees every event), which isolates routing from the 0.1 -> 1.x value-semantics changes
        win_ids = [rid for rid in lib.active_ids if _is_windows(lib.rules[rid])]
        t0 = time.perf_counter()
        hits_nr: Counter = Counter()
        for e in sample:
            for rid in win_ids:
                try:
                    if lib.compiled[rid].matches(e):
                        hits_nr[rid] += 1
                except (TypeError, ValueError, AttributeError):
                    continue
        t_nr = time.perf_counter() - t0
        benign = {"events": len(sample),
                  "anvil": {"alerts": sum(r02.hits.values()), "rules_fired": len(r02.hits),
                            "evaluations": r02.evaluations, "seconds": round(r02.seconds, 2)},
                  "anvil_unrouted": {"alerts": sum(hits_nr.values()), "rules_fired": len(hits_nr),
                                     "evaluations": len(sample) * len(win_ids), "seconds": round(t_nr, 2),
                                     "note": "1.x engine, routing disabled: every Windows rule on every event"},
                  "anvil_v01": {"alerts": sum(hits01.values()), "rules_fired": len(hits01),
                                "evaluations": len(sample) * len(compiled01),
                                "seconds": round(time.perf_counter() - t0, 2)}}

    st = Counter(r.status for r in ours)
    evaluable = sum(st[s] for s in ("pass", "fail"))
    res = {
        "cases": len(cases), "sample_events": n_events,
        "anvil": {**dict(st), "evaluable": evaluable, "pass_rate": round(st["pass"] / max(1, evaluable), 4),
                  "exact_count": sum(r.exact for r in ours if r.status == "pass"),
                  "seconds": round(t_ours, 2)},
        "anvil_v01": {**dict(v01), "pass_rate": round(v01["pass"] / max(1, len(cases) - v01["unreadable"]), 4),
                      "seconds": round(t_v01, 2)},
        "pysigma_sqlite": oracle,
        "benign_sample": benign,
        "failures": [r.to_dict() for r in ours if r.status == "fail"],
        "passing_rule_ids": sorted({r.rule_id for r in ours if r.status == "pass"}),
    }
    save("engine.json", res)
    return res


# ------------------------------------------------------------------------------- benign FP corpus
def _corpus_span(shards: list[Path]) -> dict[str, Any]:
    """Time span covered per corpus (days) from TimeCreated, per host set."""
    spans = {}
    for group in sorted({s.parent.name for s in shards}):
        lo = hi = None
        for s in [x for x in shards if x.parent.name == group]:
            with gzip.open(s, "rt", encoding="utf-8") as fh:
                for line in fh:
                    i = line.find('"TimeCreated": "')
                    if i < 0:
                        continue
                    ts = line[i + 16:i + 35]
                    lo = ts if lo is None or ts < lo else lo
                    hi = ts if hi is None or ts > hi else hi
        if lo and hi:
            a, b = dt.datetime.fromisoformat(lo), dt.datetime.fromisoformat(hi)
            spans[group] = {"first": lo, "last": hi, "days": round(max((b - a).total_seconds() / 86400, 1 / 24), 3)}
    return spans


def _known_fps() -> dict[str, list[str]]:
    p = sigma_root() / ".github" / "workflows" / "known-FPs.csv"
    out: dict[str, list[str]] = defaultdict(list)
    if p.exists():
        for row in csv.reader(p.open(encoding="utf-8"), delimiter=";"):
            if row and row[0] != "RuleId":
                out[row[0]].append(row[2] if len(row) > 2 else ".*")
    return out


def stage_fp(workers: int = 8) -> dict[str, Any]:
    shards = benign_shards()
    if not shards:
        raise SystemExit("no benign corpus: run `python -m anvil ingest --benign` first")
    rules, _ = _rules()
    lib = Library.build(rules)
    scan = scan_files(_rule_dirs(), shards, workers=workers, keep_examples=2)
    spans = _corpus_span(shards)
    days = sum(s["days"] for s in spans.values())
    # events routed to each rule (ignores EventType guards; used as the FP-rate denominator)
    key_counts = Counter()
    for k, n in scan.by_key.items():
        chan, eid = k.rsplit("|", 1)
        key_counts[(chan, int(eid))] += n
    routed: dict[str, int] = {}
    for rid in lib.active_ids:
        rt = lib.routes[rid]
        routed[rid] = sum(n for (c, e), n in key_counts.items()
                          for ch, ids in rt.channels if (ch == "*" or ch == c) and (not ids or e in ids))
    known = _known_fps()
    per_rule = []
    for rid in lib.active_ids:
        r = lib.rules[rid]
        if not _is_windows(r):
            continue
        hits = scan.hits.get(rid, 0)
        per_day = hits / days if days else hits
        per_rule.append({"id": rid, "title": r.title, "level": r.level, "status": r.status, "folder": _folder(r),
                         "category": r.logsource.category or r.logsource.service, "routed_events": routed[rid],
                         "hits": hits, "alerts_per_day": round(per_day, 2),
                         "gate": "pass" if per_day <= BUDGET else "fail", "known_fp": rid in known})
    fired = [p for p in per_rule if p["hits"]]
    observable = [p for p in per_rule if p["routed_events"]]

    def grp(key: str) -> dict[str, Any]:
        out = {}
        for val in sorted({p[key] for p in observable}):
            g = [p for p in observable if p[key] == val]
            out[val] = {"observable": len(g), "fired": sum(1 for p in g if p["hits"]),
                        "fired_pct": round(100 * sum(1 for p in g if p["hits"]) / len(g), 1),
                        "gate_fail": sum(1 for p in g if p["gate"] == "fail")}
        return out

    med_plus = [p for p in fired if p["level"] in ("medium", "high", "critical")]
    non_low = [p for p in fired if p["level"] != "low"]
    # The rates are per *host-day*: the three evtx-baseline hosts were recorded on different dates and
    # their spans are summed. A fleet of H hosts multiplies every rule's daily volume by H.
    fleet = {str(h): sum(1 for p in fired if p["alerts_per_day"] * h > BUDGET) for h in (1, 3, 10, 100, 1000)}
    res = {
        "corpus": {"shards": len(shards), "events": scan.events, "evaluations": scan.evaluations,
                   "cpu_seconds": round(scan.cpu_seconds, 1), "wall_seconds": round(scan.wall_seconds, 1),
                   "events_per_cpu_second": round(scan.events / max(scan.cpu_seconds, 1e-9)),
                   "spans": spans, "days": round(days, 2),
                   "top_sources": [[k, n] for k, n in scan.by_key.most_common(15)]},
        "policy": {"capacity_per_day": CAPACITY, "share": SHARE, "budget_per_rule_per_day": BUDGET},
        "rate_unit": "alerts per host-day (hits / sum of per-host spans)",
        "gate_fail_by_fleet_size": fleet,
        "windows_rules": len(per_rule), "observable_rules": len(observable),
        "fired_rules": len(fired), "total_alerts": sum(p["hits"] for p in fired),
        "gate_fail": sum(1 for p in per_rule if p["gate"] == "fail"),
        "alerts_per_day_total": round(sum(p["alerts_per_day"] for p in fired), 1),
        "by_status": grp("status"), "by_level": grp("level"), "by_folder": grp("folder"),
        "sigmahq_known_fp_agreement": {
            "fired_medium_plus": len(med_plus),
            "on_known_fp_list": sum(p["known_fp"] for p in med_plus),
            "not_on_list": [{"id": p["id"], "title": p["title"], "hits": p["hits"]}
                            for p in med_plus if not p["known_fp"]],
            "note": "per-rule match only (MatchString filters not applied); the list was also used during "
                    "development to find a routing bug, so it is not a fully independent check",
            "known_fp_rules_listed": len(known),
            "known_fp_rules_fired": sum(1 for rid in known if scan.hits.get(rid)),
            # SigmaHQ's goodlog CI (matchgrep.sh) fails on any non-low finding missing from the list; its
            # win10/win11/win2022 jobs are green at the pinned commit, so each row is a disagreement.
            "non_low_not_on_list": [{"id": p["id"], "title": p["title"], "level": p["level"], "hits": p["hits"]}
                                    for p in non_low if not p["known_fp"]]},
        "rules": sorted(per_rule, key=lambda p: -p["hits"]),
        "examples": {k: v for k, v in scan.examples.items() if k in {p["id"] for p in fired}},
    }
    save("fp.json", compact_fp(res))
    return res


def compact_fp(res: dict[str, Any]) -> dict[str, Any]:
    """Keep the committed fp.json under ~600 KB: silent rules lose their free-text fields, one short example each."""
    for p in res["rules"]:
        if not p["hits"]:
            p.pop("title", None)
            p.pop("category", None)
    res["examples"] = {rid: [{k: (v[:160] if isinstance(v, str) else v) for k, v in ex[0].items()}]
                       for rid, ex in res["examples"].items() if ex}
    return res


# ------------------------------------------------------------------------------- OTRF emulation
def _tech_match(rule_techs: set[str], ds_techs: list[str]) -> bool:
    """Strict (documented) rule: the exact technique, or the rule is tagged with its parent."""
    return any(t in rule_techs or t.split(".")[0] in rule_techs for t in ds_techs)


def _tech_match_lenient(rule_techs: set[str], ds_techs: list[str]) -> bool:
    """Also credits sibling sub-techniques (the 1.0 definition, kept for comparison)."""
    return any(t in rule_techs or t.split(".")[0] in {x.split(".")[0] for x in rule_techs} for t in ds_techs)


def stage_otrf(workers: int = 8) -> dict[str, Any]:
    root = data_dir() / "otrf"
    cat = load_catalog(root)
    rules, _ = _rules()
    by_id = {r.id: r for r in rules}
    files = sorted({str(p) for d in cat for p in d.host_files if p.exists()})
    compound = sorted(str(p) for p in (root / "compound").rglob("*.zip"))
    readable = []
    for f in files + compound:
        try:
            with open(f, "rb") as fh:
                fh.read(4)
            readable.append(f)
        except OSError:
            pass
    scan = scan_files(_rule_dirs(), readable, workers=workers, split_channels=True)
    rows = []
    for d in cat:
        paths = [str(p) for p in d.host_files if str(p) in scan.per_file_hits]
        if not paths:
            continue
        hits: Counter = Counter()
        for p in paths:
            hits.update(scan.per_file_hits[p])
        ev = sum(scan.per_file_events[p] for p in paths)
        fired = {rid for rid in hits}
        tech_rules = [rid for rid in fired if _tech_match(set(by_id[rid].techniques), d.techniques)]
        lenient = any(_tech_match_lenient(set(by_id[rid].techniques), d.techniques) for rid in fired)
        rows.append({"id": d.id, "title": d.title, "techniques": d.techniques, "events": ev,
                     "rules_fired": len(fired), "alerts": sum(hits.values()),
                     "any_alert": bool(fired), "technique_detected": bool(tech_rules),
                     "technique_detected_lenient": lenient,
                     "technique_rules": sorted(by_id[r].title for r in tech_rules)[:8],
                     "claimed": any(_tech_match(set(r.techniques), d.techniques) for r in rules
                                    if _is_windows(r) and r.status != "deprecated"),
                     "top_rules": [by_id[r].title for r, _ in hits.most_common(5)]})
    comp = {}
    for p in compound:
        if p in scan.per_file_hits:
            h = scan.per_file_hits[p]
            techs = sorted({t for rid in h for t in by_id[rid].techniques})
            comp[Path(p).name] = {"events": scan.per_file_events[p], "rules_fired": len(h),
                                  "alerts": sum(h.values()), "technique_tags_on_fired_rules": len(techs),
                                  "top_rules": [by_id[r].title for r, _ in Counter(h).most_common(10)]}
    n = len(rows)
    claimed = [r for r in rows if r["claimed"]]
    res = {
        "datasets": n, "events": sum(r["events"] for r in rows), "files_blocked_by_av": len(files + compound) - len(readable),
        "wall_seconds": round(scan.wall_seconds, 1),
        "any_alert": sum(r["any_alert"] for r in rows),
        "technique_detected": sum(r["technique_detected"] for r in rows),
        "technique_detected_ci95": wilson(sum(r["technique_detected"] for r in rows), n),
        "technique_detected_lenient": sum(r["technique_detected_lenient"] for r in rows),
        "any_alert_ci95": wilson(sum(r["any_alert"] for r in rows), n),
        "claimed_coverage": len(claimed),
        "claimed_but_not_detected": [{"id": r["id"], "title": r["title"], "techniques": r["techniques"]}
                                     for r in claimed if not r["technique_detected"]],
        "median_rules_fired": statistics.median([r["rules_fired"] for r in rows]) if rows else 0,
        "rows": rows, "compound": comp,
        "rule_fire_counts": Counter(r for p in files for r in scan.per_file_hits.get(p, {})).most_common(40),
    }
    res["rule_fire_counts"] = [[by_id[r].title, c] for r, c in res["rule_fire_counts"]]
    res["sysmon_removal"] = _sysmon_removal(cat, scan, by_id)
    save("otrf.json", res)
    return res


def _sysmon_removal(cat: list[Any], scan: Any, by_id: dict[str, Rule]) -> dict[str, Any]:
    """Real (not simulated) Sysmon decommissioning on OTRF captures that also log native 4688.

    A capture qualifies when it holds both Sysmon EventID 1 and Security 4688 events. Rule hits
    are split by channel, so the hits that survive dropping the Sysmon channel are exactly the
    hits on the remaining events. ``fired_before`` / ``fired_after`` are the Windows rules that
    fire on at least one qualifying capture with / without its Sysmon events.
    """
    dual, ev_sysmon1, ev_4688 = [], 0, 0
    before: set[str] = set()
    after: set[str] = set()
    for d in cat:
        paths = [str(p) for p in d.host_files if str(p) in scan.per_file_hits]
        keys: Counter = Counter()
        for p in paths:
            keys.update(scan.per_file_by_key.get(p, {}))
        s1, s4688 = keys.get(f"{SYSMON}|1", 0), keys.get("security|4688", 0)
        if not (s1 and s4688):
            continue
        dual.append(d.id)
        ev_sysmon1 += s1
        ev_4688 += s4688
        for p in paths:
            for rid, chans in scan.per_file_hits_by_channel.get(p, {}).items():
                if rid not in by_id or not _is_windows(by_id[rid]):
                    continue
                before.add(rid)
                if any(c != SYSMON for c in chans):
                    after.add(rid)
    return {"description": "OTRF Windows captures holding both Sysmon EID 1 and Security 4688; the Sysmon "
                           "channel is dropped from the real capture (no simulator)",
            "datasets": len(dual), "dataset_ids": dual, "sysmon_eid1_events": ev_sysmon1,
            "security_4688_events": ev_4688, "fired_before": sorted(before), "fired_after": sorted(after)}


# ------------------------------------------------------------------------------- coverage
def stage_coverage() -> dict[str, Any]:
    rules, _ = _rules()
    win = [r for r in rules if _is_windows(r)]
    cat = _catalog()
    eng, fp = load("engine.json"), load("fp.json")
    tp_ok = set(eng["passing_rule_ids"])
    gate_fail = {p["id"] for p in fp["rules"] if p["gate"] == "fail"}
    otrf = load("otrf.json") if (RESULTS / "otrf.json").exists() else None
    out = {"catalog": cat.version if cat else "bundled-subset"}
    for name, ids in [("claimed", None), ("tp_validated", tp_ok), ("tp_validated_and_gated", tp_ok - gate_fail)]:
        rep = coverage(win, ids, cat, platform="Windows")
        out[name] = {k: rep[k] for k in ("catalog_size", "covered", "validated", "coverage_pct", "validated_pct",
                                         "parent_total", "parent_covered", "parent_validated")}
        out[name]["tactics"] = rep["tactics"]
        if name == "tp_validated_and_gated":
            layer = navigator_layer(rep, "SigmaHQ Windows rules: claimed vs ANVIL-validated")
            # Navigator layers allow name/value metadata: carry the same provenance as the JSON results.
            prov = provenance()
            layer["metadata"] = ([{"name": k, "value": str(prov.get(k, ""))} for k in ("git_sha", "ci_run")]
                                 + [{"name": f"dataset {k}", "value": v} for k, v in prov.get("datasets", {}).items()])
            (RESULTS / "navigator_sigmahq_windows.json").write_text(json.dumps(layer, indent=1))
            out["stale_tags"] = rep["stale_tags"]
    if otrf:
        out["otrf_emulation"] = {"datasets": otrf["datasets"], "claimed": otrf["claimed_coverage"],
                                 "detected": otrf["technique_detected"]}
    save("coverage.json", out)
    return out


# ------------------------------------------------------------------------------- decay
def stage_decay(stride: int = 5) -> dict[str, Any]:
    """Ground truth from TP captures vs. a diff-based static monitor on production-like telemetry.

    Two kinds of ground truth:

    * **simulated**: each change in ``SCHEMA_CHANGES`` is applied to the SigmaHQ regression
      captures of TP-validated rules; a rule is broken when it no longer fires on them. The
      same transform builds the post-change benign inventory, so precision is partly a
      soundness property relative to the transform.
    * **real** (``real_sysmon_removal``): OTRF captures that log both Sysmon EID 1 and native
      Security 4688; the Sysmon channel is dropped from the real capture, and the prediction
      uses the benign inventory with its real Sysmon events dropped (native 4688 only). No
      simulator is involved on either side.

    Per-rule flag sets are stored as index lists into ``tp_rule_ids`` / ``real.rule_ids`` so
    the McNemar tests can be recomputed from the committed file.
    """
    rules, _ = _rules()
    lib = Library.build(rules)
    win = [lib.rules[r] for r in lib.active_ids if _is_windows(lib.rules[r])]
    win_ids = {r.id for r in win}
    cases = discover(sigma_root())
    base = {c["rule_id"]: run_case(lib, c) for c in cases}
    tp_ok = {rid for rid, rc in base.items() if rc.status == "pass"}
    # "production" field inventory = benign corpus only (every stride-th event), before and after
    # each simulated change. The TP captures are never part of the inventory (no attack data).
    changes = ["none", *SCHEMA_CHANGES]
    invs = {c: FieldInventory() for c in changes}
    inv_real = FieldInventory()   # real Sysmon removal: drop the Sysmon events, keep native 4688 as logged

    def feed(ev: dict[str, Any]) -> None:
        invs["none"].add(ev)
        if event_key(ev)[0] != SYSMON:
            inv_real.add(ev)
        for c in SCHEMA_CHANGES:
            t = SCHEMA_CHANGES[c][1](ev)
            if t is not None:
                invs[c].add(t)

    n = 0
    for shard in benign_shards():
        for i, ev in enumerate(iter_path(shard)):
            if i % stride == 0:
                feed(ev)
                n += 1
    rank = {"ok": 0, "degraded": 1, "broken": 2, "source-missing": 3}
    before = {r.id: analyse(r, invs["none"]) for r in win}
    flds = {r.id: rule_fields(r) - META_FIELDS for r in win}

    def presence(inv: FieldInventory) -> dict[str, set[str] | None]:
        """Field-presence baseline: which referenced fields are absent for the rule's own log source."""
        out: dict[str, set[str] | None] = {}
        for r in win:
            got = inv.fields_for(r)
            out[r.id] = None if got is None else {f for f in flds[r.id] if f not in got}
        return out

    def global_fields(inv: FieldInventory) -> set[str]:
        return set().union(*inv.by_key.values()) if inv.by_key else set()

    pres0, glob0 = presence(invs["none"]), global_fields(invs["none"])

    def flags(inv: FieldInventory) -> dict[str, set[str]]:
        """Rules each method flags when the inventory changes from the unchanged one to ``inv``."""
        after = {r.id: analyse(r, inv) for r in win}
        sym = {rid for rid, v in after.items()
               if v["status"] in ("broken", "source-missing") and rank[v["status"]] > rank[before[rid]["status"]]}
        pres1, glob1 = presence(inv), global_fields(inv)
        pres = {rid for rid in pres1 if (pres1[rid] is None and pres0[rid] is not None)
                or (pres1[rid] is not None and pres0[rid] is not None and pres1[rid] - pres0[rid])}
        glob = {r.id for r in win if (flds[r.id] - glob1) - (flds[r.id] - glob0)}
        worse = {rid for rid, v in after.items() if rank[v["status"]] > rank[before[rid]["status"]]}
        return {SYM: sym, PRES: pres, GLOB: glob, "_worsened": worse}

    def score(flag: set[str], universe: set[str], decayed: set[str]) -> dict[str, Any]:
        tpf = flag & universe
        k_r, k_p = len(decayed & flag), len(decayed & tpf)
        return {"flagged_tp_rules": len(tpf), "library_flagged": len(flag),
                "recall": round(k_r / len(decayed), 4) if decayed else None,
                "recall_k_n": [k_r, len(decayed)], "recall_ci95": wilson(k_r, len(decayed)),
                "precision": round(k_p / len(tpf), 4) if tpf else None,
                "precision_k_n": [k_p, len(tpf)], "precision_ci95": wilson(k_p, len(tpf)),
                "false_alarms": len(tpf - decayed)}

    def tests(fl: dict[str, set[str]], universe: set[str], decayed: set[str]) -> dict[str, Any]:
        """Exact McNemar tests, symbolic vs each presence baseline, on the same rules."""
        ok = universe - decayed
        return {base_name: {"false_alarms_on_unbroken_rules": {**paired_mcnemar(fl[SYM], fl[base_name], ok),
                                                               "rules": len(ok)},
                            "recall_on_broken_rules": {**paired_mcnemar(fl[SYM], fl[base_name], decayed),
                                                       "rules": len(decayed)}}
                for base_name in (PRES, GLOB)}

    tp_list = sorted(tp_ok & win_ids)
    tp_index = {rid: i for i, rid in enumerate(tp_list)}

    def idx(ids: set[str], index: dict[str, int]) -> list[int]:
        return sorted(index[r] for r in ids if r in index)

    floor = {rid for rid, v in before.items() if v["status"] in ("broken", "source-missing")}
    res: dict[str, Any] = {
        "benign_events_inventoried": n, "inventory": "benign evtx-baseline only (no TP captures)",
        "rules_with_tp_evidence": len(tp_ok), "windows_rules": len(win),
        "baseline_status": dict(Counter(v["status"] for v in before.values())),
        "none": {"description": "no change: rules flagged broken/source-missing on unchanged "
                                "telemetry (the false-alarm floor; excluded from 'worsened')",
                 "library_flagged": len(floor),
                 "library_flagged_pct": round(100 * len(floor) / len(win), 1),
                 "tp_validated_flagged": len(floor & tp_ok),
                 "tp_validated_flagged_rules": [{"id": rid, "title": lib.rules[rid].title,
                                                 "status": before[rid]["status"],
                                                 "missing": before[rid]["missing"][:6]}
                                                for rid in sorted(floor & tp_ok)]},
        "tp_rule_ids": tp_list,
        "flag_sets_note": "index lists into tp_rule_ids (simulated changes) or real_sysmon_removal.rule_ids",
        "changes": {}}
    for c in SCHEMA_CHANGES:
        # 1) ground truth: TP-validated rules that stop firing on their own captures after the change
        decayed = set()
        for case in cases:
            rid = case["rule_id"]
            if rid not in tp_ok:
                continue
            evs = apply_change(iter_json_file(case["sample"]), c)
            rc, rt = lib.compiled[rid], lib.routes[rid]
            if sum(1 for e in evs if applies(rt, e) and rc.matches(e)) < (case["expected"] or 1):
                decayed.add(rid)
        # 2) static monitor: re-analyse against the changed schema, flag rules whose verdict worsened
        #    to broken/source-missing (no attack data needed, works for every rule)
        fl = flags(invs[c])
        flagged, tp_flagged = fl[SYM], fl[SYM] & tp_ok
        res["changes"][c] = {
            "description": SCHEMA_CHANGES[c][0],
            "ground_truth": "simulated: the change is applied to the regression captures",
            "decayed_tp_rules": len(decayed),
            "static_flagged_tp_rules": len(tp_flagged),
            "static_recall": round(len(decayed & flagged) / len(decayed), 4) if decayed else None,
            "static_precision": round(len(decayed & tp_flagged) / len(tp_flagged), 4) if tp_flagged else None,
            "methods": {m: score(fl[m], tp_ok, decayed) for m in (SYM, PRES, GLOB)},
            "mcnemar_symbolic_vs": tests(fl, tp_ok, decayed),
            "regression_monitor_coverage": round(len(tp_ok) / len(win), 3),
            "library_flagged": len(flagged),
            "library_flagged_pct": round(100 * len(flagged) / len(win), 1),
            "library_worsened": len(fl["_worsened"]),
            "missed_examples": [lib.rules[r].title for r in sorted(decayed - flagged)][:8],
            "false_alarm_examples": [lib.rules[r].title for r in sorted(tp_flagged - decayed)][:8],
            "decayed_idx": idx(decayed, tp_index),
            "flagged_tp_idx": {m: idx(fl[m] & tp_ok, tp_index) for m in (SYM, PRES, GLOB)},
        }
    res["real_sysmon_removal"] = _decay_real(flags, score, tests, invs, inv_real, win_ids, lib)
    save("decay.json", res)
    return res


SYM, PRES, GLOB = "symbolic (ANVIL)", "field presence, per log source", "field presence, global (0.1 schema_drift)"


def _decay_real(flags: Any, score: Any, tests: Any, invs: dict[str, FieldInventory], inv_real: FieldInventory,
                win_ids: set[str], lib: Library) -> dict[str, Any] | None:
    """Score the static monitor against real Sysmon removal on OTRF captures (see ``_sysmon_removal``)."""
    if not (RESULTS / "otrf.json").exists():
        return None
    sr = load("otrf.json").get("sysmon_removal")
    if not sr or not sr.get("datasets"):
        return None
    universe = set(sr["fired_before"]) & win_ids
    decayed = universe - set(sr["fired_after"])
    ids = sorted(universe)
    index = {rid: i for i, rid in enumerate(ids)}
    out: dict[str, Any] = {
        "description": sr["description"], "datasets": sr["datasets"],
        "sysmon_eid1_events": sr["sysmon_eid1_events"], "security_4688_events": sr["security_4688_events"],
        "ground_truth": "real: rules that fire on the captures (for any reason) and fire on none of them once "
                        "the Sysmon channel is dropped",
        "rules_firing_before": len(universe), "rules_that_stop_firing": len(decayed),
        "rule_ids": ids, "decayed_idx": sorted(index[r] for r in decayed), "inventories": {}}
    for name, inv in (("native 4688: benign inventory with its Sysmon events dropped", inv_real),
                      ("simulated: sysmon_to_4688 transform of the benign inventory", invs["sysmon_to_4688"])):
        fl = flags(inv)
        out["inventories"][name] = {
            "methods": {m: score(fl[m], universe, decayed) for m in (SYM, PRES, GLOB)},
            "mcnemar_symbolic_vs": tests(fl, universe, decayed),
            "flagged_idx": {m: sorted(index[r] for r in fl[m] & universe) for m in (SYM, PRES, GLOB)},
            "missed_examples": [lib.rules[r].title for r in sorted(decayed - fl[SYM])][:8],
            "false_alarm_examples": [lib.rules[r].title for r in sorted((fl[SYM] & universe) - decayed)][:8]}
    return out


# ------------------------------------------------------------------------------- conversion
def stage_convert() -> dict[str, Any]:
    from anvil.convert import TARGETS, Converter
    rules, _ = _rules()
    win = [r for r in rules if _is_windows(r)]
    out: dict[str, Any] = {"rules": len(win)}
    for t in TARGETS:
        try:
            conv = Converter(t)
        except ImportError as exc:
            out[t] = {"error": str(exc)}
            continue
        ok, errs, t0 = 0, Counter(), time.perf_counter()
        for r in win:
            c = conv.convert_yaml(Path(r.path).read_text(encoding="utf-8"), r.id)
            if c.ok:
                ok += 1
            else:
                cls = c.error.split(":")[0]
                if "table name" in c.error:
                    cls += " (log source has no table)"
                elif "field name" in c.error.lower():
                    cls += " (field cannot be mapped)"
                errs[cls] += 1
        out[t] = {"converted": ok, "pct": round(100 * ok / len(win), 1), "seconds": round(time.perf_counter() - t0, 1),
                  "errors": dict(errs.most_common(6))}
    save("convert.json", out)
    return out


# ------------------------------------------------------------------------------- FP-prediction model
def stage_fpmodel() -> dict[str, Any]:
    from anvil.fpmodel import cross_validate, repeated_cv
    rules, _ = _rules()
    by_id = {r.id: r for r in rules}
    fp = load("fp.json")
    obs = sorted((p for p in fp["rules"] if p["routed_events"] > 0 and p["id"] in by_id), key=lambda p: p["id"])
    import random
    random.Random(7).shuffle(obs)  # fp.json is sorted by hits, i.e. by label: never feed that order through
    X, y = [by_id[p["id"]] for p in obs], [int(p["hits"] > 0) for p in obs]
    res = cross_validate(X, y, bootstrap=True)
    res["repeated"] = repeated_cv(X, y, seeds=range(10))
    res["label"] = "rule fires at least once on the benign evtx-baseline corpus (observable rules only)"
    save("fpmodel.json", res)
    return res


# ------------------------------------------------------------------------------- drafter
def stage_draft(workers: int = 4) -> dict[str, Any]:
    """Draft rules from each OTRF dataset's description + attacker transcript, then test them."""
    from anvil.draft import draft
    root = data_dir() / "otrf"
    cat = [d for d in load_catalog(root) if d.available and (d.adversary_view or d.description)]
    otrf = load("otrf.json")
    sigmahq_detected = {r["id"]: r["technique_detected"] for r in otrf["rows"]}
    tmp = Path(tempfile.mkdtemp(prefix="anvil-drafts-"))
    backends = ["heuristic", "keywords"]
    meta: dict[str, dict[str, list[str]]] = {b: defaultdict(list) for b in backends}
    for b in backends:
        for d in cat:
            text = f"{d.description}\n{d.adversary_view}"
            for i, dr in enumerate(draft(text, d.title, d.id, backend=b)):
                dr.rule["anvil"]["reviewed"] = True  # benchmark only: measure the raw drafts
                dr.rule["id"] = f"{dr.rule['id'][:-4]}{backends.index(b)}{i:03d}"  # unique per backend
                (tmp / f"{b}-{d.id}-{i}.yml").write_text(dr.to_yaml(), encoding="utf-8")
                meta[b][d.id].append(dr.rule["id"])
    ds_files = {d.id: [str(p) for p in d.host_files if p.exists()] for d in cat}
    readable = []
    for f in sorted({f for fs in ds_files.values() for f in fs}):
        try:
            with open(f, "rb") as fh:
                fh.read(4)
            readable.append(f)
        except OSError:
            pass
    att = scan_files([tmp], readable, workers=workers)
    ben = scan_files([tmp], benign_shards(), workers=workers)
    out: dict[str, Any] = {"datasets": len(cat), "benign_events": ben.events, "backends": {}}
    for b in backends:
        rows = []
        for d in cat:
            ids = set(meta[b][d.id])
            fired = any(att.per_file_hits.get(f, {}).get(rid) for f in ds_files[d.id] for rid in ids)
            rows.append({"id": d.id, "drafts": len(ids), "fires_on_own_capture": fired,
                         "capture_readable": any(f in att.per_file_hits for f in ds_files[d.id]),
                         "benign_alerts": sum(ben.hits.get(rid, 0) for rid in ids),
                         "rules_over_budget": sum(1 for rid in ids if ben.hits.get(rid, 0) / max(1e-9, _days()) > BUDGET)})
        with_drafts = [r for r in rows if r["drafts"] and r["capture_readable"]]
        tp = sum(r["fires_on_own_capture"] for r in with_drafts)
        n_rules = sum(r["drafts"] for r in with_drafts)
        out["backends"][b] = {
            "drafts": n_rules, "datasets_with_drafts": len(with_drafts),
            "unreadable_excluded": sum(1 for r in rows if r["drafts"] and not r["capture_readable"]),
            "fires_on_own_capture": tp, "tp_rate": round(tp / max(1, len(with_drafts)), 3),
            "tp_rate_ci95": wilson(tp, len(with_drafts)),
            "datasets_with_benign_fp": sum(1 for r in with_drafts if r["benign_alerts"]),
            "benign_alerts_total": sum(r["benign_alerts"] for r in with_drafts),
            "rules_over_budget": sum(r["rules_over_budget"] for r in with_drafts),
            "gate_pass_and_fires": sum(1 for r in with_drafts if r["fires_on_own_capture"] and not r["rules_over_budget"]),
            "rows": rows}
    both = [r["id"] for r in out["backends"]["heuristic"]["rows"] if r["drafts"] and r["capture_readable"]]
    sigmahq_any = {r["id"]: r["any_alert"] for r in otrf["rows"]}
    out["sigmahq_same_datasets"] = {
        "datasets": len(both), "technique_detected": sum(bool(sigmahq_detected.get(i)) for i in both),
        "any_alert": sum(bool(sigmahq_any.get(i)) for i in both),
        "note": "drafts are scored on 'any alert on their own capture'; compare with SigmaHQ any_alert"}
    out["paired"] = draft_paired(out)
    save("draft.json", out)
    return out


def draft_paired(out: dict[str, Any]) -> dict[str, Any]:
    """Heuristic vs keyword drafter on the same datasets, with exact McNemar tests.

    A dataset scores for a backend when that backend drafted at least one rule that fires on the
    dataset's own capture (``fires``), and additionally when none of its drafts is over the
    benign alert budget (``fires_within_budget``). Datasets without a draft count as misses.
    """
    rows = {b: {r["id"]: r for r in v["rows"] if r["capture_readable"]} for b, v in out["backends"].items()}
    h, k = rows["heuristic"], rows["keywords"]

    def ok(r: dict[str, Any] | None, budget: bool) -> bool:
        return bool(r and r["drafts"] and r["fires_on_own_capture"] and (not budget or not r["rules_over_budget"]))

    res: dict[str, Any] = {}
    for scope, ids in (("all datasets", sorted(set(h) | set(k))),
                       ("datasets where both backends drafted", sorted(i for i in set(h) & set(k)
                                                                      if h[i]["drafts"] and k[i]["drafts"]))):
        block: dict[str, Any] = {"datasets": len(ids)}
        for metric, budget in (("fires", False), ("fires_within_budget", True)):
            hs = {i for i in ids if ok(h.get(i), budget)}
            ks = {i for i in ids if ok(k.get(i), budget)}
            block[metric] = {"heuristic": len(hs), "keywords": len(ks),
                             **paired_mcnemar(hs, ks, set(ids))}
        res[scope] = block
    return res


def _days() -> float:
    try:
        return float(load("fp.json")["corpus"]["days"]) or 1.0
    except (OSError, KeyError, ValueError):
        return 1.0


def stage_nixcloud() -> dict[str, Any]:
    """Linux / AWS captures (opt-in data; normally run by the CI bench job)."""
    from benchmarks.nixcloud_bench import stage_linux_benign
    from benchmarks.nixcloud_bench import stage_nixcloud as run
    res = run(data_dir(), _rule_dirs())
    res["linux_benign"] = stage_linux_benign(data_dir(), _rule_dirs())
    save("nixcloud.json", res)
    return res


EXTRA_STAGES = {"nixcloud": stage_nixcloud}  # not part of "all": needs the opt-in nixcloud download

STAGES = {"lint": stage_lint, "engine": stage_engine, "fp": stage_fp, "otrf": stage_otrf,
          "coverage": stage_coverage, "decay": stage_decay, "convert": stage_convert,
          "fpmodel": stage_fpmodel, "draft": stage_draft}


VOLATILE = ("provenance", "seconds", "wall_seconds", "cpu_seconds", "lint_seconds", "events_per_cpu_second")


def _strip_volatile(x: Any) -> Any:
    """Drop provenance and timing keys, which differ on every run."""
    if isinstance(x, dict):
        return {k: _strip_volatile(v) for k, v in x.items()
                if k not in VOLATILE and not k.endswith("_seconds") and k != "metadata"}
    if isinstance(x, list):
        return [_strip_volatile(v) for v in x]
    return x


def _diff(a: Any, b: Any, path: str = "$") -> list[str]:
    if isinstance(a, dict) and isinstance(b, dict):
        out = []
        for k in sorted(set(a) | set(b), key=str):
            if k not in a or k not in b:
                out.append(f"{path}.{k}: only in {'reference' if k in a else 'this run'}")
            else:
                out += _diff(a[k], b[k], f"{path}.{k}")
        return out
    if isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        return [d for i, (x, y) in enumerate(zip(a, b)) for d in _diff(x, y, f"{path}[{i}]")]
    return [] if a == b else [f"{path}: {str(a)[:60]} -> {str(b)[:60]}"]


def verify(against: str | None = None, show: int = 20) -> int:
    """Compare results/*.json with a reference (a folder, or the committed files at git HEAD).

    Provenance and timing keys are ignored, so a faithful reproduction prints no differences.
    """
    import subprocess
    bad = 0
    for f in sorted(RESULTS.glob("*.json")):
        if against:
            ref_p = Path(against) / f.name
            ref_text = ref_p.read_text(encoding="utf-8") if ref_p.exists() else None
        else:
            r = subprocess.run(["git", "show", f"HEAD:results/{f.name}"], cwd=RESULTS.parent, capture_output=True,
                               text=True, encoding="utf-8")
            ref_text = r.stdout if r.returncode == 0 else None
        if ref_text is None:
            print(f"{f.name}: no reference")
            continue
        diffs = _diff(_strip_volatile(json.loads(ref_text)), _strip_volatile(json.loads(f.read_text(encoding="utf-8"))))
        print(f"{f.name}: {'identical' if not diffs else f'{len(diffs)} difference(s)'}")
        for d in diffs[:show]:
            print(f"    {d}")
        bad += bool(diffs)
    return 1 if bad else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("stages", nargs="+", choices=[*STAGES, *EXTRA_STAGES, "report", "all", "verify"],
                    help="stages to run; 'verify' compares results/*.json with --against or git HEAD")
    ap.add_argument("--workers", type=int, default=4, help="processes for corpus scans")
    ap.add_argument("--against", help="verify: reference results folder (default: committed files at HEAD)")
    a = ap.parse_args(argv)
    if a.stages == ["verify"]:
        return verify(a.against)
    extra = [n for n in a.stages if n in EXTRA_STAGES]
    names = [*STAGES, *extra, "report"] if "all" in a.stages else a.stages
    for n in names:
        t0 = time.perf_counter()
        print(f"== {n}", flush=True)
        if n == "report":
            from benchmarks.report import build
            build()
        else:
            fn = STAGES.get(n) or EXTRA_STAGES[n]
            r = fn(workers=a.workers) if "workers" in fn.__code__.co_varnames else fn()
            print(json.dumps({k: v for k, v in r.items() if not isinstance(v, (list, dict)) or k in
                              ("anvil", "anvil_v01", "backends")}, default=str)[:1500])
        print(f"   {n} done in {time.perf_counter() - t0:.1f}s", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
