"""ANVIL command-line interface."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__
from .coverage import coverage, navigator_layer
from .decay import FieldInventory, analyse, regressions, schema_drift
from .harness import GatePolicy, evaluate_all
from .lint import PROFILES, has_errors, lint_rules
from .loader import load_events, load_rule, load_rules
from .quality import score_rule
from .synth import generate, write_jsonl


def _policy(a: argparse.Namespace) -> GatePolicy:
    return GatePolicy(max_fp_rate=a.max_fp_rate, soc_capacity_per_day=a.capacity,
                      capacity_share=a.share, corpus_days=a.days)


def _catalog(path: str | None):
    if not path:
        return None
    from .attack import load_stix
    return load_stix(path)


class UsageError(Exception):
    """A user-facing error: printed as one line, exit code 2."""


def _load(a) -> list:
    """Load every ``--rules`` path (files or folders, any number of them).

    The ``sigma`` profile reads multi-document SigmaHQ YAML; the default reads ANVIL
    rules with fixtures. A missing path, or zero rules without ``--allow-empty``, is
    a usage error so a CI gate cannot pass vacuously.
    """
    missing = [p for p in a.rules if not Path(p).exists()]
    if missing:
        raise UsageError(f"--rules path(s) not found: {', '.join(missing)}")
    if getattr(a, "profile", "anvil") == "sigma":
        from .runner import load_rule_dir
        rules = load_rule_dir(a.rules)[0]
    else:
        rules = []
        for p in a.rules:
            rules += [load_rule(p)] if Path(p).is_file() else load_rules(p)
    if not rules and not getattr(a, "allow_empty", False):
        raise UsageError(f"no rules found under {' '.join(a.rules)} (pass --allow-empty to accept)")
    return rules


def _events(path: str) -> list:
    if not Path(path).exists():
        raise UsageError(f"corpus {path} not found: run `anvil synth` or pass --corpus")
    return load_events(path)


def cmd_lint(a) -> int:
    rules = _load(a)
    findings = lint_rules(rules, a.profile, _catalog(a.attack))
    if a.summary:
        from collections import Counter
        for (sev, code), n in Counter((f.severity, f.code) for f in findings).most_common():
            print(f"{n:6d}  {sev:7} {code}")
    else:
        for f in findings:
            print(f)
    errs = has_errors(findings)
    print(f"lint: {len(rules)} rule(s), {len(findings)} finding(s), {'FAIL' if errs else 'OK'}")
    return 1 if errs or (a.strict and findings) else 0


def cmd_test(a) -> int:
    rules = _load(a)
    results = evaluate_all(rules, _events(a.corpus), _policy(a))
    if a.json:
        print(json.dumps([r.to_dict() for r in results], indent=2))
    else:
        print(f"{'RESULT':6} {'RECALL':>6} {'PREC':>6} {'FP':>5} {'A/DAY':>7}  RULE")
        for r in results:
            print(f"{'PASS' if r.passed else 'FAIL':6} {r.recall:6.2f} {r.precision:6.2f} "
                  f"{r.fp_hits:5d} {r.alerts_per_day:7.1f}  {r.title}")
            for reason in r.reasons:
                print(f"       - {reason}")
    if a.save_baseline:
        Path(a.save_baseline).write_text(json.dumps({r.rule_id: r.to_dict() for r in results}, indent=2))
    failed = sum(not r.passed for r in results)
    print(f"test: {len(results) - failed}/{len(results)} rules passed the gate", file=sys.stderr)
    return 1 if failed else 0


def cmd_scan(a) -> int:
    """Library-scale scan: route every rule to its log source and count hits on real telemetry."""
    from .runner import Library, scan
    from .telemetry import iter_path

    rules = _load(argparse.Namespace(rules=a.rules, profile="sigma", allow_empty=False))
    for c in a.corpus:
        if not Path(c).exists():
            raise UsageError(f"corpus {c} not found")
    lib = Library.build(rules)

    def events():
        for c in a.corpus:
            yield from iter_path(c)

    res = scan(lib, events())
    budget = a.capacity * a.share
    rows = sorted(res.hits.items(), key=lambda kv: -kv[1])
    out = [{"id": rid, "title": lib.rules[rid].title, "level": lib.rules[rid].level, "hits": n,
            "alerts_per_day": round(n / a.days, 2), "gate": "pass" if n / a.days <= budget else "fail"}
           for rid, n in rows]
    if a.json:
        print(json.dumps({"events": res.events, "seconds": round(res.seconds, 2), "rules": len(lib.compiled),
                          "unsupported": len(lib.unsupported), "unroutable": len(lib.unroutable),
                          "hits": out}, indent=2))
    else:
        print(f"scanned {res.events} events with {len(lib.active_ids)} routed rules "
              f"({len(lib.unsupported)} unsupported, {len(lib.unroutable)} unroutable) "
              f"in {res.seconds:.1f}s ({res.events_per_second:.0f} ev/s)")
        for o in out[: a.top]:
            print(f"{o['gate'].upper():4} {o['hits']:7d} {o['alerts_per_day']:9.1f}/day  {o['level']:13} {o['title']}")
    return 1 if any(o["gate"] == "fail" for o in out) and a.fail_on_gate else 0


def cmd_regress(a) -> int:
    from collections import Counter

    from .regression import run_all
    from .runner import Library, load_rule_dir
    root = Path(a.sigma)
    dirs = [root / d for d in ("rules", "rules-emerging-threats", "rules-threat-hunting") if (root / d).exists()]
    lib = Library.build(load_rule_dir(dirs)[0])
    res = run_all(lib, root)
    st = Counter(r.status for r in res)
    for r in res:
        if r.status == "fail" or a.verbose:
            print(f"{r.status.upper():11} {r.matched}/{r.expected or '>=1'}  {r.title}")
    print(f"regression: {dict(st)}")
    return 1 if st.get("fail") else 0


def cmd_ingest(a) -> int:
    from .telemetry import ingest
    if a.benign:
        base = Path(os.environ.get("ANVIL_DATA", "data"))
        total = 0
        for d in sorted((base / "evtx-baseline").iterdir()):
            if d.is_dir():
                shards = ingest([d], base / "corpus" / f"benign-{d.name}", a.shard, d.name)
                total += len(shards)
                print(f"{d.name}: {len(shards)} shard(s)")
        print(f"ingested {total} shard(s) into {base / 'corpus'}")
        return 0
    if not a.sources or not a.out:
        raise SystemExit("ingest: give SOURCES and --out, or --benign")
    shards = ingest(a.sources, a.out, a.shard, a.prefix)
    print(f"wrote {len(shards)} shard(s) to {a.out}")
    return 0


def cmd_draft(a) -> int:
    from .draft import draft
    text = Path(a.report).read_text(encoding="utf-8", errors="replace")
    drafts = draft(text, a.title or Path(a.report).stem, a.source or str(a.report), a.backend)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    for d in drafts:
        name = d.rule["title"].lower().replace("drafted: ", "")
        slug = "".join(ch if ch.isalnum() else "_" for ch in name)[:60].strip("_")
        p = out / f"draft_{slug}.yml"
        p.write_text(d.to_yaml(), encoding="utf-8")
        print(f"DRAFT {p}  ({d.rationale})")
    print(f"draft: {len(drafts)} candidate rule(s) - status experimental, anvil.reviewed=false. "
          f"Review, set reviewed: true in a PR, and run `anvil test` before merging.")
    return 0 if drafts else 1


def cmd_convert(a) -> int:
    from .convert import Converter
    conv = Converter(a.target)
    p = Path(a.rule)
    files = sorted(p.rglob("*.yml")) if p.is_dir() else [p]
    bad = 0
    for f in files:
        c = conv.convert_yaml(f.read_text(encoding="utf-8"), f.stem)
        if c.ok:
            for q in c.queries:
                print(f"# {f.name}\n{q}\n")
        else:
            bad += 1
            print(f"# {f.name}: {c.error}", file=sys.stderr)
    return 1 if bad else 0


def cmd_coverage(a) -> int:
    rules = _load(a)
    passing = None
    if a.corpus:
        passing = {r.rule_id for r in evaluate_all(rules, _events(a.corpus)) if r.passed}
    rep = coverage(rules, passing, _catalog(a.attack), a.platform)
    if a.navigator:
        Path(a.navigator).write_text(json.dumps(navigator_layer(rep), indent=2))
    if a.json:
        print(json.dumps(rep, indent=2))
        return 0
    print(f"ATT&CK {rep['catalog']} ({rep['platform']}): {rep['covered']}/{rep['catalog_size']} techniques "
          f"({rep['coverage_pct']}%), validated {rep['validated']} ({rep['validated_pct']}%)")
    for tac, s in rep["tactics"].items():
        width = 30
        fill = round(width * s["covered"] / s["total"]) if s["total"] else 0
        print(f"  {tac:22} {'#' * fill}{'.' * (width - fill)} {s['covered']}/{s['total']}")
    gaps = [r["technique"] for r in rep["techniques"] if not r["rules"]]
    print(f"gaps ({len(gaps)}): " + ", ".join(gaps[:40]) + (" ..." if len(gaps) > 40 else ""))
    if rep["stale_tags"]:
        print(f"stale technique tags in {len(rep['stale_tags'])} rule(s)")
    return 0


def cmd_score(a) -> int:
    rules = _load(a)
    results = {r.rule_id: r for r in evaluate_all(rules, _events(a.corpus))}
    for r in rules:
        q = score_rule(r, results.get(r.id))
        print(f"{q.score:3d} {q.grade}  {q.title}  {q.breakdown}")
    return 0


def cmd_decay(a) -> int:
    rules = _load(a)
    events = load_events(a.corpus) if a.corpus.endswith((".jsonl", ".json")) else None
    if events is None:
        from .telemetry import iter_path
        events = list(iter_path(a.corpus))
    issues = 0
    for rid, fields in schema_drift(rules, events).items():
        issues += 1
        print(f"DRIFT {rid}: fields not present in telemetry: {fields}")
    if a.routed:
        inv = FieldInventory.from_events(events)
        for r in rules:
            v = analyse(r, inv)
            if v["status"] != "ok":
                print(f"{v['status'].upper():14} {r.title}  missing={v['missing']} blind={v['blind_filters']}")
    if a.baseline:
        base = json.loads(Path(a.baseline).read_text())
        for rid, msgs in regressions(base, evaluate_all(rules, events)).items():
            issues += 1
            print(f"REGRESSION {rid}: {'; '.join(msgs)}")
    print(f"decay: {issues} issue(s)")
    return 1 if issues else 0


def cmd_synth(a) -> int:
    write_jsonl(generate(a.n, a.seed, a.schema), a.out)
    print(f"wrote {a.n} synthetic benign events ({a.schema}) to {a.out}")
    return 0


def cmd_report(a) -> int:
    from .dashboard import render
    out = render(Path(a.results), Path(a.out))
    print(f"wrote {out}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="anvil", description="Detection-as-code lifecycle toolkit")
    fmt = argparse.ArgumentDefaultsHelpFormatter
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    def rules_arg(sp, default=("rules",)):
        sp.add_argument("--rules", nargs="+", default=list(default), help="rule file(s) or folder(s)")
        sp.add_argument("--allow-empty", action="store_true", help="do not fail when no rules are found")

    def gate_args(sp):
        sp.add_argument("--capacity", type=float, default=200.0, help="SOC alerts/day capacity")
        sp.add_argument("--share", type=float, default=0.10, help="max capacity share per rule")
        sp.add_argument("--days", type=float, default=1.0, help="days the corpus represents")

    s = sub.add_parser(formatter_class=fmt, name="lint", help="validate rule files")
    rules_arg(s)
    s.add_argument("--profile", choices=PROFILES, default="anvil",
                   help="anvil: rules carry TP/TN fixtures; sigma: SigmaHQ conventions")
    s.add_argument("--attack", help="ATT&CK STIX bundle for stale-tag checks")
    s.add_argument("--summary", action="store_true", help="counts per finding code only")
    s.add_argument("--strict", action="store_true", help="fail on warnings too")
    s.set_defaults(fn=cmd_lint)

    s = sub.add_parser(formatter_class=fmt, name="test", help="run TP/TN fixtures + FP corpus and apply the CI gate")
    rules_arg(s)
    s.add_argument("--corpus", default="telemetry/benign.jsonl", help="benign JSONL corpus (see `anvil synth`)")
    s.add_argument("--max-fp-rate", type=float, default=0.001, help="max share of benign events a rule may hit")
    gate_args(s)
    s.add_argument("--json", action="store_true", help="machine-readable output")
    s.add_argument("--save-baseline", metavar="FILE", help="write per-rule results for `decay --baseline`")
    s.set_defaults(fn=cmd_test)

    s = sub.add_parser(formatter_class=fmt, name="scan", help="scan real telemetry with a whole (Sigma) rule library")
    rules_arg(s)
    s.add_argument("--corpus", nargs="+", required=True, help="EVTX / JSON / JSONL(.gz) / OTRF zip / folders")
    gate_args(s)
    s.add_argument("--top", type=int, default=25, help="rows to print")
    s.add_argument("--json", action="store_true", help="machine-readable output")
    s.add_argument("--fail-on-gate", action="store_true", help="exit 1 if any rule exceeds its alert budget")
    s.set_defaults(fn=cmd_scan)

    s = sub.add_parser(formatter_class=fmt, name="regress", help="replay SigmaHQ regression_data (real TP captures)")
    s.add_argument("--sigma", required=True, help="path to a SigmaHQ checkout")
    s.add_argument("-v", "--verbose", action="store_true")
    s.set_defaults(fn=cmd_regress)

    s = sub.add_parser(formatter_class=fmt, name="ingest", help="normalise EVTX/JSON/OTRF sources into sharded JSONL.gz")
    s.add_argument("sources", nargs="*", help="EVTX / JSON / OTRF zip files or folders")
    s.add_argument("--out", help="output folder for the shards")
    s.add_argument("--prefix", default="part", help="shard file-name prefix")
    s.add_argument("--shard", type=int, default=100_000, help="events per shard")
    s.add_argument("--benign", action="store_true", help="ingest $ANVIL_DATA/evtx-baseline/* into corpus/")
    s.set_defaults(fn=cmd_ingest)

    s = sub.add_parser(formatter_class=fmt, name="draft", help="draft candidate Sigma rules from a CTI report (needs human review)")
    s.add_argument("report", help="text/markdown file")
    s.add_argument("--out", default="drafts", help="output folder for draft rules")
    s.add_argument("--title", help="report title (default: file name)")
    s.add_argument("--source", help="report URL for references")
    s.add_argument("--backend", choices=["heuristic", "llm", "keywords"], default="heuristic")
    s.set_defaults(fn=cmd_draft)

    s = sub.add_parser(formatter_class=fmt, name="convert", help="convert rules to SIEM queries via pySigma")
    s.add_argument("rule", help="rule file or folder")
    s.add_argument("--target", choices=["splunk", "elastic", "kusto", "sqlite"], default="splunk")
    s.set_defaults(fn=cmd_convert)

    s = sub.add_parser(formatter_class=fmt, name="coverage", help="ATT&CK coverage report")
    rules_arg(s)
    s.add_argument("--profile", choices=PROFILES, default="anvil")
    s.add_argument("--corpus", help="if given, count only gate-passing rules as validated")
    s.add_argument("--attack", help="ATT&CK Enterprise STIX bundle (default: bundled subset)")
    s.add_argument("--platform", help="e.g. Windows")
    s.add_argument("--navigator", help="write ATT&CK Navigator layer JSON")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_coverage)

    s = sub.add_parser(formatter_class=fmt, name="score", help="rule quality scores")
    rules_arg(s)
    s.add_argument("--corpus", default="telemetry/benign.jsonl", help="benign JSONL corpus")
    s.set_defaults(fn=cmd_score)

    s = sub.add_parser(formatter_class=fmt, name="decay", help="schema-drift + regression check")
    rules_arg(s)
    s.add_argument("--profile", choices=PROFILES, default="anvil")
    s.add_argument("--corpus", default="telemetry/benign.jsonl", help="current telemetry (JSONL or EVTX/JSON)")
    s.add_argument("--baseline", help="results saved earlier with `test --save-baseline`")
    s.add_argument("--routed", action="store_true",
                   help="per-log-source symbolic analysis: ok / degraded / broken / source-missing")
    s.set_defaults(fn=cmd_decay)

    s = sub.add_parser(formatter_class=fmt, name="synth", help="generate synthetic benign telemetry")
    s.add_argument("--out", default="telemetry/benign.jsonl", help="output JSONL file")
    s.add_argument("-n", type=int, default=5000, help="number of events")
    s.add_argument("--seed", type=int, default=1337, help="random seed")
    s.add_argument("--schema", choices=["v1", "v2"], default="v1", help="v2 renames fields (decay demo)")
    s.set_defaults(fn=cmd_synth)

    s = sub.add_parser(formatter_class=fmt, name="report", help="render the static detection-health dashboard from results/*.json")
    s.add_argument("--results", default="results", help="folder with results/*.json")
    s.add_argument("--out", default="docs/dashboard.html", help="output HTML file")
    s.set_defaults(fn=cmd_report)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    try:
        return a.fn(a)
    except UsageError as exc:
        print(f"anvil {a.cmd}: error: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"anvil {a.cmd}: error: file not found: {exc.filename}", file=sys.stderr)
        return 2
    except ModuleNotFoundError as exc:
        extra = {"sigma": "sigma", "anthropic": "llm", "sklearn": "ml", "evtx": "evtx",
                 "matplotlib": "plots"}.get((exc.name or "").split(".")[0])
        hint = f"pip install 'anvil-dac[{extra}]'" if extra else "install the missing package"
        print(f"anvil {a.cmd}: error: optional dependency {exc.name!r} missing; {hint}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
