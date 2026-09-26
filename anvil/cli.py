"""ANVIL command-line interface."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .coverage import coverage, navigator_layer
from .decay import regressions, schema_drift
from .harness import GatePolicy, evaluate_all
from .lint import has_errors, lint_rules
from .loader import load_events, load_rules
from .quality import score_rule
from .synth import generate, write_jsonl


def _policy(a: argparse.Namespace) -> GatePolicy:
    return GatePolicy(max_fp_rate=a.max_fp_rate, soc_capacity_per_day=a.capacity,
                      capacity_share=a.share, corpus_days=a.days)


def cmd_lint(a) -> int:
    findings = lint_rules(load_rules(a.rules))
    for f in findings:
        print(f)
    errs = has_errors(findings)
    print(f"lint: {len(findings)} finding(s), {'FAIL' if errs else 'OK'}")
    return 1 if errs or (a.strict and findings) else 0


def cmd_test(a) -> int:
    rules = load_rules(a.rules)
    results = evaluate_all(rules, load_events(a.corpus), _policy(a))
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


def cmd_coverage(a) -> int:
    rules = load_rules(a.rules)
    passing = None
    if a.corpus:
        passing = {r.rule_id for r in evaluate_all(rules, load_events(a.corpus)) if r.passed}
    rep = coverage(rules, passing)
    if a.navigator:
        Path(a.navigator).write_text(json.dumps(navigator_layer(rep), indent=2))
    if a.json:
        print(json.dumps(rep, indent=2))
        return 0
    print(f"ATT&CK coverage: {rep['covered']}/{rep['catalog_size']} techniques "
          f"({rep['coverage_pct']}%), validated {rep['validated']} ({rep['validated_pct']}%)")
    for tac, s in sorted(rep["tactics"].items()):
        bar = "#" * s["covered"] + "." * (s["total"] - s["covered"])
        print(f"  {tac:22} {bar:8} {s['covered']}/{s['total']}")
    gaps = [r["technique"] + " " + r["name"] for r in rep["techniques"] if not r["rules"]]
    print("gaps: " + ", ".join(gaps))
    return 0


def cmd_score(a) -> int:
    rules = load_rules(a.rules)
    results = {r.rule_id: r for r in evaluate_all(rules, load_events(a.corpus))}
    for r in rules:
        q = score_rule(r, results.get(r.id))
        print(f"{q.score:3d} {q.grade}  {q.title}  {q.breakdown}")
    return 0


def cmd_decay(a) -> int:
    rules = load_rules(a.rules)
    events = load_events(a.corpus)
    issues = 0
    for rid, fields in schema_drift(rules, events).items():
        issues += 1
        print(f"DRIFT {rid}: fields not present in telemetry: {fields}")
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


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="anvil", description="Detection-as-code lifecycle toolkit")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    def rules_arg(sp):
        sp.add_argument("--rules", default="rules")

    s = sub.add_parser("lint", help="validate rule files")
    rules_arg(s)
    s.add_argument("--strict", action="store_true", help="fail on warnings too")
    s.set_defaults(fn=cmd_lint)

    s = sub.add_parser("test", help="run TP/TN fixtures + FP corpus and apply the CI gate")
    rules_arg(s)
    s.add_argument("--corpus", default="telemetry/benign.jsonl")
    s.add_argument("--max-fp-rate", type=float, default=0.001)
    s.add_argument("--capacity", type=float, default=200.0, help="SOC alerts/day capacity")
    s.add_argument("--share", type=float, default=0.10, help="max capacity share per rule")
    s.add_argument("--days", type=float, default=1.0, help="days the corpus represents")
    s.add_argument("--json", action="store_true")
    s.add_argument("--save-baseline")
    s.set_defaults(fn=cmd_test)

    s = sub.add_parser("coverage", help="ATT&CK coverage report")
    rules_arg(s)
    s.add_argument("--corpus", help="if given, count only gate-passing rules as validated")
    s.add_argument("--navigator", help="write ATT&CK Navigator layer JSON")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_coverage)

    s = sub.add_parser("score", help="rule quality scores")
    rules_arg(s)
    s.add_argument("--corpus", default="telemetry/benign.jsonl")
    s.set_defaults(fn=cmd_score)

    s = sub.add_parser("decay", help="schema-drift + regression check")
    rules_arg(s)
    s.add_argument("--corpus", default="telemetry/benign.jsonl")
    s.add_argument("--baseline")
    s.set_defaults(fn=cmd_decay)

    s = sub.add_parser("synth", help="generate synthetic benign telemetry")
    s.add_argument("--out", default="telemetry/benign.jsonl")
    s.add_argument("-n", type=int, default=5000)
    s.add_argument("--seed", type=int, default=1337)
    s.add_argument("--schema", choices=["v1", "v2"], default="v1")
    s.set_defaults(fn=cmd_synth)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    raise SystemExit(main())
