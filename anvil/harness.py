"""Test harness: TP/TN fixtures + benign corpus FP measurement + CI gate."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from .engine import compile_rule
from .models import Rule


@dataclass
class GatePolicy:
    max_fp_rate: float = 0.001          # fraction of benign corpus events
    soc_capacity_per_day: float = 200.0  # alerts/day the SOC can triage
    capacity_share: float = 0.10         # one rule may use at most this share
    corpus_days: float = 1.0             # time span the benign corpus represents


@dataclass
class RuleResult:
    rule_id: str
    title: str
    tp_total: int
    tp_fired: int
    tn_total: int
    tn_fired: int
    corpus_size: int
    fp_hits: int
    precision: float
    recall: float
    fp_rate: float
    alerts_per_day: float
    passed: bool
    reasons: list[str] = field(default_factory=list)
    missed_tps: list[int] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def evaluate(rule: Rule, corpus: list[dict[str, Any]], policy: GatePolicy | None = None) -> RuleResult:
    policy = policy or GatePolicy()
    cr = compile_rule(rule)
    tps, tns = rule.tests.true_positives, rule.tests.true_negatives
    tp_hits = [cr.matches(e) for e in tps]
    tp_fired = sum(tp_hits)
    tn_fired = sum(cr.matches(e) for e in tns)
    fp_hits = sum(cr.matches(e) for e in corpus)
    denom = tp_fired + fp_hits + tn_fired
    precision = tp_fired / denom if denom else 0.0
    recall = tp_fired / len(tps) if tps else 0.0
    fp_rate = fp_hits / len(corpus) if corpus else 0.0
    per_day = fp_hits / policy.corpus_days if policy.corpus_days else float(fp_hits)
    budget = policy.soc_capacity_per_day * policy.capacity_share

    reasons = []
    if not tps:
        reasons.append("no true-positive fixtures")
    elif tp_fired < len(tps):
        reasons.append(f"missed {len(tps) - tp_fired}/{len(tps)} true positives")
    if tn_fired:
        reasons.append(f"fired on {tn_fired} true-negative fixture(s)")
    if fp_rate > policy.max_fp_rate:
        reasons.append(f"FP rate {fp_rate:.4%} > {policy.max_fp_rate:.4%}")
    if per_day > budget:
        reasons.append(f"~{per_day:.0f} alerts/day exceeds budget {budget:.0f}/day "
                       f"({policy.capacity_share:.0%} of {policy.soc_capacity_per_day:.0f} SOC capacity)")
    return RuleResult(
        rule.id, rule.title, len(tps), tp_fired, len(tns), tn_fired, len(corpus), fp_hits,
        round(precision, 4), round(recall, 4), round(fp_rate, 6), round(per_day, 2),
        not reasons, reasons, [i for i, h in enumerate(tp_hits) if not h],
    )


def evaluate_all(rules: list[Rule], corpus: list[dict[str, Any]],
                 policy: GatePolicy | None = None) -> list[RuleResult]:
    return [evaluate(r, corpus, policy) for r in rules if r.status != "deprecated"]
