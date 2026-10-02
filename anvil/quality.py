"""Rule-quality scoring (0-100) combining metadata hygiene and measured efficacy."""
from __future__ import annotations

from dataclasses import dataclass, field

from .harness import RuleResult
from .lint import ERROR, lint_rule
from .models import Rule


@dataclass
class QualityScore:
    """A 0-100 rule quality score, letter grade and per-component breakdown."""
    rule_id: str
    title: str
    score: int
    grade: str
    breakdown: dict[str, int] = field(default_factory=dict)


def _grade(s: int) -> str:
    return "A" if s >= 90 else "B" if s >= 75 else "C" if s >= 60 else "D" if s >= 40 else "F"


def score_rule(rule: Rule, result: RuleResult | None) -> QualityScore:
    """Score a rule on lint, tests, gate result and metadata."""
    b: dict[str, int] = {}
    findings = lint_rule(rule)
    errs = sum(f.severity == ERROR for f in findings)
    warns = len(findings) - errs
    b["lint"] = max(0, 20 - 10 * errs - 3 * warns)                         # 20
    b["metadata"] = (4 * bool(rule.references) + 4 * bool(rule.falsepositives)
                     + 4 * bool(rule.author) + 3 * (len(rule.description) >= 40))  # 15
    b["attack_mapping"] = 10 if rule.techniques else 0                     # 10
    n_tests = len(rule.tests.true_positives) + len(rule.tests.true_negatives)
    b["test_depth"] = min(15, 3 * n_tests)                                  # 15
    if result is None:
        b["recall"] = b["precision"] = b["noise"] = 0
    else:
        b["recall"] = round(20 * result.recall)                             # 20
        b["precision"] = round(10 * result.precision)                       # 10
        b["noise"] = 10 if result.fp_hits == 0 else 5 if result.passed else 0  # 10
    total = sum(b.values())
    return QualityScore(rule.id, rule.title, total, _grade(total), b)
