"""Rule linting / schema validation."""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass

from .engine import MODIFIERS, ConditionError, parse_condition, referenced_selections
from .models import ATTACK_TAG, LEVELS, STATUSES, Rule

ERROR, WARN = "error", "warning"


@dataclass
class Finding:
    rule_id: str
    severity: str
    code: str
    message: str

    def __str__(self) -> str:
        return f"[{self.severity.upper()}] {self.rule_id or '?'} {self.code}: {self.message}"


def _check_selection(rule: Rule, name: str, sel, out: list[Finding]) -> None:
    items = sel if isinstance(sel, list) else [sel]
    if not items:
        out.append(Finding(rule.id, ERROR, "A105", f"selection {name!r} is empty"))
    for item in items:
        if not isinstance(item, dict):
            continue
        for key, val in item.items():
            _field, *mods = str(key).split("|")
            bad = set(mods) - MODIFIERS
            if bad:
                out.append(Finding(rule.id, ERROR, "A106", f"{name}.{key}: unknown modifier {sorted(bad)}"))
            if "re" in mods:
                for v in val if isinstance(val, list) else [val]:
                    try:
                        re.compile(str(v))
                    except re.error as exc:
                        out.append(Finding(rule.id, ERROR, "A107", f"{name}.{key}: bad regex {v!r}: {exc}"))
            if "contains" in mods:
                for v in val if isinstance(val, list) else [val]:
                    if len(str(v)) < 3:
                        out.append(Finding(rule.id, WARN, "W205", f"{name}.{key}: very short contains value {v!r} (FP risk)"))
            if isinstance(val, str) and val.strip() in ("*", ""):
                out.append(Finding(rule.id, WARN, "W206", f"{name}.{key}: match-anything value"))


def lint_rule(rule: Rule) -> list[Finding]:
    out: list[Finding] = []
    rid = rule.id
    try:
        uuid.UUID(rid)
    except ValueError:
        out.append(Finding(rid, ERROR, "A101", "id must be a UUID"))
    for fld in ("title", "description"):
        if not getattr(rule, fld).strip():
            out.append(Finding(rid, ERROR, "A102", f"missing {fld}"))
    if len(rule.title) > 120:
        out.append(Finding(rid, WARN, "W201", "title longer than 120 chars"))
    if rule.level not in LEVELS:
        out.append(Finding(rid, ERROR, "A103", f"level must be one of {LEVELS}"))
    if rule.status not in STATUSES:
        out.append(Finding(rid, ERROR, "A104", f"status must be one of {STATUSES}"))
    if not (rule.logsource.product or rule.logsource.category or rule.logsource.service):
        out.append(Finding(rid, ERROR, "A108", "logsource needs product/category/service"))
    if not rule.condition:
        out.append(Finding(rid, ERROR, "A109", "detection.condition missing"))
    else:
        try:
            ast = parse_condition(rule.condition, list(rule.selections))
            unused = set(rule.selections) - referenced_selections(ast)
            if unused:
                out.append(Finding(rid, WARN, "W202", f"unused selections: {sorted(unused)}"))
        except ConditionError as exc:
            out.append(Finding(rid, ERROR, "A110", f"condition invalid: {exc}"))
    for name, sel in rule.selections.items():
        _check_selection(rule, name, sel, out)
    if not rule.techniques:
        out.append(Finding(rid, WARN, "W203", "no ATT&CK technique tag (attack.tNNNN)"))
    for t in rule.tags:
        if t.startswith("attack.t") and not ATTACK_TAG.match(t):
            out.append(Finding(rid, ERROR, "A111", f"malformed ATT&CK tag {t!r}"))
    if not rule.falsepositives:
        out.append(Finding(rid, WARN, "W204", "falsepositives not documented"))
    if not rule.tests.true_positives:
        out.append(Finding(rid, ERROR, "A112", "no true-positive test fixtures"))
    if not rule.tests.true_negatives:
        out.append(Finding(rid, WARN, "W207", "no true-negative test fixtures"))
    return out


def lint_rules(rules: list[Rule]) -> list[Finding]:
    out: list[Finding] = []
    seen: dict[str, str] = {}
    for r in rules:
        out.extend(lint_rule(r))
        if r.id in seen:
            out.append(Finding(r.id, ERROR, "A113", f"duplicate id (also in {seen[r.id]})"))
        seen[r.id] = r.path
    return out


def has_errors(findings: list[Finding]) -> bool:
    return any(f.severity == ERROR for f in findings)
