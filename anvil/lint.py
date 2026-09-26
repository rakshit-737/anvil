"""Rule linting / schema validation."""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass

from .engine import MODIFIERS, UNSUPPORTED_MODS, ConditionError, UnsupportedRule, parse_condition, referenced_selections
from .models import ATTACK_TAG, LEVELS, STATUSES, Rule

# Sigma tag namespaces (Sigma specification, appendix "Tags")
TAG_NAMESPACES = {"attack", "car", "cve", "detection", "tlp", "stp", "d3fend", "cwe"}
PROFILES = ("anvil", "sigma")

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
            if set(mods) & UNSUPPORTED_MODS:
                out.append(Finding(rule.id, WARN, "W210", f"{name}.{key}: placeholder modifier needs a pipeline"))
            bad = set(mods) - MODIFIERS - UNSUPPORTED_MODS
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


def lint_rule(rule: Rule, profile: str = "anvil", catalog=None) -> list[Finding]:
    """Lint one rule.

    ``profile="anvil"`` requires in-rule TP/TN fixtures (ANVIL's own rules);
    ``profile="sigma"`` follows SigmaHQ conventions, where tests live in
    ``regression_data`` and are referenced by ``regression_tests_path``.
    ``catalog`` (an :class:`anvil.attack.Catalog`) enables stale-tag checks.
    """
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
        except UnsupportedRule as exc:
            out.append(Finding(rid, WARN, "W211", f"condition not evaluable by ANVIL: {exc}"))
        except ConditionError as exc:
            out.append(Finding(rid, ERROR, "A110", f"condition invalid: {exc}"))
    for name, sel in rule.selections.items():
        _check_selection(rule, name, sel, out)
    if not rule.techniques:
        out.append(Finding(rid, WARN, "W203", "no ATT&CK technique tag (attack.tNNNN)"))
    for t in rule.tags:
        if t.startswith("attack.t") and not ATTACK_TAG.match(t):
            out.append(Finding(rid, ERROR, "A111", f"malformed ATT&CK tag {t!r}"))
        if t.split(".", 1)[0] not in TAG_NAMESPACES:
            out.append(Finding(rid, WARN, "W212", f"unknown tag namespace {t!r}"))
    if catalog is not None:
        for tid in rule.techniques:
            tech = catalog.techniques.get(tid)
            if tech is None:
                out.append(Finding(rid, WARN, "W208", f"{tid} is not in ATT&CK {catalog.version}"))
            elif not tech.active:
                now = catalog.resolve(tid)
                hint = f" (now {now})" if now else ""
                out.append(Finding(rid, WARN, "W208",
                                   f"{tid} is {'revoked' if tech.revoked else 'deprecated'} in ATT&CK "
                                   f"{catalog.version}{hint}"))
    if not rule.falsepositives:
        out.append(Finding(rid, WARN, "W204", "falsepositives not documented"))
    meta = rule.raw.get("anvil") if isinstance(rule.raw.get("anvil"), dict) else {}
    if meta.get("draft") and not meta.get("reviewed"):
        out.append(Finding(rid, ERROR, "A114", "unreviewed machine-drafted rule: a human must review it "
                                                "and set anvil.reviewed: true before it can ship"))
    if profile == "sigma":
        if rule.status in ("test", "stable") and not rule.regression_tests_path:
            out.append(Finding(rid, WARN, "W209", f"status {rule.status} but no regression_tests_path"))
        return out
    if not rule.tests.true_positives:
        out.append(Finding(rid, ERROR, "A112", "no true-positive test fixtures"))
    if not rule.tests.true_negatives:
        out.append(Finding(rid, WARN, "W207", "no true-negative test fixtures"))
    return out


def lint_rules(rules: list[Rule], profile: str = "anvil", catalog=None) -> list[Finding]:
    out: list[Finding] = []
    seen: dict[str, str] = {}
    for r in rules:
        out.extend(lint_rule(r, profile, catalog))
        if r.id in seen:
            out.append(Finding(r.id, ERROR, "A113", f"duplicate id (also in {seen[r.id]})"))
        seen[r.id] = r.path
    return out


def has_errors(findings: list[Finding]) -> bool:
    return any(f.severity == ERROR for f in findings)
