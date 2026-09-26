"""Decay monitor: schema drift + regression against a stored baseline."""
from __future__ import annotations

from typing import Any

from .engine import rule_fields
from .harness import RuleResult
from .models import Rule


def observed_fields(events: list[dict[str, Any]]) -> set[str]:
    out: set[str] = set()

    def walk(d: dict[str, Any], prefix: str = "") -> None:
        for k, v in d.items():
            out.add(prefix + k)
            if isinstance(v, dict):
                walk(v, prefix + k + ".")

    for e in events:
        walk(e)
    return out


def schema_drift(rules: list[Rule], telemetry: list[dict[str, Any]]) -> dict[str, list[str]]:
    """Rules whose referenced fields no longer appear in current telemetry."""
    seen = observed_fields(telemetry)
    drift = {}
    for r in rules:
        missing = sorted(f for f in rule_fields(r) if f not in seen)
        if missing:
            drift[r.id] = missing
    return drift


def regressions(baseline: dict[str, dict[str, Any]], current: list[RuleResult],
                fp_spike_factor: float = 3.0) -> dict[str, list[str]]:
    """Compare current results to a baseline {rule_id: RuleResult.to_dict()}."""
    out: dict[str, list[str]] = {}
    for r in current:
        b = baseline.get(r.rule_id)
        if not b:
            continue
        issues = []
        if r.recall < b["recall"]:
            issues.append(f"recall dropped {b['recall']} -> {r.recall} (stopped firing)")
        if r.fp_hits > max(1, b["fp_hits"]) * fp_spike_factor:
            issues.append(f"FP spike {b['fp_hits']} -> {r.fp_hits}")
        if issues:
            out[r.rule_id] = issues
    return out
