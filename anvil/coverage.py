"""ATT&CK coverage reporting against a (small, bundled) technique catalog."""
from __future__ import annotations

from collections import defaultdict
from typing import Any

from .models import Rule

# Minimal offline catalog (subset of ATT&CK Enterprise). Full STIX import is a TODO.
CATALOG: dict[str, tuple[str, str]] = {
    "T1059.001": ("PowerShell", "execution"),
    "T1059.003": ("Windows Command Shell", "execution"),
    "T1047": ("Windows Management Instrumentation", "execution"),
    "T1053.005": ("Scheduled Task", "persistence"),
    "T1547.001": ("Registry Run Keys / Startup Folder", "persistence"),
    "T1136.001": ("Create Account: Local Account", "persistence"),
    "T1003.001": ("LSASS Memory", "credential-access"),
    "T1110": ("Brute Force", "credential-access"),
    "T1033": ("System Owner/User Discovery", "discovery"),
    "T1087.001": ("Account Discovery: Local Account", "discovery"),
    "T1105": ("Ingress Tool Transfer", "command-and-control"),
    "T1071.001": ("Web Protocols", "command-and-control"),
    "T1070.001": ("Clear Windows Event Logs", "defense-evasion"),
    "T1218.011": ("Rundll32", "defense-evasion"),
    "T1021.001": ("Remote Desktop Protocol", "lateral-movement"),
    "T1486": ("Data Encrypted for Impact", "impact"),
}


def coverage(rules: list[Rule], passing_ids: set[str] | None = None) -> dict[str, Any]:
    """Map techniques -> rules. If passing_ids given, only tested-passing rules count as 'validated'."""
    by_tech: dict[str, list[str]] = defaultdict(list)
    for r in rules:
        if r.status == "deprecated":
            continue
        for t in r.techniques:
            by_tech[t].append(r.id)
    rows = []
    for tid, (name, tactic) in sorted(CATALOG.items(), key=lambda kv: (kv[1][1], kv[0])):
        ids = by_tech.get(tid, [])
        validated = [i for i in ids if passing_ids is None or i in passing_ids]
        rows.append({"technique": tid, "name": name, "tactic": tactic,
                     "rules": len(ids), "validated": len(validated)})
    tactics: dict[str, dict[str, int]] = defaultdict(lambda: {"total": 0, "covered": 0, "validated": 0})
    for row in rows:
        s = tactics[row["tactic"]]
        s["total"] += 1
        s["covered"] += row["rules"] > 0
        s["validated"] += row["validated"] > 0
    covered = sum(r["rules"] > 0 for r in rows)
    validated = sum(r["validated"] > 0 for r in rows)
    unknown = sorted(set(by_tech) - set(CATALOG))
    return {
        "catalog_size": len(CATALOG), "covered": covered, "validated": validated,
        "coverage_pct": round(100 * covered / len(CATALOG), 1),
        "validated_pct": round(100 * validated / len(CATALOG), 1),
        "techniques": rows, "tactics": dict(tactics), "uncatalogued_techniques": unknown,
    }


def navigator_layer(report: dict[str, Any], name: str = "ANVIL coverage") -> dict[str, Any]:
    """Export an ATT&CK Navigator layer (v4.x schema subset)."""
    return {
        "name": name, "domain": "enterprise-attack",
        "versions": {"layer": "4.5", "navigator": "4.9"},
        "techniques": [
            {"techniqueID": r["technique"], "score": 2 if r["validated"] else 1,
             "comment": f"{r['rules']} rule(s), {r['validated']} validated"}
            for r in report["techniques"] if r["rules"]
        ],
        "gradient": {"colors": ["#ffe766", "#8ec843"], "minValue": 1, "maxValue": 2},
    }
