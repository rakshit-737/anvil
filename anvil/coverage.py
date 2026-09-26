"""ATT&CK coverage reporting.

``coverage(rules, passing_ids, catalog)`` maps rule tags onto an ATT&CK
catalog. A technique is *claimed* when any active rule is tagged with it and
*validated* when at least one of those rules also passed ANVIL's tests
(e.g. SigmaHQ regression replay + benign FP gate). Sub-technique tags roll up
to their parent in the ``parent_*`` figures, the way ATT&CK Navigator does.

With no catalog argument the small bundled subset below is used, which keeps
the tool usable offline; pass ``attack.load_stix(...)`` for the full matrix.
"""
from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING, Any

from .models import Rule

if TYPE_CHECKING:
    from .attack import Catalog

# Minimal offline catalog (subset of ATT&CK Enterprise), used when no STIX bundle is given.
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


def coverage(rules: list[Rule], passing_ids: set[str] | None = None,
             catalog: "Catalog | None" = None, platform: str | None = None) -> dict[str, Any]:
    """Map techniques -> rules. If passing_ids is given, only those rules count as 'validated'."""
    if catalog is None:
        from .attack import fallback_catalog
        catalog = fallback_catalog()
    active = catalog.active(platform)
    by_tech: dict[str, list[str]] = defaultdict(list)
    stale: dict[str, list[str]] = defaultdict(list)
    for r in rules:
        if r.status == "deprecated":
            continue
        for t in r.techniques:
            by_tech[t].append(r.id)
            tech = catalog.techniques.get(t)
            if catalog.version != "bundled-subset" and (tech is None or not tech.active):
                stale[r.id].append(t)
    rows = []
    for tid, t in sorted(active.items(), key=lambda kv: (_tactic_rank(kv[1].tactics), kv[0])):
        ids = by_tech.get(tid, [])
        validated = [i for i in ids if passing_ids is None or i in passing_ids]
        rows.append({"technique": tid, "name": t.name, "tactic": t.tactics[0] if t.tactics else "",
                     "tactics": t.tactics, "rules": len(ids), "validated": len(validated)})
    tactics: dict[str, dict[str, int]] = defaultdict(lambda: {"total": 0, "covered": 0, "validated": 0})
    for row in rows:
        for tac in row["tactics"] or [""]:
            s = tactics[tac]
            s["total"] += 1
            s["covered"] += row["rules"] > 0
            s["validated"] += row["validated"] > 0
    n = len(rows) or 1
    covered = sum(r["rules"] > 0 for r in rows)
    validated = sum(r["validated"] > 0 for r in rows)
    # parent-technique roll-up (a rule on T1059.001 covers T1059)
    parents = {tid for tid, t in active.items() if not t.is_subtechnique}
    par_cov = {tid.split(".")[0] for r in rows if r["rules"] for tid in [r["technique"]]}
    par_val = {tid.split(".")[0] for r in rows if r["validated"] for tid in [r["technique"]]}
    return {
        "catalog": catalog.version, "platform": platform or "all",
        "catalog_size": len(rows), "covered": covered, "validated": validated,
        "coverage_pct": round(100 * covered / n, 1),
        "validated_pct": round(100 * validated / n, 1),
        "parent_total": len(parents), "parent_covered": len(par_cov & parents),
        "parent_validated": len(par_val & parents),
        "techniques": rows,
        "tactics": {k: tactics[k] for k in sorted(tactics, key=lambda x: _tactic_rank([x]))},
        "uncatalogued_techniques": sorted(set(by_tech) - set(active)),
        "stale_tags": dict(stale),
    }


def _tactic_rank(tactics: list[str]) -> int:
    from .attack import TACTIC_ORDER
    ranks = [TACTIC_ORDER.index(t) for t in tactics if t in TACTIC_ORDER]
    return min(ranks) if ranks else len(TACTIC_ORDER)


def navigator_layer(report: dict[str, Any], name: str = "ANVIL coverage") -> dict[str, Any]:
    """Export an ATT&CK Navigator layer (v4.5 schema subset)."""
    return {
        "name": name, "domain": "enterprise-attack",
        "versions": {"layer": "4.5", "navigator": "5.1"},
        "description": f"claimed={report['covered']} validated={report['validated']} "
                       f"of {report['catalog_size']} techniques ({report.get('catalog', '')})",
        "techniques": [
            {"techniqueID": r["technique"], "score": 2 if r["validated"] else 1,
             "comment": f"{r['rules']} rule(s), {r['validated']} validated"}
            for r in report["techniques"] if r["rules"]
        ],
        "gradient": {"colors": ["#ffe766", "#8ec843"], "minValue": 1, "maxValue": 2},
        "legendItems": [{"label": "claimed (tagged only)", "color": "#ffe766"},
                        {"label": "validated (tested)", "color": "#8ec843"}],
    }
