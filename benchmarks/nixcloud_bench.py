"""Linux and AWS CloudTrail stage: SigmaHQ Linux/AWS rules on public attack captures.

Inputs (``python scripts/download_data.py nixcloud``, normally in the CI bench job):

* splunk/attack_data captures (Sysmon for Linux, auditd, CloudTrail), one dataset
  folder per emulation, labelled by its ATT&CK folder name (``T1053.003/...``);
* OTRF Linux / AWS atomic datasets and the Log4Shell Syslog captures, labelled by
  their metadata YAML;
* optionally ``$ANVIL_DATA/linux-live/{benign,emulation}`` recorded on the CI
  runner itself (auditd + Sysmon for Linux; benign commands only).

A dataset counts as *technique detected* when a Linux/AWS rule tagged with the
same technique, or its parent technique (never a sibling sub-technique), fires.
"""
from __future__ import annotations

import math
import re
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from anvil.runner import Library, load_rule_dir
from anvil.telemetry import iter_path

T_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def wilson(k: int, n: int, z: float = 1.96) -> list[float]:
    """Wilson score 95% interval for k successes out of n."""
    if not n:
        return [0.0, 0.0]
    p = k / n
    den = 1 + z * z / n
    c = (p + z * z / (2 * n)) / den
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return [round(max(0.0, c - h), 4), round(min(1.0, c + h), 4)]


def strict_match(rule_techs: set[str], ds_techs: list[str]) -> bool:
    """Exact technique, or the rule carries the dataset technique's parent."""
    for t in ds_techs:
        t = t.upper()
        if t in rule_techs or t.split(".")[0] in rule_techs:
            return True
    return False


def _datasets(data: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    sp = data / "nixcloud" / "splunk" / "datasets" / "attack_techniques"
    groups: dict[Path, list[Path]] = defaultdict(list)
    for f in sorted(sp.rglob("*")):
        if f.is_file() and not f.name.endswith(".part") and f.suffix.lower() in (".log", ".json", ".gz"):
            groups[f.parent].append(f)
    for d, files in groups.items():
        rel = d.relative_to(sp).as_posix()
        out.append({"id": "splunk:" + rel, "source": "splunk/attack_data",
                    "techniques": [rel.split("/")[0].upper()], "files": files})
    otrf = data / "otrf"
    meta = {}
    for m in list((otrf / "atomic" / "_metadata").glob("SD[LA]*.yaml")) + \
            list((otrf / "compound" / "_metadata").glob("Log4Shell.yaml")):
        text = m.read_text(encoding="utf-8", errors="replace")
        meta[m.stem] = sorted(set(T_ID.findall(text)))
    for f in sorted(list((otrf / "atomic" / "linux").rglob("*.zip")) + list((otrf / "atomic" / "aws").rglob("*.zip"))
                    + list((otrf / "compound" / "Log4Shell").rglob("*.zip"))):
        techs = sorted({t for v in meta.values() for t in v}) if "Log4Shell" in str(f) else []
        for k, v in meta.items():
            if k.startswith(("SDLIN", "SDAWS")) and v and _meta_names_file(otrf, k, f):
                techs = v
        out.append({"id": "otrf:" + f.relative_to(otrf).as_posix(), "source": "OTRF", "techniques": techs,
                    "files": [f]})
    live = data / "linux-live"
    for kind in ("emulation",):
        files = sorted((live / kind).glob("*")) if (live / kind).exists() else []
        if files:
            out.append({"id": f"live:{kind}", "source": "CI runner (benign commands)", "techniques": [],
                        "files": files})
    return out


def _meta_names_file(otrf: Path, key: str, f: Path) -> bool:
    p = otrf / "atomic" / "_metadata" / f"{key}.yaml"
    try:
        return f.name in p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False


def _channel_kind(ch: Counter) -> str:
    if not ch:
        return "none"
    top = ch.most_common(1)[0][0]
    return {"linux-sysmon/operational": "sysmon-linux", "linux-auditd": "auditd",
            "aws-cloudtrail": "cloudtrail"}.get(top, top or "unknown")


def stage_nixcloud(data: Path, rule_dirs: list[str]) -> dict[str, Any]:
    """Scan every Linux/AWS capture with the full SigmaHQ library and label the hits."""
    t0 = time.perf_counter()
    rules, _ = load_rule_dir(rule_dirs)
    lib = Library.build(rules)
    nix = {r.id for r in rules if r.logsource.product.lower() in ("linux", "aws") and r.status != "deprecated"}
    routed = sorted(rid for rid in nix if rid in lib.compiled and lib.routes[rid].routable)
    unrouted = Counter(lib.unroutable.get(rid, lib.unsupported.get(rid, "?")).split(" '")[0] for rid in nix
                       if rid not in routed)
    rows = []
    for ds in _datasets(data):
        ch: Counter = Counter()
        hits: Counter = Counter()
        n = 0
        for f in ds["files"]:
            for ev in iter_path(f):
                n += 1
                ch[str(ev.get("Channel", "")).lower()] += 1
                for rid in lib.match_event(ev):
                    hits[rid] += 1
        fired = [rid for rid in hits if rid in nix]
        tech = [rid for rid in fired if ds["techniques"] and strict_match(set(lib.rules[rid].techniques),
                                                                            ds["techniques"])]
        rows.append({"id": ds["id"], "source": ds["source"], "kind": _channel_kind(ch), "events": n,
                     "techniques": ds["techniques"], "rules_fired": len(fired),
                     "alerts": sum(hits[r] for r in fired), "any_alert": bool(fired),
                     "technique_detected": bool(tech),
                     "technique_rules": sorted(lib.rules[r].title for r in tech)[:6],
                     "top_rules": [lib.rules[r].title for r, _ in Counter({r: hits[r] for r in fired})
                                   .most_common(5)]})
    labelled = [r for r in rows if r["events"] and r["techniques"]]
    by_kind: dict[str, Any] = {}
    for k in sorted({r["kind"] for r in labelled}):
        sub = [r for r in labelled if r["kind"] == k]
        td = sum(r["technique_detected"] for r in sub)
        aa = sum(r["any_alert"] for r in sub)
        by_kind[k] = {"datasets": len(sub), "events": sum(r["events"] for r in sub),
                      "technique_detected": td, "technique_detected_ci95": wilson(td, len(sub)),
                      "any_alert": aa, "any_alert_ci95": wilson(aa, len(sub)),
                      "median_alerts": sorted(r["alerts"] for r in sub)[len(sub) // 2]}
    td = sum(r["technique_detected"] for r in labelled)
    aa = sum(r["any_alert"] for r in labelled)
    return {
        "rules": {"linux_aws": len(nix), "routed": len(routed), "unrouted_reasons": dict(unrouted.most_common())},
        "datasets": len(rows), "labelled": len(labelled),
        "zero_event_datasets": [r["id"] for r in rows if not r["events"]],
        "technique_detected": td, "technique_detected_ci95": wilson(td, len(labelled)),
        "any_alert": aa, "any_alert_ci95": wilson(aa, len(labelled)),
        "by_kind": by_kind, "rows": rows, "seconds": round(time.perf_counter() - t0, 1),
    }


def stage_linux_benign(data: Path, rule_dirs: list[str]) -> dict[str, Any] | None:
    """Alert volume of SigmaHQ Linux rules on benign telemetry recorded on the CI runner."""
    live = data / "linux-live" / "benign"
    if not live.exists():
        return None
    rules, _ = load_rule_dir(rule_dirs)
    lib = Library.build(rules)
    meta = {}
    mf = live / "window.txt"
    if mf.exists():
        for line in mf.read_text().splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                meta[k.strip()] = v.strip()
    hours = float(meta.get("seconds", "0") or 0) / 3600 or None
    hits: Counter = Counter()
    ch: Counter = Counter()
    n = 0
    for f in sorted(live.glob("*.log")):
        for ev in iter_path(f):
            n += 1
            ch[str(ev.get("Channel", "")).lower()] += 1
            for rid in lib.match_event(ev):
                if lib.rules[rid].logsource.product.lower() == "linux":
                    hits[rid] += 1
    # A sample shorter than an hour cannot support a per-day projection: omit it.
    per_day = {rid: c / hours * 24 for rid, c in hits.items()} if hours and hours >= 1 else None
    return {"events": n, "channels": dict(ch), "window_hours": round(hours, 3) if hours else None,
            "workload": meta.get("workload", ""),
            "rules_fired": len(hits), "alerts": sum(hits.values()),
            "over_budget_20_per_day": sum(v > 20 for v in per_day.values()) if per_day is not None else None,
            "fired": [{"title": lib.rules[r].title, "level": lib.rules[r].level, "hits": c,
                       "alerts_per_day_projected": round(per_day.get(r, 0), 1) if per_day is not None else None} for r, c in hits.most_common(40)]}
