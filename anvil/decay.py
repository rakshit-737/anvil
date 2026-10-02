"""Decay monitor: catch detections that silently stop working.

Two complementary checks:

* **Static schema analysis** (no attack data needed). For every rule, look up
  which fields its log source actually carries in *current* telemetry and
  evaluate the condition symbolically: a selection is satisfiable only if the
  fields it needs exist. Verdicts: ``ok``, ``degraded`` (some referenced fields
  missing but a detection path survives, or an exclusion filter went blind -
  expect more FPs), ``broken`` (no path can fire any more) and
  ``source-missing`` (the log source itself disappeared).
* **Regression vs. baseline** (needs TP evidence). Re-run the rule on its
  stored true-positive samples and compare recall/FP with the saved baseline.

``SCHEMA_CHANGES`` holds realistic telemetry changes used by the benchmark to
measure how many decays each check catches.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Iterable
from typing import Any

from .engine import parse_condition, rule_fields
from .harness import RuleResult
from .logsource import SYSMON, event_key, route
from .models import Rule

META_FIELDS = {"EventID", "Channel", "Provider_Name", "Computer", "TimeCreated"}


def observed_fields(events: Iterable[dict[str, Any]]) -> set[str]:
    out: set[str] = set()

    def walk(d: dict[str, Any], prefix: str = "") -> None:
        for k, v in d.items():
            if k.startswith("__"):
                continue
            out.add(prefix + k)
            if isinstance(v, dict):
                walk(v, prefix + k + ".")

    for e in events:
        walk(e)
    return out


def schema_drift(rules: list[Rule], telemetry: list[dict[str, Any]]) -> dict[str, list[str]]:
    """Rules whose referenced fields no longer appear anywhere in current telemetry (0.1 API)."""
    seen = observed_fields(telemetry)
    drift = {}
    for r in rules:
        missing = sorted(f for f in rule_fields(r) if f not in seen)
        if missing:
            drift[r.id] = missing
    return drift


class FieldInventory:
    """Which fields occur per (channel, EventID) in a telemetry stream."""

    def __init__(self) -> None:
        self.by_key: dict[tuple[str, int], set[str]] = defaultdict(set)

    def add(self, ev: dict[str, Any]) -> None:
        self.by_key[event_key(ev)].update(k for k in ev if not k.startswith("__"))

    @classmethod
    def from_events(cls, events: Iterable[dict[str, Any]]) -> FieldInventory:
        inv = cls()
        for e in events:
            inv.add(e)
        return inv

    def fields_for(self, rule: Rule) -> set[str] | None:
        """Union of fields over the keys the rule's log source routes to; None if absent."""
        rt = route(rule.logsource)
        found: set[str] = set()
        hit = False
        for (chan, eid), fields in self.by_key.items():
            for c, ids in rt.channels:
                if (c == "*" or c == chan) and (not ids or eid in ids):
                    found |= fields
                    hit = True
        return found if hit else None


def _sel_fields_ok(sel: Any, present: set[str]) -> bool:
    if isinstance(sel, dict):
        for k, v in sel.items():
            if k is None or str(k).startswith("|"):
                continue
            name, *mods = str(k).split("|")
            if name in present or name in META_FIELDS:
                continue
            vals = v if isinstance(v, list) else [v]
            if ("exists" in mods and vals and not vals[0]) or any(x is None for x in vals):
                continue  # "field must be absent" is still satisfiable
            return False
        return True
    if isinstance(sel, list):
        if all(isinstance(s, dict) for s in sel):
            return any(_sel_fields_ok(s, present) for s in sel)
        return True  # keywords search all fields
    return True


def _satisfiable(node, sels: dict[str, Any], present: set[str], blind: list[str]) -> bool:
    op = node[0]
    if op == "sel":
        return _sel_fields_ok(sels[node[1]], present)
    if op == "not":
        inner = node[1]
        names = [inner[1]] if inner[0] == "sel" else inner[1] if inner[0] in ("any", "all") else []
        for n in names:
            if not _sel_fields_ok(sels[n], present):
                blind.append(n)  # an exclusion filter can no longer exclude anything
        return True
    if op == "and":
        return _satisfiable(node[1], sels, present, blind) and _satisfiable(node[2], sels, present, blind)
    if op == "or":
        a = _satisfiable(node[1], sels, present, blind)
        b = _satisfiable(node[2], sels, present, blind)
        return a or b
    oks = [_sel_fields_ok(sels[n], present) for n in node[1]]
    return any(oks) if op == "any" else all(oks)


def analyse(rule: Rule, inventory: FieldInventory) -> dict[str, Any]:
    present = inventory.fields_for(rule)
    if present is None:
        return {"status": "source-missing", "missing": [], "blind_filters": []}
    referenced = rule_fields(rule) - META_FIELDS
    missing = sorted(f for f in referenced if f not in present)
    blind: list[str] = []
    try:
        conds = rule.detection.get("condition")
        conds = conds if isinstance(conds, list) else [conds]
        sat = any(_satisfiable(parse_condition(str(c), list(rule.selections)), rule.selections, present, blind)
                  for c in conds)
    except ValueError:
        sat = True
    status = "broken" if not sat else "degraded" if (missing or blind) else "ok"
    return {"status": status, "missing": missing, "blind_filters": sorted(set(blind))}


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


# ----------------------------------------------------------------- realistic schema changes

ECS = {"Image": "process.executable", "CommandLine": "process.command_line",
       "ParentImage": "process.parent.executable", "ParentCommandLine": "process.parent.command_line",
       "OriginalFileName": "process.pe.original_file_name", "User": "user.name",
       "TargetObject": "registry.path", "Details": "registry.data.strings", "TargetFilename": "file.path",
       "ImageLoaded": "dll.path", "DestinationIp": "destination.ip", "DestinationPort": "destination.port",
       "QueryName": "dns.question.name", "PipeName": "file.name", "ScriptBlockText": "powershell.file.script_block_text",
       "Hashes": "process.hash", "IntegrityLevel": "winlog.event_data.IntegrityLevel",
       "TargetImage": "winlog.event_data.TargetImage", "SourceImage": "winlog.event_data.SourceImage",
       "GrantedAccess": "winlog.event_data.GrantedAccess", "CallTrace": "winlog.event_data.CallTrace"}

# Fields Security 4688 carries (with command-line auditing on) after aliasing.
SEC_4688 = {"NewProcessName", "Image", "CommandLine", "ParentProcessName", "ParentImage", "SubjectUserName",
            "SubjectDomainName", "SubjectUserSid", "SubjectLogonId", "NewProcessId", "ProcessId",
            "TokenElevationType", "MandatoryLabel", "TargetUserName", "TargetDomainName"}


def _ecs(ev: dict[str, Any]) -> dict[str, Any] | None:
    """A pipeline migration: Sysmon fields renamed to Elastic Common Schema names."""
    return {ECS.get(k, k): v for k, v in ev.items() if not k.startswith("__")}


def _sysmon_to_4688(ev: dict[str, Any], keep_cmdline: bool = True,
                    fleet_wide: bool = True) -> dict[str, Any] | None:
    """Sysmon decommissioned: process creation now only from Security 4688; other Sysmon events vanish.

    With ``keep_cmdline=False`` command-line auditing is off: CommandLine disappears from the
    converted events and, when ``fleet_wide``, from the hosts' native Security 4688 events too.
    """
    chan, eid = event_key(ev)
    if chan != SYSMON:
        out = {k: v for k, v in ev.items() if not k.startswith("__")}
        if not keep_cmdline and fleet_wide and chan == "security" and eid == 4688:
            out.pop("CommandLine", None)
        return out
    if eid != 1:
        return None
    out = {"Channel": "Security", "EventID": 4688, "Provider_Name": "Microsoft-Windows-Security-Auditing",
           "Computer": ev.get("Computer"), "NewProcessName": ev.get("Image"), "Image": ev.get("Image"),
           "ParentProcessName": ev.get("ParentImage"), "ParentImage": ev.get("ParentImage"),
           "SubjectUserName": ev.get("User"), "NewProcessId": ev.get("ProcessId")}
    if keep_cmdline and ev.get("CommandLine") is not None:
        out["CommandLine"] = ev["CommandLine"]
    return {k: v for k, v in out.items() if v is not None and k in SEC_4688 | META_FIELDS}


def _drop_field(name: str) -> Callable[[dict[str, Any]], dict[str, Any] | None]:
    def f(ev: dict[str, Any]) -> dict[str, Any] | None:
        return {k: v for k, v in ev.items() if k != name and not k.startswith("__")}
    return f


SCHEMA_CHANGES: dict[str, tuple[str, Callable[[dict[str, Any]], dict[str, Any] | None]]] = {
    "ecs_rename": ("SIEM pipeline migrated to ECS field names (Image -> process.executable ...)", _ecs),
    "sysmon_to_4688": ("Sysmon removed; process creation only from Security 4688 (cmdline auditing on)",
                       _sysmon_to_4688),
    "4688_no_cmdline": ("Sysmon removed and 4688 command-line auditing off on every host",
                        lambda e: _sysmon_to_4688(e, keep_cmdline=False)),
    "4688_no_cmdline_mixed": ("As above, but hosts that already logged 4688 keep CommandLine "
                              "(mixed pre/post-change inventory window)",
                              lambda e: _sysmon_to_4688(e, keep_cmdline=False, fleet_wide=False)),
    "no_commandline": ("Collector drops CommandLine (size limits / privacy filter)", _drop_field("CommandLine")),
    "no_hashes": ("Sysmon config without file hashing", _drop_field("Hashes")),
}


def apply_change(events: Iterable[dict[str, Any]], name: str) -> list[dict[str, Any]]:
    fn = SCHEMA_CHANGES[name][1]
    out = []
    for e in events:
        t = fn(e)
        if t is not None:
            out.append(t)
    return out
