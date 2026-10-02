"""MITRE ATT&CK Enterprise catalog loaded from the official STIX 2.1 bundle.

Replaces the 16-technique bundled subset used by ANVIL 0.1 (which is still the
offline fallback). Besides names and tactics, the catalog keeps what a
detection engineer needs to judge coverage honestly:

* revoked / deprecated techniques (rules still tagged with them are stale)
* platforms (a Windows-only rule library should be measured against the
  techniques that apply to Windows, not the whole matrix)
* data components that ``detect`` each technique (log-source requirements)
"""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

TACTIC_ORDER = ["reconnaissance", "resource-development", "initial-access", "execution", "persistence",
                "privilege-escalation", "defense-evasion", "credential-access", "discovery",
                "lateral-movement", "collection", "command-and-control", "exfiltration", "impact"]


@dataclass
class Technique:
    """One ATT&CK technique or sub-technique parsed from the STIX bundle."""
    id: str
    name: str
    tactics: list[str]
    platforms: list[str]
    is_subtechnique: bool
    revoked: bool = False
    deprecated: bool = False
    revoked_by: str = ""
    data_components: list[str] = field(default_factory=list)

    @property
    def active(self) -> bool:
        """True unless the technique is revoked or deprecated."""
        return not (self.revoked or self.deprecated)

    @property
    def parent(self) -> str:
        """Parent technique ID (``T1059`` for ``T1059.001``)."""
        return self.id.split(".")[0]


@dataclass
class Catalog:
    """ATT&CK technique catalogue keyed by technique ID, with its release version."""
    version: str
    techniques: dict[str, Technique]

    def active(self, platform: str | None = None, include_sub: bool = True) -> dict[str, Technique]:
        """Return the active techniques.

        Args:
            platform: Keep only techniques for this platform (case-insensitive).
            include_sub: Include sub-techniques.

        Returns:
            Mapping of technique ID to Technique.
        """
        out = {}
        for tid, t in self.techniques.items():
            if not t.active or (not include_sub and t.is_subtechnique):
                continue
            if platform and platform.lower() not in {p.lower() for p in t.platforms}:
                continue
            out[tid] = t
        return out

    def resolve(self, tid: str) -> str | None:
        """Follow revocations to the current technique id, if any."""
        seen = set()
        t = self.techniques.get(tid)
        while t is not None and t.revoked and t.revoked_by and t.id not in seen:
            seen.add(t.id)
            t = self.techniques.get(t.revoked_by)
        return t.id if t is not None and t.active else None


def _ext_id(obj: dict[str, Any]) -> str:
    for ref in obj.get("external_references") or []:
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return str(ref["external_id"])
    return ""


def load_stix(path: str | Path) -> Catalog:
    """Load an ATT&CK enterprise STIX 2.x bundle into a Catalog.

    Args:
        path: Path to the STIX JSON bundle.

    Returns:
        The parsed technique catalogue.
    """
    bundle = json.loads(Path(path).read_text(encoding="utf-8"))
    objs = bundle.get("objects", [])
    by_stix: dict[str, dict[str, Any]] = {o["id"]: o for o in objs if "id" in o}
    version = ""
    for o in objs:
        if o.get("type") == "x-mitre-collection":
            version = str(o.get("x_mitre_version", ""))
    techs: dict[str, Technique] = {}
    stix_to_tid: dict[str, str] = {}
    for o in objs:
        if o.get("type") != "attack-pattern":
            continue
        tid = _ext_id(o)
        if not tid:
            continue
        stix_to_tid[o["id"]] = tid
        techs[tid] = Technique(
            id=tid, name=str(o.get("name", "")),
            tactics=[k["phase_name"] for k in o.get("kill_chain_phases") or []
                     if k.get("kill_chain_name") == "mitre-attack"],
            platforms=list(o.get("x_mitre_platforms") or []),
            is_subtechnique=bool(o.get("x_mitre_is_subtechnique")),
            revoked=bool(o.get("revoked")), deprecated=bool(o.get("x_mitre_deprecated")),
        )
    dcs: dict[str, list[str]] = defaultdict(list)
    for o in objs:
        if o.get("type") != "relationship":
            continue
        rel = o.get("relationship_type")
        src, dst = o.get("source_ref", ""), o.get("target_ref", "")
        if rel == "revoked-by" and src in stix_to_tid and dst in stix_to_tid:
            techs[stix_to_tid[src]].revoked_by = stix_to_tid[dst]
        elif rel == "detects" and dst in stix_to_tid and not o.get("revoked") \
                and not o.get("x_mitre_deprecated"):
            name = by_stix.get(src, {}).get("name", "")
            if name:
                dcs[stix_to_tid[dst]].append(name)
    for tid, names in dcs.items():
        techs[tid].data_components = sorted(set(names))
    return Catalog(version, techs)


def fallback_catalog() -> Catalog:
    """The small offline subset from ANVIL 0.1 (used when no STIX file is present)."""
    from .coverage import CATALOG
    return Catalog("bundled-subset", {
        tid: Technique(tid, name, [tactic], ["Windows"], "." in tid)
        for tid, (name, tactic) in CATALOG.items()})
