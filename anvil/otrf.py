"""OTRF Security-Datasets (Mordor) catalog: emulated-attack telemetry with labels.

Each atomic dataset has a metadata YAML (``_metadata/SDWIN-*.yaml``) with a
description, ATT&CK mappings and the attacker's console transcript
(``adversary_view``), plus a zipped JSON-lines capture of the host logs
recorded while the technique was emulated in a lab. ANVIL uses them as:

* emulated true-positive telemetry at the *technique* level (did any rule
  tagged with the emulated technique fire on the capture?)
* CTI-like input for the drafter (description + adversary view -> rule)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

import yaml

from .telemetry import iter_zip_json

_Loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)


@dataclass
class Dataset:
    id: str
    title: str
    description: str
    techniques: list[str]
    host_files: list[Path]
    adversary_view: str = ""
    tags: list[str] = field(default_factory=list)

    @property
    def available(self) -> bool:
        return any(p.exists() for p in self.host_files)

    def events(self) -> Iterator[dict[str, Any]]:
        for p in self.host_files:
            if p.exists():
                try:
                    yield from iter_zip_json(p)
                except OSError:  # AV-quarantined sample
                    continue


def _techniques(meta: dict[str, Any]) -> list[str]:
    out = []
    for m in meta.get("attack_mappings") or []:
        t = str(m.get("technique") or "").strip()
        if not t:
            continue
        sub = m.get("sub-technique")
        out.append(f"{t}.{int(sub):03d}" if sub not in (None, "", "null") and str(sub).isdigit() else t)
    return sorted(set(out))


def load_catalog(otrf_root: str | Path) -> list[Dataset]:
    """Load atomic Windows datasets from a download produced by ``scripts/download_data.py otrf``."""
    root = Path(otrf_root)
    out = []
    for f in sorted((root / "atomic" / "_metadata").glob("SDWIN-*.yaml")):
        try:
            meta = yaml.load(f.read_text(encoding="utf-8"), Loader=_Loader) or {}
        except (yaml.YAMLError, OSError):
            continue
        hosts = []
        for fl in meta.get("files") or []:
            if str(fl.get("type", "")).lower() != "host":
                continue
            link = str(fl.get("link", ""))
            if "/datasets/" in link:
                hosts.append(root / link.split("/datasets/", 1)[1])
        if not hosts:
            continue
        sim = meta.get("simulation") or {}
        out.append(Dataset(
            id=str(meta.get("id", f.stem)), title=str(meta.get("title", "")),
            description=str(meta.get("description", "")), techniques=_techniques(meta),
            host_files=hosts, adversary_view=str(sim.get("adversary_view") or ""),
            tags=[str(t) for t in meta.get("tags") or []]))
    return out
