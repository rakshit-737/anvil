"""Load rules (YAML) and telemetry (JSONL)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterator

import yaml

from .models import Rule

_Loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)


def load_rule(path: str | Path) -> Rule:
    p = Path(path)
    data = yaml.load(p.read_text(encoding="utf-8"), Loader=_Loader) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{p}: rule must be a mapping")
    return Rule.from_dict(data, str(p))


def load_rules(directory: str | Path) -> list[Rule]:
    d = Path(directory)
    files = sorted(list(d.rglob("*.yml")) + list(d.rglob("*.yaml")))
    return [load_rule(f) for f in files]


def iter_events(path: str | Path) -> Iterator[dict[str, Any]]:
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                yield json.loads(line)


def load_events(path: str | Path) -> list[dict[str, Any]]:
    return list(iter_events(path))
