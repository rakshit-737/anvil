"""Typed rule models (Sigma-like subset)."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

LEVELS = ("informational", "low", "medium", "high", "critical")
STATUSES = ("experimental", "test", "stable", "deprecated", "unsupported")
NON_SELECTION_KEYS = {"condition", "timeframe"}
ATTACK_TAG = re.compile(r"^attack\.t\d{4}(\.\d{3})?$")


@dataclass
class LogSource:
    product: str = ""
    category: str = ""
    service: str = ""


@dataclass
class RuleTests:
    true_positives: list[dict[str, Any]] = field(default_factory=list)
    true_negatives: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class Rule:
    id: str
    title: str
    description: str
    status: str
    level: str
    logsource: LogSource
    detection: dict[str, Any]
    tags: list[str] = field(default_factory=list)
    falsepositives: list[str] = field(default_factory=list)
    author: str = ""
    version: int = 1
    references: list[str] = field(default_factory=list)
    tests: RuleTests = field(default_factory=RuleTests)
    path: str = ""
    date: str = ""
    modified: str = ""
    regression_tests_path: str = ""
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @property
    def condition(self) -> str:
        c = self.detection.get("condition", "")
        return " or ".join(f"({x})" for x in c) if isinstance(c, list) else str(c)

    @property
    def selections(self) -> dict[str, Any]:
        return {k: v for k, v in self.detection.items() if k not in NON_SELECTION_KEYS}

    @property
    def techniques(self) -> list[str]:
        return sorted({t.split(".", 1)[1].upper() for t in self.tags if ATTACK_TAG.match(t)})

    @property
    def tactics(self) -> list[str]:
        return sorted({t.split(".", 1)[1] for t in self.tags
                       if t.startswith("attack.") and not re.match(r"^attack\.[tgs]\d{4}", t)})

    @classmethod
    def from_dict(cls, d: dict[str, Any], path: str = "") -> Rule:
        ls = d.get("logsource") or {}
        t = d.get("tests") or {}
        return cls(
            id=str(d.get("id", "")),
            title=str(d.get("title", "")),
            description=str(d.get("description", "")),
            status=str(d.get("status", "")),
            level=str(d.get("level", "")),
            logsource=LogSource(**{k: str(ls.get(k, "")) for k in ("product", "category", "service")}),
            detection=dict(d.get("detection") or {}),
            tags=[str(x).lower() for x in d.get("tags") or []],
            falsepositives=list(d.get("falsepositives") or []),
            author=str(d.get("author", "")),
            version=int(d.get("version", 1) or 1),
            references=list(d.get("references") or []),
            tests=RuleTests(list(t.get("true_positives") or []), list(t.get("true_negatives") or [])),
            path=path,
            date=str(d.get("date", "") or ""),
            modified=str(d.get("modified", "") or ""),
            regression_tests_path=str(d.get("regression_tests_path", "") or ""),
            raw=d,
        )
