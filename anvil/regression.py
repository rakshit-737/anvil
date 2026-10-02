"""Replay SigmaHQ ``regression_data`` (real captured true-positive events).

Every SigmaHQ rule with status ``test``/``stable`` must ship an ``info.yml``
pointing at an EVTX capture of the behaviour plus the expected number of
matches. SigmaHQ's own CI checks those with Nextron's ``evtx-sigma-checker``.
ANVIL replays the same captures (the JSON rendering that sits next to each
``.evtx``) through its engine and logsource router, which gives a real,
externally-labelled true-positive corpus for ~460 rules.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import yaml

from .logsource import applies
from .runner import Library
from .telemetry import iter_json_file

_Loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)


@dataclass
class RegressionCase:
    """Outcome of replaying one SigmaHQ regression capture."""
    rule_id: str
    title: str
    sample: str
    expected: int | None
    events: int = 0
    routed: int = 0
    matched: int = 0
    exact: bool = False
    status: str = ""   # pass | fail | unsupported | unroutable | missing-rule | unreadable

    @property
    def passed(self) -> bool:
        """True if the match count equalled the expected count."""
        return self.status == "pass"

    def to_dict(self) -> dict[str, Any]:
        """Return the case as a plain dict."""
        return asdict(self)


def discover(sigma_root: str | Path) -> list[dict[str, Any]]:
    """Return one dict per regression test case found under ``regression_data``."""
    root = Path(sigma_root)
    out = []
    for info in sorted((root / "regression_data").rglob("info.yml")):
        try:
            doc = yaml.load(info.read_text(encoding="utf-8"), Loader=_Loader) or {}
        except (yaml.YAMLError, OSError):
            continue
        meta = (doc.get("rule_metadata") or [{}])[0]
        for t in doc.get("regression_tests_info") or []:
            if not isinstance(t, dict) or t.get("type") not in ("evtx", "json", "ndjson", "jsonl"):
                continue
            path = Path(str(t.get("path", "")))
            sample = info.parent / (path.stem + ".json")
            out.append({"rule_id": str(meta.get("id", "")), "title": str(meta.get("title", "")),
                        "sample": str(sample), "expected": (int(t["match_count"]) if t.get("match_count") is not None else None)})
    return out


def run_case(lib: Library, case: dict[str, Any],
             matcher: Callable[[str, dict[str, Any]], bool] | None = None,
             use_routing: bool = True) -> RegressionCase:
    """Replay one regression capture against the library.

    Args:
        lib: Compiled rule library.
        case: Case dict from ``discover()``.
        matcher: Optional alternative matcher ``(rule_id, event) -> bool``.
        use_routing: Apply logsource routing before matching.

    Returns:
        The RegressionCase.
    """
    rc = RegressionCase(case["rule_id"], case["title"], case["sample"], case["expected"])
    rid = rc.rule_id
    if rid in lib.unsupported:
        rc.status = "unsupported"
        return rc
    if rid not in lib.compiled:
        rc.status = "missing-rule"
        return rc
    try:
        events = list(iter_json_file(rc.sample))
    except (OSError, ValueError):
        rc.status = "unreadable"  # e.g. an AV product quarantined the sample file
        return rc
    rc.events = len(events)
    rt = lib.routes.get(rid)
    if use_routing and (rt is None or not rt.routable):
        rc.status = "unroutable"
        return rc
    cr = lib.compiled[rid]
    for ev in events:
        if use_routing and not applies(rt, ev):
            continue
        rc.routed += 1
        ok = matcher(rid, ev) if matcher else cr.matches(ev)
        rc.matched += bool(ok)
    # SigmaHQ semantics: fail if no match or fewer than expected; more is only a warning
    rc.status = "pass" if rc.matched > 0 and rc.matched >= (rc.expected or 1) else "fail"
    rc.exact = rc.expected is None or rc.matched == rc.expected
    return rc


def run_all(lib: Library, sigma_root: str | Path, **kw: Any) -> list[RegressionCase]:
    """Replay every regression capture under a SigmaHQ checkout."""
    return [run_case(lib, c, **kw) for c in discover(sigma_root)]
