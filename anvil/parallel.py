"""Multi-process scanning of large, sharded telemetry corpora.

Compiled rules are closures and cannot be pickled, so every worker builds its
own :class:`~anvil.runner.Library` from the rule directories once (about two
seconds for the full SigmaHQ corpus) and then scans whole files.
"""
from __future__ import annotations

import concurrent.futures as cf
import os
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .runner import Library, load_rule_dir, scan
from .telemetry import iter_path

_LIB: Library | None = None


def _init(rule_dirs: list[str], drop_ids: list[str]) -> None:
    global _LIB
    rules, _ = load_rule_dir(rule_dirs)
    drop = set(drop_ids)
    _LIB = Library.build([r for r in rules if r.id not in drop])


def _scan_file(path: str, keep_examples: int) -> dict[str, Any]:
    assert _LIB is not None
    examples: dict[str, list[dict[str, Any]]] = {}

    def on_hit(rid: str, ev: dict[str, Any]) -> None:
        bucket = examples.setdefault(rid, [])
        if len(bucket) < keep_examples:
            bucket.append({k: (v[:300] if isinstance(v, str) else v)
                           for k, v in ev.items() if not k.startswith("__")})

    res = scan(_LIB, iter_path(path), on_hit=on_hit if keep_examples else None)
    return {"path": path, "events": res.events, "evaluations": res.evaluations, "seconds": res.seconds,
            "hits": dict(res.hits), "by_key": {f"{c}|{e}": n for (c, e), n in res.by_key.items()},
            "examples": examples}


@dataclass
class CorpusScan:
    files: int = 0
    events: int = 0
    evaluations: int = 0
    cpu_seconds: float = 0.0
    wall_seconds: float = 0.0
    hits: Counter = field(default_factory=Counter)
    by_key: Counter = field(default_factory=Counter)
    per_file_hits: dict[str, dict[str, int]] = field(default_factory=dict)
    per_file_events: dict[str, int] = field(default_factory=dict)
    examples: dict[str, list[dict[str, Any]]] = field(default_factory=dict)


def scan_files(rule_dirs: Iterable[str | Path], files: Iterable[str | Path], workers: int | None = None,
               keep_examples: int = 0, drop_rule_ids: Iterable[str] = ()) -> CorpusScan:
    import time
    files = [str(f) for f in files]
    workers = workers or max(1, min(len(files), (os.cpu_count() or 2) - 1, 8))
    out = CorpusScan(files=len(files))
    t0 = time.perf_counter()
    dirs = [str(d) for d in rule_dirs]
    with cf.ProcessPoolExecutor(max_workers=workers, initializer=_init,
                                initargs=(dirs, list(drop_rule_ids))) as pool:
        # biggest files first keeps the pool busy until the end
        order = sorted(files, key=lambda f: -Path(f).stat().st_size)
        for r in pool.map(_scan_file, order, [keep_examples] * len(order)):
            out.events += r["events"]
            out.evaluations += r["evaluations"]
            out.cpu_seconds += r["seconds"]
            out.hits.update(r["hits"])
            out.by_key.update(r["by_key"])
            out.per_file_hits[r["path"]] = r["hits"]
            out.per_file_events[r["path"]] = r["events"]
            for rid, ex in r["examples"].items():
                bucket = out.examples.setdefault(rid, [])
                bucket.extend(ex[: max(0, keep_examples - len(bucket))])
    out.wall_seconds = time.perf_counter() - t0
    return out
