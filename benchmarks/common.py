"""Shared paths/helpers for the benchmark suite (see benchmarks/bench.py)."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"


def data_dir() -> Path:
    return Path(os.environ.get("ANVIL_DATA", ROOT / "data")).resolve()


def sigma_root() -> Path:
    return data_dir() / "sigma"


def sigma_rule_dirs(windows_only: bool = False) -> list[Path]:
    """Detection rule folders of the SigmaHQ repo (not deprecated/unsupported/placeholder)."""
    base = sigma_root()
    dirs = [base / "rules", base / "rules-emerging-threats", base / "rules-threat-hunting"]
    if windows_only:
        dirs = [base / "rules" / "windows", base / "rules-emerging-threats", base / "rules-threat-hunting"]
    return [d for d in dirs if d.exists()]


def benign_shards() -> list[Path]:
    return sorted((data_dir() / "corpus").glob("benign-*/*.jsonl.gz"))


def provenance() -> dict[str, Any]:
    """Git SHA, Python and key package versions, written into every results file."""
    import importlib.metadata as md
    import platform
    import subprocess
    try:
        sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True,
                             timeout=10).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        sha = ""
    pk = {}
    for name in ("pySigma", "pySigma-backend-sqlite", "pySigma-backend-kusto", "pysigma-backend-opensearch",
                 "scikit-learn", "numpy", "pyahocorasick", "evtx"):
        try:
            pk[name] = md.version(name)
        except md.PackageNotFoundError:
            pass
    return {"git_sha": sha, "python": platform.python_version(), "packages": pk,
            "ci_run": os.environ.get("GITHUB_RUN_ID", "")}


def save(name: str, obj: Any) -> Path:
    RESULTS.mkdir(parents=True, exist_ok=True)
    if isinstance(obj, dict):
        obj = {**obj, "provenance": provenance()}
    p = RESULTS / name
    text = json.dumps(obj, indent=1, default=str)
    if len(text) > 400_000:  # keep committed result files well under 1 MB
        text = json.dumps(obj, separators=(",", ":"), default=str)
    p.write_text(text + "\n", encoding="utf-8")
    return p


def load(name: str) -> Any:
    return json.loads((RESULTS / name).read_text(encoding="utf-8"))
