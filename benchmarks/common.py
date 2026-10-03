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


def dataset_pins() -> dict[str, str]:
    """Pinned dataset versions from scripts/download_data.py plus hashes of the checksum manifests."""
    import hashlib
    import importlib.util
    spec = importlib.util.spec_from_file_location("_anvil_download_data", ROOT / "scripts" / "download_data.py")
    if spec is None or spec.loader is None:
        return {}
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    pins = {"sigmahq": mod.SIGMA_COMMIT, "attack": f"{mod.ATTACK_VERSION} @ {mod.ATTACK_COMMIT}",
            "otrf_security_datasets": mod.OTRF_COMMIT, "evtx_baseline": mod.BASELINE_TAG,
            "splunk_attack_data": mod.SPLUNK_ATTACK_DATA_COMMIT}
    for name in ("checksums.sha256", "splunk_attack_data.tsv"):
        f = ROOT / "scripts" / name
        if f.exists():
            # hash with normalised line endings so a Windows checkout gives the same digest
            pins[f"sha256({name})"] = hashlib.sha256(f.read_bytes().replace(b"\r\n", b"\n")).hexdigest()
    return pins


def provenance() -> dict[str, Any]:
    """Git SHA, Python, key package versions, dataset pins and the CI run, written into every results file."""
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
    run = os.environ.get("GITHUB_RUN_ID", "")
    out = {"git_sha": sha, "python": platform.python_version(), "packages": pk, "datasets": dataset_pins(),
           "ci_run": run}
    if run and os.environ.get("GITHUB_REPOSITORY"):
        out["ci_run_url"] = f"https://github.com/{os.environ['GITHUB_REPOSITORY']}/actions/runs/{run}"
    return out


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
