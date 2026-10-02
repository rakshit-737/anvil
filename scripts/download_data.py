#!/usr/bin/env python3
"""Download the public datasets ANVIL benchmarks against.

Every source is pinned (git commit or release tag) and every file is checked
against ``scripts/checksums.sha256``. Nothing here is executable content: the
sources are YAML rules, JSON/EVTX *log records* and the ATT&CK STIX bundle.

    python scripts/download_data.py all            # ~0.45 GB download
    python scripts/download_data.py sigma attack   # just some sources
    python scripts/download_data.py all --record   # (maintainers) refresh checksums

Data goes to $ANVIL_DATA (default: ./data, which is git-ignored).

Sources and licences
--------------------
sigma     SigmaHQ/sigma rules + regression_data           Detection Rule License 1.1
attack    MITRE ATT&CK Enterprise STIX 2.1 (v19.2)          ATT&CK Terms of Use (royalty-free)
otrf      OTRF Security-Datasets (Mordor) Windows host logs MIT          (~66 MB)
baseline  NextronSystems/evtx-baseline clean Windows EVTX   (repository README, public)
nixcloud  Linux + AWS attack telemetry (1.1):                                        (~780 MB)
          splunk/attack_data Sysmon-for-Linux, auditd and CloudTrail captures        Apache-2.0
          (Git LFS objects, pinned by the LFS sha256 in scripts/splunk_attack_data.tsv)
          OTRF Linux/AWS atomic datasets and the Log4Shell Linux Syslog captures     MIT

``all`` means sigma, attack, otrf and baseline (~0.45 GB download, ~4 GB on disk
after extraction and ingest). ``nixcloud`` (~0.78 GB) is opt-in and is meant to be
fetched by the CI benchmark job (.github/workflows/bench.yml), not on a laptop.

Files that local endpoint antivirus refuses to write (PermissionError) are skipped
and listed in ``<data>/blocked_locally.txt``; they are never processed locally. The
CI benchmark job downloads them fresh on a clean runner. Any other network or I/O
error fails the run.

Every file is verified before use: against the pinned sha256 in
scripts/checksums.sha256, or (OTRF files without a pin) against the git blob SHA-1
the pinned OTRF tree lists, or (Splunk LFS objects) against the LFS sha256 in the
manifest. An unverifiable file aborts the run unless ``--allow-unpinned`` is given.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import hashlib
import json
import os
import shutil
import sys
import tarfile
import time
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECKSUMS = ROOT / "scripts" / "checksums.sha256"

SIGMA_COMMIT = "07ec293a51695cb1131a2e05260247872b31e1e1"
ATTACK_COMMIT = "6cda5ad8462c79e14fbb872f4e09059b18e0cfc4"
ATTACK_VERSION = "19.2"
OTRF_COMMIT = "d9d40ef123d2c87d5d3df28c96bcab4f0faccc87"
BASELINE_TAG = "v0.8.5"
# Benign corpus: win10-client (71 MB), win11-client (133 MB) and win2022-ad (66 MB),
# the same clean installs SigmaHQ uses for its own "goodlog" CI job.
BASELINE_ASSETS = ["win10-client.tgz", "win11-client.tgz", "win2022-ad.tgz"]
# Compound (multi-technique) OTRF host datasets, used as a noisier attack corpus.
SPLUNK_ATTACK_DATA_COMMIT = "b4573ed3b6bf05473b01048dd36380dbd52288c0"
SPLUNK_MANIFEST = ROOT / "scripts" / "splunk_attack_data.tsv"
# OTRF non-Windows datasets (metadata + captures).
OTRF_NIXCLOUD = [
    "datasets/atomic/_metadata/SDLIN-201110074812.yaml",
    "datasets/atomic/_metadata/SDLIN-201110081941.yaml",
    "datasets/atomic/_metadata/SDAWS-200914011940.yaml",
    "datasets/atomic/linux/discovery/host/sh_arp_cache.zip",
    "datasets/atomic/linux/defense_evasion/host/sh_binary_padding_dd.zip",
    "datasets/atomic/aws/collection/ec2_proxy_s3_exfiltration.zip",
    "datasets/compound/_metadata/Log4Shell.yaml",
    "datasets/compound/Log4Shell/syslog_sysmon_log4shell_cve2021_44228_jndi_reference.zip",
    "datasets/compound/Log4Shell/syslog_auoms_auditd_log4shell_cve2021_44228_jndi_reference.zip",
]
OTRF_COMPOUND = [
    "datasets/compound/apt29/day1/apt29_evals_day1_manual.zip",
    "datasets/compound/apt29/day2/apt29_evals_day2_manual.zip",
]


def splunk_manifest() -> list[tuple[str, int, str]]:
    """(sha256, size, repo path) for every pinned splunk/attack_data LFS object."""
    out = []
    for line in SPLUNK_MANIFEST.read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#"):
            sha, size, path = line.split(chr(9))
            out.append((sha, int(size), path))
    return out


def splunk_url(path: str) -> str:
    return f"https://media.githubusercontent.com/media/splunk/attack_data/{SPLUNK_ATTACK_DATA_COMMIT}/{path}"


def data_dir() -> Path:
    return Path(os.environ.get("ANVIL_DATA", ROOT / "data")).resolve()


def load_checksums() -> dict[str, str]:
    out: dict[str, str] = {}
    if CHECKSUMS.exists():
        for line in CHECKSUMS.read_text().splitlines():
            if line.strip() and not line.startswith("#"):
                digest, name = line.split(maxsplit=1)
                out[name.strip()] = digest
    return out


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _download(url: str, dest: Path, attempts: int = 8) -> None:
    """Stream ``url`` to ``dest`` via a ``.part`` file, resuming with HTTP Range on retry."""
    print(f"  GET {url}")
    tmp = dest.with_suffix(dest.suffix + ".part")
    for attempt in range(1, attempts + 1):
        have = tmp.stat().st_size if tmp.exists() else 0
        headers = {"User-Agent": "anvil-dac-downloader"}
        if have:
            headers["Range"] = f"bytes={have}-"
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=120) as r:
                mode = "ab" if have and r.status == 206 else "wb"
                with open(tmp, mode) as fh:
                    shutil.copyfileobj(r, fh, 1 << 20)
            break
        except OSError as exc:  # connection resets are common on large GitHub downloads
            if attempt == attempts:
                raise
            print(f"  retry {attempt}/{attempts} ({dest.name}) after {exc}")
            time.sleep(2 * attempt)
    tmp.replace(dest)


def _github_token() -> str | None:
    """Opt-in token: only GITHUB_TOKEN / GH_TOKEN from the environment are used."""
    return os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or None


def git_blob_sha1(path: Path) -> str:
    """SHA-1 of ``path`` as a git blob (what the GitHub tree API lists)."""
    data = path.read_bytes()
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()  # noqa: S324 - git's own id


class Blocked(Exception):
    """A file local antivirus would not let us write; skipped, never processed."""


class Fetcher:
    def __init__(self, record: bool, force: bool, allow_unpinned: bool = False):
        self.record, self.force, self.allow_unpinned = record, force, allow_unpinned
        self.blocked: list[str] = []
        self.sums = load_checksums()
        self.dirty = False
        self.baseline_assets = list(BASELINE_ASSETS)

    def get(self, url: str, dest: Path, key: str, blob_sha1: str | None = None) -> Path:
        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            if self.force or not dest.exists():
                _download(url, dest)
            digest = sha256(dest)
        except PermissionError as exc:  # endpoint AV refused the write/read
            raise Blocked(f"{key}: {exc}") from exc
        expected = self.sums.get(key)
        if self.record:
            if expected is None:
                self.sums[key] = digest
                self.dirty = True
            elif expected != digest:
                raise SystemExit(f"--record refuses to overwrite a mismatching pin for {key}; "
                                 f"remove the line from {CHECKSUMS.name} by hand if upstream changed.")
        elif expected is None:
            if blob_sha1 and git_blob_sha1(dest) == blob_sha1:
                return dest
            if not self.allow_unpinned:
                raise SystemExit(f"no pinned checksum for {key} ({digest}); run with --record "
                                 f"(maintainers) or --allow-unpinned")
            print(f"  WARN no pinned checksum for {key} ({digest[:12]}...)")
        elif expected != digest:
            raise SystemExit(f"checksum mismatch for {key}: expected {expected}, got {digest}. "
                             f"Delete {dest} and retry, or re-run with --record if the upstream "
                             f"archive was legitimately regenerated.")
        return dest

    def save(self) -> None:
        if self.dirty:
            # merge with the file as it is now, so concurrent runs don't drop each other's keys
            self.sums = {**load_checksums(), **self.sums}
            lines = ["# sha256  source-key  (generated by scripts/download_data.py --record)"]
            lines += [f"{v}  {k}" for k, v in sorted(self.sums.items())]
            CHECKSUMS.write_text("\n".join(lines) + "\n")
            print(f"recorded {len(self.sums)} checksums in {CHECKSUMS.relative_to(ROOT)}")


def fetch_sigma(f: Fetcher, d: Path) -> None:
    print("[sigma] SigmaHQ rules + regression data @", SIGMA_COMMIT[:10])
    z = f.get(f"https://codeload.github.com/SigmaHQ/sigma/zip/{SIGMA_COMMIT}",
              d / "raw" / f"sigma-{SIGMA_COMMIT[:10]}.zip", f"sigma-{SIGMA_COMMIT}.zip")
    out = d / "sigma"
    if not (out / "rules").exists():
        with zipfile.ZipFile(z) as zf:
            prefix = f"sigma-{SIGMA_COMMIT}/"
            for m in zf.infolist():
                if m.is_dir() or not m.filename.startswith(prefix):
                    continue
                rel = m.filename[len(prefix):]
                target = (out / rel).resolve()
                if not target.is_relative_to(out.resolve()) or (m.external_attr >> 16) & 0o170000 == 0o120000:
                    raise SystemExit(f"unsafe zip member {m.filename!r}")
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(zf.read(m))
    print(f"  -> {out}")


def fetch_attack(f: Fetcher, d: Path) -> None:
    print(f"[attack] ATT&CK Enterprise STIX v{ATTACK_VERSION}")
    name = f"enterprise-attack-{ATTACK_VERSION}.json"
    f.get(f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/{ATTACK_COMMIT}/"
          f"enterprise-attack/{name}", d / "attack" / name, name)
    print(f"  -> {d / 'attack' / name}")


def _otrf_tree() -> list[dict]:
    url = f"https://api.github.com/repos/OTRF/Security-Datasets/git/trees/{OTRF_COMMIT}?recursive=1"
    headers = {"User-Agent": "anvil-dac-downloader"}
    if tok := _github_token():  # the anonymous API limit (60/h) is easy to hit
        headers["Authorization"] = f"Bearer {tok}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.load(r)["tree"]


def fetch_otrf(f: Fetcher, d: Path) -> None:
    print("[otrf] Security-Datasets (Mordor) Windows host datasets @", OTRF_COMMIT[:10])
    tree = _otrf_tree()
    blobs = {i["path"]: i["sha"] for i in tree if i["type"] == "blob"}
    raw = f"https://raw.githubusercontent.com/OTRF/Security-Datasets/{OTRF_COMMIT}/"
    wanted = [i["path"] for i in tree if i["type"] == "blob" and (
        (i["path"].startswith("datasets/atomic/windows/") and "/host/" in i["path"]
         and i["path"].endswith((".zip", ".tar.gz")))
        or i["path"].startswith("datasets/atomic/_metadata/SDWIN")
        or i["path"] in OTRF_COMPOUND)]
    blocked = []
    with cf.ThreadPoolExecutor(max_workers=6) as pool:
        futs = {pool.submit(f.get, raw + p, d / "otrf" / p.removeprefix("datasets/"), "otrf/" + p,
                            blobs.get(p)): p
                for p in sorted(wanted)}
        for fut in cf.as_completed(futs):
            try:
                fut.result()
            except Blocked as exc:
                # Endpoint AV sometimes quarantines attack *logs* (they contain tool names and
                # command lines). Skip and report; the CI benchmark job covers these files.
                blocked.append((futs[fut], str(exc)))
    for p, err in blocked:
        print(f"  SKIP {p}: blocked locally ({err[:80]}); computed in the CI bench job")
        f.blocked.append(p)
    print(f"  -> {len(wanted)} files under {d / 'otrf'}")


def fetch_baseline(f: Fetcher, d: Path) -> None:
    print("[baseline] evtx-baseline clean Windows installs", BASELINE_TAG)
    base = f"https://github.com/NextronSystems/evtx-baseline/releases/download/{BASELINE_TAG}/"
    for asset in f.baseline_assets:
        tgz = f.get(base + asset, d / "raw" / f"evtx-baseline-{asset}", f"evtx-baseline/{BASELINE_TAG}/{asset}")
        out = d / "evtx-baseline" / asset.removesuffix(".tgz")
        if not out.exists():
            out.mkdir(parents=True)
            with tarfile.open(tgz) as tf:
                members = [m for m in tf.getmembers() if m.isfile() and m.name.lower().endswith(".evtx")]
                for m in members:
                    src = tf.extractfile(m)
                    if src is None:
                        continue
                    (out / Path(m.name).name).write_bytes(src.read())
        print(f"  -> {out}")


def fetch_nixcloud(f: Fetcher, d: Path) -> None:
    print("[nixcloud] splunk/attack_data @", SPLUNK_ATTACK_DATA_COMMIT[:10], "+ OTRF Linux/AWS")
    out = d / "nixcloud"
    blobs = {i["path"]: i["sha"] for i in _otrf_tree() if i["type"] == "blob"}
    raw = f"https://raw.githubusercontent.com/OTRF/Security-Datasets/{OTRF_COMMIT}/"

    def lfs(url: str, dest: Path, sha: str) -> None:
        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            if not dest.exists() or f.force:
                _download(url, dest)
            got = sha256(dest)
        except PermissionError as exc:
            raise Blocked(str(exc)) from exc
        if got != sha:  # LFS objects are pinned by their own sha256
            raise SystemExit(f"checksum mismatch for {url}: {got}")

    jobs: list[tuple] = [(lfs, splunk_url(p), out / "splunk" / p, sha) for sha, _, p in splunk_manifest()]
    jobs += [(f.get, raw + p, d / "otrf" / p.removeprefix("datasets/"), "otrf/" + p, blobs.get(p))
             for p in OTRF_NIXCLOUD]
    n0 = len(f.blocked)
    with cf.ThreadPoolExecutor(max_workers=4) as pool:
        futs = {pool.submit(*j): j for j in jobs}
        for fut in cf.as_completed(futs):
            try:
                fut.result()
            except Blocked as exc:
                f.blocked.append(str(futs[fut][1]))
                print(f"  SKIP {futs[fut][2].name}: blocked locally ({str(exc)[:80]})")
    print(f"  -> {len(jobs)} files, {len(f.blocked) - n0} blocked locally")


DEFAULT_SOURCES = ["sigma", "attack", "otrf", "baseline"]  # "all"; nixcloud is opt-in
SOURCES = {"sigma": fetch_sigma, "attack": fetch_attack, "otrf": fetch_otrf, "baseline": fetch_baseline,
           "nixcloud": fetch_nixcloud}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("sources", nargs="+", choices=[*SOURCES, "all"])
    ap.add_argument("--record", action="store_true", help="write observed checksums to the manifest")
    ap.add_argument("--force", action="store_true", help="re-download even if present")
    ap.add_argument("--allow-unpinned", action="store_true",
                    help="accept files with no pinned or upstream checksum (prints a warning)")
    ap.add_argument("--baseline-assets", nargs="+", default=BASELINE_ASSETS, metavar="TGZ",
                    help="evtx-baseline release assets to fetch (default: %(default)s)")
    a = ap.parse_args(argv)
    d = data_dir()
    d.mkdir(parents=True, exist_ok=True)
    f = Fetcher(a.record, a.force, a.allow_unpinned)
    f.baseline_assets = a.baseline_assets
    names = a.sources
    if "all" in names:
        names = DEFAULT_SOURCES + [n for n in names if n not in (*DEFAULT_SOURCES, "all")]
    try:
        for n in names:
            SOURCES[n](f, d)
    finally:
        f.save()
        (d / "blocked_locally.txt").write_text("".join(p + "\n" for p in sorted(f.blocked)))
    print(f"done. ANVIL_DATA={d}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
