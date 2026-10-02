"""Real-telemetry loaders and normalisers.

Every source is flattened to the same event shape Sigma rules expect::

    {"EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational",
     "Provider_Name": "...", "Computer": "...", "TimeCreated": "...",
     "Image": "...", "CommandLine": "...", ...}   # EventData / UserData fields

Supported inputs

* EVTX-as-JSON (the ``Event.System`` / ``Event.EventData`` layout produced by
  ``evtx_dump`` / pyevtx-rs, used by SigmaHQ ``regression_data``) - single,
  concatenated or NDJSON objects
* OTRF Security-Datasets (Mordor) JSON lines, flat nxlog/winlogbeat-style keys
* raw ``.evtx`` files (pyevtx-rs ``evtx`` if installed, else ``python-evtx``)
* ANVIL's own normalised JSONL (optionally ``.gz``)
"""
from __future__ import annotations

import gzip
import io
import json
import tarfile
import zipfile
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

from .logsource import add_aliases
from .nixcloud import from_syslog_wrapper, is_cloudtrail, iter_text_lines, normalise_cloudtrail

Event = dict[str, Any]

# OTRF/nxlog envelope keys that are collector metadata, not Windows event fields.
# ``Message`` is the rendered text of the whole event; keeping it would let
# keyword rules match on text that no Sigma backend would search.
_OTRF_DROP = {"Message", "@version", "tags", "host", "port", "EventReceivedTime", "SourceModuleName",
              "SourceModuleType", "Keywords", "Severity", "SeverityValue", "Category", "Opcode",
              "OpcodeValue", "RecordNumber", "ExecutionProcessID", "ExecutionThreadID", "EventType",
              "Version", "Task", "ProviderGuid", "ActivityID", "log_name", "beat", "agent",
              "ecs", "input", "log", "event", "winlog", "type"}


def _text(v: Any) -> Any:
    if isinstance(v, dict):
        if "#text" in v:
            return _text(v["#text"])
        if set(v) == {"#attributes"}:
            return None
    return v


def flatten_evtx_json(obj: dict[str, Any]) -> Event:
    """Flatten an ``{"Event": {"System":..., "EventData":...}}`` record."""
    ev_root = obj.get("Event", obj)
    sysd = ev_root.get("System") or {}
    out: Event = {}
    prov = sysd.get("Provider") or {}
    attrs = prov.get("#attributes", prov) if isinstance(prov, dict) else {}
    out["Provider_Name"] = attrs.get("Name", "")
    eid = _text(sysd.get("EventID"))
    try:
        out["EventID"] = int(eid)
    except (TypeError, ValueError):
        out["EventID"] = eid
    out["Channel"] = sysd.get("Channel", "")
    out["Computer"] = sysd.get("Computer", "")
    tc = sysd.get("TimeCreated") or {}
    out["TimeCreated"] = (tc.get("#attributes") or {}).get("SystemTime", "") if isinstance(tc, dict) else tc
    sec = sysd.get("Security") or {}
    uid = (sec.get("#attributes") or {}).get("UserID") if isinstance(sec, dict) else None
    if uid:
        out["UserID"] = uid
    for section in ("EventData", "UserData"):
        data = ev_root.get(section)
        if not isinstance(data, dict):
            if data not in (None, ""):
                out["Data"] = data
            continue
        if section == "UserData" and len(data) == 1:  # UserData wraps one named element
            inner = next(iter(data.values()))
            data = inner if isinstance(inner, dict) else data
        for k, v in data.items():
            if k == "#attributes":
                continue
            v = _text(v)
            if k == "Data" and isinstance(v, list):
                v = [_text(x) for x in v]
            out[k] = v
            if " " in k:  # e.g. Defender "New Value": Sigma field names drop the spaces
                out.setdefault(k.replace(" ", ""), v)
    return add_aliases(out)


def flatten_otrf(obj: dict[str, Any]) -> Event:
    """Normalise one OTRF Security-Datasets JSON record."""
    out: Event = {k: v for k, v in obj.items() if k not in _OTRF_DROP}
    if "SourceName" in out and "Provider_Name" not in out:
        out["Provider_Name"] = out.pop("SourceName")
    if "Hostname" in out and "Computer" not in out:
        out["Computer"] = out.pop("Hostname")
    if "@timestamp" in out:
        out["TimeCreated"] = out.pop("@timestamp")
    try:
        out["EventID"] = int(out.get("EventID"))
    except (TypeError, ValueError):
        pass
    return add_aliases(out)


def normalise(obj: dict[str, Any]) -> Event:
    """Normalise a raw record (EVTX JSON, syslog, CloudTrail) to a flat event."""
    if is_cloudtrail(obj):
        return normalise_cloudtrail(obj)
    if "SyslogMessage" in obj:
        ev = from_syslog_wrapper(obj)
        if ev is not None:
            return ev
    if "Event" in obj and isinstance(obj["Event"], dict):
        return flatten_evtx_json(obj)
    if "SourceName" in obj or "Hostname" in obj or "@timestamp" in obj:
        return flatten_otrf(obj)
    return add_aliases(dict(obj))


def iter_json_objects(text: str) -> Iterator[dict[str, Any]]:
    """Yield objects from a JSON doc, a JSON array, NDJSON or concatenated JSON."""
    dec = json.JSONDecoder()
    i, n = 0, len(text)
    while i < n:
        while i < n and text[i].isspace():
            i += 1
        if i >= n:
            break
        obj, i = dec.raw_decode(text, i)
        if isinstance(obj, list):
            yield from (o for o in obj if isinstance(o, dict))
        elif isinstance(obj, dict):
            yield obj


def iter_json_file(path: str | Path) -> Iterator[Event]:
    """Yield normalised events from a JSON, JSON-array or JSONL file (optionally gzipped)."""
    p = Path(path)
    opener = gzip.open if p.suffix == ".gz" else open
    with opener(p, "rt", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    for obj in iter_json_objects(text):
        yield normalise(obj)


def iter_evtx(path: str | Path) -> Iterator[Event]:
    """Parse a binary ``.evtx`` file (pyevtx-rs preferred, python-evtx fallback)."""
    try:
        from evtx import PyEvtxParser  # type: ignore[import-not-found]
    except ImportError:
        PyEvtxParser = None
    if PyEvtxParser is not None:
        for rec in PyEvtxParser(str(path)).records_json():
            try:
                yield flatten_evtx_json(json.loads(rec["data"]))
            except (ValueError, KeyError):
                continue
        return
    yield from _iter_evtx_python(path)


def _iter_evtx_python(path: str | Path) -> Iterator[Event]:  # pragma: no cover - slow fallback
    try:  # EVTX XML is untrusted input: prefer the hardened parser when available
        import defusedxml.ElementTree as ET  # type: ignore[import-untyped]
    except ImportError:
        import xml.etree.ElementTree as ET  # expat >= 2.4 already refuses entity expansion bombs

    import Evtx.Evtx as pyevtx  # type: ignore[import-not-found]
    ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
    with pyevtx.Evtx(str(path)) as log:
        for rec in log.records():
            try:
                root = ET.fromstring(rec.xml())
            except (ET.ParseError, ValueError):
                continue
            sysd = root.find(f"{ns}System")
            ev: Event = {}
            if sysd is not None:
                prov = sysd.find(f"{ns}Provider")
                ev["Provider_Name"] = prov.get("Name", "") if prov is not None else ""
                ev["EventID"] = int((sysd.findtext(f"{ns}EventID") or "0").strip() or 0)
                ev["Channel"] = sysd.findtext(f"{ns}Channel") or ""
                ev["Computer"] = sysd.findtext(f"{ns}Computer") or ""
                tc = sysd.find(f"{ns}TimeCreated")
                ev["TimeCreated"] = tc.get("SystemTime", "") if tc is not None else ""
            ed = root.find(f"{ns}EventData")
            if ed is not None:
                for d in ed.findall(f"{ns}Data"):
                    if d.get("Name"):
                        ev[d.get("Name")] = d.text
            yield add_aliases(ev)


def iter_zip_json(path: str | Path) -> Iterator[Event]:
    """OTRF ships each dataset as a .zip (or .tar.gz) holding one JSON-lines file."""
    p = Path(path)
    if p.name.endswith(".tar.gz"):
        with tarfile.open(p) as tf:
            for m in tf.getmembers():
                if m.isfile() and m.name.endswith(".json"):
                    fh = tf.extractfile(m)
                    if fh:
                        yield from _iter_lines(io.TextIOWrapper(fh, encoding="utf-8", errors="replace"))
        return
    with zipfile.ZipFile(p) as zf:
        for name in zf.namelist():
            if name.startswith("__MACOSX"):
                continue
            if name.endswith(".json"):
                with zf.open(name) as fh:
                    yield from _iter_lines(io.TextIOWrapper(fh, encoding="utf-8", errors="replace"))
            elif name.endswith(".log"):  # OTRF Linux datasets: raw auditd text
                with zf.open(name) as fh:
                    yield from iter_text_lines(io.TextIOWrapper(fh, encoding="utf-8", errors="replace"))


def _iter_lines(fh: Iterable[str]) -> Iterator[Event]:
    for line in fh:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if isinstance(obj, dict):
            yield normalise(obj)


def iter_path(path: str | Path) -> Iterator[Event]:
    """Dispatch on file type; directories are walked recursively (sorted)."""
    p = Path(path)
    if p.is_dir():
        for f in sorted(p.rglob("*")):
            if f.is_file() and f.suffix.lower() in (".evtx", ".json", ".jsonl", ".ndjson", ".gz", ".zip", ".log"):
                yield from iter_path(f)
        return
    name = p.name.lower()
    if name.endswith(".evtx"):
        yield from iter_evtx(p)
    elif name.endswith((".zip", ".tar.gz")):
        yield from iter_zip_json(p)
    elif name.endswith((".log", ".log.gz")):  # Sysmon-for-Linux XML / auditd / CloudTrail lines
        opener = gzip.open if name.endswith(".gz") else open
        with opener(p, "rt", encoding="utf-8", errors="replace") as fh:
            yield from iter_text_lines(fh)
    elif name.endswith((".jsonl", ".ndjson", ".jsonl.gz")):
        opener = gzip.open if name.endswith(".gz") else open
        with opener(p, "rt", encoding="utf-8", errors="replace") as fh:
            yield from _iter_lines(fh)
    else:
        yield from iter_json_file(p)


def write_jsonl(events: Iterable[Event], path: str | Path) -> int:
    """Write events as JSON lines (gzip if the path ends in .gz)."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    opener = gzip.open if p.suffix == ".gz" else open
    n = 0
    with opener(p, "wt", encoding="utf-8") as fh:
        for e in events:
            fh.write(json.dumps({k: v for k, v in e.items() if not k.startswith("__")},
                                default=str) + "\n")
            n += 1
    return n


def ingest(sources: Iterable[str | Path], out_dir: str | Path, shard_size: int = 100_000,
           prefix: str = "part") -> list[Path]:
    """Normalise any supported sources into sharded ``.jsonl.gz`` files (fast to re-scan)."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    shards: list[Path] = []
    buf: list[Event] = []

    def flush() -> None:
        if buf:
            path = out / f"{prefix}-{len(shards):04d}.jsonl.gz"
            write_jsonl(buf, path)
            shards.append(path)
            buf.clear()

    for src in sources:
        for ev in iter_path(src):
            buf.append(ev)
            if len(buf) >= shard_size:
                flush()
    flush()
    return shards
