"""Linux and cloud telemetry parsers (1.1).

Every parser produces the same flat event shape as the Windows loaders, with a
pseudo ``Channel`` so the logsource router can index it:

* Sysmon for Linux XML (one ``<Event>`` per line, as Splunk ``attack_data`` and
  Azure Monitor ``Syslog.SyslogMessage`` ship it) -> ``linux-sysmon/operational``
  with the Sysmon EventID and ``EventData`` fields (``Image``, ``CommandLine``...)
* auditd raw records (``type=SYSCALL msg=audit(...): key=value ...``) ->
  ``linux-auditd``, one event per record, quoted values unquoted, ``type`` kept.
  Hex-encoded EXECVE arguments are left as auditd wrote them, which is what a
  SIEM without an auditd decoder would index.
* AWS CloudTrail JSON (one record per line, a JSON array, or ``{"Records": [...]}``)
  -> ``aws-cloudtrail``, nested fields kept (Sigma uses dotted paths such as
  ``requestParameters.userName``; the engine resolves them).
"""
from __future__ import annotations

import html
import io
import json
import re
import zipfile
from collections.abc import Iterable, Iterator
from typing import Any

from .logsource import AWS_CLOUDTRAIL, LINUX_AUDITD, LINUX_SYSMON

Event = dict[str, Any]

_EID = re.compile(r"<EventID>(\d+)</EventID>")
_DATA = re.compile(r'<Data Name="([^"]+)">(.*?)</Data>|<Data Name="([^"]+)"\s*/>', re.S)
_COMPUTER = re.compile(r"<Computer>(.*?)</Computer>")
_TIME = re.compile(r'<TimeCreated SystemTime="([^"]+)"')
_KV = re.compile(r'([A-Za-z0-9_\-]+)=("(?:[^"\\]|\\.)*"|\'[^\']*\'|\S*)')
# Raw records: ``audit(1700000000.123:42):``; ``ausearch -i`` output: ``audit(04/16/2025 08:20:23.552:47372) :``
_AUDIT_HDR = re.compile(r"^type=(\S+)\s+(?:msg=)?audit\(([^)]*)\)\s*:\s*(.*)$", re.S)


def parse_sysmon_xml(line: str) -> Event | None:
    """Parse one Sysmon-for-Linux ``<Event>`` XML record into a flat event."""
    m = _EID.search(line)
    if not m:
        return None
    ev: Event = {"Channel": LINUX_SYSMON, "EventID": int(m.group(1)), "Provider_Name": "Linux-Sysmon"}
    if c := _COMPUTER.search(line):
        ev["Computer"] = c.group(1)
    if t := _TIME.search(line):
        ev["TimeCreated"] = t.group(1)
    for name, val, empty in _DATA.findall(line):
        if empty:
            ev[empty] = ""
        else:
            ev[name] = html.unescape(val)
    return ev


def parse_auditd(line: str) -> Event | None:
    """Parse one raw or ``ausearch -i`` auditd record into a flat event."""
    line = line.split("\x1d", 1)[0].strip()  # drop the enriched (interpreted) suffix
    m = _AUDIT_HDR.match(line)
    if not m:
        return None
    ev: Event = {"Channel": LINUX_AUDITD, "EventID": 0, "type": m.group(1), "audit_id": m.group(2)}
    for k, v in _KV.findall(m.group(3)):
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        ev.setdefault(k, v)
    return ev


def normalise_cloudtrail(obj: dict[str, Any]) -> Event:
    """Stamp a CloudTrail record with the ``aws-cloudtrail`` pseudo-channel."""
    ev = {k: v for k, v in obj.items() if k not in ("@version", "@timestamp", "tags", "host", "port")}
    ev["Channel"] = AWS_CLOUDTRAIL
    ev["EventID"] = 0
    return ev


def is_cloudtrail(obj: dict[str, Any]) -> bool:
    """True if ``obj`` looks like one CloudTrail record."""
    return "eventSource" in obj and "eventName" in obj


def from_syslog_wrapper(obj: dict[str, Any]) -> Event | None:
    """Azure Monitor ``Syslog`` rows carrying Sysmon-for-Linux XML or auditd text."""
    msg = obj.get("SyslogMessage")
    if not isinstance(msg, str):
        return None
    if "<Event>" in msg and "Linux-Sysmon" in msg:
        return parse_sysmon_xml(msg)
    if msg.startswith("type="):
        return parse_auditd(msg)
    return None


def iter_text_lines(lines: Iterable[str]) -> Iterator[Event]:
    """Auto-detect per line: Sysmon XML, auditd, CloudTrail/Syslog JSON."""
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        ev: Event | None = None
        if line.startswith("<Event"):
            ev = parse_sysmon_xml(line)
        elif line.startswith("type="):
            ev = parse_auditd(line)
        elif line.startswith("{"):
            try:
                obj = json.loads(line)
            except ValueError:
                obj = None
            if isinstance(obj, dict):
                if isinstance(obj.get("Records"), list):
                    for r in obj["Records"]:
                        if isinstance(r, dict) and is_cloudtrail(r):
                            yield normalise_cloudtrail(r)
                    continue
                ev = normalise_cloudtrail(obj) if is_cloudtrail(obj) else from_syslog_wrapper(obj)
        if ev is not None:
            yield ev


def iter_bytes(name: str, data: bytes) -> Iterator[Event]:
    """Parse the bytes of a ``.zip`` or text capture.

    Accepts a JSON array, a ``{"Records": ...}`` document, or one record per line. Callers read the bytes from a file on disk.
    """
    if name.lower().endswith(".zip") or data[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for n in zf.namelist():
                if n.startswith("__MACOSX") or n.endswith("/"):
                    continue
                yield from iter_text_lines(io.TextIOWrapper(zf.open(n), encoding="utf-8", errors="replace"))
        return
    text = data.decode("utf-8", errors="replace")
    stripped = text.lstrip()
    if stripped.startswith("[") or (stripped.startswith("{") and '"Records"' in stripped[:200]):
        try:
            doc = json.loads(stripped)
            recs = doc.get("Records", []) if isinstance(doc, dict) else doc
            for r in recs:
                if isinstance(r, dict) and is_cloudtrail(r):
                    yield normalise_cloudtrail(r)
            return
        except ValueError:
            pass
    yield from iter_text_lines(text.splitlines())
