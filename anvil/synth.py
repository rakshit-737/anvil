"""Deterministic synthetic *benign* Windows-like telemetry (no real hosts/users)."""
from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

HOSTS = [f"WS-{i:03d}.lab.example" for i in range(1, 21)]
USERS = [f"LAB\\user{i:02d}" for i in range(1, 16)] + ["NT AUTHORITY\\SYSTEM"]

BENIGN_PROCS = [
    (r"C:\Windows\System32\svchost.exe", r"C:\Windows\system32\svchost.exe -k netsvcs -p", r"C:\Windows\System32\services.exe"),
    (r"C:\Program Files\Google\Chrome\Application\chrome.exe", '"chrome.exe" --type=renderer', r"C:\Windows\explorer.exe"),
    (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "powershell.exe -NoProfile -File C:\\Scripts\\inventory.ps1", r"C:\Windows\System32\svchost.exe"),
    (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "powershell.exe Get-Service", r"C:\Windows\explorer.exe"),
    (r"C:\Windows\System32\cmd.exe", "cmd.exe /c dir C:\\Users", r"C:\Windows\explorer.exe"),
    (r"C:\Windows\System32\conhost.exe", "conhost.exe 0xffffffff -ForceV1", r"C:\Windows\System32\cmd.exe"),
    (r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", '"WINWORD.EXE" /n report.docx', r"C:\Windows\explorer.exe"),
    (r"C:\Windows\System32\taskhostw.exe", "taskhostw.exe", r"C:\Windows\System32\svchost.exe"),
    (r"C:\Windows\System32\schtasks.exe", "schtasks.exe /query /fo LIST", r"C:\Windows\System32\cmd.exe"),
    (r"C:\Windows\System32\certutil.exe", "certutil.exe -verify C:\\certs\\root.cer", r"C:\Windows\System32\cmd.exe"),
    (r"C:\Windows\System32\rundll32.exe", "rundll32.exe shell32.dll,Control_RunDLL", r"C:\Windows\explorer.exe"),
    (r"C:\Windows\System32\wbem\WmiPrvSE.exe", "wmiprvse.exe -Embedding", r"C:\Windows\System32\svchost.exe"),
    (r"C:\Program Files\Git\cmd\git.exe", "git.exe fetch origin", r"C:\Program Files\Microsoft VS Code\Code.exe"),
    (r"C:\Windows\System32\net.exe", "net.exe use", r"C:\Windows\System32\cmd.exe"),
]

# Schema v2 renames, used to simulate log-source drift for the decay monitor.
V2_RENAMES = {"Image": "process.executable", "CommandLine": "process.command_line",
              "ParentImage": "process.parent.executable"}


def generate(n: int = 5000, seed: int = 1337, schema: str = "v1") -> list[dict[str, Any]]:
    rng = random.Random(seed)
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    events = []
    for i in range(n):
        ts = start + timedelta(seconds=int(86400 * i / n))
        image, cmd, parent = rng.choice(BENIGN_PROCS)
        e: dict[str, Any] = {
            "timestamp": ts.isoformat(), "EventID": 1, "Computer": rng.choice(HOSTS),
            "User": rng.choice(USERS), "Image": image, "CommandLine": cmd, "ParentImage": parent,
        }
        if schema == "v2":
            for old, new in V2_RENAMES.items():
                e[new] = e.pop(old)
        events.append(e)
    return events


def write_jsonl(events: list[dict[str, Any]], path: str | Path) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        for e in events:
            fh.write(json.dumps(e) + "\n")
