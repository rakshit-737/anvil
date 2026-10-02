"""Detection drafter: CTI text -> candidate Sigma rules (AI proposes, human approves).

Two backends:

``heuristic`` (default, offline, deterministic)
    Extracts ATT&CK ids, command lines, executables and PowerShell cmdlets
    from the report, keeps the *behavioural* tokens (switches, cmdlets, LOLBin
    verbs) and drops incident-specific IOCs (IPs, hosts, users, hashes, GUIDs)
    that would make the rule an IOC match instead of a detection. Emits a
    process_creation rule per distinctive command line and a ps_script rule
    for in-memory PowerShell cmdlets.

``llm`` (optional, ``pip install anvil-dac[llm]`` + ``ANTHROPIC_API_KEY``)
    Asks Claude for Sigma YAML, then runs the *same* validation gate.

Every draft is written with ``status: experimental`` and an ``anvil`` block
``{draft: true, reviewed: false}``. ``anvil lint`` refuses unreviewed drafts
inside the deployable rules directory (A114), so nothing an AI wrote can reach
production without a human flipping ``reviewed`` in a PR *and* the rule
passing ``anvil test``.
"""
from __future__ import annotations

import hashlib
import re
import uuid
from dataclasses import dataclass, field
from typing import Any

import yaml

T_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
EXE = re.compile(r"(?i)\b([\w.-]+\.(?:exe|dll|ps1|vbs|js|hta|bat|cmd|msi|scr))\b")
CMDLET = re.compile(r"(?<![\w-])((?:Add|Clear|Compress|ConvertFrom|ConvertTo|Copy|Disable|Enable|Enter|Expand|Export|"
                    r"Find|Get|Import|Install|Invoke|New|Out|Register|Remove|Rename|Resolve|Restart|Set|Start|"
                    r"Stop|Test|Write)-[A-Z][A-Za-z]+)\b")
PROMPT = re.compile(r"^\s*(?:\(?[\w: ]+\)?\s*[>#$]\s*|PS [A-Z]:\\[^>]*>\s*|[A-Z]:\\[^>]*>\s*)"
                    r"(?:(?:shell|scriptcmd|execute|run)\s+)?(.+)$")
IOC_LIKE = re.compile(r"(?ix)^(?:\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?|[0-9a-f]{16,}|\{?[0-9a-f-]{36}\}?|"
                      r"https?://.*|\\\\.*|[\w.-]+\.(?:local|com|net|org|io)|s-1-5-.*)$")
GENERIC = {"-command", "/c", "-c", "-noprofile", "-nop", "-w", "hidden", "-windowstyle", "-exec", "bypass",
           "-executionpolicy", "-ep", "-noninteractive", "-noni", "cmd", "cmd.exe", "powershell",
           "powershell.exe", "/q", "/k", "-f", "-y"}
KNOWN_BINARIES = {"certutil", "bitsadmin", "rundll32", "regsvr32", "mshta", "wmic", "schtasks", "reg", "net",
                  "net1", "sc", "vssadmin", "wevtutil", "bcdedit", "msiexec", "cscript", "wscript", "nltest",
                  "whoami", "procdump", "at", "netsh", "dsquery", "ntdsutil", "esentutl", "cmstp", "installutil",
                  "regasm", "regsvcs", "msbuild", "forfiles", "mavinject", "odbcconf", "pcalua", "diskshadow",
                  "adfind", "psexec", "wmiprvse", "systeminfo", "tasklist", "ipconfig", "quser", "qwinsta",
                  "cmdkey", "klist", "setspn", "dsget", "icacls", "takeown", "attrib", "curl", "tar", "expand",
                  "makecab", "fsutil", "wbadmin", "mimikatz", "rubeus", "sharphound", "seatbelt"}


@dataclass
class Draft:
    rule: dict[str, Any]
    rationale: str
    backend: str
    tp_fixtures: list[dict[str, Any]] = field(default_factory=list)

    def to_yaml(self) -> str:
        return yaml.safe_dump(self.rule, sort_keys=False, allow_unicode=True, width=110)


# ------------------------------------------------------------------ extraction

def extract_commands(text: str) -> list[str]:
    """Command lines from a report: console prompts, code lines and quoted commands."""
    out: list[str] = []
    for line in text.splitlines():
        s = line.strip().strip("`")
        if not s or len(s) > 600:
            continue
        m = PROMPT.match(s)
        cand = m.group(1).strip() if m else s
        first = cand.split()[0].lower().strip('"\'') if cand.split() else ""
        base = first.rsplit("\\", 1)[-1].removesuffix(".exe")
        if base in KNOWN_BINARIES or base in ("powershell", "pwsh", "cmd") or CMDLET.search(cand) \
                or (m and EXE.search(cand)):
            if not cand.startswith(("[*]", "[+]", "[!]", "Job started", "Name ", "----")):
                out.append(cand)
    return list(dict.fromkeys(out))


def _tokens(cmd: str) -> list[str]:
    return [t.strip("\"'(),;{}") for t in re.split(r"\s+", cmd) if t.strip("\"'(),;{}")]


def behavioural_tokens(cmd: str, limit: int = 3) -> list[str]:
    """Distinctive, non-IOC tokens: switches, cmdlets and verbs (most specific first)."""
    toks = _tokens(cmd)[1:]
    keep: list[str] = []
    for t in toks:
        tl = t.lower()
        if tl in GENERIC or IOC_LIKE.match(t) or len(t) < 3 or len(t) > 40:
            continue
        if re.fullmatch(r"[\w.-]+\.(?:txt|log|dat|tmp|zip|bin|out|csv)", tl):
            continue  # incident-specific output files
        if t.startswith(("-", "/")) or CMDLET.fullmatch(t) or tl.endswith(("::", ".exe")) or "::" in t:
            keep.append(t)
    # fall back to the first plain verb-like word (e.g. `sc create`, `net user`)
    if not keep:
        keep = [t for t in toks if t.isalpha() and 3 <= len(t) <= 20][:1]
    return list(dict.fromkeys(keep))[:limit]


def _rid(seed: str) -> str:
    return str(uuid.UUID(hashlib.sha256(seed.encode()).hexdigest()[:32], version=4))


def _base_rule(title: str, desc: str, techniques: list[str], logsource: dict[str, str],
               detection: dict[str, Any], source: str, level: str = "medium") -> dict[str, Any]:
    tags = [f"attack.{t.lower()}" for t in techniques]
    return {
        "title": title[:110], "id": _rid(title + str(detection)), "status": "experimental",
        "description": desc[:400], "references": [source] if source.startswith("http") else [],
        "author": "ANVIL drafter (unreviewed)", "tags": tags, "logsource": logsource,
        "detection": detection, "falsepositives": ["Unknown - drafted automatically, review before use"],
        "level": level, "anvil": {"draft": True, "reviewed": False, "source": source[:200]},
    }


# ------------------------------------------------------------------ backends

def draft_heuristic(text: str, title: str = "", source: str = "", max_rules: int = 4) -> list[Draft]:
    techniques = sorted(set(T_ID.findall(text)))
    cmds = extract_commands(text)
    drafts: list[Draft] = []
    seen: set[tuple[str, ...]] = set()
    cmdlets = sorted({c for cmd in cmds for c in CMDLET.findall(cmd)}
                     | set(CMDLET.findall(text)))
    for cmd in cmds:
        first = _tokens(cmd)[0] if _tokens(cmd) else ""
        exe = first.rsplit("\\", 1)[-1].lower()
        exe = exe if exe.endswith(".exe") else exe + ".exe"
        if exe in ("powershell.exe", "pwsh.exe", "cmd.exe") or CMDLET.match(first):
            continue  # handled by the cmdlet/script rule below
        if exe.removesuffix(".exe") not in KNOWN_BINARIES and not first.lower().endswith(".exe"):
            continue  # prose or console output, not a process launch
        toks = behavioural_tokens(cmd)
        if not toks:
            continue
        key = (exe, *toks)
        if key in seen:
            continue
        seen.add(key)
        det = {"selection_img": [{"Image|endswith": "\\" + exe}, {"OriginalFileName": exe}],
               "selection_cli": {"CommandLine|contains|all": toks}, "condition": "all of selection_*"}
        name = f"{exe.removesuffix('.exe')} {' '.join(toks)}"
        fixture = {"Image": "C:\\Windows\\System32\\" + exe, "CommandLine": cmd, "OriginalFileName": exe}
        drafts.append(Draft(_base_rule(f"Drafted: {name} ({title or 'CTI report'})",
                                       f"Auto-drafted from CTI: {title}. Behaviour: `{cmd[:160]}`",
                                       techniques, {"product": "windows", "category": "process_creation"},
                                       det, source), f"command line `{cmd[:80]}` -> {toks}", "heuristic",
                            [fixture]))
        if len(drafts) >= max_rules:
            break
    if cmdlets and len(drafts) < max_rules:
        chosen = [c for c in cmdlets if not c.startswith(("Get-Item", "Write-", "Out-", "Get-Date"))][:6]
        if chosen:
            det = {"selection": {"ScriptBlockText|contains": chosen}, "condition": "selection"}
            drafts.append(Draft(_base_rule(f"Drafted: PowerShell {', '.join(chosen[:3])} ({title or 'CTI'})",
                                           f"Auto-drafted from CTI: {title}. In-memory PowerShell usage of "
                                           f"{', '.join(chosen)}", techniques,
                                           {"product": "windows", "category": "ps_script"}, det, source),
                                f"cmdlets {chosen}", "heuristic",
                                [{"ScriptBlockText": f"{chosen[0]} -Verbose"}]))
    return drafts


def draft_keywords_baseline(text: str, title: str = "", source: str = "") -> list[Draft]:
    """Naive baseline: every extracted executable/cmdlet as a product-wide keyword rule."""
    kws = sorted({m.lower() for m in EXE.findall(text)} | set(CMDLET.findall(text)))
    kws = [k for k in kws if k not in GENERIC][:25]
    if not kws:
        return []
    det = {"keywords": kws, "condition": "keywords"}
    return [Draft(_base_rule(f"Keyword baseline ({title or 'CTI'})", "naive keyword rule",
                             sorted(set(T_ID.findall(text))), {"product": "windows"}, det, source),
                  "keyword baseline", "keywords")]


LLM_PROMPT = """You are a detection engineer. Read the threat report below and write 1-3 Sigma rules
(YAML, one document per rule, separated by ---) that detect the *behaviour* described, not the
incident's IOCs (no IPs, hostnames, usernames, hashes). Use standard Sigma logsource categories
(process_creation, ps_script, registry_set, ...) and Sysmon field names. Include ATT&CK tags.
Output only YAML.

REPORT TITLE: {title}
REPORT:
{text}
"""


def draft_llm(text: str, title: str = "", source: str = "", model: str = "claude-opus-5") -> list[Draft]:
    """Draft with Claude. Requires the ``anthropic`` package and credentials."""
    import anthropic  # type: ignore[import-not-found]

    client = anthropic.Anthropic()
    msg = client.messages.create(
        model=model, max_tokens=16000, thinking={"type": "adaptive"},
        messages=[{"role": "user", "content": LLM_PROMPT.format(title=title, text=text[:60000])}])
    if msg.stop_reason == "refusal":
        return []
    body = "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")
    body = re.sub(r"^```(?:ya?ml)?\s*|```\s*$", "", body.strip(), flags=re.M)
    drafts = []
    for doc in yaml.safe_load_all(body):
        if not isinstance(doc, dict) or "detection" not in doc:
            continue
        doc["id"] = _rid(str(doc.get("title", "")) + str(doc["detection"]))
        doc["status"] = "experimental"
        doc["anvil"] = {"draft": True, "reviewed": False, "source": source[:200], "model": model}
        drafts.append(Draft(doc, "LLM draft", "llm"))
    return drafts


def draft(text: str, title: str = "", source: str = "", backend: str = "heuristic") -> list[Draft]:
    if backend == "llm":
        return draft_llm(text, title, source)
    if backend == "keywords":
        return draft_keywords_baseline(text, title, source)
    return draft_heuristic(text, title, source)
