"""Sigma ``logsource`` -> telemetry routing and field aliasing.

A Sigma rule says *what kind of log* it applies to (``category: process_creation``,
``service: security``...). Real telemetry says *where it came from* (a Windows
``Channel`` plus ``EventID``). This module bridges the two so that a rule is
only evaluated against events it was written for. Without it, a keyword rule
for PowerShell script blocks would be tested against every Sysmon event and
the FP numbers would be meaningless.

The mapping follows the public Sigma conventions (the SigmaHQ ``logsource``
guide and the Windows/Sysmon pipelines of pySigma). Security 4688 process
creation is aliased to Sysmon field names (``NewProcessName`` -> ``Image``) the
same way pySigma's ``windows`` pipeline does.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .models import LogSource

SYSMON = "microsoft-windows-sysmon/operational"
SECURITY = "security"
PS_OP = "microsoft-windows-powershell/operational"
PS_CLASSIC = "windows powershell"

# category -> list of (channel, event ids). An empty id tuple means "any id".
CATEGORY_MAP: dict[str, list[tuple[str, tuple[int, ...]]]] = {
    "process_creation": [(SYSMON, (1,)), (SECURITY, (4688,))],
    "file_change": [(SYSMON, (2,))],
    "network_connection": [(SYSMON, (3,))],
    "sysmon_status": [(SYSMON, (4, 16))],
    "process_termination": [(SYSMON, (5,))],
    "driver_load": [(SYSMON, (6,))],
    "image_load": [(SYSMON, (7,))],
    "create_remote_thread": [(SYSMON, (8,))],
    "raw_access_thread": [(SYSMON, (9,))],
    "process_access": [(SYSMON, (10,))],
    "file_event": [(SYSMON, (11,))],
    "registry_add": [(SYSMON, (12,))],
    "registry_delete": [(SYSMON, (12,))],
    "registry_set": [(SYSMON, (13,))],
    "registry_rename": [(SYSMON, (14,))],
    "registry_event": [(SYSMON, (12, 13, 14))],
    "create_stream_hash": [(SYSMON, (15,))],
    "pipe_created": [(SYSMON, (17, 18))],
    "wmi_event": [(SYSMON, (19, 20, 21))],
    "dns_query": [(SYSMON, (22,))],
    "file_delete": [(SYSMON, (23, 26))],
    "clipboard_change": [(SYSMON, (24,))],
    "process_tampering": [(SYSMON, (25,))],
    "file_block_executable": [(SYSMON, (27,))],
    "file_block_shredding": [(SYSMON, (28,))],
    "file_executable_detected": [(SYSMON, (29,))],
    "sysmon_error": [(SYSMON, (255,))],
    "ps_module": [(PS_OP, (4103,))],
    "ps_script": [(PS_OP, (4104,))],
    "ps_classic_start": [(PS_CLASSIC, (400,))],
    "ps_classic_provider_start": [(PS_CLASSIC, (600,))],
    "ps_classic_script": [(PS_CLASSIC, (800,))],
    "antivirus": [("microsoft-windows-windows defender/operational",
                   (1006, 1007, 1008, 1009, 1010, 1011, 1012, 1017, 1018, 1019, 1115, 1116))],
}

# Categories that share an EventID with siblings need an extra field condition
# (Sysmon EID 12 is both "registry key created" and "registry key deleted").
CATEGORY_WHERE: dict[str, tuple[str, frozenset[str]]] = {
    "registry_add": ("EventType", frozenset({"createkey"})),
    "registry_delete": ("EventType", frozenset({"deletekey", "deletevalue"})),
}

# service -> channel(s) (Windows). Matching is case-insensitive.
SERVICE_MAP: dict[str, tuple[str, ...]] = {
    "security": (SECURITY,),
    "system": ("system",),
    "application": ("application",),
    "sysmon": (SYSMON,),
    "powershell": (PS_OP,),
    "powershell-classic": (PS_CLASSIC,),
    "taskscheduler": ("microsoft-windows-taskscheduler/operational",),
    "wmi": ("microsoft-windows-wmi-activity/operational",),
    "windefend": ("microsoft-windows-windows defender/operational",),
    "bits-client": ("microsoft-windows-bits-client/operational",),
    "codeintegrity-operational": ("microsoft-windows-codeintegrity/operational",),
    "firewall-as": ("microsoft-windows-windows firewall with advanced security/firewall",),
    "dns-server": ("dns server",),
    "dns-server-analytic": ("microsoft-windows-dns-server/analytical",),
    "dns-client": ("microsoft-windows-dns client events/operational",),
    "driver-framework": ("microsoft-windows-driverframeworks-usermode/operational",),
    "ntlm": ("microsoft-windows-ntlm/operational",),
    "applocker": ("microsoft-windows-applocker/exe and dll", "microsoft-windows-applocker/msi and script",
                  "microsoft-windows-applocker/packaged app-deployment",
                  "microsoft-windows-applocker/packaged app-execution"),
    "msexchange-management": ("msexchange management",),
    "printservice-admin": ("microsoft-windows-printservice/admin",),
    "printservice-operational": ("microsoft-windows-printservice/operational",),
    "smbclient-security": ("microsoft-windows-smbclient/security",),
    "smbclient-connectivity": ("microsoft-windows-smbclient/connectivity",),
    "smbserver-connectivity": ("microsoft-windows-smbserver/connectivity",),
    "terminalservices-localsessionmanager": (
        "microsoft-windows-terminalservices-localsessionmanager/operational",),
    "security-mitigations": ("microsoft-windows-security-mitigations/kernel mode",
                             "microsoft-windows-security-mitigations/user mode"),
    "openssh": ("openssh/operational",),
    "appxdeployment-server": ("microsoft-windows-appxdeploymentserver/operational",),
    "appxpackaging-om": ("microsoft-windows-appxpackaging/operational",),
    "appmodel-runtime": ("microsoft-windows-appmodel-runtime/admin",),
    "capi2": ("microsoft-windows-capi2/operational",),
    "lsa-server": ("microsoft-windows-lsa/operational",),
    "diagnosis-scripted": ("microsoft-windows-diagnosis-scripted/operational",),
    "shell-core": ("microsoft-windows-shell-core/operational",),
    "certificateservicesclient-lifecycle-system": (
        "microsoft-windows-certificateservicesclient-lifecycle-system/operational",),
    "hyper-v-worker": ("microsoft-windows-hyper-v-worker",),
    "kernel-shimengine": ("microsoft-windows-kernel-shimengine/operational",),
    "ldap": ("microsoft-windows-ldap-client/debug",),
    "vhdmp": ("microsoft-windows-vhdmp-operational",),
    "bitlocker": ("microsoft-windows-bitlocker/bitlocker management",),
    "iis-configuration": ("microsoft-iis-configuration/operational",),
    "microsoft-servicebus-client": ("microsoft-servicebus-client",),
    "sense": ("microsoft-windows-sense/operational",),
    "dhcp": ("microsoft-windows-dhcp-server/operational",),
    "wmi-activity": ("microsoft-windows-wmi-activity/operational",),
    "terminalservices-remoteconnectionmanager": (
        "microsoft-windows-terminalservices-remoteconnectionmanager/operational",),
    "rdp": ("microsoft-windows-remotedesktopservices-rdpcorets/operational",),
    "ntfs": ("microsoft-windows-ntfs/operational",),
    "kernel-event-tracing": ("microsoft-windows-kernel-eventtracing/admin",),
}

# Security 4688 -> Sysmon-style names (as pySigma's windows pipeline does).
SECURITY_4688_ALIASES = {"NewProcessName": "Image", "ParentProcessName": "ParentImage",
                         "NewProcessId": "ProcessId"}
# Defender detections -> the generic Sigma "antivirus" field names.
DEFENDER_ALIASES = {"ThreatName": "Signature", "Path": "Filename"}
DEFENDER = "microsoft-windows-windows defender/operational"


@dataclass(frozen=True)
class Route:
    """Where a rule's events live. ``channels`` empty = unroutable."""
    channels: tuple[tuple[str, tuple[int, ...]], ...]
    reason: str = ""
    where: tuple[str, frozenset[str]] | None = None  # extra (field, allowed lower-cased values)

    @property
    def routable(self) -> bool:
        return bool(self.channels)


def route(ls: LogSource) -> Route:
    """Resolve a rule logsource to (channel, event-ids) pairs."""
    product = ls.product.lower()
    if product and product != "windows":
        return Route((), f"product {product!r} has no Windows event-log route")
    if ls.category:
        cat = ls.category.lower()
        if cat not in CATEGORY_MAP:
            return Route((), f"category {cat!r} not mapped")
        pairs = CATEGORY_MAP[cat]
        if ls.service:  # category + service narrows it, e.g. process_creation + security
            chans = SERVICE_MAP.get(ls.service.lower(), ())
            pairs = [p for p in pairs if p[0] in chans] or pairs
        return Route(tuple(pairs), where=CATEGORY_WHERE.get(cat))
    if ls.service:
        svc = ls.service.lower()
        if svc not in SERVICE_MAP:
            return Route((), f"service {svc!r} not mapped")
        return Route(tuple((c, ()) for c in SERVICE_MAP[svc]))
    if product == "windows":
        return Route((("*", ()),))  # product-only rule: all Windows events
    return Route((), "no product/category/service")


def event_key(ev: dict[str, Any]) -> tuple[str, int]:
    chan = str(ev.get("Channel") or "").lower()
    try:
        eid = int(ev.get("EventID") or 0)
    except (TypeError, ValueError):
        eid = 0
    return chan, eid


def where_ok(r: Route, ev: dict[str, Any]) -> bool:
    if r.where is None:
        return True
    field, allowed = r.where
    return str(ev.get(field, "")).lower() in allowed


def applies(r: Route, ev: dict[str, Any]) -> bool:
    if not where_ok(r, ev):
        return False
    chan, eid = event_key(ev)
    for c, ids in r.channels:
        if (c == "*" or c == chan) and (not ids or eid in ids):
            return True
    return False


def add_aliases(ev: dict[str, Any]) -> dict[str, Any]:
    """Add Sigma-canonical alias fields in place (non-destructive)."""
    chan, eid = event_key(ev)
    if chan == SECURITY and eid == 4688:
        for src, dst in SECURITY_4688_ALIASES.items():
            if src in ev and dst not in ev:
                ev[dst] = ev[src]
    elif chan == DEFENDER:
        for src, dst in DEFENDER_ALIASES.items():
            if src in ev and dst not in ev:
                ev[dst] = ev[src]
    return ev
