"""Linux / cloud parsers and routing (hand-written, benign fixtures)."""
from __future__ import annotations

import json

from anvil.logsource import AWS_CLOUDTRAIL, LINUX_AUDITD, LINUX_SYSMON, LogSource, applies, route
from anvil.models import Rule
from anvil.nixcloud import (
    from_syslog_wrapper,
    iter_bytes,
    iter_text_lines,
    parse_auditd,
    parse_sysmon_xml,
)
from anvil.runner import Library

SYSMON_XML = (
    '<Event><System><Provider Name="Linux-Sysmon" Guid="{x}"/><EventID>1</EventID>'
    '<TimeCreated SystemTime="2023-01-01T00:00:00.000Z"/><Computer>lab</Computer></System>'
    '<EventData><Data Name="Image">/usr/bin/whoami</Data>'
    '<Data Name="CommandLine">whoami &amp;&amp; id</Data><Data Name="ParentImage"/></EventData></Event>'
)
AUDIT_RAW = 'type=EXECVE msg=audit(1700000000.123:42): argc=2 a0="whoami" a1=\'x y\'\x1dUID="root"'
AUDIT_INTERP = "type=SYSCALL msg=audit(04/16/2025 08:20:23.552:47372) : arch=x86_64 syscall=execve exe=/usr/bin/id"
CT = {"eventSource": "iam.amazonaws.com", "eventName": "CreateUser",
      "requestParameters": {"userName": "dummy"}, "@timestamp": "t"}


def test_parse_sysmon_xml_unescapes_and_keeps_empty():
    ev = parse_sysmon_xml(SYSMON_XML)
    assert ev["Channel"] == LINUX_SYSMON and ev["EventID"] == 1 and ev["Computer"] == "lab"
    assert ev["CommandLine"] == "whoami && id" and ev["ParentImage"] == ""


def test_parse_auditd_raw_and_interpreted():
    ev = parse_auditd(AUDIT_RAW)
    assert ev["Channel"] == LINUX_AUDITD and ev["type"] == "EXECVE"
    assert ev["a0"] == "whoami" and ev["a1"] == "x y" and "UID" not in ev
    ev2 = parse_auditd(AUDIT_INTERP)
    assert ev2 is not None and ev2["syscall"] == "execve" and ev2["exe"] == "/usr/bin/id"
    assert parse_auditd("not audit") is None


def test_cloudtrail_forms():
    one = list(iter_text_lines([json.dumps(CT)]))
    rec = list(iter_text_lines([json.dumps({"Records": [CT, CT]})]))
    arr = list(iter_bytes("ct.json", json.dumps([CT, CT, CT]).encode()))
    assert len(one) == 1 and len(rec) == 2 and len(arr) == 3
    assert one[0]["Channel"] == AWS_CLOUDTRAIL and "@timestamp" not in one[0]


def test_syslog_wrapper():
    assert from_syslog_wrapper({"SyslogMessage": SYSMON_XML})["EventID"] == 1
    assert from_syslog_wrapper({"SyslogMessage": AUDIT_RAW})["type"] == "EXECVE"
    assert from_syslog_wrapper({"SyslogMessage": "hello"}) is None


def test_routes_linux_aws():
    assert route(LogSource("linux", "", "auditd")).channels == ((LINUX_AUDITD, ()),)
    assert route(LogSource("aws", "", "cloudtrail")).channels == ((AWS_CLOUDTRAIL, ()),)
    assert not route(LogSource("linux", "")).routable
    assert not route(LogSource("azure", "", "activitylogs")).routable
    assert applies(route(LogSource("linux", "process_creation")), parse_sysmon_xml(SYSMON_XML))


def _r(i, ls, det):
    return Rule.from_dict({"id": f"00000000-0000-4000-8000-{i:012d}", "title": f"r{i}", "level": "high",
                           "logsource": ls, "detection": det})


def test_library_global_rules_skip_non_windows():
    rules = [
        _r(1, {"product": "linux", "category": "process_creation"},
           {"s": {"Image|endswith": "/whoami"}, "condition": "s"}),
        _r(2, {"product": "aws", "service": "cloudtrail"},
           {"s": {"eventName": "CreateUser", "requestParameters.userName": "dummy"}, "condition": "s"}),
        _r(3, {"product": "linux", "service": "auditd"}, {"s": {"type": "EXECVE", "a0": "whoami"},
                                                         "condition": "s"}),
        _r(4, {}, {"s": {"Image|endswith": "/whoami"}, "condition": "s"}),  # global (no logsource)
    ]
    lib = Library.build(rules)
    ids = lambda ev: {r[-1] for r in lib.match_event(ev)}  # noqa: E731
    assert ids(parse_sysmon_xml(SYSMON_XML)) == {"1"}
    assert ids(list(iter_text_lines([json.dumps(CT)]))[0]) == {"2"}
    assert ids(parse_auditd(AUDIT_RAW)) == {"3"}
