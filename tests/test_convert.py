"""pySigma bridge: SIEM conversion and the independent SQLite oracle (skipped without pySigma)."""
import pytest
import yaml

from anvil.models import Rule

sigma = pytest.importorskip("sigma", reason="pySigma not installed")


RULE_YAML = """
title: Certutil Download
id: 00000000-0000-4000-8000-00000000000a
status: test
logsource: {product: windows, category: process_creation}
detection:
  selection:
    Image|endswith: '\\\\certutil.exe'
    CommandLine|contains: 'urlcache'
  condition: selection
level: high
"""


@pytest.mark.parametrize("target", ["splunk", "elastic", "sqlite"])
def test_convert_targets(target):
    try:
        from anvil.convert import Converter
        conv = Converter(target)
    except ImportError:
        pytest.skip(f"backend for {target} not installed")
    c = conv.convert_yaml(RULE_YAML, "x")
    assert c.ok, c.error
    assert "certutil" in c.queries[0].lower()


def test_sqlite_oracle_agrees_with_engine():
    try:
        from anvil.convert import SqliteOracle
        o = SqliteOracle()
    except ImportError:
        pytest.skip("sqlite backend not installed")
    from anvil.engine import compile_rule
    rule = Rule.from_dict(yaml.safe_load(RULE_YAML))
    events = [{"Image": r"C:\Windows\System32\certutil.exe", "CommandLine": "certutil -urlcache -f http://x"},
              {"Image": r"C:\Windows\System32\certutil.exe", "CommandLine": "certutil -verify a.cer"},
              {"Image": r"C:\x\notepad.exe"}]
    conv = o.compile(RULE_YAML)
    assert conv.ok
    ours = sum(compile_rule(rule).matches(e) for e in events)
    assert o.count(conv.queries[0], events) == ours == 1
