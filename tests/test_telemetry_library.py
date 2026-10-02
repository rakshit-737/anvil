"""Telemetry normalisation, logsource routing, the routed rule library and regression replay."""
import json
import zipfile

import yaml

from anvil.logsource import applies, route
from anvil.models import LogSource, Rule
from anvil.regression import run_all
from anvil.runner import Library, load_rule_dir, scan
from anvil.telemetry import flatten_evtx_json, flatten_otrf, ingest, iter_json_objects, iter_path, write_jsonl

SYSMON = "Microsoft-Windows-Sysmon/Operational"


def evtx_record(eid, channel, data, provider="Microsoft-Windows-Sysmon"):
    return {"Event": {"System": {"Provider": {"#attributes": {"Name": provider}},
                                 "EventID": eid, "Channel": channel, "Computer": "WS01",
                                 "TimeCreated": {"#attributes": {"SystemTime": "2026-01-01T00:00:00Z"}}},
                      "EventData": data}}


def test_flatten_evtx_json_variants():
    ev = flatten_evtx_json(evtx_record({"#text": 4688, "#attributes": {"Qualifiers": 0}}, "Security",
                                       {"NewProcessName": r"C:\x\cmd.exe", "New Value": "v"},
                                       provider="Microsoft-Windows-Security-Auditing"))
    assert ev["EventID"] == 4688 and ev["Channel"] == "Security"
    assert ev["Image"] == r"C:\x\cmd.exe"            # 4688 -> Sysmon-style alias
    assert ev["NewValue"] == "v"                      # spaces dropped, as Sigma field names do
    ud = {"Event": {"System": {"EventID": 1102, "Channel": "Security"},
                    "UserData": {"LogFileCleared": {"SubjectUserName": "bob"}}}}
    assert flatten_evtx_json(ud)["SubjectUserName"] == "bob"


def test_flatten_otrf_drops_rendered_message():
    ev = flatten_otrf({"SourceName": "Microsoft-Windows-Sysmon", "Hostname": "WS", "EventID": "1",
                       "Channel": SYSMON, "Message": "Process Create: ... mimikatz", "Image": "a.exe",
                       "@timestamp": "t"})
    assert ev["EventID"] == 1 and ev["Provider_Name"] == "Microsoft-Windows-Sysmon"
    assert "Message" not in ev and ev["Computer"] == "WS"


def test_iter_json_objects_handles_concatenated_array_and_ndjson():
    text = '{"a": 1}\n{"a": 2}{"a": 3} [{"a": 4}, {"a": 5}]'
    assert [o["a"] for o in iter_json_objects(text)] == [1, 2, 3, 4, 5]


def test_jsonl_roundtrip_ingest_and_zip(tmp_path):
    evs = [{"EventID": i, "Channel": SYSMON, "Image": f"p{i}.exe"} for i in range(5)]
    write_jsonl(evs, tmp_path / "a.jsonl.gz")
    assert [e["EventID"] for e in iter_path(tmp_path / "a.jsonl.gz")] == list(range(5))
    shards = ingest([tmp_path / "a.jsonl.gz"], tmp_path / "out", shard_size=2)
    assert len(shards) == 3
    z = tmp_path / "otrf.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("x.json", "\n".join(json.dumps({"SourceName": "S", "EventID": 1, "Channel": SYSMON,
                                                    "Image": "a"}) for _ in range(3)))
    assert sum(1 for _ in iter_path(z)) == 3


def test_routes():
    assert route(LogSource("windows", "process_creation")).channels[0][0].endswith("sysmon/operational")
    assert route(LogSource("windows", "", "security")).routable
    assert route(LogSource("linux", "process_creation")).channels == (("linux-sysmon/operational", (1,)),)
    assert not route(LogSource("linux", "image_load")).routable
    assert not route(LogSource("windows", "file_access")).routable
    rt = route(LogSource("windows", "process_creation"))
    assert applies(rt, {"Channel": "Security", "EventID": 4688})
    assert not applies(rt, {"Channel": "Security", "EventID": 4624})
    ps = route(LogSource("windows", "ps_script"))
    assert applies(ps, {"Channel": "Microsoft-Windows-PowerShell/Operational", "EventID": 4104})


def _rule(i, ls, det, **kw):
    d = {"id": f"00000000-0000-4000-8000-{i:012d}", "title": f"r{i}", "description": "d", "status": "test",
         "level": "high", "logsource": ls, "detection": det, "tags": ["attack.execution", "attack.t1059.001"]}
    d.update(kw)
    return d


def _write_rules(d, docs):
    d.mkdir(parents=True, exist_ok=True)
    for i, doc in enumerate(docs):
        (d / f"r{i}.yml").write_text(yaml.safe_dump(doc), encoding="utf-8")


def test_library_routing_and_scan(tmp_path):
    rules_dir = tmp_path / "rules"
    _write_rules(rules_dir, [
        _rule(1, {"product": "windows", "category": "process_creation"},
              {"s": {"Image|endswith": "\\powershell.exe", "CommandLine|contains": " -enc "}, "condition": "s"}),
        _rule(2, {"product": "windows", "service": "security"},
              {"s": {"EventID": 4625}, "condition": "s"}),
        _rule(3, {"product": "linux", "category": "image_load"}, {"s": {"Image": "/bin/sh"},
                                                                         "condition": "s"}),
        _rule(4, {"product": "windows", "category": "process_creation"},
              {"s": {"User|expand": "%x%"}, "condition": "s"}),
        {"title": "correlation doc", "correlation": {"type": "event_count"}},
    ])
    rules, rep = load_rule_dir([rules_dir])
    assert rep.loaded == 4 and rep.skipped_non_detection == 1
    lib = Library.build(rules)
    assert len(lib.unsupported) == 1 and len(lib.unroutable) == 1
    events = [
        {"Channel": SYSMON, "EventID": 1, "Image": r"C:\ps\powershell.exe", "CommandLine": "powershell -enc AA"},
        {"Channel": "Security", "EventID": 4688, "NewProcessName": r"C:\ps\powershell.exe",
         "CommandLine": "powershell -enc AA"},
        {"Channel": "Security", "EventID": 4625},
        {"Channel": "Security", "EventID": 4624},
        # right fields, wrong log source -> must not be counted
        {"Channel": "Application", "EventID": 1, "Image": r"C:\ps\powershell.exe", "CommandLine": " -enc "},
    ]
    from anvil.logsource import add_aliases
    res = scan(lib, [add_aliases(e) for e in events])
    assert res.hits["00000000-0000-4000-8000-000000000001"] == 2
    assert res.hits["00000000-0000-4000-8000-000000000002"] == 1
    # rule 2 is indexed by its EventID, so 4624 events never evaluate it
    assert "00000000-0000-4000-8000-000000000002" not in lib.candidates(events[3])


def test_regression_replay(tmp_path):
    root = tmp_path / "sigma"
    rid = "00000000-0000-4000-8000-000000000001"
    _write_rules(root / "rules", [_rule(1, {"product": "windows", "category": "process_creation"},
                                        {"s": {"CommandLine|contains": "whoami"}, "condition": "s"})])
    case = root / "regression_data" / "rules" / "windows" / "x"
    case.mkdir(parents=True)
    (case / "info.yml").write_text(yaml.safe_dump({
        "rule_metadata": [{"id": rid, "title": "r1"}],
        "regression_tests_info": [{"type": "evtx", "match_count": 1, "path": f"regression_data/x/{rid}.evtx"}]}))
    recs = [evtx_record(1, SYSMON, {"CommandLine": "whoami /all"}),
            evtx_record(1, SYSMON, {"CommandLine": "ipconfig"})]
    (case / f"{rid}.json").write_text("\n".join(json.dumps(r) for r in recs))
    rules, _ = load_rule_dir([root / "rules"])
    (res,) = run_all(Library.build(rules), root)
    assert res.status == "pass" and res.matched == 1 and res.routed == 2 and res.exact


def test_registry_delete_needs_delete_event_type():
    rt = route(LogSource("windows", "registry_delete"))
    base = {"Channel": SYSMON, "EventID": 12, "TargetObject": r"HKU\x\RunMRU"}
    assert applies(rt, {**base, "EventType": "DeleteKey"})
    assert not applies(rt, {**base, "EventType": "CreateKey"})
    lib = Library.build([Rule.from_dict(_rule(9, {"product": "windows", "category": "registry_delete"},
                                              {"s": {"TargetObject|endswith": r"\RunMRU"}, "condition": "s"}))])
    res = scan(lib, [{**base, "EventType": "CreateKey"}, {**base, "EventType": "DeleteKey"}])
    assert sum(res.hits.values()) == 1
