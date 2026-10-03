"""ATT&CK STIX catalog, catalog-aware coverage + lint and the OTRF catalog."""
import json
import zipfile

import pytest
import yaml

from anvil.attack import load_stix
from anvil.coverage import coverage, navigator_layer
from anvil.lint import lint_rule
from anvil.models import Rule
from anvil.otrf import load_catalog


def ap(stix_id, tid, name, tactic, platforms=("Windows",), **kw):
    o = {"type": "attack-pattern", "id": stix_id, "name": name,
         "external_references": [{"source_name": "mitre-attack", "external_id": tid}],
         "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": tactic}],
         "x_mitre_platforms": list(platforms), "x_mitre_is_subtechnique": "." in tid}
    o.update(kw)
    return o


@pytest.fixture
def stix(tmp_path):
    objs = [
        {"type": "x-mitre-collection", "id": "x-mitre-collection--1", "x_mitre_version": "99.0"},
        ap("attack-pattern--1", "T1059", "Command and Scripting Interpreter", "execution"),
        ap("attack-pattern--2", "T1059.001", "PowerShell", "execution"),
        ap("attack-pattern--3", "T1003.001", "LSASS Memory", "credential-access"),
        ap("attack-pattern--4", "T1086", "PowerShell (old)", "execution", revoked=True),
        ap("attack-pattern--5", "T1548.001", "Setuid and Setgid", "privilege-escalation", platforms=("Linux",)),
        {"type": "relationship", "id": "relationship--1", "relationship_type": "revoked-by",
         "source_ref": "attack-pattern--4", "target_ref": "attack-pattern--2"},
        {"type": "x-mitre-data-component", "id": "x-mitre-data-component--1", "name": "Process Creation"},
        {"type": "relationship", "id": "relationship--2", "relationship_type": "detects",
         "source_ref": "x-mitre-data-component--1", "target_ref": "attack-pattern--2"},
    ]
    p = tmp_path / "enterprise-attack.json"
    p.write_text(json.dumps({"type": "bundle", "objects": objs}))
    return load_stix(p)


def mkrule(tags, **kw):
    d = {"id": "00000000-0000-4000-8000-000000000001", "title": "t", "description": "d" * 50,
         "status": "test", "level": "high", "logsource": {"product": "windows", "category": "process_creation"},
         "detection": {"s": {"Image|endswith": "\\x.exe"}, "condition": "s"}, "tags": tags,
         "falsepositives": ["none"]}
    d.update(kw)
    return Rule.from_dict(d)


def test_stix_catalog(stix):
    assert stix.version == "99.0"
    assert set(stix.active()) == {"T1059", "T1059.001", "T1003.001", "T1548.001"}
    assert set(stix.active("Windows")) == {"T1059", "T1059.001", "T1003.001"}
    assert stix.resolve("T1086") == "T1059.001"
    assert stix.techniques["T1059.001"].data_components == ["Process Creation"]


def test_coverage_with_catalog(stix):
    rules = [mkrule(["attack.execution", "attack.t1059.001"]),
             mkrule(["attack.t1086"], id="00000000-0000-4000-8000-000000000002")]
    rep = coverage(rules, passing_ids={"00000000-0000-4000-8000-000000000001"}, catalog=stix,
                   platform="Windows")
    assert rep["catalog_size"] == 3 and rep["covered"] == 1 and rep["validated"] == 1
    assert rep["parent_total"] == 1 and rep["parent_covered"] == 1   # T1059.001 rolls up to T1059
    assert rep["stale_tags"] == {"00000000-0000-4000-8000-000000000002": ["T1086"]}
    assert navigator_layer(rep)["techniques"][0]["techniqueID"] == "T1059.001"


def test_lint_sigma_profile_and_stale_tags(stix):
    r = mkrule(["attack.t1086", "attack.t9999", "foo.bar"], status="stable")
    codes = {f.code for f in lint_rule(r, profile="sigma", catalog=stix)}
    assert {"W208", "W212", "W209"} <= codes
    assert "A112" not in codes                     # sigma profile does not require in-rule fixtures
    assert "A112" in {f.code for f in lint_rule(r)}  # anvil profile does


def test_otrf_catalog(tmp_path):
    meta = tmp_path / "atomic" / "_metadata"
    meta.mkdir(parents=True)
    host = tmp_path / "atomic" / "windows" / "execution" / "host"
    host.mkdir(parents=True)
    with zipfile.ZipFile(host / "ds.zip", "w") as zf:
        zf.writestr("ds.json", json.dumps({"SourceName": "Microsoft-Windows-Sysmon", "EventID": 1,
                                           "Channel": "Microsoft-Windows-Sysmon/Operational"}))
    (meta / "SDWIN-1.yaml").write_text(yaml.safe_dump({
        "id": "SDWIN-1", "title": "demo", "description": "desc",
        "attack_mappings": [{"technique": "T1059", "sub-technique": "001"}, {"technique": "T1105"}],
        "files": [{"type": "Host", "link": "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/"
                                           "datasets/atomic/windows/execution/host/ds.zip"}],
        "simulation": {"adversary_view": "powershell -enc AAAA"}}))
    (ds,) = load_catalog(tmp_path)
    assert ds.techniques == ["T1059.001", "T1105"] and ds.available
    assert len(list(ds.events())) == 1 and "powershell" in ds.adversary_view


@pytest.mark.parametrize("pattern", ["^(a+)+$", "(a*)*", "(a|a)*", r"(\w+\s?)*$", r"(?:.*\))+"])
def test_lint_flags_redos_prone_regex(pattern):
    d = {"title": "t", "id": "5f1d0f4e-1c2b-4c55-9a7e-6f0b7c1d2e3a", "description": "d", "level": "low",
         "status": "test", "logsource": {"category": "process_creation", "product": "windows"},
         "detection": {"selection": {"CommandLine|re": pattern}, "condition": "selection"},
         "tags": ["attack.t1059"], "falsepositives": ["x"]}
    codes = [f.code for f in lint_rule(Rule.from_dict(d), profile="sigma")]
    assert "W213" in codes


@pytest.mark.parametrize("pattern", [r"\\[a-z]+\.exe$",r"(\d{1,3}\.){3}\d{1,3}", "(abc)+", "(a|b)+", "[(a+)]+"])
def test_lint_accepts_linear_regex(pattern):
    d = {"title": "t", "id": "5f1d0f4e-1c2b-4c55-9a7e-6f0b7c1d2e3a", "description": "d", "level": "low",
         "status": "test", "logsource": {"category": "process_creation", "product": "windows"},
         "detection": {"selection": {"CommandLine|re": pattern}, "condition": "selection"},
         "tags": ["attack.t1059"], "falsepositives": ["x"]}
    assert "W213" not in [f.code for f in lint_rule(Rule.from_dict(d), profile="sigma")]
