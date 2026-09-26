from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from anvil.cli import main
from anvil.coverage import coverage, navigator_layer
from anvil.decay import regressions, schema_drift
from anvil.engine import ConditionError, match_selection, parse_condition, run
from anvil.harness import GatePolicy, evaluate, evaluate_all
from anvil.lint import has_errors, lint_rule, lint_rules
from anvil.loader import load_rules
from anvil.models import Rule
from anvil.quality import score_rule
from anvil.synth import generate

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "rules"
NOISY = ROOT / "examples" / "noisy"


@pytest.fixture(scope="module")
def corpus():
    return generate(3000, seed=7)


@pytest.fixture(scope="module")
def rules():
    return load_rules(RULES)


def mk(detection, **kw) -> Rule:
    base = {
        "id": "11111111-2222-3333-4444-555555555555", "title": "t", "description": "d",
        "status": "test", "level": "low", "logsource": {"product": "windows"},
        "tags": ["attack.t1033"], "falsepositives": ["x"], "detection": detection,
        "tests": {"true_positives": [{"a": 1}], "true_negatives": [{"a": 2}]},
    }
    base.update(kw)
    return Rule.from_dict(base)


# ---------- engine ----------
EV = {"Image": r"C:\Windows\System32\cmd.exe", "CommandLine": "cmd /c whoami /all", "Pid": 42,
      "proc": {"name": "cmd.exe"}, "Tags": ["a", "b"]}


@pytest.mark.parametrize("sel,expected", [
    ({"Image|endswith": r"\cmd.exe"}, True),
    ({"Image|endswith": r"\CMD.EXE"}, True),                 # case-insensitive
    ({"Image|endswith|cased": r"\CMD.EXE"}, False),
    ({"CommandLine|contains": ["foo", "whoami"]}, True),     # list = OR
    ({"CommandLine|contains|all": ["whoami", "/all"]}, True),
    ({"CommandLine|contains|all": ["whoami", "/priv"]}, False),
    ({"CommandLine|startswith": "cmd"}, True),
    ({"CommandLine|re": r"who\w+"}, True),
    ({"Image": r"C:\Windows\*\cmd.exe"}, True),               # glob
    ({"Pid": 42}, True),
    ({"Missing|exists": False}, True),
    ({"Image|exists": True}, True),
    ({"Missing": "x"}, False),
    ({"proc.name": "cmd.exe"}, True),                        # dotted path
    ({"Tags": "b"}, True),                                   # multi-valued field
    ({"Image|endswith": r"\cmd.exe", "Pid": 1}, False),      # map = AND
    ([{"Pid": 1}, {"Pid": 42}], True),                       # list of maps = OR
    (["whoami"], True),                                      # keywords
])
def test_match_selection(sel, expected):
    assert match_selection(EV, sel) is expected


def test_unknown_modifier_raises():
    with pytest.raises(ValueError):
        match_selection(EV, {"Image|bogus": "x"})


@pytest.mark.parametrize("cond,expected", [
    ("a and b", True), ("a and c", False), ("a or c", True), ("not c", True),
    ("a and not (b and c)", True), ("1 of sel*", True), ("all of sel*", False),
    ("all of them", False), ("1 of them", True), ("c or a and b", True),
])
def test_conditions(cond, expected):
    det = {"a": {"Pid": 42}, "b": {"Image|contains": "cmd"}, "c": {"Pid": 0},
           "sel1": {"Pid": 42}, "sel2": {"Pid": 1}, "condition": cond}
    r = mk(det)
    assert (run(r, [EV]) == [0]) is expected


@pytest.mark.parametrize("cond", ["a and", "(a", "a b", "zzz", "1 of nope*", "", "a & b"])
def test_bad_conditions(cond):
    with pytest.raises(ConditionError):
        parse_condition(cond, ["a", "b"])


# ---------- lint ----------
def test_shipped_rules_lint_clean(rules):
    assert len(rules) >= 5
    assert lint_rules(rules) == []


def test_lint_catches_problems():
    r = mk({"sel": {"X|re": "(", "Y|contains": "a"}, "unused": {"Z": 1}, "condition": "sel"},
           id="not-a-uuid", level="urgent", tags=["attack.t12"], tests={})
    codes = {f.code for f in lint_rule(r)}
    assert {"A101", "A103", "A107", "A111", "A112", "W202", "W205", "W203"} <= codes
    assert has_errors(lint_rule(r))


def test_lint_duplicate_ids(rules):
    codes = [f.code for f in lint_rules([rules[0], copy.deepcopy(rules[0])])]
    assert "A113" in codes


def test_lint_bad_condition():
    codes = {f.code for f in lint_rule(mk({"s": {"a": 1}, "condition": "s and x"}))}
    assert "A110" in codes


# ---------- harness ----------
def test_shipped_rules_pass_gate(rules, corpus):
    results = evaluate_all(rules, corpus)
    assert all(r.passed for r in results), [(r.title, r.reasons) for r in results if not r.passed]
    assert all(r.recall == 1.0 and r.fp_hits == 0 for r in results)


def test_noisy_rule_blocked(corpus):
    (noisy,) = load_rules(NOISY)
    res = evaluate(noisy, corpus, GatePolicy(soc_capacity_per_day=200, capacity_share=0.1))
    assert not res.passed
    assert res.fp_hits > 100
    assert any("alerts/day" in x for x in res.reasons)
    assert any("FP rate" in x for x in res.reasons)


def test_missed_tp_and_tn_fire_fail():
    r = mk({"s": {"a": 2}, "condition": "s"})  # TP a=1 misses, TN a=2 fires
    res = evaluate(r, [])
    assert not res.passed and res.missed_tps == [0] and res.tn_fired == 1


# ---------- coverage / quality / decay ----------
def test_coverage(rules):
    rep = coverage(rules)
    assert rep["covered"] == 5 and rep["catalog_size"] >= 10
    none_valid = coverage(rules, passing_ids=set())
    assert none_valid["validated"] == 0
    layer = navigator_layer(rep)
    assert {t["techniqueID"] for t in layer["techniques"]} >= {"T1059.001", "T1105"}


def test_quality_scores(rules, corpus):
    for r in rules:
        q = score_rule(r, evaluate(r, corpus))
        assert 0 <= q.score <= 100 and q.grade in "ABCDF"
        assert q.score >= 75
    (noisy,) = load_rules(NOISY)
    assert score_rule(noisy, evaluate(noisy, corpus)).score < 75


def test_schema_drift(rules):
    assert schema_drift(rules, generate(200, schema="v1")) == {}
    drift = schema_drift(rules, generate(200, schema="v2"))
    assert set(drift) == {r.id for r in rules}


def test_regression_detection(rules, corpus):
    base = {r.rule_id: r.to_dict() for r in evaluate_all(rules, corpus)}
    broken = copy.deepcopy(rules[0])
    broken.detection = {"s": {"Image": "nope"}, "condition": "s"}
    msgs = regressions(base, evaluate_all([broken], corpus))
    assert "stopped firing" in msgs[broken.id][0]


# ---------- CLI ----------
def test_cli_end_to_end(tmp_path, capsys):
    corpus = tmp_path / "c.jsonl"
    assert main(["synth", "--out", str(corpus), "-n", "500"]) == 0
    assert main(["lint", "--rules", str(RULES)]) == 0
    base = tmp_path / "base.json"
    assert main(["test", "--rules", str(RULES), "--corpus", str(corpus), "--save-baseline", str(base)]) == 0
    assert json.loads(base.read_text())
    assert main(["test", "--rules", str(NOISY), "--corpus", str(corpus)]) == 1
    nav = tmp_path / "layer.json"
    assert main(["coverage", "--rules", str(RULES), "--corpus", str(corpus), "--navigator", str(nav)]) == 0
    assert nav.exists()
    assert main(["score", "--rules", str(RULES), "--corpus", str(corpus)]) == 0
    assert main(["decay", "--rules", str(RULES), "--corpus", str(corpus), "--baseline", str(base)]) == 0
    v2 = tmp_path / "v2.jsonl"
    main(["synth", "--out", str(v2), "-n", "100", "--schema", "v2"])
    assert main(["decay", "--rules", str(RULES), "--corpus", str(v2)]) == 1
