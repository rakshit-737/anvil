"""--rules handling: several paths, single files, missing paths and empty sets."""
import shutil
from pathlib import Path

from anvil.cli import main

ROOT = Path(__file__).resolve().parents[1]


def _corpus(tmp_path):
    out = tmp_path / "b.jsonl"
    assert main(["synth", "--out", str(out), "-n", "300"]) == 0
    return str(out)


def test_test_uses_every_rules_folder(tmp_path):
    c = _corpus(tmp_path)
    assert main(["test", "--rules", "rules", "--corpus", c]) == 0
    # the noisy example must be evaluated (and fail) even when listed second
    assert main(["test", "--rules", "rules", "examples/noisy", "--corpus", c, "--max-fp-rate", "0"]) == 1


def test_single_rule_file_is_loaded(tmp_path):
    c = _corpus(tmp_path)
    f = next((ROOT / "examples" / "noisy").glob("*.yml"))
    assert main(["test", "--rules", str(f), "--corpus", c, "--max-fp-rate", "0"]) == 1


def test_missing_path_and_empty_set_fail(tmp_path, capsys):
    assert main(["lint", "--rules", "does-not-exist"]) == 2
    empty = tmp_path / "empty"
    empty.mkdir()
    assert main(["lint", "--rules", str(empty)]) == 2
    assert main(["lint", "--rules", str(empty), "--allow-empty"]) == 0
    assert "not found" in capsys.readouterr().err


def test_lint_single_draft_file_runs_review_gate(tmp_path):
    d = tmp_path / "d"
    assert main(["draft", str(ROOT / "examples" / "cti" / "fin_x_report.md"), "--out", str(d)]) == 0
    f = next(d.glob("*.yml"))
    assert main(["lint", "--rules", str(f)]) == 1
    shutil.rmtree(d)


def test_missing_corpus_is_usage_error(tmp_path):
    assert main(["test", "--corpus", str(tmp_path / "nope.jsonl")]) == 2
