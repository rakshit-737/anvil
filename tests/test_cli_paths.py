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


def test_regress_missing_or_empty_sigma_path_fails(tmp_path, capsys):
    assert main(["regress", "--sigma", str(tmp_path / "nope")]) == 2
    empty = tmp_path / "empty"
    empty.mkdir()
    assert main(["regress", "--sigma", str(empty)]) == 2           # no rule folders
    (empty / "rules").mkdir()
    assert main(["regress", "--sigma", str(empty)]) == 2           # rule folder without rules
    err = capsys.readouterr().err
    assert "not found" in err and "SigmaHQ checkout" in err


def test_regress_without_regression_cases_fails(tmp_path, capsys):
    r = tmp_path / "sigma" / "rules"
    r.mkdir(parents=True)
    shutil.copy(next((ROOT / "rules").rglob("*.yml")), r / "x.yml")
    assert main(["regress", "--sigma", str(tmp_path / "sigma")]) == 2
    assert "regression_data" in capsys.readouterr().err


def test_report_needs_result_files(tmp_path):
    assert main(["report", "--results", str(tmp_path / "nope"), "--out", str(tmp_path / "x.html")]) == 2
    assert main(["report", "--results", str(tmp_path), "--out", str(tmp_path / "x.html")]) == 2
    assert not (tmp_path / "x.html").exists()


def test_ingest_missing_source_is_usage_error(tmp_path, capsys):
    assert main(["ingest", str(tmp_path / "nope.evtx"), "--out", str(tmp_path / "o")]) == 2
    assert "not found" in capsys.readouterr().err
