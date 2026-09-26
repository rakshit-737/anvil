"""Checks against the real public datasets. Skipped unless $ANVIL_DATA holds a download.

    python scripts/download_data.py all
    ANVIL_DATA=./data python -m pytest -m realdata
"""
import os
from collections import Counter
from pathlib import Path

import pytest

DATA = Path(os.environ.get("ANVIL_DATA", Path(__file__).resolve().parents[1] / "data"))
pytestmark = pytest.mark.realdata


def need(*parts):
    p = DATA.joinpath(*parts)
    if not p.exists():
        pytest.skip(f"{p} not downloaded")
    return p


@pytest.fixture(scope="module")
def sigma_lib():
    from anvil.runner import Library, load_rule_dir
    root = need("sigma")
    rules, rep = load_rule_dir([root / "rules", root / "rules-emerging-threats", root / "rules-threat-hunting"])
    assert rep.loaded > 3000 and not rep.parse_errors
    return root, Library.build(rules)


def test_sigmahq_regression_replay(sigma_lib):
    from anvil.regression import run_all
    root, lib = sigma_lib
    st = Counter(r.status for r in run_all(lib, root))
    evaluable = st["pass"] + st["fail"]
    assert evaluable > 400
    assert st["pass"] / evaluable >= 0.99


def test_sigmahq_compiles_and_routes(sigma_lib):
    _, lib = sigma_lib
    assert len(lib.unsupported) < 0.01 * len(lib.rules)
    windows = [r for r in lib.rules.values() if r.logsource.product == "windows"]
    unroutable = [r for r in windows if r.id in lib.unroutable]
    assert len(unroutable) < 0.02 * len(windows)


def test_attack_stix_catalog():
    from anvil.attack import load_stix
    cat = load_stix(need("attack", "enterprise-attack-19.2.json"))
    assert len(cat.active("Windows")) > 400
    assert any(t.revoked for t in cat.techniques.values())


def test_otrf_catalog():
    from anvil.otrf import load_catalog
    ds = load_catalog(need("otrf"))
    assert len(ds) > 80 and sum(d.available for d in ds) > 80
