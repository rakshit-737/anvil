"""Predict whether a rule will be noisy *before* running it on a benign corpus.

Spec item "FP-rate prediction ML": static rule features -> P(rule fires on
clean telemetry). The model is trained on labels produced by ANVIL itself
(did the rule fire on the evtx-baseline corpus?), restricted to rules whose
log source actually occurs in that corpus, and evaluated with stratified
cross-validation against simple heuristics a reviewer would otherwise use.

Requires scikit-learn (``pip install anvil-dac[ml]``).
"""
from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from .engine import ENCODING_MODS, UNSUPPORTED_MODS
from .models import Rule

LEVEL = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
STATUS = {"unsupported": 0, "deprecated": 0, "experimental": 1, "test": 2, "stable": 3}
CATEGORIES = ["process_creation", "registry_set", "registry_event", "image_load", "file_event",
              "network_connection", "process_access", "ps_script", "ps_module", "pipe_created",
              "dns_query", "create_remote_thread", "registry_delete", "registry_add", "driver_load"]
SERVICES = ["security", "system", "application", "powershell", "windefend", "sysmon"]


def _walk_values(sel: Any):
    if isinstance(sel, dict):
        for k, v in sel.items():
            yield str(k), v
    elif isinstance(sel, list):
        for s in sel:
            if isinstance(s, dict):
                yield from _walk_values(s)
            else:
                yield "", s


def features(rule: Rule) -> dict[str, float]:
    """Return the static FP-prediction features of a rule."""
    f: dict[str, float] = {}
    f["level"] = LEVEL.get(rule.level, 2)
    f["status"] = STATUS.get(rule.status, 1)
    path = rule.path.replace("\\", "/").lower()
    f["hunting"] = float("rules-threat-hunting" in path)
    f["emerging"] = float("rules-emerging-threats" in path)
    cat = rule.logsource.category.lower()
    for c in CATEGORIES:
        f[f"cat_{c}"] = float(cat == c)
    f["cat_other"] = float(bool(cat) and cat not in CATEGORIES)
    for s in SERVICES:
        f[f"svc_{s}"] = float(rule.logsource.service.lower() == s)
    sels = rule.selections
    cond = rule.condition.lower()
    f["n_selections"] = len(sels)
    f["n_filters"] = sum(1 for n in sels if n.lower().startswith("filter"))
    f["n_optional_filters"] = sum(1 for n in sels if n.lower().startswith("filter_optional"))
    f["has_not"] = float(" not " in f" {cond} ")
    f["n_or"] = cond.count(" or ")
    f["n_and"] = cond.count(" and ")
    f["one_of"] = float("1 of" in cond)
    mods = {m: 0 for m in ["contains", "startswith", "endswith", "re", "all", "eq", "exists", "cidr",
                           "windash", "enc", "expand"]}
    lens: list[int] = []
    fields: set[str] = set()
    n_values = n_keywords = 0
    for _name, sel in sels.items():
        for key, val in _walk_values(sel):
            vals = val if isinstance(val, list) else [val]
            if not key:
                n_keywords += len(vals)
                continue
            field, *ms = key.split("|")
            fields.add(field)
            n_values += len(vals)
            if not ms or all(m == "cased" for m in ms):
                mods["eq"] += len(vals)
            for m in ms:
                if m in mods:
                    mods[m] += len(vals)
                elif m in ENCODING_MODS:
                    mods["enc"] += len(vals)
                elif m in UNSUPPORTED_MODS:
                    mods["expand"] += 1
            lens.extend(len(str(v)) for v in vals if v is not None)
    for m, n in mods.items():
        f[f"mod_{m}"] = n
    f["n_values"] = n_values
    f["n_keywords"] = n_keywords
    f["n_fields"] = len(fields)
    f["min_len"] = min(lens) if lens else 0
    f["mean_len"] = sum(lens) / len(lens) if lens else 0
    f["short_values"] = sum(1 for n in lens if n < 5)
    f["wildcards"] = sum(1 for _, s in sels.items() for _k, v in _walk_values(s)
                         for x in (v if isinstance(v, list) else [v]) if isinstance(x, str) and "*" in x)
    for fld in ("Image", "CommandLine", "ParentImage", "OriginalFileName", "TargetObject", "ImageLoaded",
                "TargetFilename", "Hashes", "EventID"):
        f[f"field_{fld}"] = float(fld in fields)
    fps = " ".join(str(x) for x in rule.falsepositives).lower()
    f["n_falsepositives"] = len(rule.falsepositives)
    f["fp_mentions_legit"] = float(bool(re.search(r"legitimate|admin|software|installer|update", fps)))
    f["fp_unknown"] = float(fps.strip() in ("unknown", "unlikely", ""))
    f["n_tags"] = len(rule.tags)
    f["desc_len"] = len(rule.description)
    return f


def matrix(rules: list[Rule]) -> tuple[list[str], list[list[float]]]:
    """Return (feature names, feature matrix) for a list of rules."""
    rows = [features(r) for r in rules]
    names = sorted(rows[0]) if rows else []
    return names, [[row[n] for n in names] for row in rows]


def expected_top_k(y: Any, s: Any, k: int) -> float:
    """Expected positives among the top-``k`` scores when ties are broken uniformly at random.

    ``np.argsort`` breaks ties by row order, which flatters coarse scores (a 5-valued
    heuristic) whenever rows happen to be sorted by label.
    """
    import numpy as np
    y, s = np.asarray(y), np.asarray(s)
    got, left = 0.0, k
    for v in sorted(set(s.tolist()), reverse=True):
        grp = s == v
        n = int(grp.sum())
        pos = float(y[grp].sum())
        if n <= left:
            got += pos
            left -= n
        else:
            got += pos * left / n
            left = 0
        if left == 0:
            break
    return got


def bootstrap_auc(y: Any, scores: dict[str, Any], reference: str, n_boot: int = 1000,
                  seed: int = 7) -> dict[str, Any]:
    """95% percentile intervals over rules (resampled with replacement) and paired deltas vs ``reference``."""
    import numpy as np
    from sklearn.metrics import average_precision_score, roc_auc_score
    y = np.asarray(y)
    rng = np.random.default_rng(seed)
    vals: dict[str, dict[str, list[float]]] = {m: {"roc_auc": [], "pr_auc": []} for m in scores}
    for _ in range(n_boot):
        idx = rng.integers(0, len(y), len(y))
        if y[idx].sum() in (0, len(idx)):
            continue
        for m, s in scores.items():
            s = np.asarray(s)
            vals[m]["roc_auc"].append(roc_auc_score(y[idx], s[idx]))
            vals[m]["pr_auc"].append(average_precision_score(y[idx], s[idx]))
    out: dict[str, Any] = {"n_boot": n_boot, "reference": reference, "models": {}}
    for m in scores:
        row: dict[str, Any] = {}
        for metric in ("roc_auc", "pr_auc"):
            a = np.asarray(vals[m][metric])
            row[metric + "_ci95"] = [round(float(np.percentile(a, 2.5)), 3), round(float(np.percentile(a, 97.5)), 3)]
            if m != reference:
                d = a - np.asarray(vals[reference][metric])
                row[metric + "_delta_vs_ref_ci95"] = [round(float(np.percentile(d, 2.5)), 3),
                                                      round(float(np.percentile(d, 97.5)), 3)]
                row[metric + "_p_delta_le_0"] = round(float((d <= 0).mean()), 3)
        out["models"][m] = row
    return out


def cross_validate(rules: list[Rule], labels: list[int], seed: int = 7, folds: int = 5,
                   importance: bool = True, bootstrap: bool = False) -> dict[str, Any]:
    """Stratified k-fold CV for the ML models vs. reviewer heuristics. Returns metrics."""
    import numpy as np
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import average_precision_score, roc_auc_score
    from sklearn.model_selection import StratifiedKFold
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler

    names, X = matrix(rules)
    Xa, y = np.asarray(X, dtype=float), np.asarray(labels)
    skf = StratifiedKFold(n_splits=folds, shuffle=True, random_state=seed)
    models = {
        "logreg": lambda: make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000, C=0.5,
                                                                             class_weight="balanced")),
        "gbdt": lambda: HistGradientBoostingClassifier(max_depth=3, learning_rate=0.05, max_iter=300,
                                                       class_weight="balanced", random_state=seed),
    }
    oof = {k: np.zeros(len(y)) for k in models}
    for tr, te in skf.split(Xa, y):
        for k, mk in models.items():
            m = mk().fit(Xa[tr], y[tr])
            oof[k][te] = m.predict_proba(Xa[te])[:, 1]
    col = {n: i for i, n in enumerate(names)}
    heur = {
        # what a reviewer would use without a model
        "heuristic_level": -Xa[:, col["level"]],                          # low/info = noisy
        "heuristic_hunting": Xa[:, col["hunting"]] - 0.1 * Xa[:, col["level"]],
        "heuristic_no_filter": -(Xa[:, col["n_filters"]]) - 0.1 * Xa[:, col["level"]],
    }
    scores = {**oof, **heur}
    k = max(1, int(y.sum()))
    out: dict[str, Any] = {"n_rules": int(len(y)), "positives": int(y.sum()), "features": len(names),
                           "models": {}}
    rng = np.random.default_rng(seed)
    scores["random"] = rng.random(len(y))
    k10 = max(1, len(y) // 10)
    for name, s in scores.items():
        out["models"][name] = {
            "roc_auc": round(float(roc_auc_score(y, s)), 3),
            "pr_auc": round(float(average_precision_score(y, s)), 3),
            f"precision_at_{k}": round(expected_top_k(y, s, k) / k, 3),
            "recall_at_top10pct": round(expected_top_k(y, s, k10) / max(1, y.sum()), 3),
        }
    out["tie_breaking"] = "expected value under uniformly random tie-breaking"
    if bootstrap:
        out["bootstrap"] = bootstrap_auc(y, scores, "heuristic_level", seed=seed)
    if not importance:
        return out
    final = models["gbdt"]().fit(Xa, y)
    try:
        from sklearn.inspection import permutation_importance
        imp = permutation_importance(final, Xa, y, scoring="average_precision", n_repeats=5, random_state=seed)
        order = np.argsort(-imp.importances_mean)[:10]
        out["top_features"] = [(names[i], round(float(imp.importances_mean[i]), 4)) for i in order]
    except Exception:  # noqa: BLE001 - importance is a nice-to-have
        out["top_features"] = []
    return out


def repeated_cv(rules: list[Rule], labels: list[int], seeds: Iterable[int] = range(10),
                folds: int = 5) -> dict[str, Any]:
    """Repeat stratified CV over several seeds; report the mean and a 95% t-interval per metric.

    The interval only measures fold-assignment (CV-seed) variation on the same rules, not
    sampling uncertainty over rules: use ``cross_validate(..., bootstrap=True)`` for that.
    The heuristics are deterministic, so their interval collapses to a point.
    """
    import statistics

    seeds = list(seeds)
    runs = [cross_validate(rules, labels, seed=s, folds=folds, importance=False) for s in seeds]
    t975 = {2: 12.706, 3: 4.303, 4: 3.182, 5: 2.776, 6: 2.571, 7: 2.447, 8: 2.365, 9: 2.306, 10: 2.262}
    out: dict[str, Any] = {"seeds": seeds, "folds": folds, "models": {}}
    for model in runs[0]["models"]:
        out["models"][model] = {}
        for metric in runs[0]["models"][model]:
            vals = [r["models"][model][metric] for r in runs]
            mean = statistics.fmean(vals)
            sd = statistics.stdev(vals) if len(vals) > 1 else 0.0
            half = t975.get(len(vals), 1.96) * sd / len(vals) ** 0.5
            out["models"][model][metric] = {"mean": round(mean, 3),
                                            "cv_repeat_interval95": [round(mean - half, 3), round(mean + half, 3)]}
    return out
