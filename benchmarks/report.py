"""Render results/SUMMARY.md, docs/img/*.png and docs/dashboard.html from results/*.json.

Every proportion is printed as ``k/n, p% [lo, hi]`` (Wilson 95%), rounded once here
from the full-precision values in the JSON files.
"""
from __future__ import annotations

import json
from typing import Any

from benchmarks.common import RESULTS, ROOT
from benchmarks.stats import fmt_ci, fmt_p, fmt_prop, wilson

IMG = ROOT / "docs" / "img"
INK, MUTED, GRID = "#0b0b0b", "#52514e", "#e3e2dc"
BLUE, BLUE_LIGHT, ORANGE, AQUA = "#2a78d6", "#a9c8ee", "#eb6834", "#1baf7a"   # categorical slots 1-3
SYM, PRES, GLOB = "symbolic (ANVIL)", "field presence, per log source", "field presence, global (0.1 schema_drift)"
METHOD_LABEL = {SYM: "symbolic (ANVIL)", PRES: "field presence, per source", GLOB: "field presence, global"}


def _j(name: str) -> dict[str, Any] | None:
    p = RESULTS / name
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def _style(ax) -> None:
    for s in ("top", "right", "left"):
        ax.spines[s].set_visible(False)
    ax.spines["bottom"].set_color(GRID)
    ax.tick_params(colors=MUTED, labelsize=9, length=0)
    ax.xaxis.grid(True, color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)


def _kn(m: dict[str, Any], key: str) -> tuple[int, int]:
    """(k, n) of a decay method's recall or precision; older files lack the explicit pair."""
    kn = m.get(f"{key}_k_n")
    if kn:
        return int(kn[0]), int(kn[1])
    return 0, 0


def _decay_rows(dec: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """(label, methods) per scenario for the ablation figure: simulated changes, then the real check."""
    names = {"sysmon_to_4688": "Sysmon removed, 4688 only", "4688_no_cmdline": "... and 4688 command line off",
             "4688_no_cmdline_mixed": "... off on converted hosts only", "ecs_rename": "ECS field rename",
             "no_commandline": "CommandLine dropped"}
    rows = [(f"simulated: {names[c]}", d["methods"]) for c, d in dec["changes"].items()
            if c in names and d.get("decayed_tp_rules")]
    real = dec.get("real_sysmon_removal")
    if real:
        for inv, v in real["inventories"].items():
            if inv.startswith("native"):
                rows.append(("real OTRF: Sysmon removed (native 4688)", v["methods"]))
    return rows


def figures() -> list[str]:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return []
    IMG.mkdir(parents=True, exist_ok=True)
    made = []
    cov = _j("coverage.json")
    if cov:
        claimed, val = cov["claimed"]["tactics"], cov["tp_validated_and_gated"]["tactics"]
        tacs = [t for t in claimed if t][::-1]
        fig, ax = plt.subplots(figsize=(7.2, 4.6), dpi=110)
        tot = [claimed[t]["total"] for t in tacs]
        ax.barh(tacs, [100 * claimed[t]["covered"] / max(1, n) for t, n in zip(tacs, tot)], height=0.62,
                color=BLUE_LIGHT, label="claimed (ATT&CK tag on a rule)")
        ax.barh(tacs, [100 * val.get(t, {}).get("validated", 0) / max(1, n) for t, n in zip(tacs, tot)],
                height=0.62, color=BLUE, label="validated (fires on a real capture, within alert budget)")
        _style(ax)
        ax.set_xlim(0, 100)
        ax.set_xlabel("% of Windows techniques + sub-techniques", color=MUTED, fontsize=9)
        ax.set_title("SigmaHQ Windows rules: ATT&CK coverage claimed vs validated", loc="left", fontsize=11,
                     color=INK)
        ax.legend(frameon=False, fontsize=8, loc="upper center", bbox_to_anchor=(0.4, -0.13), ncol=2)
        fig.tight_layout()
        fig.savefig(IMG / "coverage_tactics.png")
        plt.close(fig)
        made.append("coverage_tactics.png")
    fp = _j("fp.json")
    if fp:
        groups = [("status", fp["by_status"]), ("folder", fp["by_folder"]), ("level", fp["by_level"])]
        labels, vals, lo, hi = [], [], [], []
        order = ["informational", "low", "medium", "high", "critical"]
        for name, g in groups:
            for k, v in sorted(g.items(), key=lambda kv: (order.index(kv[0]) if kv[0] in order else -1, kv[0])):
                n, f = v["observable"], v["fired"]
                ci = wilson(f, n) or [0.0, 0.0]
                p = 100 * f / n if n else 0.0
                labels.append(f"{name}: {k} ({f}/{n})")
                vals.append(p)
                lo.append(p - 100 * ci[0])
                hi.append(100 * ci[1] - p)
        fig, ax = plt.subplots(figsize=(7.2, 0.34 * len(labels) + 1.3), dpi=110)
        ax.barh(labels[::-1], vals[::-1], height=0.6, color=BLUE, xerr=[lo[::-1], hi[::-1]],
                error_kw={"ecolor": MUTED, "elinewidth": 1, "capsize": 2})
        for y, (v, h) in enumerate(zip(vals[::-1], hi[::-1])):
            ax.text(v + h + 0.8, y, f"{v:.1f}%", va="center", fontsize=8, color=MUTED)
        _style(ax)
        ax.set_xlabel("% of observable rules that fire on clean Windows hosts (bars: Wilson 95% CI)", color=MUTED,
                      fontsize=9)
        ax.set_title(f"Benign replay: {fp['corpus']['events']:,} events from evtx-baseline", loc="left",
                     fontsize=11, color=INK)
        fig.tight_layout()
        fig.savefig(IMG / "fp_by_group.png")
        plt.close(fig)
        made.append("fp_by_group.png")
    fm = _j("fpmodel.json")
    if fm:
        names = [n for n in fm["models"] if n != "random"] + ["random"]
        vals = [fm["models"][n]["pr_auc"] for n in names]
        bs = (fm.get("bootstrap") or {}).get("models", {})
        lo = [v - bs.get(n, {}).get("pr_auc_ci95", [v, v])[0] for n, v in zip(names, vals)]
        hi = [bs.get(n, {}).get("pr_auc_ci95", [v, v])[1] - v for n, v in zip(names, vals)]
        fig, ax = plt.subplots(figsize=(7.2, 2.8), dpi=110)
        colors = [BLUE if n in ("gbdt", "logreg") else BLUE_LIGHT for n in names]
        ax.barh(names[::-1], vals[::-1], height=0.6, color=colors[::-1],
                xerr=[lo[::-1], hi[::-1]], error_kw={"ecolor": MUTED, "elinewidth": 1, "capsize": 2})
        for y, (v, h) in enumerate(zip(vals[::-1], hi[::-1])):
            ax.text(v + h + 0.006, y, f"{v:.2f}", va="center", fontsize=8, color=MUTED)
        _style(ax)
        ax.set_xlabel("PR-AUC, 5-fold CV, seed 7; bars: 95% bootstrap CI over rules", color=MUTED, fontsize=9)
        ax.set_title("Predicting benign-noisy rules before testing", loc="left", fontsize=11, color=INK)
        fig.tight_layout()
        fig.savefig(IMG / "fpmodel.png")
        plt.close(fig)
        made.append("fpmodel.png")
    dec = _j("decay.json")
    if dec and dec.get("changes"):
        rows = _decay_rows(dec)
        if rows and all(_kn(m, "recall")[1] or m.get("recall") is None for _, ms in rows for m in ms.values()):
            fig, axes = plt.subplots(1, 2, figsize=(9.6, 0.62 * len(rows) + 1.9), dpi=110, sharey=True)
            colors = {SYM: BLUE, PRES: ORANGE, GLOB: AQUA}
            h = 0.26
            for ax, key, title in ((axes[0], "recall", "recall: broken rules flagged"),
                                   (axes[1], "precision", "precision: flags that are real breaks")):
                for j, m in enumerate((SYM, PRES, GLOB)):
                    ys, xs, el, eh = [], [], [], []
                    for i, (_, ms) in enumerate(rows[::-1]):
                        k, n = _kn(ms[m], key)
                        if not n:
                            continue
                        ci = wilson(k, n) or [0.0, 0.0]
                        p = 100 * k / n
                        ys.append(i + (1 - j) * h)
                        xs.append(p)
                        el.append(p - 100 * ci[0])
                        eh.append(100 * ci[1] - p)
                    ax.barh(ys, xs, height=h * 0.92, color=colors[m], label=METHOD_LABEL[m],
                            xerr=[el, eh], error_kw={"ecolor": MUTED, "elinewidth": 0.9, "capsize": 1.5})
                _style(ax)
                ax.set_xlim(0, 105)
                ax.set_title(title, loc="left", fontsize=10, color=INK)
                ax.set_xlabel("% (Wilson 95% CI)", color=MUTED, fontsize=9)
            axes[0].set_yticks(range(len(rows)))
            axes[0].set_yticklabels([r[0] for r in rows[::-1]], fontsize=8.5, color=INK)
            handles, labels = axes[0].get_legend_handles_labels()
            fig.legend(handles, labels, frameon=False, fontsize=8.5, loc="lower center", ncol=3,
                       bbox_to_anchor=(0.55, 0.0))
            fig.suptitle("Decay prediction without attack data: symbolic check vs field-presence checks",
                         x=0.01, ha="left", fontsize=11, color=INK)
            fig.tight_layout(rect=(0, 0.07, 1, 0.97))
            fig.savefig(IMG / "decay_ablation.png")
            plt.close(fig)
            made.append("decay_ablation.png")
    return made


def _t(rows: list[list[Any]], head: list[str]) -> str:
    out = ["| " + " | ".join(head) + " |", "|" + "|".join("---" for _ in head) + "|"]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


def _provenance_line() -> str:
    runs: dict[tuple[str, str], list[str]] = {}
    for p in sorted(RESULTS.glob("*.json")):
        d = json.loads(p.read_text(encoding="utf-8"))
        meta = d.get("provenance") if isinstance(d, dict) else None
        if meta is None and isinstance(d, dict):
            meta = {m["name"]: m["value"] for m in d.get("metadata", [])}
        if meta:
            runs.setdefault((str(meta.get("ci_run") or "local"), str(meta.get("git_sha", ""))[:7]), []).append(p.name)
    if len(runs) == 1:
        (run, sha), _ = next(iter(runs.items()))
        link = f"[{run}](https://github.com/rakshit-737/anvil-detection-engineering/actions/runs/{run})" if run != "local" else run
        return f"All result files come from `bench` run {link} at commit `{sha}`."
    return "Result files come from several runs: " + "; ".join(
        f"{run} at `{sha}` ({', '.join(files)})" for (run, sha), files in runs.items()) + "."


def summary() -> str:
    s = ["# ANVIL benchmark results", "", "Generated by `python benchmarks/bench.py report` from `results/*.json`. "
         + _provenance_line() + " Proportions are `k/n, p% [95% Wilson CI]`.", ""]
    lint = _j("lint.json")
    if lint:
        s += ["### SigmaHQ corpus lint", "",
              _t([[lint["rules"], lint["windows_rules"], lint["compiled"], lint["unsupported"],
                   lint["with_regression_test"], lint["test_or_stable_without_regression"],
                   lint["rules_with_errors"]]],
                 ["rules", "windows", "compiled", "unsupported", "with regression test",
                  "test/stable w/o regression test", "rules with lint errors"]), "",
              _t([[k, v] for k, v in lint["findings_by_code"].items()], ["finding", "count"]), ""]
        ag = lint.get("aggregation_census")
        if ag:
            u, d = ag.get("unsupported", {}), ag.get("deprecated", {})
            corr = sum(v.get("correlation_documents", 0) for v in ag.values())
            s += [f"Aggregations and correlations at the pinned commit: `unsupported/` holds {u.get('files')} rules, "
                  f"{u.get('with_count_call')} with `count()` and {u.get('with_aggregation_condition')} with any "
                  f"aggregation in the condition; `deprecated/` has {d.get('with_count_call')} `count()` rule; the "
                  f"rule folders have none; {corr} `correlation:` documents in total.", ""]
    eng = _j("engine.json")
    if eng:
        a, v, o = eng["anvil"], eng["anvil_v01"], eng["pysigma_sqlite"]
        n_cases = eng["cases"] - a.get("unreadable", 0)
        rows = [["ANVIL engine (1.x)", a.get("pass", 0), a.get("fail", 0), n_cases - a.get("pass", 0) - a.get("fail", 0),
                 fmt_prop(a.get("pass", 0), n_cases)],
                ["ANVIL 0.1 (baseline)", v.get("pass", 0), v.get("fail", 0), v.get("error", 0) + v.get("unsupported", 0),
                 fmt_prop(v.get("pass", 0), n_cases)]]
        if o.get("available"):
            n_o = o.get("pass", 0) + o.get("fail", 0) + o.get("convert-error", 0) + o.get("exec-error", 0)
            rows.append(["pySigma -> SQLite", o.get("pass", 0), o.get("fail", 0),
                         o.get("convert-error", 0) + o.get("exec-error", 0), fmt_prop(o.get("pass", 0), n_o)])
        s += ["### TP replay (recall) on SigmaHQ regression captures", "",
              "TP-only check, and the development acceptance set: over-matching is detectable in only a few "
              "captures.", "",
              f"{eng['cases']} regression cases ({eng['sample_events']} real events); "
              f"{a.get('unreadable', 0)} samples unreadable.", "",
              _t(rows, ["engine", "detected", "missed", "could not evaluate", "detection rate"]), ""]
        if o.get("available"):
            s += [f"ANVIL vs pySigma->SQLite: agree on {o.get('agree', 0)} cases, disagree on "
                  f"{o.get('disagree', 0)}.", ""]
            for d in o.get("disagreements", []):
                s.append(f"- {d['title']}: ANVIL {d.get('anvil', '?')}, SQLite {d.get('oracle', d.get('why'))}, "
                         f"expected {d.get('expected', '?')}")
            s.append("")
        b = eng.get("benign_sample")
        if b:
            nr = b.get("anvil_unrouted")
            s += [f"Benign sample ({b['events']} events): ANVIL 1.x raised {b['anvil']['alerts']} alerts from "
                  f"{b['anvil']['rules_fired']} rules with {b['anvil']['evaluations']:,} rule evaluations"
                  + (f"; the same 1.x engine with routing disabled raised {nr['alerts']} alerts from "
                     f"{nr['rules_fired']} rules with {nr['evaluations']:,} evaluations" if nr else "")
                  + f"; the 0.1 engine (no routing, older value semantics) raised {b['anvil_v01']['alerts']} alerts "
                  f"from {b['anvil_v01']['rules_fired']} rules with {b['anvil_v01']['evaluations']:,} evaluations.", ""]
    fp = _j("fp.json")
    if fp:
        c = fp["corpus"]
        s += ["### Benign replay (false positives)", "",
              f"{c['events']:,} events, {c['days']} host-days of clean Windows 10/11/Server 2022 AD telemetry "
              f"(install-day recordings); {fp['observable_rules']} of {fp['windows_rules']} Windows rules have their "
              f"log source present. Budget: {fp['policy']['budget_per_rule_per_day']:.0f} alerts per host-day per "
              f"rule ({100 * fp['policy']['share']:.0f}% of a {fp['policy']['capacity_per_day']:.0f}/day SOC).", "",
              _t([[fmt_prop(fp["fired_rules"], fp["observable_rules"]), fp["total_alerts"], fp["gate_fail"],
                   c["events_per_cpu_second"]]],
                 ["observable rules firing", "alerts", "rules over budget (1 host)", "events / CPU-second"]), ""]
        if fp.get("gate_fail_by_fleet_size"):
            s += ["Rates are alerts per host-day. Rules over the 20/day budget when the per-host rate is "
                  "projected to a fleet:", "",
                  _t([[h, n] for h, n in fp["gate_fail_by_fleet_size"].items()], ["hosts", "rules over budget"]), ""]
        for name in ("by_status", "by_folder", "by_level"):
            s += [_t([[k, v["observable"], fmt_prop(v["fired"], v["observable"]), v["gate_fail"]]
                      for k, v in fp[name].items()], [name.replace("by_", ""), "observable", "fired", "over budget"]),
                  ""]
        ag = fp["sigmahq_known_fp_agreement"]
        s += [f"Cross-check with SigmaHQ's `known-FPs.csv` (per rule id, MatchString filters not applied; the list "
              f"was also used during development): {fmt_prop(ag['on_known_fp_list'], ag['fired_medium_plus'])} of the "
              f"medium+ rules ANVIL saw firing are on the list.", ""]
        if "non_low_not_on_list" in ag:
            s += [f"SigmaHQ's goodlog CI is green on the same images, so these {len(ag['non_low_not_on_list'])} "
                  f"non-low rules that fire in ANVIL but are not excused by the list are rules where ANVIL fires and "
                  f"the reference checker does not (a lower bound: per-id excusing is more lenient than "
                  f"MatchString filtering):", ""]
            s += [f"- {r['title']} ({r['level']}, {r['hits']} hits)" for r in ag["non_low_not_on_list"]] + [""]
            s += [f"Reverse direction: {ag['known_fp_rules_fired']} of {ag['known_fp_rules_listed']} listed rules "
                  f"fire here (the list covers 7 images, ANVIL replays 3).", ""]
        s += ["Top noisy rules:", "", _t([[r["title"], r["level"], r["status"], r["folder"], r["hits"],
                                          r["alerts_per_day"], r["gate"]] for r in fp["rules"][:15] if r["hits"]],
                                        ["rule", "level", "status", "folder", "alerts", "per day", "gate"]), ""]
    ot = _j("otrf.json")
    if ot:
        n = ot["datasets"]
        s += ["### Emulated attacks (OTRF Security-Datasets)", "",
              "Technique detected = a rule tagged with the dataset technique or its parent fired (sibling "
              "sub-techniques do not count; they are credited only in the lenient column).", "",
              _t([[n, f"{ot['events']:,}", fmt_prop(ot["any_alert"], n, 0), ot["claimed_coverage"],
                   fmt_prop(ot["technique_detected"], n, 0), fmt_prop(ot.get("technique_detected_lenient", 0), n, 0)]],
                 ["datasets", "events", "any alert", "technique claimed by a rule", "technique detected",
                  "lenient (siblings credited)"]), ""]
        if ot["compound"]:
            s += [_t([[k, f"{v['events']:,}", v["rules_fired"], v["alerts"], v.get("technique_tags_on_fired_rules",
                                                                                   v.get("techniques_alerted"))]
                      for k, v in ot["compound"].items()],
                     ["APT29 evaluation capture", "events", "rules fired", "alerts",
                      "distinct technique tags on fired rules"]), ""]
    cov = _j("coverage.json")
    if cov:
        rows = [[k, v["catalog_size"], fmt_prop(v["covered"], v["catalog_size"]),
                 fmt_prop(v["validated"], v["catalog_size"]), f"{v['parent_validated']}/{v['parent_total']}"]
                for k, v in cov.items() if isinstance(v, dict) and "catalog_size" in v]
        s += [f"### ATT&CK coverage (Enterprise {cov['catalog']}, Windows)", "",
              _t(rows, ["view", "techniques", "tagged", "validated", "parent techniques validated"]), ""]
    dec = _j("decay.json")
    if dec:
        s += _decay_summary(dec)
    cv = _j("convert.json")
    if cv:
        s += ["### SIEM conversion (pySigma)", "",
              _t([[t, fmt_prop(v.get("converted", 0), cv["rules"]), v.get("seconds"),
                   "; ".join(f"{k}: {n}" for k, n in v.get("errors", {}).items())]
                  for t, v in cv.items() if isinstance(v, dict) and "converted" in v],
                 ["target", "converted (of Windows rules)", "seconds", "errors"]), ""]
    fm = _j("fpmodel.json")
    if fm:
        s += _fpmodel_summary(fm)
    dr = _j("draft.json")
    if dr:
        s += _draft_summary(dr)
    nx = _j("nixcloud.json")
    if nx:
        s += _nix_summary(nx)
    bo = _j("backend_opensearch.json")
    if bo:
        s += _backend_summary(bo)
    return "\n".join(s)


def _decay_summary(dec: dict[str, Any]) -> list[str]:
    nn = dec.get("none")
    s = ["### Decay monitor under telemetry changes", "",
         f"Field inventory: {dec.get('inventory', 'benign corpus')}."
         + (f" False-alarm floor on unchanged telemetry: {nn['library_flagged']} rules "
            f"({nn['library_flagged_pct']}%) are already broken/source-missing and are excluded; "
            f"{nn['tp_validated_flagged']} of them are TP-validated." if nn else ""), ""]
    if nn and nn.get("tp_validated_flagged_rules"):
        s += [f"- {r['title']} ({r['status']}; missing {', '.join(r['missing']) or '-'})"
              for r in nn["tp_validated_flagged_rules"]] + [""]

    def cell(m: dict[str, Any], key: str) -> str:
        k, n = _kn(m, key)
        if not n:
            return "-" if m.get(key) is None else f"{100 * m[key]:.1f}%"
        return fmt_prop(k, n)

    s += ["Simulated changes (ground truth: the change applied to each TP-validated rule's regression captures; "
          "the same transform builds the post-change benign inventory):", "",
          _t([[c, d["decayed_tp_rules"], METHOD_LABEL.get(m, m), cell(v, "recall"), cell(v, "precision"),
               v["library_flagged"]]
              for c, d in dec["changes"].items() for m, v in d.get("methods", {}).items()],
             ["change", "TP rules that stop firing", "method", "recall", "precision", "library flagged"]), ""]
    tests = [(c, b, t) for c, d in dec["changes"].items() for b, t in d.get("mcnemar_symbolic_vs", {}).items()]
    if tests:
        s += ["Exact McNemar tests, symbolic vs each presence check on the same rules (discordant counts "
              "symbolic-only / baseline-only):", "",
              _t([[c, METHOD_LABEL.get(b, b),
                   f"{t['false_alarms_on_unbroken_rules']['only_a']} / {t['false_alarms_on_unbroken_rules']['only_b']}"
                   f" of {t['false_alarms_on_unbroken_rules']['rules']}, p = "
                   f"{fmt_p(t['false_alarms_on_unbroken_rules']['p_exact'])}",
                   f"{t['recall_on_broken_rules']['only_a']} / {t['recall_on_broken_rules']['only_b']} of "
                   f"{t['recall_on_broken_rules']['rules']}, p = {fmt_p(t['recall_on_broken_rules']['p_exact'])}"]
                  for c, b, t in tests],
                 ["change", "vs", "false alarms on unbroken TP rules", "flags on broken TP rules"]), ""]
    real = dec.get("real_sysmon_removal")
    if real:
        s += [f"Real Sysmon removal (no simulator): {real['datasets']} OTRF captures that log both Sysmon EID 1 "
              f"({real['sysmon_eid1_events']:,} events) and native Security 4688 ({real['security_4688_events']:,}). "
              f"{real['rules_firing_before']} Windows rules fire on them; {real['rules_that_stop_firing']} fire on "
              "none once the Sysmon channel is dropped. Predictions come from the benign inventory:", "",
              _t([[inv.split(":")[0], METHOD_LABEL.get(m, m), cell(v, "recall"), cell(v, "precision"),
                   v["false_alarms"]]
                  for inv, d in real["inventories"].items() for m, v in d["methods"].items()],
                 ["inventory", "method", "recall", "precision", "false alarms"]), ""]
        flagged = [d.get("flagged_idx") for d in real["inventories"].values()]
        if len(flagged) == 2 and flagged[0] == flagged[1]:
            s += ["Both inventories flag exactly the same rules: the benign hosts' native 4688 events carry the same "
                  "per-source field set as the simulated conversion, so here the simulator and the real inventory "
                  "agree; only the ground truth differs from the simulated rows above.", ""]
        rt =[(inv, b, t) for inv, d in real["inventories"].items() for b, t in d["mcnemar_symbolic_vs"].items()]
        s += [_t([[inv.split(":")[0], METHOD_LABEL.get(b, b),
                   f"{t['false_alarms_on_unbroken_rules']['only_a']} / {t['false_alarms_on_unbroken_rules']['only_b']}"
                   f", p = {fmt_p(t['false_alarms_on_unbroken_rules']['p_exact'])}",
                   f"{t['recall_on_broken_rules']['only_a']} / {t['recall_on_broken_rules']['only_b']}, p = "
                   f"{fmt_p(t['recall_on_broken_rules']['p_exact'])}"] for inv, b, t in rt],
                 ["inventory", "symbolic vs", "false alarms (symbolic-only / baseline-only)",
                  "flags on broken rules (symbolic-only / baseline-only)"]), ""]
        for inv, d in real["inventories"].items():
            if d.get("false_alarm_examples") or d.get("missed_examples"):
                s += [f"{inv.split(':')[0]}: missed e.g. {'; '.join(d['missed_examples'][:4]) or '-'}; false alarms "
                      f"e.g. {'; '.join(d['false_alarm_examples'][:4]) or '-'}.", ""]
    return s


def _fpmodel_summary(fm: dict[str, Any]) -> list[str]:
    k = [x for x in next(iter(fm["models"].values())) if x.startswith("precision_at")][0]
    s = ["### FP-prediction model", "", f"{fm['n_rules']} observable rules, {fm['positives']} noisy "
         f"({fm['label']}). Point estimates from one CV run (seed 7); precision@k and recall use expected values "
         "under random tie-breaking.", "",
         _t([[n, m["roc_auc"], m["pr_auc"], m[k], m["recall_at_top10pct"]] for n, m in fm["models"].items()],
            ["scorer", "ROC-AUC", "PR-AUC", k.replace("_", " "), "recall @ top 10%"]), ""]
    rp = fm.get("repeated")
    if rp:
        def _ci(v: dict) -> str:
            ci = v.get("cv_repeat_interval95") or v.get("ci95")
            return f"{v['mean']:.3f} [{ci[0]:.3f}, {ci[1]:.3f}]"
        s += [f"Repeated {rp['folds']}-fold CV over {len(rp['seeds'])} seeds (mean [interval over CV "
              f"repetitions only, not over rules]):", "",
              _t([[n, _ci(m["roc_auc"]), _ci(m["pr_auc"]), _ci(m[k])] for n, m in rp["models"].items()],
                 ["scorer", "ROC-AUC", "PR-AUC", k.replace("_", " ")]), ""]
    bs = fm.get("bootstrap")
    if bs:
        def tail(m: dict[str, Any]) -> str:
            kn = m.get("pr_auc_n_delta_le_0")
            if kn:
                return f"{kn[0]}/{kn[1]}"
            p = m.get("pr_auc_p_delta_le_0")
            if p is None:
                return "-"
            n = bs["n_boot"]
            return f"{round(p * n)}/{n}"

        def ci3(x: Any) -> str:
            return f"[{x[0]:.3f}, {x[1]:.3f}]" if x else "-"
        s += [f"Bootstrap over rules ({bs['n_boot']} resamples, seed-7 out-of-fold scores), paired against "
              f"`{bs['reference']}`. The last column counts resamples with a PR-AUC difference <= 0 (a one-sided "
              "bootstrap tail; 1000/1000 means p > 0.999 for 'better than the reference').", "",
              _t([[n, ci3(m["roc_auc_ci95"]), ci3(m["pr_auc_ci95"]), ci3(m.get("pr_auc_delta_vs_ref_ci95")),
                   tail(m) if n != bs["reference"] else "-"] for n, m in bs["models"].items()],
                 ["scorer", "ROC-AUC 95% CI", "PR-AUC 95% CI", "dPR-AUC vs ref 95% CI", "resamples with d <= 0"]),
              ""]
    return s


def _draft_summary(dr: dict[str, Any]) -> list[str]:
    s = ["### Drafter: CTI text -> rule -> tested", "",
         _t([[b, v["drafts"], v["datasets_with_drafts"], fmt_prop(v["fires_on_own_capture"], v["datasets_with_drafts"]),
              v.get("gate_pass_and_fires", "-"), v["datasets_with_benign_fp"], v["benign_alerts_total"]]
             for b, v in dr["backends"].items()],
            ["backend", "drafts", "datasets with a draft (readable)", "fires on its emulation",
             "fires and within budget", "datasets with benign FPs", "benign alerts"]), "",
         f"SigmaHQ on the same {dr['sigmahq_same_datasets']['datasets']} datasets: any alert in "
         f"{dr['sigmahq_same_datasets'].get('any_alert', '?')}, technique detected in "
         f"{dr['sigmahq_same_datasets']['technique_detected']}.", ""]
    pr = dr.get("paired")
    if pr:
        s += ["Paired comparison on the same datasets (a dataset without a draft counts as a miss), exact McNemar:", "",
              _t([[scope, metric.replace("_", " "), fmt_prop(v["heuristic"], blk["datasets"], 0),
                   fmt_prop(v["keywords"], blk["datasets"], 0), f"{v['only_a']} / {v['only_b']}", fmt_p(v["p_exact"])]
                  for scope, blk in pr.items() for metric, v in blk.items() if metric != "datasets"],
                 ["datasets", "outcome", "heuristic", "keywords", "discordant (heuristic-only / keywords-only)",
                  "p"]), ""]
    return s


def _nix_summary(nx: dict[str, Any]) -> list[str]:
    s = ["### Linux and AWS CloudTrail (SigmaHQ linux + cloud/aws rules)", "",
         f"{nx['rules']['routed']} of {nx['rules']['linux_aws']} Linux/AWS rules routed; "
         f"{nx['labelled']} labelled captures.", "",
         _t([[k, v["datasets"], f"{v['events']:,}", fmt_prop(v["technique_detected"], v["datasets"], 0),
              fmt_prop(v["any_alert"], v["datasets"], 0)] for k, v in nx["by_kind"].items()]
            + [["all", nx["labelled"], "", fmt_prop(nx["technique_detected"], nx["labelled"], 0),
                fmt_prop(nx["any_alert"], nx["labelled"], 0)]],
            ["source", "captures", "events", "technique detected", "any alert"]), ""]
    if nx.get("zero_event_datasets"):
        s += ["Captures that parsed to 0 events: " + ", ".join(nx["zero_event_datasets"]), ""]
    le = nx.get("live_emulation")
    if le:
        n = len(le["techniques_emulated"])
        s += [f"Benign command emulation recorded on the CI runner ({le['events']:,} events: "
              + ", ".join(f"{k} {v:,}" for k, v in le["channels"].items())
              + f"): technique detected for {fmt_prop(len(le['techniques_detected']), n, 0)} emulated techniques "
              f"(detected {', '.join(le['techniques_detected']) or 'none'}; missed "
              f"{', '.join(le['techniques_missed']) or 'none'}); {le['rules_fired']} Linux rules fired "
              f"{le['alerts']} alerts.", ""]
    lb = nx.get("linux_benign")
    if lb:
        s += [f"Benign Linux telemetry recorded on the CI runner ({lb['events']:,} events: "
              + ", ".join(f"{k} {v:,}" for k, v in lb.get("channels", {}).items())
              + f"; {lb['window_hours']} h; {lb['workload']}): {lb['rules_fired']} Linux rules fired "
              f"{lb['alerts']} alerts. The window is too short to project a daily rate, so this is a smoke test of "
              "the Linux parsers and rules on benign activity, not an FP-rate estimate.", ""]
    return s


def _backend_summary(bo: dict[str, Any]) -> list[str]:
    rg, bn = bo["regression"], bo["benign"]
    ft = bn["fire_table"]
    either = bn.get("fire_in_either", ft["both"] + ft["anvil_only"] + ft["opensearch_only"])
    either_same = bn.get("fire_in_either_same_event_set")
    kci = bn.get("fire_kappa_ci95_bootstrap")
    s = [f"### Real backend: OpenSearch {bo['backend']['version']} vs ANVIL", "",
         "Rules converted by pySigma's OpenSearch Lucene backend with pySigma's own Sysmon + Windows "
         "log-source pipelines (independent of ANVIL's router), executed with `_search` in an OpenSearch "
         "container in CI.", "",
         _t([["regression captures: verdict", fmt_prop(rg.get("verdict_agree", 0), rg.get("compared", 0))],
             ["regression captures: exact count", fmt_prop(rg.get("count_agree", 0), rg.get("compared", 0))],
             ["benign sample: same matching events per rule",
              fmt_prop(bn.get("same_event_set", 0), bn.get("compared", 0), 2)]]
            + ([["benign sample: same events, rules that fire in either engine",
                 fmt_prop(either_same, either, 0)]] if either_same is not None else []),
            ["comparison", "agree"]), "",
         f"Benign fire/no-fire table: {ft}; Cohen's kappa {bn['fire_kappa']:.2f}"
         + (f" (bootstrap 95% CI [{kci[0]:.2f}, {kci[1]:.2f}])" if kci else "")
         + f". Disagreements by modifier: {bn.get('disagreements_by_modifier', {})}.", ""]
    qe = bo.get("query_errors_by_type")
    s += [f"Query errors: regression {rg.get('query-error', 0)}, benign {bn.get('query-error', 0)}"
          + (f" ({qe})" if qe else "") + f"; conversion errors {bo.get('convert_errors', {})}; values above Lucene's "
          f"term limit (not indexed): {bo.get('values_over_term_limit', {})}.", ""]
    if bo.get("query_errors"):
        s += [_t([[q["rule"], q["set"], q.get("status"), q.get("type"),
                   str(q.get("caused_by") or q.get("reason", ""))[:160].replace("|", "\\|")]
                  for q in bo["query_errors"]], ["rule", "set", "HTTP", "error type", "reason"]), ""]
    return s


def build() -> None:
    made = figures()
    (RESULTS / "SUMMARY.md").write_text(summary(), encoding="utf-8")
    from anvil.dashboard import render
    render(RESULTS, ROOT / "docs" / "dashboard.html")
    print(f"figures: {made}; wrote results/SUMMARY.md and docs/dashboard.html")


__all__ = ["build", "figures", "fmt_ci", "summary"]
