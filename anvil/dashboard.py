"""Static detection-health dashboard (single self-contained HTML file).

Rendered from the ``results/*.json`` written by ``benchmarks/bench.py`` (or by
a scheduled CI job). No JavaScript framework, no CDN: it opens from disk, can
be published as a CI artifact or GitHub Pages, and diffs cleanly in git.
"""
from __future__ import annotations

import html
import json
import math
from pathlib import Path
from typing import Any

CSS = """
:root{--bg:#f7f7f5;--panel:#fff;--ink:#1d1d1b;--muted:#6b6b66;--line:#e3e2dc;--ok:#2f7d4f;--warn:#b7791f;
--bad:#b23b3b;--accent:#2f5d8a;--bar:#2f5d8a;--bar2:#9cb7d1}
@media (prefers-color-scheme:dark){:root{--bg:#141413;--panel:#1d1d1b;--ink:#ecebe6;--muted:#a3a29b;
--line:#33332f;--ok:#5fb383;--warn:#d9a441;--bad:#e06c6c;--accent:#7aa7d6;--bar:#7aa7d6;--bar2:#3c5a78}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1180px;margin:0 auto;padding:28px 16px 60px}
h1{font-size:26px;margin:0 0 4px}h2{font-size:18px;margin:34px 0 10px}
.sub{color:var(--muted);margin:0 0 22px}
.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}
@media(max-width:900px){.kpis{grid-template-columns:repeat(2,1fr)}}@media(max-width:420px){.kpis{grid-template-columns:1fr}}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.kpi b{display:block;font-size:26px;font-variant-numeric:tabular-nums}.kpi span{color:var(--muted);font-size:13px}
.kpi i{display:block;font-style:normal;color:var(--ink);font-size:12px;margin-top:4px;font-variant-numeric:tabular-nums}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px;overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:14px}th,td{text-align:left;padding:6px 8px;
border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-weight:600}
td.n{text-align:right;font-variant-numeric:tabular-nums}
.pill{display:inline-block;padding:1px 8px;border-radius:99px;font-size:12px;font-weight:600}
.pass{background:color-mix(in srgb,var(--ok) 18%,transparent);color:var(--ok)}
.fail{background:color-mix(in srgb,var(--bad) 18%,transparent);color:var(--bad)}
.warn{background:color-mix(in srgb,var(--warn) 18%,transparent);color:var(--warn)}
.bars{display:grid;grid-template-columns:190px 1fr 70px;gap:6px 10px;align-items:center;font-size:13px}
.track{background:var(--line);border-radius:4px;height:12px;position:relative;overflow:hidden}
.fill{position:absolute;left:0;top:0;bottom:0;background:var(--bar2)}
.fill2{position:absolute;left:0;top:0;bottom:0;background:var(--bar)}
.legend{color:var(--muted);font-size:12px;margin-top:8px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px}@media(max-width:800px){.grid2{grid-template-columns:1fr}}
footer{color:var(--muted);font-size:12px;margin-top:40px}
nav.top{display:flex;flex-wrap:wrap;gap:6px 18px;font-size:14px;margin-bottom:18px}
nav.top a,footer a{color:var(--accent)}
.cap{color:var(--muted);font-size:13px;margin:0 0 8px}
"""

DOCS = "https://rakshit-737.github.io/anvil/"


def _load(results: Path, name: str) -> dict[str, Any] | None:
    p = results / name
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def _e(x: Any) -> str:
    return html.escape(str(x))


def _kpi(value: Any, label: str, note: str = "") -> str:
    extra = f"<i>{_e(note)}</i>" if note else ""
    return f'<div class="kpi"><b>{_e(value)}</b><span>{_e(label)}</span>{extra}</div>'


def _wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float] | None:
    if not n:
        return None
    p = k / n
    den = 1 + z * z / n
    c = (p + z * z / (2 * n)) / den
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return max(0.0, c - h), min(1.0, c + h)


def _ci(k: int, n: int, digits: int = 0) -> str:
    """``p% [lo, hi]`` with a Wilson 95% interval."""
    ci = _wilson(k, n)
    if ci is None:
        return "n/a"
    return f"{100 * k / n:.{digits}f}% [{100 * ci[0]:.{digits}f}, {100 * ci[1]:.{digits}f}]"


def _stamp(results: Path) -> str:
    """Run id (linked) and commit of the results, or every pair if the files disagree."""
    seen: dict[tuple[str, str], int] = {}
    for p in sorted(results.glob("*.json")):
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        prov = d.get("provenance") if isinstance(d, dict) else None
        if prov and prov.get("git_sha"):
            key = (str(prov.get("ci_run") or ""), prov["git_sha"][:10])
            seen[key] = seen.get(key, 0) + 1
    parts = []
    for run, sha in seen:
        if run:
            parts.append(f'bench run <a href="https://github.com/rakshit-737/anvil/actions/runs/{_e(run)}">'
                         f'{_e(run)}</a> at commit <code>{_e(sha)}</code>')
        else:
            parts.append(f"a local run at commit <code>{_e(sha)}</code>")
    return f" Results from {' and '.join(parts)}." if parts else ""


def render(results: Path, out: Path) -> Path:
    """Write the dashboard HTML for the result files in ``results`` to ``out``."""
    lint, eng, fp = _load(results, "lint.json"), _load(results, "engine.json"), _load(results, "fp.json")
    cov, dec, otrf = _load(results, "coverage.json"), _load(results, "decay.json"), _load(results, "otrf.json")
    parts = [f'<main><nav class="top"><a href="{DOCS}">ANVIL docs</a><a href="{DOCS}evaluation/">Evaluation</a>'
             f'<a href="{DOCS}reproduce/">Reproduce</a><a href="https://github.com/rakshit-737/anvil">GitHub</a></nav>'
             '<h1>Detection health</h1><p class="sub">SigmaHQ rule library measured by ANVIL '
             f'against real public telemetry. Generated from <code>results/*.json</code>.{_stamp(results)}</p>'
             '<div class="kpis">']
    real = (dec or {}).get("real_sysmon_removal")
    inv = next((v for k, v in real["inventories"].items() if k.startswith("native")), None) if real else None
    sm = (dec or {}).get("changes", {}).get("sysmon_to_4688")
    if inv:
        sym = inv["methods"].get("symbolic (ANVIL)", {})
        pres = inv["methods"].get("field presence, per log source", {})
        k, n = sym.get("recall_k_n", [0, 0])
        parts.append(_kpi(f"{k}/{n}", "Sysmon removed from real OTRF captures: broken rules flagged statically",
                          f"{sym.get('false_alarms', 0)} false alarms vs {pres.get('false_alarms', '?')} for "
                          "field presence"))
    elif sm and "methods" in sm:
        sym = sm["methods"].get("symbolic (ANVIL)", {})
        pres = sm["methods"].get("field presence, per log source", {})
        k, n = sym.get("recall_k_n") or [sm.get("static_flagged_tp_rules", 0), sm.get("decayed_tp_rules", 0)]
        fa_sym = sym.get("false_alarms", sym.get("flagged_tp_rules", 0) - k)
        fa_pres = pres.get("false_alarms")
        parts.append(_kpi(f"{k}/{n}", "Sysmon to 4688 (simulated): broken rules flagged statically",
                          f"{fa_sym} false alarms" + (f" vs {fa_pres} for field presence" if fa_pres is not None
                                                     else "")))
    if eng:
        a = eng["anvil"]
        parts.append(_kpi(f"{a['pass']}/{a['evaluable']}", "regression captures detected",
                          _ci(a["pass"], a["evaluable"], 1)))
    if otrf:
        parts.append(_kpi(f"{otrf['technique_detected']}/{otrf['datasets']}", "OTRF emulations: technique detected",
                          _ci(otrf["technique_detected"], otrf["datasets"])))
    if cov:
        c, v = cov["claimed"], cov["tp_validated_and_gated"]
        parts.append(_kpi(f"{v['validated']}/{v['catalog_size']}", "ATT&CK Windows techniques validated",
                          f"{_ci(v['validated'], v['catalog_size'], 1)}; claimed {c['covered']}"))
    if lint:
        parts.append(_kpi(f"{lint['rules']:,}", "SigmaHQ rules linted"))
    if fp:
        parts.append(_kpi(f"{fp['corpus']['events']:,}", "benign events replayed",
                          f"{fp['corpus'].get('days', '?')} host-days"))
        obs = fp.get("observable_rules") or 0
        parts.append(_kpi(f"{fp['fired_rules']}", "rules firing on clean hosts",
                          f"of {obs:,} observable: {_ci(fp['fired_rules'], obs, 1)}" if obs else ""))
        parts.append(_kpi(f"{fp['gate_fail']}",
                          f"rules over {fp['policy']['budget_per_rule_per_day']:.0f}/day budget (per host)"))
    parts.append("</div>")

    if cov:
        parts.append('<h2>ATT&amp;CK coverage by tactic: claimed vs validated</h2><div class="card"><div class="bars">')
        claimed, val = cov["claimed"]["tactics"], cov["tp_validated_and_gated"]["tactics"]
        for tac, s in claimed.items():
            if not tac:
                continue
            tot = max(1, s["total"])
            vc = val.get(tac, {}).get("validated", 0)
            parts.append(f'<span>{_e(tac)}</span><div class="track"><div class="fill" style="width:'
                         f'{100 * s["covered"] / tot:.1f}%"></div><div class="fill2" style="width:'
                         f'{100 * vc / tot:.1f}%"></div></div><span>{vc}/{s["covered"]}/{s["total"]}</span>')
        parts.append('</div><p class="legend">dark = validated (fires on a real capture and stays within the '
                     'alert budget) · light = claimed by tags only · numbers: validated / claimed / techniques</p></div>')

    if fp:
        firing = [x for x in fp["rules"] if x["hits"]]
        parts.append(f'<h2>Noisiest rules on clean Windows installs</h2><p class="cap">Top {min(25, len(firing))} '
                     f'of {len(firing)} firing rules; rates are alerts per host-day.</p><div class="card"><table>'
                     '<tr><th>rule</th><th>level</th><th>status</th><th>folder</th><th class="n">alerts</th>'
                     '<th class="n">per day</th><th>gate</th></tr>')
        for r in firing[:25]:
            parts.append(f'<tr><td>{_e(r["title"])}</td><td>{_e(r["level"])}</td><td>{_e(r["status"])}</td>'
                         f'<td>{_e(r["folder"])}</td><td class="n">{r["hits"]:,}</td><td class="n">'
                         f'{r["alerts_per_day"]:,}</td><td><span class="pill {r["gate"]}">{r["gate"]}</span></td></tr>')
        parts.append("</table></div>")

    if dec:
        parts.append('<h2>Decay monitor: what breaks when telemetry changes</h2><p class="cap">Recall and precision '
                     'of the static check (Wilson 95% CI). Simulated changes are applied to the TP-validated rules\' '
                     'regression captures; the last row drops Sysmon from real OTRF captures.</p><div class="card">'
                     '<table><tr><th>change</th><th class="n">rules that stopped firing</th>'
                     '<th class="n">symbolic recall</th><th class="n">symbolic precision</th>'
                     '<th class="n">field-presence precision</th></tr>')
        rows = [(name, c["description"], c) for name, c in dec["changes"].items()]
        real = dec.get("real_sysmon_removal")
        if real:
            inv = next((v for k, v in real["inventories"].items() if k.startswith("native")), None)
            if inv:
                rows.append(("real: Sysmon removed (OTRF)", f"{real['datasets']} captures with native 4688",
                             {"decayed_tp_rules": real["rules_that_stop_firing"], "methods": inv["methods"]}))
        for name, desc, c in rows:
            m = c.get("methods", {})
            cells = []
            for meth, key in (("symbolic (ANVIL)", "recall"), ("symbolic (ANVIL)", "precision"),
                              ("field presence, per log source", "precision")):
                kn = m.get(meth, {}).get(f"{key}_k_n")
                cells.append(f"{kn[0]}/{kn[1]}, {_ci(kn[0], kn[1])}" if kn and kn[1] else "-")
            parts.append(f'<tr><td><b>{_e(name)}</b><br><span class="sub">{_e(desc)}</span></td>'
                         f'<td class="n">{c["decayed_tp_rules"]}</td>'
                         + "".join(f'<td class="n">{_e(x)}</td>' for x in cells) + "</tr>")
        parts.append("</table></div>")

    if otrf:
        parts.append(f'<h2>Emulated attacks (OTRF Security-Datasets)</h2><p class="cap">All {otrf["datasets"]} '
                     f'datasets: technique detected {otrf["technique_detected"]}, any alert {otrf["any_alert"]}.</p>'
                     '<div class="card"><table><tr><th>dataset</th>'
                     '<th>techniques</th><th class="n">rules fired</th><th>technique detected</th></tr>')
        for r in otrf["rows"]:
            ok = "pass" if r["technique_detected"] else ("warn" if r["any_alert"] else "fail")
            label = "yes" if r["technique_detected"] else ("other alerts" if r["any_alert"] else "no")
            parts.append(f'<tr><td>{_e(r["title"])}</td><td>{_e(", ".join(r["techniques"]))}</td>'
                         f'<td class="n">{r["rules_fired"]}</td><td><span class="pill {ok}">{label}</span></td></tr>')
        parts.append("</table></div>")

    parts.append(f'<footer><a href="{DOCS}">ANVIL</a> detection-as-code · data: SigmaHQ (DRL 1.1), MITRE '
                 'ATT&amp;CK, OTRF Security-Datasets (MIT), NextronSystems evtx-baseline</footer></main>')
    doc = ('<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" '
           'content="width=device-width,initial-scale=1"><title>ANVIL detection health</title>'
           f'<style>{CSS}</style></head><body>{"".join(parts)}</body></html>')
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(doc, encoding="utf-8")
    return out
