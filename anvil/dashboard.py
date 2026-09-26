"""Static detection-health dashboard (single self-contained HTML file).

Rendered from the ``results/*.json`` written by ``benchmarks/bench.py`` (or by
a scheduled CI job). No JavaScript framework, no CDN: it opens from disk, can
be published as a CI artifact or GitHub Pages, and diffs cleanly in git.
"""
from __future__ import annotations

import html
import json
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
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.kpi b{display:block;font-size:26px;font-variant-numeric:tabular-nums}.kpi span{color:var(--muted);font-size:13px}
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
"""


def _load(results: Path, name: str) -> dict[str, Any] | None:
    p = results / name
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def _e(x: Any) -> str:
    return html.escape(str(x))


def _kpi(value: Any, label: str) -> str:
    return f'<div class="kpi"><b>{_e(value)}</b><span>{_e(label)}</span></div>'


def render(results: Path, out: Path) -> Path:
    lint, eng, fp = _load(results, "lint.json"), _load(results, "engine.json"), _load(results, "fp.json")
    cov, dec, otrf = _load(results, "coverage.json"), _load(results, "decay.json"), _load(results, "otrf.json")
    parts = ['<main><h1>Detection health</h1><p class="sub">SigmaHQ rule library measured by ANVIL '
             'against real public telemetry. Generated from <code>results/*.json</code>.</p><div class="kpis">']
    if lint:
        parts.append(_kpi(f"{lint['rules']:,}", "rules linted"))
    if eng:
        a = eng["anvil"]
        parts.append(_kpi(f"{a['pass']}/{a['evaluable']}", "regression captures detected"))
    if fp:
        parts.append(_kpi(f"{fp['corpus']['events']:,}", "benign events replayed"))
        parts.append(_kpi(f"{fp['fired_rules']}", "rules firing on clean hosts"))
        parts.append(_kpi(f"{fp['gate_fail']}", f"rules over {fp['policy']['budget_per_rule_per_day']:.0f}/day budget"))
    if cov:
        c, v = cov["claimed"], cov["tp_validated_and_gated"]
        parts.append(_kpi(f"{c['coverage_pct']}% / {v['validated_pct']}%", "ATT&CK (Windows) claimed / validated"))
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
        parts.append('<h2>Noisiest rules on clean Windows installs</h2><div class="card"><table><tr><th>rule</th>'
                     '<th>level</th><th>status</th><th>folder</th><th class="n">alerts</th><th class="n">per day</th>'
                     '<th>gate</th></tr>')
        for r in [x for x in fp["rules"] if x["hits"]][:25]:
            parts.append(f'<tr><td>{_e(r["title"])}</td><td>{_e(r["level"])}</td><td>{_e(r["status"])}</td>'
                         f'<td>{_e(r["folder"])}</td><td class="n">{r["hits"]:,}</td><td class="n">'
                         f'{r["alerts_per_day"]:,}</td><td><span class="pill {r["gate"]}">{r["gate"]}</span></td></tr>')
        parts.append("</table></div>")

    if dec:
        parts.append('<h2>Decay monitor: what breaks when telemetry changes</h2><div class="card"><table><tr>'
                     '<th>change</th><th class="n">TP rules that stopped firing</th><th class="n">caught statically</th>'
                     '<th class="n">library flagged</th></tr>')
        for name, c in dec["changes"].items():
            rec = "-" if c["static_recall"] is None else f'{100 * c["static_recall"]:.0f}%'
            parts.append(f'<tr><td><b>{_e(name)}</b><br><span class="sub">{_e(c["description"])}</span></td>'
                         f'<td class="n">{c["decayed_tp_rules"]}</td><td class="n">{rec}</td>'
                         f'<td class="n">{c["library_flagged_pct"]}%</td></tr>')
        parts.append("</table></div>")

    if otrf:
        parts.append('<h2>Emulated attacks (OTRF Security-Datasets)</h2><div class="card"><table><tr><th>dataset</th>'
                     '<th>techniques</th><th class="n">rules fired</th><th>technique detected</th></tr>')
        for r in otrf["rows"][:60]:
            ok = "pass" if r["technique_detected"] else ("warn" if r["any_alert"] else "fail")
            label = "yes" if r["technique_detected"] else ("other alerts" if r["any_alert"] else "no")
            parts.append(f'<tr><td>{_e(r["title"])}</td><td>{_e(", ".join(r["techniques"]))}</td>'
                         f'<td class="n">{r["rules_fired"]}</td><td><span class="pill {ok}">{label}</span></td></tr>')
        parts.append("</table></div>")

    parts.append('<footer>ANVIL detection-as-code · data: SigmaHQ (DRL 1.1), MITRE ATT&amp;CK, OTRF Security-Datasets '
                 '(MIT), NextronSystems evtx-baseline</footer></main>')
    doc = ('<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" '
           'content="width=device-width,initial-scale=1"><title>ANVIL detection health</title>'
           f'<style>{CSS}</style></head><body>{"".join(parts)}</body></html>')
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(doc, encoding="utf-8")
    return out
