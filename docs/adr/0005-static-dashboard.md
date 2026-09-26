# ADR 0005: A static HTML health dashboard instead of a React app

- Status: accepted (0.2.0)
- Date: 2026-09-26

## Context
The spec sketches a React + Recharts dashboard. The data behind it is a handful of JSON files that CI regenerates. The readers are detection engineers opening a CI artifact or a GitHub Pages link.

## Decision
`anvil report` renders one self-contained HTML file from `results/*.json`: inline CSS, no JavaScript, light and dark themes. The README embeds PNG figures rendered by `benchmarks/report.py`.

## Consequences
- There is no Node toolchain, no CDN and nothing to patch. The file works offline and is trivial to publish as a CI artifact.
- There is no interactive filtering. If that becomes necessary, the JSON contract in `results/` is the API a richer front end would consume.
