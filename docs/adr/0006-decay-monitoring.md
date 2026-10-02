# ADR 0006: Two decay checks: symbolic schema analysis and TP regression

- Status: accepted (0.2.0)
- Date: 2026-09-26

## Context
Detections rot silently. A pipeline migration renames fields, Sysmon gets decommissioned, or a collector truncates command lines. The rule still parses and still passes lint, but it can never fire again. Re-running TP samples catches this, but only for rules that have TP samples: about 460 of the 2,860 Windows rules in SigmaHQ.

## Decision
- **Regression monitor.** Re-run the stored TP captures and compare with the saved baseline. It is exact, but limited to rules that have evidence.
- **Static schema analysis.** Build a field inventory per (channel, EventID) from current production telemetry, then evaluate each rule's condition symbolically:
  - a selection is satisfiable only if its fields exist;
  - `not filter` over a missing field marks the filter as blind, which means more FPs, not fewer detections.

  This check works for every rule and needs no attack data.
- The benchmark simulates five realistic changes: ECS rename, Sysmon replaced by 4688, 4688 without command lines, CommandLine dropped, and hashes turned off. For each change it reports how many of the rules that actually stopped firing each check catches (recall) and how many of its flags are real (precision), using the regression captures as ground truth.

## Consequences
- Static analysis can over-flag when the inventory is thin, for example a field that exists but never appeared in the sample. The benchmark reports that false-alarm floor as `baseline_status` in `results/decay.json` (183 rules, 6.4%, on unchanged telemetry), and compares the symbolic check with per-source and global field-presence checks.
- Both checks are meant to run in CI on a schedule. Regression failures block the build; static findings are meant to open issues (a scheduled job is on the roadmap, not yet built).
