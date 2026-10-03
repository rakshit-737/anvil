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
- The benchmark simulates six changes: ECS rename, Sysmon replaced by 4688, 4688 without command lines (fleet-wide, and only on converted hosts), CommandLine dropped, and hashes turned off. For each change it reports how many of the rules that actually stopped firing each check catches (recall) and how many of its flags are real (precision), using the regression captures as ground truth. The same transform also builds the post-change inventory, so precision there is partly a soundness property of the transform.
- A real-data check that uses no simulator (added after 1.1.0): OTRF captures that log both Sysmon EID 1 and native Security 4688 are replayed with and without their Sysmon channel, and the prediction comes from the benign inventory with its real Sysmon events dropped.

## Consequences
- Static analysis can over-flag when the inventory is thin, for example a field that exists but never appeared in the sample. The benchmark reports that false-alarm floor as `baseline_status` in `results/decay.json` (183 rules, 6.4%, on unchanged telemetry, bench run 37093721154), and compares the symbolic check with per-source and global field-presence checks.
- Both checks are meant to run in CI on a schedule. Regression failures block the build; static findings open an issue (`.github/workflows/decay.yml`, weekly, added after 1.1.0; it uses the bundled synthetic telemetry until a real inventory export is configured).
