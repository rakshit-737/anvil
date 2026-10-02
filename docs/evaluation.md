# Evaluation

## Methodology

- **Data.** Everything is pinned and checksum-verified: SigmaHQ `07ec293` (rules, `regression_data`, `known-FPs.csv`), evtx-baseline v0.8.5 (benign), OTRF `d9d40ef` (Windows, Linux, AWS emulations), Splunk attack_data (Linux, CloudTrail), ATT&CK 19.2. See [Datasets](datasets.md).
- **Run.** One `bench` workflow run on a clean `ubuntu-latest` runner (4 vCPU, 16 GB). Each `results/*.json` records the git SHA, package versions and dataset pins under `provenance`. The run asserts that every OTRF archive and regression capture was readable, so the files that endpoint AV quarantines on the development laptop are included.
- **Technique detected.** A rule tagged with the capture's technique or its parent fired on the capture. Sibling sub-techniques are reported separately as "lenient".
- **Alerts per host-day.** Hits divided by the sum of per-host recording spans (2.55 host-days). The budget is 20 alerts per host-day per rule (10% of a 200/day SOC); the fleet table projects it to N hosts.
- **Decay ground truth.** A TP-validated rule is broken by a change when its regression captures, replayed through the simulated change, no longer fire it. The static check only sees the benign field inventory.
- **Intervals.** Wilson 95% intervals for proportions; a bootstrap over rules for the FP-model AUCs; the "interval over CV repetitions" in the FP model only measures fold-assignment noise.
- **Exclusions.** The 23-rule `rules-placeholder` folder; deprecated rules; 2 rules with unsupported features.

## Results

--8<-- "README.md:results"

--8<-- "README.md:comparison"

## Full summary

--8<-- "results/SUMMARY.md:2:"
