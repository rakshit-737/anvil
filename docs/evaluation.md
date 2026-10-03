# Evaluation

## Methodology

- **Data.** Everything is pinned and checksum-verified: SigmaHQ `07ec293` (rules, `regression_data`, `known-FPs.csv`), evtx-baseline v0.8.5 (benign), OTRF `d9d40ef` (Windows, Linux, AWS emulations), Splunk attack_data `b4573ed` (Linux, CloudTrail), ATT&CK 19.2. See [Datasets](datasets.md).
- **Run.** One `bench` workflow run, [37093721154](https://github.com/rakshit-737/anvil/actions/runs/37093721154) at commit `9906b42` with all three jobs green, on clean `ubuntu-latest` runners (4 vCPU, 16 GB): the `bench` job (all stages), the `backend` job (OpenSearch) and the `report` job, which joins both and checks that every results file carries that run's id and commit. The run id and commit are stated at the top of the results below and in every file's `provenance` (with package versions and dataset pins). The run asserts that every OTRF archive and regression capture was readable, so the files that endpoint AV quarantines on the development laptop are included.
- **Technique detected.** A rule tagged with the capture's technique or its parent fired on the capture. Sibling sub-techniques are reported separately as "lenient".
- **Alerts per host-day.** Hits divided by the sum of per-host recording spans (2.55 host-days). The budget is 20 alerts per host-day per rule (10% of a 200/day SOC); the fleet table projects it to N hosts. The recordings are install-day telemetry, so install-related rules are likely noisier here than in steady state.
- **Decay ground truth, simulated.** A TP-validated rule is broken by a change when its regression captures, replayed through the simulated change, no longer fire it. The static check only sees the benign field inventory, transformed by the same change, so its precision there is partly a soundness property of the transform.
- **Decay ground truth, real.** OTRF captures that log both Sysmon EID 1 and native Security 4688 are replayed with and without their Sysmon channel; a rule is broken when it fires on them before and on none of them after. The prediction uses the benign inventory with its real Sysmon events dropped. No simulator is involved.
- **Intervals and tests.** Wilson 95% intervals for proportions, printed as `k/n, p% [lo, hi]`; exact McNemar tests for paired comparisons on the same rules or datasets; a bootstrap over rules for the FP-model AUCs and for Cohen's kappa; the "interval over CV repetitions" in the FP model only measures fold-assignment noise.
- **Exclusions.** The 23-rule `rules-placeholder` folder; deprecated rules; 2 rules with unsupported features.

## Results

--8<-- "README.md:results"

--8<-- "README.md:comparison"

## Full summary

<details markdown="1">
<summary>Every table generated from <code>results/*.json</code> (results/SUMMARY.md)</summary>

--8<-- "results/SUMMARY.md:2:"

</details>
