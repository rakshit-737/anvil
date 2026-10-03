# Reproduce

## Environment

Python 3.10+ (CI uses 3.12), about 3 GB RAM, about 0.46 GB download and about 4 GB free
disk after extraction and ingest. The optional `nixcloud` source (Linux and AWS captures)
adds about 0.78 GB and is not part of `all`.

## Easiest: run it in GitHub Actions

The `bench` workflow (`.github/workflows/bench.yml`, workflow_dispatch and weekly) has three
jobs. `bench` downloads every dataset fresh and checksum-verified, records Linux telemetry on
the runner and runs all stages plus the Linux/AWS stage; `backend` runs the OpenSearch
cross-check; `report` joins both, checks that every results file carries this run's id and
commit, and renders SUMMARY.md, the figures, the dashboard and its screenshot. Its `results`
artefact is exactly what is committed.

```bash
gh workflow run bench.yml && gh run watch
gh run download <run-id> -n results            # results/, docs/img/, docs/dashboard.html
gh run download <run-id> -n bench-results      # + bench.log (stage timings and console summaries)
gh run download <run-id> -n backend-results    # + backend.log and the OpenSearch container log
python benchmarks/bench.py verify              # compare with the committed results
```

## Locally

```bash
pip install -e ".[dev,sigma,ml,fast,evtx,plots]" -r requirements-bench.txt
python scripts/download_data.py all          # sigma, baseline, attack, otrf
python -m anvil ingest --benign              # evtx -> JSONL shards
python benchmarks/bench.py all --workers 4   # every stage, then report
python benchmarks/bench.py verify            # diff against the committed files, ignoring provenance and timings
```

`verify` prints `identical` per file for a faithful reproduction; a plain `git diff --stat results/`
always shows changes because provenance and timing fields differ on every run.

Runtimes and console summaries from `bench` run [37093721154](https://github.com/rakshit-737/anvil/actions/runs/37093721154) at `9906b42` (ubuntu-latest, 4 workers; the whole run took 13 minutes: bench 12.3, backend 3.6 in parallel, report 0.7):

| Stage | Writes | Runtime | Expected summary |
| --- | --- | ---: | --- |
| lint | results/lint.json | 2 s | 3,757 rules, 0 parse errors, 2,844 routable Windows, 3 W213 (ReDoS-prone regex) |
| engine | results/engine.json | 34 s | anvil 463/463, 0.1 baseline 420/463; benign sample 15 alerts routed, 163 unrouted |
| fp | results/fp.json | 222 s | 75 rules fire, 12 over budget |
| otrf | results/otrf.json | 102 s | 98 datasets, 0 blocked, technique detected 62 (lenient 69); 88 captures with Sysmon and 4688 |
| coverage | results/coverage.json, navigator layer | 1 s | 299 claimed, 164 validated of 474 |
| decay | results/decay.json | 25 s | inventory from 598,829 benign events; real Sysmon removal 114/122 flagged, 0 false alarms |
| convert | results/convert.json | 25 s | Splunk 2,857 / Elastic 2,855 / KQL 2,074 / SQLite 2,842 of 2,861 |
| fpmodel | results/fpmodel.json | 33 s | 2,789 rules, 75 positives |
| draft | results/draft.json | 111 s | heuristic fires on 32 of 68 |
| nixcloud (opt-in) | results/nixcloud.json | 20 s | 168 labelled captures, technique detected 27, any alert 89; live emulation 7 of 8 techniques |
| report | results/SUMMARY.md, docs/img, docs/dashboard.html | 1 s | |
| backend job | results/backend_opensearch.json | 67 s (3.6 min job) | regression verdicts agree 450/458 |

Files that endpoint antivirus quarantines on a workstation are skipped and counted locally,
never forced; the CI run computes them.
