# Reproduce

## Environment

Python 3.10+ (CI uses 3.12), about 3 GB RAM, about 0.45 GB download and about 4 GB free
disk after extraction and ingest. The optional `nixcloud` source (Linux and AWS captures)
adds about 0.75 GB and is not part of `all`.

## Easiest: run it in GitHub Actions

The `bench` workflow (`.github/workflows/bench.yml`, workflow_dispatch and weekly)
downloads every dataset fresh and checksum-verified, runs all stages plus the Linux/AWS
stage and the OpenSearch cross-check, and uploads `results/` as an artefact.

```bash
gh workflow run bench.yml && gh run watch
gh run download --name bench-results
```

## Locally

```bash
pip install -e ".[dev,sigma,ml,fast,evtx,plots]" -r requirements-bench.txt
python scripts/download_data.py all          # sigma, baseline, attack, otrf
python -m anvil ingest --benign              # evtx -> JSONL shards
python benchmarks/bench.py all --workers 4   # every stage, then report
```

Runtimes and console summaries from CI run 37016390345 (ubuntu-latest, 4 workers):

| Stage | Writes | Runtime | Expected summary |
| --- | --- | ---: | --- |
| lint | results/lint.json | 3 s | 3,757 rules, 0 parse errors, 2,844 routable Windows |
| engine | results/engine.json | 57 s | anvil 463/463, 0.1 baseline 420/463 |
| fp | results/fp.json | 426 s | 75 rules fire, 12 over budget |
| otrf | results/otrf.json | 189 s | 98 datasets, 0 blocked, technique detected 62 (lenient 69) |
| coverage | results/coverage.json, navigator layer | 2 s | 299 claimed, 164 validated of 474 |
| decay | results/decay.json | 46 s | inventory from 598,829 benign events |
| convert | results/convert.json | 47 s | Splunk 2,857 / Elastic 2,855 / KQL 2,074 / SQLite 2,842 of 2,861 |
| fpmodel | results/fpmodel.json | 63 s | 2,789 rules, 75 positives |
| draft | results/draft.json | 212 s | heuristic fires on 32 of 68 |
| nixcloud (opt-in) | results/nixcloud.json | 34 s | 168 labelled captures, technique detected 27, any alert 89 |
| report | results/SUMMARY.md, docs/img, docs/dashboard.html | 1 s | |

The OpenSearch cross-check is a separate job: `benchmarks/backend_opensearch.py` against a
local container, writing results/backend_opensearch.json.

Every results file records the git SHA, package versions and dataset pins under
`provenance`. To check a reproduction, run `git diff --stat results/`.

Files that endpoint antivirus quarantines on a workstation are skipped and counted locally,
never forced; the CI run computes them.
