# Getting started

### Quickstart

```bash
git clone https://github.com/rakshit-737/anvil && cd anvil
pip install -e ".[dev]"          # core needs only PyYAML
python -m pytest -q              # offline suite; real-data tests skip without $ANVIL_DATA

# the original lifecycle demo on bundled rules + synthetic telemetry
python -m anvil synth
python -m anvil lint
python -m anvil test --capacity 200 --share 0.1 --save-baseline telemetry/baseline.json
python -m anvil test --rules examples/noisy                 # FP / SOC-budget guardrail blocks this rule
python -m anvil draft examples/cti/fin_x_report.md          # drafts land in drafts/, reviewed: false
python -m anvil lint --rules drafts --profile sigma         # A114: unreviewed drafts cannot ship
```

`make` targets (`make test`, `make data`, `make bench`, `make demo`) wrap the same commands. On Windows without `make`, run them directly.

### Reproduce the benchmarks

```bash
pip install -e ".[dev]" -r requirements-bench.txt
export ANVIL_DATA=$PWD/data                   # PowerShell: $env:ANVIL_DATA="$PWD\data"
python scripts/download_data.py all           # ~350 MB, pinned + checksummed
python -m anvil ingest --benign               # EVTX -> 31 JSONL.gz shards (2,994,137 events)
python benchmarks/bench.py all --workers 4    # ~1-2 h on a laptop; stages can run separately
```

Stages: `lint engine fp otrf coverage decay convert fpmodel draft report`. Each writes `results/<stage>.json`, and `report` regenerates `results/SUMMARY.md`, `docs/img/*.png` and `docs/dashboard.html`.
