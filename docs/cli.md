# CLI and API reference

## CLI


| Command | Purpose |
| --- | --- |
| `anvil lint [--profile sigma] [--attack STIX] [--summary]` | Validate rules; SigmaHQ-style or ANVIL-style |
| `anvil test` | Per-rule fixtures + benign FP corpus + SOC budget gate (exit 1 on failure) |
| `anvil scan --rules DIR... --corpus PATH...` | Route a whole library over real telemetry (EVTX, JSON, OTRF zip, JSONL.gz) |
| `anvil regress --sigma PATH` | Replay SigmaHQ regression captures |
| `anvil ingest SRC... --out DIR` / `--benign` | Normalise telemetry into sharded JSONL.gz |
| `anvil draft REPORT [--backend heuristic\|llm\|keywords]` | Draft candidate rules from CTI (review required) |
| `anvil convert RULE --target splunk\|elastic\|kusto\|sqlite` | Deployable SIEM queries via pySigma |
| `anvil coverage [--attack STIX --platform Windows] [--navigator out.json]` | ATT&CK coverage, claimed vs validated |
| `anvil decay [--routed] [--baseline b.json]` | Schema drift, symbolic breakage, regressions |
| `anvil score` | 0-100 quality score per rule |
| `anvil report` | Static health dashboard from `results/*.json` |

## Python API

::: anvil.engine

::: anvil.runner

::: anvil.lint

::: anvil.harness

::: anvil.fpmodel

::: anvil.decay
