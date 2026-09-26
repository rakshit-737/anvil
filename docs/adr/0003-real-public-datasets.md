# ADR 0003: Measure against real public datasets, fetched on demand and never committed

- Status: accepted (0.2.0)
- Date: 2026-09-26

## Context
The 0.1 benign corpus was synthetic. That proves the plumbing works, but it says nothing about how rules behave on real hosts. We need true-positive evidence, benign background and emulated attacks. All of it has to be public, redistributable and small enough to download on a laptop.

## Decision
| Role | Dataset | Why |
| --- | --- | --- |
| Rules under test | SigmaHQ/sigma (pinned commit) | The de-facto open rule library (about 3.8k rules) |
| True positives, per rule | SigmaHQ `regression_data` | Real EVTX captures, labelled with the expected match count by SigmaHQ |
| Benign background | NextronSystems evtx-baseline (Win10, Win11, Server 2022 AD) | Clean installs. SigmaHQ's own "goodlog" CI uses them, which gives an external cross-check through `known-FPs.csv` |
| Emulated attacks | OTRF Security-Datasets (Mordor): atomic Windows host captures and the APT29 evaluation | Labelled with ATT&CK techniques and the attacker's console transcript |
| Technique catalog | MITRE ATT&CK Enterprise STIX 2.1 | The full matrix, with revocations and platforms |

- `scripts/download_data.py` pins every source to a commit or tag and verifies its SHA-256 against `scripts/checksums.sha256`.
- Data lives under `$ANVIL_DATA` (default `./data`, which is git-ignored). Only aggregate results are committed: `results/*.json`, each under 1 MB.
- Tests that need the data are marked `realdata` and skip in CI.

## Consequences
- Every headline number in the README can be reproduced from public inputs with three commands.
- Lab baselines are quieter than production networks, so absolute alert volumes are a lower bound. The README says so.
- Endpoint AV sometimes quarantines attack *logs*. The loaders count and skip unreadable files instead of failing.
