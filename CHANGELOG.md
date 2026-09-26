# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [semantic versioning](https://semver.org/).

## [0.2.0] - 2026-09-26

Real-data release: ANVIL now runs the full SigmaHQ library against public attack and benign telemetry.

### Added
- **Sigma engine** covering the value/modifier spec: `windash`, `base64`/`base64offset`, `wide`/`utf16*`, `cidr`, `lt`/`lte`/`gt`/`gte`, `fieldref`, `neq`, regex flags, `null`, keyless keyword maps, Sigma wildcard escaping and condition lists. Unsupported features (`expand`, aggregations) raise `UnsupportedRule` instead of mis-evaluating.
- **Log-source routing** (`anvil/logsource.py`): Sigma category/service -> Windows channel + EventID, Security 4688 aliasing, EventType guards for registry add/delete.
- **Rule library runner** that compiles, routes and indexes thousands of rules by (channel, EventID), plus multi-process corpus scanning.
- **Telemetry loaders** for EVTX (pyevtx-rs or python-evtx), EVTX-JSON, OTRF/Mordor zips and sharded JSONL.gz; `anvil ingest`.
- **SigmaHQ regression replay** (`anvil regress`) using the project's own captured true-positive events.
- **ATT&CK Enterprise STIX catalog**: full matrix, revocations, platforms; claimed-vs-validated coverage and stale-tag lint (W208).
- **Sigma lint profile** for SigmaHQ-style repos (W209, W210, W211, W212).
- **pySigma bridge**: `anvil convert` to Splunk, Elastic (ECS), Microsoft XDR KQL and SQLite; the SQLite output doubles as an independent oracle.
- **CTI drafter** (`anvil draft`): heuristic and optional Claude backends, IOC stripping, and a review gate enforced by lint A114.
- **Decay monitor v2**: symbolic per-log-source analysis (`ok` / `degraded` / `broken` / `source-missing`) and realistic schema-change simulators.
- **FP-prediction model** (scikit-learn) trained on benign-replay labels.
- **Static health dashboard** (`anvil report`) and the benchmark suite `benchmarks/bench.py` with results in `results/`.
- Pinned, checksummed dataset downloader for SigmaHQ, ATT&CK STIX, OTRF Security-Datasets and NextronSystems evtx-baseline.
- LICENSE (MIT), CONTRIBUTING, ADRs under `docs/adr`.
- Published real-data benchmark results (`results/`, `results/SUMMARY.md`, `docs/img/`, `docs/dashboard.html`): 100% on SigmaHQ regression captures vs 90.7% for the 0.1 engine, 3.0M-event benign replay, 96 OTRF emulations, claimed vs validated ATT&CK coverage, decay, conversion, FP-model and drafter tables.

### Changed
- `\*` in rule values is now an escaped literal star, as the Sigma spec defines (0.1 treated it as a wildcard).
- `coverage` accepts a STIX catalog and platform filter; the bundled 16-technique subset is only the offline fallback.
- CLI `--rules` accepts several folders.
- The synthetic demo corpora `telemetry/benign*.jsonl` (1.3-1.5 MB each) are no longer committed; `python -m anvil synth` regenerates them byte-for-byte (seeded).

### Fixed
- README said the benign corpus held 3.1M events; the ingested corpus is 2,994,137 events.
- Registry delete rules no longer fire on Sysmon EID 12 *CreateKey* events (found by diffing benign hits against SigmaHQ's `known-FPs.csv`).

## [0.1.0] - 2026-09-25

- MVP: Sigma-like engine subset, lint, TP/TN fixture harness, FP/SOC-capacity gate, bundled ATT&CK subset coverage, quality score, schema-drift decay check and synthetic telemetry.
