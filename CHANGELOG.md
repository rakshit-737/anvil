# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [semantic versioning](https://semver.org/).

## Unreleased

### Added
- Linux (Sysmon for Linux, auditd raw and `ausearch -i`) and AWS CloudTrail parsers and routing (ADR 0007); opt-in `nixcloud` download of Splunk attack_data and OTRF Linux/AWS captures; Linux/AWS benchmark stage.
- `bench` workflow: full benchmark on a clean runner with fresh, checksum-verified downloads (covers files AV blocks locally), live benign Linux telemetry, and an OpenSearch real-backend cross-check (`benchmarks/backend_opensearch.py`).
- Decay ablation against per-source and global field-presence checks, with Wilson CIs and the false-alarm floor; fleet-size projection of the alert budget; strict vs lenient OTRF technique matching; bootstrap CIs over rules for the FP model; provenance (git SHA, versions, pins) in every results file.
- Docs: How it works, Evaluation, Reproduce pages; dashboard screenshot; Try it in 60 seconds. CITATION.cff, CODEOWNERS, dependabot, issue forms, PR template.

### Changed
- Published numbers now come from one CI run. Several got worse and are published as such: OTRF technique detected 62/98 strict (was 67/96, which credited sibling sub-techniques); the level heuristic's precision@k advantage was a tie-breaking artefact; 75 rules fire on benign hosts (was 78) after `file_delete` routes to Sysmon 23 only.
- The 4688-without-command-line decay scenario now strips CommandLine fleet-wide (recall 95%); the old mixed-inventory variant (31%) is kept as its own row.
- CLI: every `--rules` path is loaded (files included); missing paths and empty rule sets fail; missing files and extras give one-line errors.
- Drafter no longer mangles `rundll32`, `runas`, `cmdkey` or drops `cmd.exe` lines.
- Downloads fail closed on missing checksums; zip-slip guard; AV-blocked files are skipped, never processed locally.
- CI: Python 3.14 and a fast/evtx leg, wheel/sdist/Docker smoke tests, pip-audit, SHA-pinned actions, scoped permissions, timeouts; release notes extracted from this file.

## [1.0.0] - 2026-09-26

### Added
- FP-prediction benchmark repeats stratified 5-fold CV over 10 seeds and reports mean and 95% confidence intervals (`anvil.fpmodel.repeated_cv`).
- Documentation site (MkDocs Material) on GitHub Pages, with API reference and the static health dashboard under `/demo/`.
- Dockerfile (slim, non-root) and a tag-driven release workflow publishing `ghcr.io/rakshit-737/anvil` plus wheel/sdist.

### Changed
- FP-model numbers corrected to the multi-seed means: logreg ROC-AUC 0.826 (was 0.836 single-seed), PR-AUC 0.188 (was 0.202); GBDT 0.817 / 0.229. The `level` heuristic still has the best precision at k.
- Architecture diagram labels quoted so Mermaid renders them reliably.

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

[1.0.0]: https://github.com/rakshit-737/anvil/releases/tag/v1.0.0
