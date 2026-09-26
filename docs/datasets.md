# Datasets


| Dataset | Used for | Size | Licence / terms |
| --- | --- | --- | --- |
| [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) @ `07ec293` | 3,757 rules under test; `regression_data` (463 real EVTX captures with expected match counts); `known-FPs.csv` cross-check | 13 MB zip | [Detection Rule License 1.1](https://github.com/SigmaHQ/Detection-Rule-License) |
| [NextronSystems/evtx-baseline](https://github.com/NextronSystems/evtx-baseline) v0.8.5 | Benign corpus: clean Windows 10 client, Windows 11 client, Server 2022 domain controller | 270 MB tgz, 2.99M events | Public research data (see repository) |
| [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) @ `d9d40ef` | 98 atomic Windows host emulations with ATT&CK labels and attacker transcripts; APT29 evaluation days 1-2 | 66 MB | MIT |
| [MITRE ATT&CK Enterprise](https://github.com/mitre-attack/attack-stix-data) v19.2 STIX 2.1 | Technique catalog (697 active, 474 on Windows), revocations | 54 MB | [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/) |

Downloads are pinned and SHA-256-verified (`scripts/checksums.sha256`) and are never committed. Two OTRF archives could not be read on the development machine because endpoint AV quarantined them. They are attack *logs*, and ANVIL counts and skips such files.
