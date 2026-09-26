# Limitations and roadmap

## Limitations

- **Engine scope.** Placeholders (`expand`), aggregations and correlation rules are not evaluated. They are reported as unsupported (2 of 3,757 rules at the pinned commit). Field-name semantics follow Sysmon/Windows event logs; other products need a mapping.
- **Benign corpus.** evtx-baseline hosts are clean lab installs. Real fleets are noisier, so treat benign alert counts as a lower bound and replay your own telemetry before trusting absolute volumes. The alerts/day figures assume the corpus's own time span.
- **Emulation labels are coarse.** OTRF datasets are labelled at technique level and include background noise. "Technique detected" means a rule tagged with that technique (or its parent) fired on the capture, not that a human verified the alert.
- **Drafter evaluation is optimistic by construction.** Drafts are generated from the same dataset's description and transcript that they are then tested on (report -> rule -> emulation, spec scenario 1). The LLM backend is implemented but not benchmarked here, because no API key was used for the published numbers.
- **FP-prediction labels come from one corpus family.** The model predicts "fires on these clean hosts". It is a triage aid for review order, not a replacement for replay.
- **No React UI / API server.** The spec's React review-gate and dashboard are replaced by git PR review and a static dashboard (ADR 0005), so there is no docker-compose; the Docker image ships the CLI.
- **LLM drafter not benchmarked** (needs an API key and blind human review, see roadmap).
- **Timings** were measured on a shared, heavily loaded laptop. Treat throughput numbers as indicative.

## Roadmap

- Correlation rules and `expand` placeholders through pySigma processing pipelines
- Linux (auditd, Sysmon for Linux) and cloud log-source routing
- Scheduled decay job that opens issues with the symbolic diff
- Benchmark the LLM drafter against the heuristic baseline, with blind human review
- GAUNTLET integration: pull emulation captures per technique and push validated coverage back
