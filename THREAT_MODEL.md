# ANVIL Threat Model

## Assets
- **Detection library** (`rules/`): the SOC's core asset. Its integrity matters most. A silently weakened rule is a blind spot.
- **Test fixtures and benign corpus:** these define what counts as "pass". Poisoning them lets a bad rule through.
- **Baseline** (`baseline.json`): the reference point for decay and regression checks.

## Trust boundaries
1. Rule authors (humans, and later an LLM drafter) submit changes to the repo through PRs.
2. CI runs ANVIL on untrusted PR content.
3. Telemetry files are loaded from disk.

## Threats and mitigations

| # | Threat (STRIDE) | Mitigation in MVP | Residual / TODO |
| --- | --- | --- | --- |
| T1 | **Tampering:** a PR weakens a rule (for example, it removes a selection) | TP fixtures must still fire. Regression check against the baseline. Human review | Protect baseline with CODEOWNERS |
| T2 | **Tampering:** a PR edits fixtures so a weak rule "passes" | Fixture changes show up in the same diff. Quality score penalises thin tests | Keep canonical TP sets outside the rule file (GAUNTLET) |
| T3 | **Elevation:** a malicious YAML or condition runs code in CI | `yaml.safe_load`. Conditions go through a recursive-descent parser with no `eval`. Regexes are compiled with Python `re` only | - |
| T4 | **DoS:** catastrophic-backtracking regex (ReDoS), or a huge corpus | Lint compiles every regex. CI job has a timeout | Add regex complexity lint and per-rule time budget |
| T5 | **Repudiation:** nobody knows who changed a rule or why | Git history, `version` and `author` fields | Signed commits |
| T6 | **Information disclosure:** real telemetry with PII committed as a corpus | Real corpora (public lab datasets) are downloaded to `$ANVIL_DATA`, never committed; only synthetic fixtures and aggregate results ship | Add a PII scanner before accepting private corpora |
| T7 | **Machine-drafted rule** is wrong, over-broad, or prompt-injected by the CTI text | Drafts are written as `status: experimental` with `anvil.reviewed: false`; lint error A114 blocks them until a human flips the flag in a PR, and they must still pass `anvil test`. Drafter output is parsed with `yaml.safe_load` and compiled by the same engine as any PR | Reviewer fatigue; keep the review diff small |
| T8 | **False assurance:** benign corpus is unrepresentative, so FP rate is underestimated | Real clean-install corpora (evtx-baseline Win10/Win11/Server 2022 AD) replace the synthetic corpus in benchmarks; results state corpus size and span | Lab baselines are quieter than production; replay your own telemetry before trusting absolute alert volumes |
| T9 | **Tampered dataset download** | Every download is pinned (commit/tag) and SHA-256-checked against `scripts/checksums.sha256` | - |
| T10 | **Attack logs trip endpoint AV** on the analyst machine | Samples are log records, not binaries; AV-quarantined files are skipped and counted, never force-extracted | - |

## Out of scope
SIEM deployment, and executing any attack technique. ANVIL never runs attack techniques; it only matches strings in logs.
