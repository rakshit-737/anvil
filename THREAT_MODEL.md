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
| T6 | **Information disclosure:** real telemetry with PII committed as a corpus | Only synthetic data ships (`*.lab.example`, TEST-NET IPs) | Add a PII scanner before accepting real corpora |
| T7 | **LLM-drafted rule (future)** is wrong or prompt-injected by the CTI text | Not built. The design requires a human gate plus the automated test gate, and the LLM never deploys | Treat LLM output as untrusted input, just like a PR |
| T8 | **False assurance:** synthetic corpus is unrepresentative, so FP rate is underestimated | README states the limitation. Capacity budget is configurable | Real benign corpora (TODO) |

## Out of scope
SIEM deployment, and executing any attack technique. ANVIL never runs attack techniques; it only matches strings in logs.
