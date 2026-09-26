# Prior art


| Existing | What it gives you | What ANVIL adds |
| --- | --- | --- |
| [Sigma](https://github.com/SigmaHQ/sigma) + [pySigma](https://github.com/SigmaHQ/pySigma) / sigma-cli | Rule format, conversion to SIEM queries | Local evaluation without a SIEM, benign-FP and alert-budget gating, decay monitoring, drafting. ANVIL uses pySigma for conversion and as a cross-check |
| SigmaHQ CI ([evtx-sigma-checker](https://github.com/NextronSystems/evtx-baseline), regression tests) | TP replay and goodlog checks for the SigmaHQ repo | The same idea as a reusable tool for *your* rules and *your* telemetry, plus volume budgets, coverage validation and decay analysis. ANVIL reproduces SigmaHQ's own regression verdicts (461/461 evaluable cases) and cross-checks against its known-FP list |
| [Elastic detection-rules](https://github.com/elastic/detection-rules), Splunk ESCU + Atomic Red Team | Versioned, tested content for one platform | Backend-agnostic measurement and an alert-budget gate; emulation output is an input, not a dependency |
| [Chainsaw](https://github.com/WithSecureLabs/chainsaw), [Hayabusa](https://github.com/Yamato-Security/hayabusa), [Zircolite](https://github.com/wagga40/Zircolite) | Fast Sigma hunting over EVTX | Lifecycle rather than hunting: gates, claimed-vs-validated coverage, decay, drafting, FP prediction |
| Detection-as-code write-ups | Methodology | A working open reference implementation, with published numbers |
