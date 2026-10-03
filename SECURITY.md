# Security Policy

## Scope
ANVIL is a defensive detection-engineering tool. It contains no exploit code, and it never executes the techniques its rules describe. Bundled test fixtures are synthetic; `results/fp.json` also carries a few example events from the public evtx-baseline lab corpus (clean lab hosts, no real users).

## Reporting a vulnerability
Please report issues privately through GitHub's private vulnerability reporting: **[Report a vulnerability](https://github.com/rakshit-737/anvil/security/advisories/new)** (Security tab, "Report a vulnerability"). Do not use public issues. Include reproduction steps. Expect an acknowledgement within 7 days.

Examples of in-scope issues:
- code execution or file access through a crafted rule YAML, condition string or JSONL input
- ReDoS or resource exhaustion via rule content (lint warns on nested quantifiers with W213, but the engine has no per-rule time budget yet; see THREAT_MODEL.md, T4)
- a gate bypass (a rule that should fail `anvil test` passes)

## Supported versions
The latest release (1.1.x, also published as `ghcr.io/rakshit-737/anvil`) and `main`. Older releases do not get fixes.

## Known dependency advisories
CI runs `pip-audit` over the `sigma`, `evtx`, `ml` and `fast` extras. One advisory is ignored there, on purpose:

| Advisory | Package | Status | Why it is accepted |
| --- | --- | --- | --- |
| PYSEC-2026-2447 / GHSA-w8v5-vhqr-4h9v (CVE-2025-69872) | `diskcache` 5.6.3, pulled in by pySigma | no fixed release yet | The vulnerable path is diskcache's pickle-based cache files. pySigma uses diskcache only for its lazily created `~/.cache/pysigma` MITRE ATT&CK and D3FEND data caches (`sigma.data.mitre_attack`, `sigma.data.mitre_d3fend`). The conversions ANVIL performs do not request that data: converting an ATT&CK-tagged rule with the Splunk, Elastic, KQL and SQLite backends leaves the cache uncreated. Do not share a writable pySigma cache directory between users. |

The ignore is re-checked by **2027-01-01**, or earlier when diskcache publishes a fix. Dependabot alerts and security updates are enabled for this repository.

## Safe use
- Load only rule and telemetry files you trust, or run ANVIL in CI sandboxes.
- Do not commit real production logs that contain personal data. Anonymise them first.
