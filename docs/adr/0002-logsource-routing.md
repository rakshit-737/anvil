# ADR 0002: Route rules by log source and index them by (channel, EventID)

- Status: accepted (0.2.0)
- Date: 2026-09-26

## Context
ANVIL 0.1 evaluated every rule against every event. On real telemetry this is wrong as well as slow:
- A rule written for PowerShell script blocks gets tested against Sysmon registry events.
- Keyword rules match unrelated logs.
- FP rates become meaningless.

Sigma rules declare a `logsource` (category, service, product), and SIEMs resolve it with a processing pipeline.

## Decision
- `anvil/logsource.py` maps Sigma categories and services to Windows `Channel` + `EventID` pairs. The mapping follows the public Sigma/pySigma conventions and the THOR log-source config that SigmaHQ uses in its CI. Categories that share an EventID carry an extra guard, for example the Sysmon EID 12 `EventType` check that separates registry add from registry delete.
- Security 4688 events get Sysmon-style aliases (`NewProcessName` -> `Image`), the same way pySigma's Windows pipeline handles them.
- The runner statically derives which EventIDs a detection requires, from `EventID` selections along every AND path. It then indexes rules by `(channel, EventID)`, so each event is only tested against rules that could match it.
- Non-Windows rules, and Windows categories with no event-log source (`file_access`, `file_rename`), are reported as unroutable.

## Consequences
- On the benign sample in `results/engine.json`, routing removes the alerts that 0.1 raised on the wrong log sources. It also cuts rule evaluations by orders of magnitude.
- The mapping is data, so it needs maintenance as Sigma adds categories. Unknown categories fail closed: the rule is marked unroutable rather than run against everything.
- Diffing benign hits against SigmaHQ's `known-FPs.csv` caught a real routing bug (the registry_delete guard) before release.
