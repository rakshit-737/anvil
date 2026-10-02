# ADR 0007: Linux and AWS CloudTrail routing

Status: accepted (1.1). Supersedes the non-Windows clause of ADR 0002.

## Context
Round 3 adds Linux and cloud telemetry: Splunk attack_data (auditd, Sysmon for Linux, CloudTrail) and OTRF Linux/AWS captures. SigmaHQ ships 210 Linux and 57 AWS rules that 1.0 reported as unroutable.

## Decision
- `anvil/nixcloud.py` parses Sysmon for Linux XML, raw and `ausearch -i` auditd records, and CloudTrail in JSON Lines, JSON array and `{"Records": [...]}` form, plus Syslog-wrapped rows.
- `anvil/logsource.py` routes `product: linux` categories to `linux-sysmon/operational` EventIDs, `service: auditd` to `linux-auditd`, and `service: cloudtrail` to `aws-cloudtrail`.
- Rules without a product never see the new non-Windows channels, so Windows-era global rules keep their behaviour.
- Files the development laptop's antivirus blocks are skipped and counted locally. They are only processed on the CI runner, where they are downloaded fresh and checksum-verified.

## Consequences
- 278 of 305 Linux/AWS rules route. Azure and M365 remain unrouted (the OTRF GoldenSAML capture is listed as unrouted).
- There is no benign CloudTrail corpus, so the alert-budget gate does not apply to AWS rules yet.
