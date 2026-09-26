# Security Policy

## Scope
ANVIL is a defensive detection-engineering tool. It contains no exploit code, and it never executes the techniques its rules describe. All bundled telemetry is synthetic.

## Reporting a vulnerability
Please report issues privately to the maintainer through GitHub Security Advisories on this repository, not through public issues. Include reproduction steps. Expect an acknowledgement within 7 days.

Examples of in-scope issues:
- code execution or file access through a crafted rule YAML, condition string or JSONL input
- ReDoS or resource exhaustion via rule content
- a gate bypass (a rule that should fail `anvil test` passes)

## Safe use
- Load only rule and telemetry files you trust, or run ANVIL in CI sandboxes.
- Do not commit real production logs that contain personal data. Anonymise them first.
- Supported versions: the latest `main` only.
