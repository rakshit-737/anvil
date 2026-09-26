# ADR 0004: The drafter proposes, a human approves, and the tests decide

- Status: accepted (0.2.0)
- Date: 2026-09-26

## Context
The spec calls for turning a CTI report into candidate detections. LLMs can write plausible Sigma, but plausible is not the same as correct. A drafted rule can be over-broad, tied to one incident's IOCs, or syntactically valid but semantically wrong. It can also be steered by text planted in the report.

## Decision
- `anvil draft` has three backends:
  - `heuristic`: offline and deterministic, and the default. It extracts commands, keeps behavioural tokens and strips IOCs.
  - `llm`: optional, uses Claude through the `anthropic` SDK.
  - `keywords`: a deliberately naive baseline, used only in benchmarks.
- Every draft is emitted as `status: experimental` with `anvil: {draft: true, reviewed: false}`.
- Lint error **A114** blocks unreviewed drafts, so CI fails if one lands in the deployable rules folder.
- A reviewed draft still has to pass the same gate as a hand-written rule: its fixtures, the benign FP rate and the alert budget.
- LLM output is treated as untrusted input. It is parsed with `yaml.safe_load`, compiled by the normal engine and never executed. The model never gets write access to the repository.

## Consequences
- The benchmark tests raw drafts in two places: against the emulation they were drafted from, and against the benign corpus. Results sit next to the naive keyword baseline and the hand-written SigmaHQ rules.
- The review step is a hard gate, not a checkbox, so the research question stays measurable and honest.
