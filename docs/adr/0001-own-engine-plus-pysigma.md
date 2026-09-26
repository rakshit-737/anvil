# ADR 0001: Evaluate rules with ANVIL's own engine; use pySigma for conversion and as an oracle

- Status: accepted (0.2.0)
- Date: 2026-09-26

## Context
ANVIL has to run thousands of Sigma rules against millions of JSON events on a laptop and in CI, with no SIEM. pySigma is the reference toolchain, but it *converts* rules to backend queries; it does not evaluate them. The only way to run pySigma output locally is through a database backend such as SQLite. That means loading every event into a table and inheriting SQL semantics: NULL handling, type affinity and `LIKE` escaping.

## Decision
- Keep a native Python engine (`anvil/engine.py`). It implements the Sigma value/modifier spec and compiles each rule to closures once.
- Use pySigma as an optional extra for two jobs:
  - `anvil convert` produces deployable Splunk, Elastic and KQL queries.
  - `SqliteOracle` is an independent implementation. `benchmarks/bench.py engine` uses it to cross-check the engine.
- Anything the engine does not implement (`expand` placeholders, aggregations, correlations) raises `UnsupportedRule`, and the count is reported. It is never silently skipped.

## Consequences
- The core install needs only PyYAML. Evaluation is deterministic and fast enough to scan the full library over millions of events with a process pool.
- The two implementations can disagree. The benchmark lists every disagreement and which side matches SigmaHQ's own expected result. In 0.2.0 both disagreements came from SQL semantics in the oracle: a boolean compared against the string `'true'`, and a CIDR expanded into string prefixes that misses a non-canonical IPv6 loopback.
- We carry the cost of tracking the Sigma spec. The regression replay over SigmaHQ's captures is the guard rail.
