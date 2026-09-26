"""SIEM query conversion and an independent evaluation oracle, via pySigma.

pySigma is optional (``pip install anvil-dac[sigma]``). ANVIL uses it for two
things:

1. ``convert`` - compile a rule to Splunk SPL, Elastic Lucene (ECS), Microsoft
   Sentinel/Defender KQL, or SQLite, so a rule tested by ANVIL can be deployed.
2. ``SqliteOracle`` - a *second, independent* Sigma implementation: the rule is
   compiled to SQL by pySigma's SQLite backend and executed against the same
   events loaded into an in-memory table. Agreement between ANVIL's engine and
   the oracle is reported by ``benchmarks/bench.py engine``.
"""
from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass
from typing import Any, Callable

TARGETS = ("splunk", "elastic", "kusto", "sqlite")


def available() -> bool:
    try:
        import sigma  # noqa: F401  # type: ignore[import-not-found]
    except ImportError:
        return False
    return True


def _backend(target: str) -> Any:
    if target == "splunk":
        from sigma.backends.splunk import SplunkBackend
        from sigma.pipelines.splunk import splunk_windows_pipeline
        return SplunkBackend(splunk_windows_pipeline())
    if target == "elastic":
        from sigma.backends.elasticsearch import LuceneBackend
        from sigma.pipelines.elasticsearch.windows import ecs_windows
        return LuceneBackend(ecs_windows())
    if target == "kusto":
        from sigma.backends.kusto import KustoBackend
        from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline
        return KustoBackend(microsoft_xdr_pipeline())
    if target == "sqlite":
        from sigma.backends.sqlite import sqliteBackend
        return sqliteBackend()
    raise ValueError(f"unknown target {target!r}; choose from {TARGETS}")


@dataclass
class Conversion:
    rule_id: str
    target: str
    queries: list[str]
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.error and bool(self.queries)


class Converter:
    def __init__(self, target: str):
        self.target = target
        self.backend = _backend(target)

    def convert_yaml(self, text: str, rule_id: str = "") -> Conversion:
        from sigma.collection import SigmaCollection
        try:
            coll = SigmaCollection.from_yaml(text)
            qs = self.backend.convert(coll)
            qs = [str(q) for q in (qs if isinstance(qs, list) else [qs])]
            return Conversion(rule_id, self.target, qs)
        except Exception as exc:  # pySigma raises many exception types per unsupported feature
            return Conversion(rule_id, self.target, [], f"{type(exc).__name__}: {str(exc)[:200]}")


def _regexp(pattern: str, value: Any) -> bool:
    if value is None:
        return False
    try:
        return re.search(pattern, str(value)) is not None
    except re.error:
        return False


class SqliteOracle:
    """Evaluate one rule's pySigma-generated SQL over a list of events."""

    def __init__(self) -> None:
        self.conv = Converter("sqlite")

    def compile(self, rule_yaml: str, rule_id: str = "") -> Conversion:
        return self.conv.convert_yaml(rule_yaml, rule_id)

    @staticmethod
    def count(sql: str, events: list[dict[str, Any]]) -> int:
        """Number of events the SQL WHERE clause selects (each event at most once)."""
        cols = sorted({k for e in events for k in e if not k.startswith("__")})
        db = sqlite3.connect(":memory:")
        try:
            db.create_function("regexp", 2, _regexp, deterministic=True)
            coldefs = ", ".join(f'"{c}" TEXT' for c in cols) or '"_dummy" TEXT'
            db.execute(f"CREATE TABLE logs (__rowid INTEGER, {coldefs})")
            for i, e in enumerate(events):
                keys = [c for c in cols if c in e]
                vals = [None if e[c] is None else (e[c] if isinstance(e[c], (int, float)) else str(e[c]))
                        for c in keys]
                ph = ", ".join("?" for _ in range(len(keys) + 1))
                names = ", ".join(["__rowid"] + [f'"{c}"' for c in keys])
                db.execute(f"INSERT INTO logs ({names}) VALUES ({ph})", [i, *vals])
            q = sql.replace("<TABLE_NAME>", "logs").replace("SELECT *", "SELECT DISTINCT __rowid", 1)
            try:
                return len(db.execute(q).fetchall())
            except sqlite3.OperationalError as exc:
                if "no such column" in str(exc):
                    # the rule references a field absent from every event: add it as NULL and retry
                    missing = str(exc).split(":")[-1].strip()
                    db.execute(f'ALTER TABLE logs ADD COLUMN "{missing}" TEXT')
                    return SqliteOracle._retry(db, q)
                raise
        finally:
            db.close()

    @staticmethod
    def _retry(db: sqlite3.Connection, q: str, depth: int = 0) -> int:
        try:
            return len(db.execute(q).fetchall())
        except sqlite3.OperationalError as exc:
            if "no such column" in str(exc) and depth < 50:
                db.execute(f'ALTER TABLE logs ADD COLUMN "{str(exc).split(":")[-1].strip()}" TEXT')
                return SqliteOracle._retry(db, q, depth + 1)
            raise


def make_matcher(sql_by_rule: dict[str, str]) -> Callable[[str, dict[str, Any]], bool]:
    """Adapter: per-event matcher over the oracle (slow; used for small samples)."""
    def m(rid: str, ev: dict[str, Any]) -> bool:
        sql = sql_by_rule.get(rid)
        return bool(sql) and SqliteOracle.count(sql, [ev]) > 0
    return m
