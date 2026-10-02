#!/usr/bin/env python3
"""Real-backend cross-check: SigmaHQ rules executed in OpenSearch vs ANVIL's engine.

Runs in CI (.github/workflows/bench.yml, job ``backend``) against an OpenSearch
service container on localhost:9200. It never contacts any other host.

1. Bulk-load the SigmaHQ regression captures (one ``_case`` per capture) and a
   deterministic benign sample of evtx-baseline (``_set: benign``) into one index.
   Every string is a ``keyword`` with a lowercase normalizer (Sigma matching is
   case-insensitive); ``EventID`` is a long.
2. Convert each Windows rule with pySigma's OpenSearch Lucene backend plus the
   *pySigma* Sysmon and Windows log-source pipelines, so log-source handling is
   independent of ANVIL's router. Only the JSON loader (flattening) is shared.
3. Per regression case: ``_count`` of the query restricted to that case, compared
   with ANVIL's matched count. On the benign sample: the set of matching docs per
   rule, compared with ANVIL's per-event matches.

Writes results/backend_opensearch.json.
"""
from __future__ import annotations

import http.client
import json
import math
import os
import re
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from anvil.regression import discover, run_case  # noqa: E402
from anvil.runner import Library, load_rule_dir  # noqa: E402
from anvil.telemetry import iter_json_file  # noqa: E402
from benchmarks.common import save, sigma_root  # noqa: E402

URL = os.environ.get("OPENSEARCH_URL", "http://localhost:9200")
INDEX = "anvil-xcheck"
MODIFIERS = ("windash", "base64offset", "base64", "cidr", "fieldref", "re", "expand", "utf16", "wide", "all",
             "exists", "gt", "lt")


def _req(method: str, path: str, body: Any = None, ndjson: bool = False) -> Any:
    if not URL.startswith(("http://localhost", "http://127.0.0.1")):
        raise SystemExit("refusing to talk to a non-local OpenSearch")
    data = None
    headers = {}
    if body is not None:
        data = body.encode() if isinstance(body, str) else json.dumps(body).encode()
        headers["Content-Type"] = "application/x-ndjson" if ndjson else "application/json"
    req = urllib.request.Request(URL + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=120) as r:  # noqa: S310 - localhost only, checked above
            return json.load(r)
    except urllib.error.HTTPError as exc:
        return {"_error": exc.code, "_body": exc.read().decode(errors="replace")[:300]}
    except (OSError, http.client.HTTPException) as exc:
        # A pathological query (huge wildcard/regex) can drop the connection or stall the
        # node; count it as a query error and wait for the cluster to come back.
        _wait_healthy()
        return {"_error": type(exc).__name__}


def _wait_healthy(seconds: int = 300) -> None:
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(URL + "/_cluster/health", timeout=10) as r:  # noqa: S310 - localhost
                if json.load(r).get("status") in ("green", "yellow"):
                    return
        except (OSError, http.client.HTTPException):
            pass
        time.sleep(5)
    raise SystemExit("OpenSearch did not recover")


def _doc(ev: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in ev.items():
        k = str(k).replace(".", "_")  # dotted keys would become object paths
        if isinstance(v, (dict, list)):
            v = json.dumps(v)
        if k == "EventID":
            try:
                v = int(v)
            except (TypeError, ValueError):
                continue
        elif v is not None and not isinstance(v, str):
            v = str(v)
        out[k] = v
    return out


def _create_index() -> None:
    _req("DELETE", f"/{INDEX}")
    r = _req("PUT", f"/{INDEX}", {
        "settings": {"number_of_shards": 1, "number_of_replicas": 0, "index.mapping.total_fields.limit": 20000,
                     "index.max_result_window": 50000,
                     "analysis": {"normalizer": {"lc": {"type": "custom", "filter": ["lowercase"]}}}},
        "mappings": {"dynamic_templates": [{"s": {"match_mapping_type": "string", "mapping": {
            "type": "keyword", "normalizer": "lc", "ignore_above": 10922}}}],
            "properties": {"EventID": {"type": "long"}, "_case": {"type": "integer"},
                           "_set": {"type": "keyword"}}}})
    if "_error" in r:
        raise SystemExit(f"index create failed: {r}")
    # Cancel runaway searches (huge leading-wildcard automata) instead of letting them
    # exhaust the heap and kill the node.
    _req("PUT", "/_cluster/settings", {"persistent": {
        "search_backpressure.mode": "enforced",
        "search.cancel_after_time_interval": "30s"}})


def _bulk(docs: list[tuple[str, dict[str, Any]]]) -> int:
    failed = 0
    for i in range(0, len(docs), 2000):
        lines = []
        for _id, d in docs[i:i + 2000]:
            lines.append(json.dumps({"index": {"_index": INDEX, "_id": _id}}))
            lines.append(json.dumps(d))
        r = _req("POST", "/_bulk", "\n".join(lines) + "\n", ndjson=True)
        failed += sum(1 for it in r.get("items", []) if it["index"].get("error"))
    _req("POST", f"/{INDEX}/_refresh")
    return failed


def _backend():
    from sigma.backends.opensearch import OpensearchLuceneBackend
    from sigma.pipelines.sysmon import sysmon_pipeline
    from sigma.pipelines.windows import windows_logsource_pipeline
    return OpensearchLuceneBackend(sysmon_pipeline() + windows_logsource_pipeline())


def _convert(backend, path: str, cache: dict[str, Any]) -> list[str] | str:
    if path in cache:
        return cache[path]
    from sigma.collection import SigmaCollection
    try:
        qs = backend.convert(SigmaCollection.from_yaml(Path(path).read_text(encoding="utf-8")))
        out: list[str] | str = [q for q in qs if isinstance(q, str)] or "empty"
    except Exception as exc:  # noqa: BLE001 - pySigma raises many error classes
        out = type(exc).__name__
    cache[path] = out
    return out


def _search_ids(q: str, flt: dict[str, Any]) -> set[str] | None:
    body = {"size": 50000, "_source": False, "timeout": "30s", "track_total_hits": True,
            "query": {"bool": {"must": [{"query_string": {"query": q, "allow_leading_wildcard": True}}],
                               "filter": [flt]}}}
    t = time.perf_counter()
    r = _req("POST", f"/{INDEX}/_search", body)
    dt = time.perf_counter() - t
    if "_error" in r or dt > 10:
        print(f"slow-or-failed query ({dt:.1f}s, {r.get('_error', 'ok')}): {q[:200]}", flush=True)
    if "_error" in r:
        return None
    return {h["_id"] for h in r["hits"]["hits"]}


def _modifiers(path: str) -> list[str]:
    text = Path(path).read_text(encoding="utf-8")
    return sorted({m for m in MODIFIERS if re.search(rf"\|{m}\b", text)})


def kappa(a: int, b: int, c: int, d: int) -> float:
    """Cohen's kappa for a 2x2 table: a=both yes, b=anvil only, c=backend only, d=both no."""
    n = a + b + c + d
    if not n:
        return float("nan")
    po = (a + d) / n
    pe = ((a + b) * (a + c) + (c + d) * (b + d)) / (n * n)
    return 1.0 if pe == 1 else (po - pe) / (1 - pe)


def wilson(k: int, n: int, z: float = 1.96) -> list[float]:
    if not n:
        return [0.0, 0.0]
    p = k / n
    den = 1 + z * z / n
    c = (p + z * z / (2 * n)) / den
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return [round(max(0.0, c - h), 4), round(min(1.0, c + h), 4)]


def main() -> int:
    from benchmarks.bench import _benign_sample, _rule_dirs
    t0 = time.perf_counter()
    info = _req("GET", "/")
    rules, _ = load_rule_dir(_rule_dirs())
    lib = Library.build(rules)
    win = {r.id: r for r in rules if r.logsource.product.lower() == "windows" and r.status != "deprecated"}
    cases = discover(sigma_root())
    _create_index()
    docs: list[tuple[str, dict[str, Any]]] = []
    case_events: dict[int, int] = {}
    for i, c in enumerate(cases):
        try:
            evs = list(iter_json_file(c["sample"]))
        except (OSError, ValueError):
            continue
        case_events[i] = len(evs)
        for j, e in enumerate(evs):
            docs.append((f"c{i}-{j}", {**_doc(e), "_case": i, "_set": "regress"}))
    sample = _benign_sample(per_group=600)
    for j, e in enumerate(sample):
        docs.append((f"b{j}", {**_doc(e), "_set": "benign"}))
    failed_docs = _bulk(docs)

    backend = _backend()
    cache: dict[str, Any] = {}
    # ---- regression captures
    reg = Counter()
    reg_rows = []
    for i, c in enumerate(cases):
        mine = run_case(lib, c)
        if i not in case_events or mine.status not in ("pass", "fail") or c["rule_id"] not in lib.rules:
            reg["skipped"] += 1
            continue
        path = lib.rules[c["rule_id"]].path
        qs = _convert(backend, path, cache)
        if isinstance(qs, str):
            reg["convert-error"] += 1
            continue
        ids: set[str] = set()
        err = False
        for q in qs:
            got = _search_ids(q, {"term": {"_case": i}})
            if got is None:
                err = True
                break
            ids |= got
        if err:
            reg["query-error"] += 1
            continue
        n_os = len(ids)
        exp = c["expected"] or 1
        os_pass = n_os >= exp and n_os > 0
        reg["compared"] += 1
        reg["anvil_pass"] += mine.status == "pass"
        reg["opensearch_pass"] += os_pass
        reg["verdict_agree"] += (mine.status == "pass") == os_pass
        reg["count_agree"] += n_os == mine.matched
        if n_os != mine.matched:
            reg_rows.append({"rule": c["rule_id"], "title": c["title"], "anvil": mine.matched, "opensearch": n_os,
                             "expected": c["expected"], "modifiers": _modifiers(path)})

    # ---- benign sample, per rule
    anvil_hits: dict[str, set[str]] = {}
    for j, e in enumerate(sample):
        for rid in lib.match_event(e):
            anvil_hits.setdefault(rid, set()).add(f"b{j}")
    ben = Counter()
    ben_rows = []
    a = b = cc = d = 0
    for rid, r in win.items():
        if rid not in lib.compiled:
            ben["anvil-unsupported-or-unroutable"] += 1
            continue
        qs = _convert(backend, r.path, cache)
        if isinstance(qs, str):
            ben["convert-error"] += 1
            continue
        ids = set()
        bad = False
        for q in qs:
            got = _search_ids(q, {"term": {"_set": "benign"}})
            if got is None:
                bad = True
                break
            ids |= got
        if bad:
            ben["query-error"] += 1
            continue
        mine = anvil_hits.get(rid, set())
        ben["compared"] += 1
        fa, fo = bool(mine), bool(ids)
        a += fa and fo
        b += fa and not fo
        cc += fo and not fa
        d += not fa and not fo
        ben["same_event_set"] += mine == ids
        if mine != ids:
            ben_rows.append({"rule": rid, "title": r.title, "anvil": len(mine), "opensearch": len(ids),
                             "both": len(mine & ids), "modifiers": _modifiers(r.path)})
    conv_errors = Counter(v for v in cache.values() if isinstance(v, str))
    res = {
        "backend": {"engine": "opensearch", "version": info.get("version", {}).get("number")},
        "pipelines": "pySigma sysmon + windows logsource (independent of ANVIL routing)",
        "documents": len(docs), "documents_rejected": failed_docs, "benign_events": len(sample),
        "regression": {**dict(reg),
                       "verdict_agreement": round(reg["verdict_agree"] / max(1, reg["compared"]), 4),
                       "verdict_agreement_ci95": wilson(reg["verdict_agree"], reg["compared"]),
                       "count_agreement": round(reg["count_agree"] / max(1, reg["compared"]), 4),
                       "disagreements": reg_rows},
        "benign": {**dict(ben),
                   "fire_table": {"both": a, "anvil_only": b, "opensearch_only": cc, "neither": d},
                   "fire_kappa": round(kappa(a, b, cc, d), 4),
                   "same_event_set_rate": round(ben["same_event_set"] / max(1, ben["compared"]), 4),
                   "same_event_set_ci95": wilson(ben["same_event_set"], ben["compared"]),
                   "disagreements": sorted(ben_rows, key=lambda x: -abs(x["anvil"] - x["opensearch"]))[:60],
                   "disagreements_by_modifier": dict(Counter(m for row in ben_rows for m in row["modifiers"]
                                                             or ["(plain)"]))},
        "convert_errors": dict(conv_errors),
        "seconds": round(time.perf_counter() - t0, 1),
    }
    save("backend_opensearch.json", res)
    print(json.dumps({k: v for k, v in res.items() if k not in ("regression", "benign")}))
    print(json.dumps({k: v for k, v in res["regression"].items() if k != "disagreements"}))
    print(json.dumps({k: v for k, v in res["benign"].items() if k != "disagreements"}))
    floor = float(os.environ.get("ANVIL_BACKEND_MIN_AGREEMENT", "0.9"))
    if res["regression"]["verdict_agreement"] < floor:
        print(f"verdict agreement below {floor}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
