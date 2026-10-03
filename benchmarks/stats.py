"""Small, dependency-free statistics used by the benchmark suite.

Intervals are stored at full precision (6 decimals) and rounded once, at display
time, by :func:`fmt_prop` / :func:`fmt_ci`.
"""
from __future__ import annotations

import math
import random
from collections.abc import Sequence


def wilson(k: int, n: int, z: float = 1.96) -> list[float] | None:
    """Wilson score 95% interval for ``k`` successes out of ``n``.

    Returns ``None`` when ``n == 0``: the proportion is undefined, so there is no
    interval to report (callers print ``n/a``).
    """
    if not n:
        return None
    p = k / n
    den = 1 + z * z / n
    c = (p + z * z / (2 * n)) / den
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return [round(max(0.0, c - h), 6), round(min(1.0, c + h), 6)]


def mcnemar_exact(b: int, c: int) -> float:
    """Two-sided exact McNemar p-value from the discordant counts ``b`` and ``c``.

    Under H0 the discordant pairs split Binomial(b + c, 1/2); the p-value is twice
    the smaller tail, capped at 1. With no discordant pairs it is 1.
    """
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n
    return min(1.0, 2 * tail)


def paired_mcnemar(a: set[str], b: set[str], universe: set[str]) -> dict[str, float | int]:
    """Exact McNemar test of two methods' positive sets over the same ``universe``.

    Returns the discordant counts (``only_a``, ``only_b``) and the two-sided p-value.
    """
    only_a = len((a - b) & universe)
    only_b = len((b - a) & universe)
    return {"only_a": only_a, "only_b": only_b, "p_exact": mcnemar_exact(only_a, only_b)}


def cohen_kappa(a: int, b: int, c: int, d: int) -> float:
    """Cohen's kappa for a 2x2 table: a=both yes, b=first only, c=second only, d=both no."""
    n = a + b + c + d
    if not n:
        return float("nan")
    po = (a + d) / n
    pe = ((a + b) * (a + c) + (c + d) * (b + d)) / (n * n)
    return float("nan") if pe == 1 else (po - pe) / (1 - pe)


def kappa_bootstrap_ci(table: Sequence[int], n_boot: int = 2000, seed: int = 7) -> list[float] | None:
    """Percentile 95% bootstrap interval for Cohen's kappa, resampling the units of a 2x2 table."""
    n = sum(table)
    if not n:
        return None
    rng = random.Random(seed)
    cells = [0, 1, 2, 3]
    vals = []
    for _ in range(n_boot):
        cnt = [0, 0, 0, 0]
        for i in rng.choices(cells, weights=table, k=n):
            cnt[i] += 1
        k = cohen_kappa(*cnt)
        if not math.isnan(k):
            vals.append(k)
    if not vals:
        return None
    vals.sort()
    return [round(vals[int(0.025 * (len(vals) - 1))], 4), round(vals[int(0.975 * (len(vals) - 1))], 4)]


def _pct(x: float, digits: int) -> str:
    return f"{100 * x:.{digits}f}"


def fmt_ci(ci: Sequence[float] | None, digits: int = 1) -> str:
    """``[lo, hi]`` in percent, or ``n/a`` for an undefined interval."""
    if not ci:
        return "n/a"
    return f"[{_pct(ci[0], digits)}, {_pct(ci[1], digits)}]"


def fmt_prop(k: int, n: int, digits: int = 1, ci: Sequence[float] | None = None) -> str:
    """``k/n, p% [lo, hi]`` with one rounding step; ``k/n, n/a`` when ``n == 0``."""
    if not n:
        return f"{k}/{n}, n/a"
    ci = ci if ci is not None else wilson(k, n)
    return f"{k}/{n}, {_pct(k / n, digits)}% {fmt_ci(ci, digits)}"


def fmt_p(p: float) -> str:
    """A p-value for tables: two significant digits, scientific below 0.001."""
    if p >= 0.001:
        return f"{p:.2g}" if p < 0.1 else f"{p:.2f}"
    return f"{p:.1e}"
