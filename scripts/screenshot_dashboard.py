#!/usr/bin/env python3
"""Capture the README/docs hero image of the static dashboard with headless Chromium.

    pip install playwright && python -m playwright install chromium
    python scripts/screenshot_dashboard.py [docs/dashboard.html] [docs/img/dashboard.png]

Runs in the ``report`` job of .github/workflows/bench.yml, so the screenshot always
shows the same run's results as the committed JSON files. The page is loaded from
disk; it has no external requests.
"""
from __future__ import annotations

import sys
from pathlib import Path


def main(argv: list[str]) -> int:
    src = Path(argv[0] if argv else "docs/dashboard.html").resolve()
    out = Path(argv[1] if len(argv) > 1 else "docs/img/dashboard.png")
    if not src.exists():
        print(f"{src} not found: run `python benchmarks/bench.py report` first", file=sys.stderr)
        return 2
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1366, "height": 900}, color_scheme="light")
        failed: list[str] = []
        page.on("requestfailed", lambda r: failed.append(r.url))
        page.goto(src.as_uri(), wait_until="load")
        page.screenshot(path=str(out), full_page=False)
        browser.close()
    if failed:
        print(f"failed requests: {failed}", file=sys.stderr)
        return 1
    size = out.stat().st_size
    print(f"wrote {out} ({size:,} bytes)")
    return 0 if size < 500_000 else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
