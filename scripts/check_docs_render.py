#!/usr/bin/env python3
"""Headless-browser check of the built docs site (run by .github/workflows/docs.yml).

    mkdocs build --strict
    python -m http.server -d site 8000 &
    python scripts/check_docs_render.py http://127.0.0.1:8000/

* The architecture page's Mermaid diagram must render to an SVG with at least
  ``--min-nodes`` nodes and no "Syntax error". mkdocs-material renders Mermaid into a
  *closed* shadow root, so an init script opens shadow roots before any page script
  runs; a plain ``.mermaid svg`` selector would always find nothing.
* Every page in sitemap.xml (plus the dashboard) must load without a failed request,
  an HTTP status >= 400 or a console error.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

OPEN_SHADOW = """
(() => {
  const orig = Element.prototype.attachShadow;
  Element.prototype.attachShadow = function (init) { return orig.call(this, {...init, mode: 'open'}); };
})();
"""

MERMAID_STATE = """
() => {
  const hosts = [...document.querySelectorAll('.mermaid')];
  return hosts.map(h => {
    const root = h.shadowRoot || h;
    const svg = root.querySelector('svg');
    return {
      svg: !!svg,
      nodes: svg ? svg.querySelectorAll('g.node').length : 0,
      edges: svg ? svg.querySelectorAll('.edgePath, path.flowchart-link, g.edgePaths > path').length : 0,
      error: /Syntax error/i.test(root.textContent || ''),
      height: svg ? svg.getBoundingClientRect().height : 0,
    };
  });
}
"""


def pages(site: Path, base: str) -> list[str]:
    """Page URLs from the built sitemap, rebased onto the local server."""
    xml = (site / "sitemap.xml").read_text(encoding="utf-8")
    locs = re.findall(r"<loc>([^<]+)</loc>", xml)
    out = []
    for loc in locs:
        m = re.match(r"https?://[^/]+/[^/]+/(.*)", loc)
        out.append(base + (m.group(1) if m else ""))
    out.append(base + "dashboard.html")
    return sorted(set(out))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("base", nargs="?", default="http://127.0.0.1:8000/")
    ap.add_argument("--site", default="site", help="built site folder (for sitemap.xml)")
    ap.add_argument("--min-nodes", type=int, default=16, help="nodes expected in the architecture diagram")
    a = ap.parse_args(argv)
    base = a.base if a.base.endswith("/") else a.base + "/"
    from playwright.sync_api import sync_playwright

    problems: list[str] = []
    with sync_playwright() as p:
        browser = p.chromium.launch()
        ctx = browser.new_context()
        ctx.add_init_script(OPEN_SHADOW)
        page = ctx.new_page()
        current = {"url": ""}
        page.on("requestfailed", lambda r: problems.append(f"{current['url']}: request failed {r.url} "
                                                            f"({r.failure})"))
        page.on("response", lambda r: r.status >= 400 and problems.append(
            f"{current['url']}: HTTP {r.status} {r.url}"))
        page.on("console", lambda m: m.type == "error" and problems.append(f"{current['url']}: console {m.text}"))
        page.on("pageerror", lambda e: problems.append(f"{current['url']}: page error {e}"))

        current["url"] = base + "architecture/"
        page.goto(current["url"], wait_until="networkidle")
        try:
            page.wait_for_function("() => [...document.querySelectorAll('.mermaid')].some("
                                   "h => (h.shadowRoot || h).querySelector('svg'))", timeout=30_000)
        except Exception as exc:  # noqa: BLE001 - report the timeout as a finding
            problems.append(f"architecture: no Mermaid SVG after 30 s ({type(exc).__name__})")
        state = page.evaluate(MERMAID_STATE)
        print(f"architecture mermaid: {state}")
        if not state:
            problems.append("architecture: no .mermaid element")
        for i, d in enumerate(state):
            if not d["svg"] or d["error"] or d["nodes"] < a.min_nodes:
                problems.append(f"architecture: diagram {i} svg={d['svg']} nodes={d['nodes']} "
                                f"syntax_error={d['error']}")

        urls = pages(Path(a.site), base)
        for url in urls:
            current["url"] = url
            page.goto(url, wait_until="networkidle")
        print(f"checked {len(urls)} pages")
        browser.close()
    for prob in problems:
        print(f"::error::{prob}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
