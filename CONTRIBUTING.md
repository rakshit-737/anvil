# Contributing to ANVIL

Thanks for helping. ANVIL treats detections as code, and so does this repo: every change is reviewed, tested and measured.

## Setup

```bash
python -m venv .venv && . .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev,sigma,ml]"                     # core needs only PyYAML
python -m pytest -q                                  # fast suite, no downloads needed
ruff check anvil benchmarks tests
```

The real-data tests are marked `realdata` and skip unless `$ANVIL_DATA` points at a download made with `python scripts/download_data.py all` (about 350 MB).

> Windows note: `pip install evtx` (the fast Rust EVTX parser) and `python-evtx` both install a package directory named `evtx`/`Evtx`, which collide on case-insensitive filesystems. Install only one per environment, or install `evtx` into a separate venv.

## Adding or changing a rule in `rules/`

1. Write Sigma YAML with a `tests:` block holding at least one true positive and, ideally, a true negative.
2. `python -m anvil lint` must report no errors.
3. `python -m anvil test` must pass: fixtures fire as expected, the FP rate on the benign corpus stays under the threshold, and the expected alert volume fits the SOC budget.
4. Machine-drafted rules (`anvil draft`) arrive with `anvil.reviewed: false`. Only a human reviewer sets it to `true`, in the PR that adds the rule.

## Code changes

- Keep modules small and dependency-free where possible: PyYAML is the only hard dependency. pySigma, scikit-learn, `evtx` and `anthropic` are optional extras.
- Add a test for every behaviour change. Engine changes should come with a Sigma-spec example in `tests/test_sigma_engine.py`.
- If a change affects benchmark numbers, rerun the affected stage (`python benchmarks/bench.py <stage> report`) and commit the updated `results/` files in the same PR, so reviewers see the numbers move.
- Conventional commit messages: `feat:`, `fix:`, `perf:`, `test:`, `docs:`, `data:`, `ci:`, `refactor:`.

## Data rules

- Never commit datasets or files larger than 1 MB. Add a pinned, checksummed fetcher to `scripts/download_data.py` instead.
- Never add live malware, exploit code or anything that executes attack techniques. ANVIL only reads logs.
