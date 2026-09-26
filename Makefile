# `make` is optional: every target is a plain command you can run directly.
PY ?= python
export ANVIL_DATA ?= $(CURDIR)/data

.PHONY: install install-all test lint data corpus bench report demo clean

install:
	$(PY) -m pip install -e ".[dev]"

install-all:
	$(PY) -m pip install -e ".[dev]" -r requirements-bench.txt

test:
	$(PY) -m pytest -q

lint:
	$(PY) -m ruff check anvil benchmarks tests scripts
	$(PY) -m anvil lint

# ~350 MB: SigmaHQ @pin, ATT&CK STIX 19.2, OTRF Security-Datasets, evtx-baseline Win10/Win11/2022-AD
data:
	$(PY) scripts/download_data.py all
	$(PY) -m anvil ingest --benign

bench:
	$(PY) benchmarks/bench.py all

report:
	$(PY) benchmarks/bench.py report

corpus:
	$(PY) -m anvil synth --out telemetry/benign.jsonl
	$(PY) -m anvil synth --schema v2 --out telemetry/benign_v2.jsonl

demo: corpus
	@echo "== 1. lint (ANVIL rules with in-rule fixtures) =="
	$(PY) -m anvil lint
	@echo "== 2. CI gate: TP/TN fixtures + benign FP corpus + SOC capacity =="
	$(PY) -m anvil test --save-baseline telemetry/baseline.json
	@echo "== 3. FP guardrail (expected to FAIL) =="
	-$(PY) -m anvil test --rules examples/noisy
	@echo "== 4. draft rules from a CTI report (unreviewed, lint blocks them) =="
	$(PY) -m anvil draft examples/cti/fin_x_report.md --out drafts
	-$(PY) -m anvil lint --rules drafts --profile sigma
	@echo "== 5. ATT&CK coverage =="
	$(PY) -m anvil coverage --corpus telemetry/benign.jsonl --navigator telemetry/navigator_layer.json
	@echo "== 6. decay monitor after a schema change (expected to FLAG) =="
	-$(PY) -m anvil decay --corpus telemetry/benign_v2.jsonl --baseline telemetry/baseline.json --routed

clean:
	rm -rf telemetry/baseline.json telemetry/navigator_layer.json drafts
