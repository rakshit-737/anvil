PY ?= python

.PHONY: install test demo corpus clean

install:
	$(PY) -m pip install -r requirements.txt

corpus:
	$(PY) -m anvil synth --out telemetry/benign.jsonl
	$(PY) -m anvil synth --schema v2 --out telemetry/benign_v2.jsonl

test:
	$(PY) -m pytest -q

demo: corpus
	@echo "== 1. lint =="
	$(PY) -m anvil lint
	@echo "== 2. CI gate: TP/TN fixtures + benign FP corpus =="
	$(PY) -m anvil test --save-baseline telemetry/baseline.json
	@echo "== 3. FP / SOC-capacity guardrail (expected to FAIL) =="
	-$(PY) -m anvil test --rules examples/noisy
	@echo "== 4. ATT&CK coverage =="
	$(PY) -m anvil coverage --corpus telemetry/benign.jsonl --navigator telemetry/navigator_layer.json
	@echo "== 5. rule quality =="
	$(PY) -m anvil score
	@echo "== 6. decay monitor after log schema change (expected to FLAG) =="
	-$(PY) -m anvil decay --corpus telemetry/benign_v2.jsonl --baseline telemetry/baseline.json

clean:
	rm -f telemetry/baseline.json telemetry/navigator_layer.json
