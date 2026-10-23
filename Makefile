.PHONY: install list scan-vuln scan-hardened diff reports server test clean

PY ?= python3

install:
	$(PY) -m pip install --break-system-packages -r requirements.txt

list:
	$(PY) -m llmsec list

scan-vuln:
	$(PY) -m llmsec scan --target mock-vulnerable --out reports/

scan-hardened:
	$(PY) -m llmsec scan --target mock-hardened --out reports/

# Regenerate the committed example reports and print the before/after diff.
reports:
	$(PY) -m llmsec scan --target mock-vulnerable --out reports/ >/dev/null
	$(PY) -m llmsec scan --target mock-hardened  --out reports/ >/dev/null
	$(PY) scripts/make_example_reports.py

diff:
	$(PY) -m llmsec diff reports/example-mock-vulnerable.json reports/example-mock-hardened.json

# Start the OpenAI-compatible mock endpoint (loopback) in the foreground.
server:
	$(PY) scripts/mock_llm_server.py --port 8765

test:
	$(PY) -m pytest -q

clean:
	rm -rf .pytest_cache
	find . -name __pycache__ -type d -exec rm -rf {} +
