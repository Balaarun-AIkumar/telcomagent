PY ?= .venv/Scripts/python
export PYTHONPATH := src
export SB_DATA_DIR ?= .sbdata

install:
	uv venv .venv && uv pip install --python .venv -e ".[dev]"
seed:
	$(PY) -m switchboard.cli seed
demo:
	$(PY) -m switchboard.cli demo
test:
	$(PY) -m pytest -q
evals:
	$(PY) evals/run_evals.py
serve:
	$(PY) -m switchboard.cli --demo serve gateway
up:
	docker compose up -d --build

.PHONY: install seed demo test evals serve up
