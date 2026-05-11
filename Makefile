PYTHON ?= python3

.PHONY: install-dev test scan build

install-dev:
	$(PYTHON) -m pip install -e .

test:
	PYTHONPATH=src $(PYTHON) -m unittest -v

scan:
	PYTHONPATH=src $(PYTHON) -m secretsweep scan . --json

build:
	$(PYTHON) -m build
