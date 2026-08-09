.PHONY: help setup install test lint fmt run clean

help:
	@echo "VoidRecon — make targets:"
	@echo "  setup    Install package with dev + full extras (editable)"
	@echo "  test     Run the test suite (pytest)"
	@echo "  lint     Lint the codebase (ruff)"
	@echo "  fmt      Auto-fix lint issues (ruff --fix)"
	@echo "  run      Show the CLI help"
	@echo "  clean    Remove caches and build artifacts"

setup install:
	./scripts/setup.sh

test:
	python3 -m pytest -q

lint:
	python3 -m ruff check .

fmt:
	python3 -m ruff check . --fix

run:
	python -m voidrecon --help

clean:
	rm -rf build dist *.egg-info .pytest_cache .ruff_cache
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
