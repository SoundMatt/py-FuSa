.PHONY: build test cover vet lint selfcheck install clean

build:
	pip install -e . --quiet

test:
	python -m pytest tests/ -v

cover:
	python -m pytest tests/ --cov=pyfusa --cov-report=term-missing --cov-fail-under=80

vet:
	python -m py_compile pyfusa/*.py pyfusa/**/*.py

lint:
	python -m flake8 pyfusa/ --max-line-length=120 --extend-ignore=E203,W503 || true

selfcheck:
	pyfusa check --dir .

qualify:
	pyfusa qualify --format json --output qualify-report.json

trace:
	pyfusa trace --format json

release:
	pyfusa release

audit-pack:
	pyfusa audit-pack

install:
	pip install -e .

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	rm -rf build dist *.egg-info .pytest_cache .coverage htmlcov
