# Contributing

## Development setup

```bash
git clone https://github.com/SoundMatt/py-FuSa
cd py-FuSa
pip install -e .
pip install pytest pytest-cov
```

## Running tests

```bash
make test        # run all tests
make cover       # run with coverage (80% minimum)
make selfcheck   # run pyfusa check on the pyfusa source itself
```

## Adding a rule

1. Choose the correct module: `pyfusa/rules/project.py`, `lint.py`, `security.py`, or `concurrency.py`
2. Implement a class inheriting from `Rule` with `rule_id`, `description`, and `run()`
3. Add the instance to the module's `ALL` list
4. Add a `#fusa:req REQ-...` annotation on the class
5. Add the requirement to `.fusa-reqs.json`
6. Write tests in `tests/`

## Commit style

- One-line imperative subject (50 chars max)
- Reference the rule id when adding a rule: `add SEC010 — open redirect detection`

## Spec conformance

All changes must maintain conformance with x-FuSa spec v1.9. The spec lives at
`../FuSaOps/docs/x-fusa-spec.md`. Run `make selfcheck` and `make qualify` before
submitting a PR.
