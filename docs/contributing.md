# Contributing

Contributions are welcome. Please read the full guidelines in [CONTRIBUTING.md](https://github.com/daneb255/unravel-sbom/blob/main/CONTRIBUTING.md) before opening a pull request.

## Quick steps

1. Fork the repository and create a feature branch.
2. Install dev dependencies: `pip install -e ".[dev]"`
3. Make your changes and write tests.
4. Run the full check suite:
    ```bash
    ruff check src tests && ruff format --check src tests
    mypy src --ignore-missing-imports
    pytest tests/ -v --cov=src --cov-report=term-missing
    ```
5. Open a pull request — CI must stay green.

## Adding a new ecosystem scanner

See the [Architecture](architecture.md) page for a step-by-step guide.

## Code of Conduct

All participants are expected to follow the [Code of Conduct](https://github.com/daneb255/unravel-sbom/blob/main/CODE_OF_CONDUCT.md).

## Security

To report a vulnerability privately, see [SECURITY.md](https://github.com/daneb255/unravel-sbom/blob/main/SECURITY.md).
