# VAULT Security Framework Tests

This directory contains comprehensive tests and demos for the VAULT security framework.

## Structure

- `unit/` - Unit tests for individual components
- `integration/` - Integration tests for the full system
- `demo/` - Demo scripts showing framework functionality
- `config/` - Test configuration files

## Running Tests

```bash
# Run all tests
python -m pytest tests/

# Run unit tests only
python -m pytest tests/unit/

# Run integration tests only
python -m pytest tests/integration/

# Run with coverage
python -m pytest tests/ --cov=vault --cov-report=html
```

## Demo Scripts

```bash
# Run all demos
python tests/demo/run_all_demos.py

# Run individual demos
python tests/demo/scanner_demo.py
python tests/demo/policy_demo.py
python tests/demo/gateway_demo.py
```