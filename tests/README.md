# VPC Flow Investigator Tests

This directory contains the test suite for the VPC Flow Log Investigator project.

## Test Structure

- `test_basic_functionality.py` - Core functionality tests including:
  - Log parsing and validation
  - Log filtering by instance and time range
  - Configuration validation
  - Time utility functions
  - End-to-end integration tests

- `test_cli.py` - Command-line interface tests including:
  - Argument parsing
  - Configuration printing
  - Debug mode functionality

- `conftest.py` - Pytest configuration and shared fixtures

## Running Tests

### Run all tests
```bash
make test
# or
poetry run pytest tests/
```

### Run with verbose output
```bash
poetry run pytest tests/ -v
```

### Run specific test file
```bash
poetry run pytest tests/test_basic_functionality.py -v
```

### Run specific test class or method
```bash
poetry run pytest tests/test_basic_functionality.py::TestLogParsing -v
poetry run pytest tests/test_basic_functionality.py::TestLogParsing::test_parse_valid_log_line -v
```

## Test Coverage

The current test suite covers:

- ✅ VPC Flow Log parsing (valid/invalid formats)
- ✅ Log filtering by instance IPs and time ranges
- ✅ Configuration validation and defaults
- ✅ Time utility functions (duration parsing, time input parsing)
- ✅ CLI argument parsing
- ✅ Configuration printing functionality
- ✅ End-to-end log processing workflow

## Adding New Tests

When adding new tests:

1. Follow the existing naming convention (`test_*.py`)
2. Use descriptive test method names starting with `test_`
3. Group related tests in classes (e.g., `TestLogParsing`)
4. Use fixtures from `conftest.py` for common test data
5. Add docstrings to explain what each test validates

## Test Data

The tests use sample VPC Flow Log data that follows the standard AWS format:
```
2 123456789012 eni-1234abcd 10.0.1.100 203.0.113.12 10.0.1.100 203.0.113.12 443 49152 6 20 4249 1418530010 1418530070 ACCEPT OK
```

This ensures tests work with realistic data structures and edge cases.