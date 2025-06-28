# Web Interface Testing Guide

This document describes how to test the investiGATOR web interface using GitHub Actions and locally.

## GitHub Actions Workflows

### 1. Main CI Workflow (`.github/workflows/ci.yml`)
- Runs on every push and pull request
- Includes basic web tests as part of the main test suite
- Tests Python 3.12 and 3.13 compatibility
- Includes code coverage reporting

### 2. Web-Specific Tests (`.github/workflows/web-tests.yml`)
- Triggered by changes to web-related files
- Comprehensive testing including:
  - **API Tests**: FastAPI endpoint testing
  - **Integration Tests**: Full workflow testing
  - **Security Tests**: XSS, injection protection
  - **Performance Tests**: Concurrent request handling

## Test Structure

### Unit Tests (`tests/test_web.py`)
- FastAPI endpoint testing using TestClient
- Individual analyzer class testing
- Service class testing (AWS profiles, file cleanup, etc.)
- Mock-based testing for external dependencies

### End-to-End Tests (`tests/test_web_e2e.py`)
- Complete workflow testing
- Error handling scenarios
- Concurrent request testing
- Large payload handling

## Running Tests Locally

### Prerequisites
```bash
# Install test dependencies
poetry install --with dev
```

### Run All Web Tests
```bash
make test-web
```

### Run Web Tests with Coverage
```bash
make test-web-cov
```

### Run Specific Test Files
```bash
# Unit tests only
poetry run pytest tests/test_web.py -v

# E2E tests only
poetry run pytest tests/test_web_e2e.py -v

# With coverage
poetry run pytest tests/test_web.py --cov=src/vpc_flow_investigator/web --cov-report=html
```

## Test Categories

### 1. API Endpoint Tests
- `/api/test` - Health check endpoint
- `/api/profiles` - AWS profiles endpoint
- `/api/analyze` - Main analysis endpoint
- `/api/scan-cidrs` - CIDR scanning endpoint
- `/api/query/{query_id}` - Query result retrieval

### 2. Analyzer Tests
- TrafficSummaryAnalyzer
- SSHInboundAnalyzer
- ExternalInboundAnalyzer
- And all other analyzer classes

### 3. Service Tests
- AWSProfileService
- FileCleanupService
- ConfigurationBuilder
- InstanceInfoService
- LogGroupService

### 4. Integration Tests
- Complete analysis workflow
- Error handling scenarios
- CIDR scanning workflow
- Concurrent request handling

### 5. Security Tests
- XSS protection verification
- SQL injection protection
- Input validation testing

### 6. Performance Tests
- Concurrent request handling
- Large payload processing
- Response time validation

## Mocking Strategy

The tests use extensive mocking to avoid:
- AWS API calls
- External network requests
- File system operations
- Time-dependent operations

Key mocked components:
- `get_instance_info()` - EC2 instance information
- `find_vpc_flow_log_group()` - CloudWatch log group discovery
- `download_vpc_flow_logs()` - Log file downloading
- `get_whois_info()` - WHOIS lookups

## Coverage Goals

- **API Endpoints**: 100% coverage
- **Analyzer Classes**: 90%+ coverage
- **Service Classes**: 95%+ coverage
- **Error Handling**: 100% coverage

## Continuous Integration

The web tests are integrated into the CI/CD pipeline:

1. **On every push/PR**: Basic web tests run as part of main CI
2. **On web file changes**: Full web test suite runs
3. **Coverage reporting**: Results uploaded to Codecov
4. **Security scanning**: Bandit and Safety checks

## Local Development Workflow

1. Make changes to web interface code
2. Run tests locally: `make test-web`
3. Check coverage: `make test-web-cov`
4. Fix any failing tests
5. Commit and push (triggers CI)

## Debugging Failed Tests

### Common Issues
1. **Import errors**: Check dependencies in pyproject.toml
2. **Mock failures**: Verify mock setup matches actual function signatures
3. **Async issues**: Ensure proper async/await usage in tests

### Debug Commands
```bash
# Run with verbose output
poetry run pytest tests/test_web.py -v -s

# Run specific test
poetry run pytest tests/test_web.py::TestWebEndpoints::test_home_page -v

# Run with pdb debugger
poetry run pytest tests/test_web.py --pdb
```

## Adding New Tests

When adding new web functionality:

1. Add unit tests to `tests/test_web.py`
2. Add integration tests to `tests/test_web_e2e.py`
3. Update this documentation
4. Ensure tests pass locally before committing

### Test Naming Convention
- `test_<functionality>_<scenario>` (e.g., `test_analyze_logs_success`)
- Group related tests in classes (e.g., `TestAnalysisEndpoint`)
- Use descriptive docstrings

## Performance Benchmarks

Current performance targets:
- API response time: < 100ms for simple endpoints
- Concurrent requests: Handle 50+ simultaneous requests
- Memory usage: < 100MB during testing

## Security Testing

Security tests verify:
- Input sanitization
- XSS protection
- SQL injection prevention
- File upload validation
- Authentication/authorization (when implemented)