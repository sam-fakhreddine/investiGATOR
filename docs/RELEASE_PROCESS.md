# Release Process

## Prerequisites

Before any release, the following requirements MUST be met:

### 🔴 MANDATORY: 100% Web Interface Test Coverage
```bash
# This MUST pass before release
make test-web-100
```

### Quality Checks
```bash
# All tests must pass
make test

# Code quality checks
make lint
make format

# Security checks
poetry run bandit -r src/
poetry run safety check
```

## Release Steps

### 1. Pre-Release Verification
```bash
# Verify web coverage (MANDATORY)
make test-web-100

# Run full test suite
make test

# Check code quality
make lint
```

### 2. Version Update
Update version in `pyproject.toml`:
```toml
[tool.poetry]
version = "1.0.4"  # Update this
```

### 3. Create Release
```bash
# Tag the release
git tag v1.0.4
git push origin v1.0.4
```

### 4. Automated Release
The GitHub Actions workflow will:
1. **Verify 100% web interface coverage** (MANDATORY)
2. Run all tests
3. Perform quality checks
4. Create GitHub release
5. Build and upload artifacts

## Coverage Requirements

### Web Interface Coverage: 100% (MANDATORY)
- **File**: `src/vpc_flow_investigator/web.py`
- **Requirement**: 100% line coverage
- **Verification**: `make test-web-100`
- **Failure**: Release will be **BLOCKED**

### Overall Coverage: 85%+ (Recommended)
- **Files**: All source files
- **Requirement**: 85% minimum
- **Verification**: `make test`

## Troubleshooting

### Web Coverage Below 100%
```bash
# Check what's missing
make test-web-cov

# View detailed report
open htmlcov/index.html

# Add tests for missing lines
# Update tests/test_web*.py files
```

### Release Blocked
If the release workflow fails:
1. Check the "Pre-Release Quality Checks" job
2. Fix any failing tests or coverage issues
3. Push fixes and re-tag

## Emergency Releases

Even for emergency releases, **100% web interface coverage is MANDATORY**. No exceptions.

If urgent fixes are needed:
1. Fix the issue
2. Add/update tests to maintain 100% web coverage
3. Verify with `make test-web-100`
4. Proceed with release

## Quality Gates

| Check | Requirement | Blocking |
|-------|-------------|----------|
| Web Interface Coverage | 100% | ✅ YES |
| All Tests | Pass | ✅ YES |
| Linting | Pass | ✅ YES |
| Security Scan | Pass | ⚠️ Warning |
| Overall Coverage | 85%+ | ⚠️ Warning |