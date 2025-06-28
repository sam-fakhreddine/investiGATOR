# Pull Request

## Description

Brief description of changes made.

## Type of Change

- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update

## Testing

- [ ] All existing tests pass
- [ ] New tests added for new functionality
- [ ] **Web interface maintains 100% test coverage** (MANDATORY)

## Checklist

- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Code is commented where necessary
- [ ] Documentation updated if needed
- [ ] **Web coverage requirement verified: `make test-web-100`**

## Web Interface Coverage

If changes affect the web interface (`src/vpc_flow_investigator/web.py`):

- [ ] **100% test coverage maintained** (run `make test-web-100` to verify)
- [ ] All web endpoints tested
- [ ] Error handling tested
- [ ] Edge cases covered

**Note: PRs affecting web interface MUST maintain 100% test coverage or will be rejected.**
