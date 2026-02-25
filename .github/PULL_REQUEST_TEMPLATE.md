## Summary

Describe what this PR changes and why.

## Type of change

- [ ] Bug fix (incorrect finding, false positive, false negative)
- [ ] New detection rule
- [ ] Improvement to existing rule
- [ ] Documentation
- [ ] CI/CD or build change
- [ ] Other

## Checklist

- [ ] Tests pass: `make test`
- [ ] Lint passes: `make lint`
- [ ] Security scan passes: `make security`
- [ ] New rules include fixtures in `fixtures/vulnerable/` and `fixtures/clean/`
- [ ] New rules include unit tests in `rules_test.go`
- [ ] No network calls added to file-based scanners
- [ ] No `os/exec` added to any scanner

## Security impact

Does this change affect detection coverage? If yes, describe:
- What was previously missed or falsely flagged
- What is now correctly detected or suppressed

## Test coverage

Paste the relevant test output or coverage delta.
