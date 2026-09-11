## Summary

Describe the change and the problem it solves.

## Security impact

- [ ] No change to mandatory-secret handling.
- [ ] No new automatic network transmission in the standard AI Handoff path.
- [ ] No weakening of `PASS / REVIEW / BLOCKED` behavior.
- [ ] Vault behavior remains fail-closed and redacted secrets are not persisted.
- [ ] All examples/fixtures are synthetic.

If any box above cannot be checked, explain why and describe the compensating controls.

## Validation

- [ ] `python -m unittest discover -v`
- [ ] `./scripts/release-check.sh`
- [ ] `./scripts/build-burp.sh` when Burp code/build files changed

Paste concise results (never client data):

```text
...
```

## Tests added or updated

Describe regression coverage for the change.
