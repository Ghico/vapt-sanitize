# Open-Source Release Checklist

Use this checklist before publishing a tag or GitHub Release.

## Source and tests

- [ ] Full unit/integration suite passes.
- [ ] Auto-detection synthetic matrix passes 10/10.
- [ ] Burp extension builds successfully.
- [ ] `VERSION`, package version, and release tag agree.
- [ ] Changelog and release notes are current.

## Security and privacy

- [ ] No `master.key` is present.
- [ ] No `mapping.enc` or engagement directory is present.
- [ ] No `.venv`, Gradle cache, build directory, or backup file is present.
- [ ] No real client IP, hostname, email, username, token, password, or assessment output is present.
- [ ] Test fixtures are synthetic only.
- [ ] Documentation screenshots/examples contain synthetic values only.
- [ ] Repository history has been checked before first public push.

## Open-source metadata

- [ ] `LICENSE` is present.
- [ ] `SECURITY.md` is present.
- [ ] `CONTRIBUTING.md` is present.
- [ ] Issue and PR templates are present.
- [ ] README links work.
- [ ] English documentation is the default landing content.
- [ ] Italian documentation remains accessible.

## GitHub settings

Recommended repository settings:

- Enable private vulnerability reporting / Security Advisories.
- Protect the default branch.
- Require CI before merge.
- Disable force pushes to the default branch.
- Require pull requests for external contributions.
- Enable Dependabot alerts/updates if appropriate.

## Final artifact

- [ ] Create the release archive from a clean checkout.
- [ ] Generate SHA-256.
- [ ] Verify the archive contents before upload.
