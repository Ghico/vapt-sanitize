# Publishing the Repository

This document describes a safe first publication workflow for VAPT Sanitizer.

## 1. Start from the public repository bundle

Do not publish a working engagement directory or a clone that has ever contained real client material unless its full Git history has been audited.

Prefer initializing Git from a clean public bundle.

## 2. Review before the first commit

```bash
git status --short
find . -type f \( -name 'master.key' -o -name 'mapping.enc' -o -name '*.enc' \) -print
find . -type d \( -name '.venv' -o -name '__pycache__' -o -name '.gradle' -o -name build \) -print
```

Optionally run a dedicated secret scanner such as Gitleaks if it is available locally.

Then inspect staged content manually:

```bash
git add .
git status
git diff --cached --stat
git diff --cached
```

Binary PDF/DOCX files will not be meaningfully diffable, so inspect those separately before the commit.

## 3. Create the repository history

```bash
git init
git branch -M main
git add .
git commit -m "Initial public release: VAPT Sanitizer v1.0.0"
```

Add the remote only after the local review is complete:

```bash
git remote add origin <repository-url>
git push -u origin main
```

## 4. Recommended GitHub settings

- Enable private vulnerability reporting / Security Advisories.
- Protect `main`.
- Require pull requests for changes to `main`.
- Require CI checks before merge.
- Disable force pushes to the protected branch.
- Enable Dependabot alerts and review update PRs before merging.

## 5. Tag v1.0.0

Only after the public repository contents and CI are confirmed:

```bash
git tag -a v1.0.0 -m "VAPT Sanitizer v1.0.0"
git push origin v1.0.0
```

The previously validated Stable archive remains the golden v1.0.0 artifact. The GitHub repository adds open-source metadata/documentation around the same core source; it is not intended to silently replace or rewrite that validated archive.

## 6. GitHub Release

Recommended release attachments:

- validated `vapt-sanitize-v1.0.0.zip`;
- SHA-256 checksum;
- optional Burp extension JAR built from the tagged source;
- release notes.

Rebuild artifacts only from a clean checkout of the tag.
