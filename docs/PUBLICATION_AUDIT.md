# Public Repository Audit — v1.0.0

Date: 2026-09-11

## Scope

This audit covers the GitHub-ready public repository bundle derived from the validated VAPT Sanitizer v1.0.0 Stable / RC2 core.

## Core integrity

The following paths were compared against the validated Stable RC2 baseline and are byte-identical:

- `vapt_sanitize/`
- `tests/`
- `scripts/`
- `policies/`
- `burp-extension/`
- `pyproject.toml`
- `requirements.txt`
- `VERSION`

The public repository bundle changes only repository-facing documentation and metadata such as README files, license, contribution/security policies, GitHub templates/workflows, and documentation files.

## Regression status

Validated Stable gate supplied from the Kali reference environment:

```text
181/181 tests OK
Auto-detection: 10/10 PASS
Burp extension: BUILD SUCCESSFUL
```

The GitHub-ready bundle was additionally checked module-by-module in the packaging environment, covering the same 181 Python tests, and the synthetic auto-detection matrix returned 10/10 PASS.

The Burp build inputs are unchanged from the Stable baseline; GitHub CI is configured to rebuild the extension using Java 17.

## Privacy / secret scan

The public bundle was checked for:

- `master.key`;
- `mapping.enc` / `*.enc` vault material;
- engagement directories;
- `.venv`;
- `__pycache__` / `.pyc`;
- Gradle cache/build outputs;
- backup files;
- local user path markers used during development;
- local test engagement identifiers.

No such material is intentionally included.

The bundled detector fixtures are synthetic and are retained because they are part of regression coverage.

## Documentation

English is the default repository language:

- `README.md`
- `docs/USER_GUIDE.md`

Italian documentation remains available via:

- `README_IT.md`
- `docs/USER_GUIDE_IT.md`

PDF and DOCX editions are also included under `docs/`.

## Open-source metadata

Included:

- `LICENSE` — Apache License 2.0
- `CONTRIBUTING.md`
- `SECURITY.md`
- `CODE_OF_CONDUCT.md`
- `THIRD_PARTY_NOTICES.md`
- GitHub issue templates
- pull request template
- GitHub Actions CI
- Dependabot configuration
- publication checklist and publishing procedure
