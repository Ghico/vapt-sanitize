# Contributing to VAPT Sanitizer

Thank you for considering a contribution to VAPT Sanitizer.

VAPT Sanitizer sits on a security boundary between assessment data and AI-assisted analysis. Changes that look small can affect confidentiality, placeholder stability, or the Security Gate. Contributions are therefore reviewed with a security-first bias.

## Ground rules

- Use VAPT Sanitizer only with systems and data you are authorized to assess.
- Never submit real client data, credentials, tokens, private keys, internal hostnames, production IP addresses, or engagement vault material.
- All tests and examples must use synthetic data.
- Do not weaken mandatory-secret handling.
- Do not add automatic external transmission to the standard AI Handoff path.
- Do not make `REVIEW` auto-approve or provide a bypass for `BLOCKED`.
- Preserve cross-tool placeholder stability when an Engagement Mapping Vault is active.

## Development setup

Requirements:

- Python 3.11+
- Python `venv`
- Java 17+ for the Burp extension

```bash
git clone <your-fork-url>
cd vapt-sanitize
./scripts/install.sh
```

Run the complete Python suite:

```bash
./.venv/bin/python -m unittest discover -v
```

Run the release checks:

```bash
./scripts/release-check.sh
```

Build the Burp extension:

```bash
./scripts/build-burp.sh
```

The v1.0.0 reference baseline is:

```text
181 tests OK
Auto-detection: 10/10 PASS
Burp extension: BUILD SUCCESSFUL
```

A pull request may legitimately increase the test count. It must not reduce coverage of existing behavior without a documented reason.

## Detector and profile changes

A detector/profile change should normally include:

1. a synthetic positive fixture or unit test;
2. a negative/false-positive regression test;
3. expected placeholder/redaction behavior;
4. Security Gate expectations when relevant;
5. confirmation that unrelated profiles still pass.

For mandatory secrets, prefer fail-closed behavior.

## Engagement Mapping Vault changes

Vault-related changes must preserve these invariants:

- redacted secrets are never stored in the vault;
- pseudonym mappings remain stable within an engagement;
- separate engagements remain isolated;
- encrypted mapping and master key remain separate;
- missing/corrupt key material fails closed;
- concurrent processes cannot allocate conflicting placeholders.

Never attach a real `master.key`, `mapping.enc`, engagement directory, or decrypted mapping to an issue or pull request.

## Burp extension changes

The Burp extension must continue to:

- use sanitized content only for AI Handoff;
- keep engagement selection session-scoped unless a future design explicitly proves project-safe persistence;
- pass the same vault roots to the Python bridge;
- make stateless mode explicit;
- preserve manual operator review.

## Pull requests

Keep PRs focused. Describe:

- what changed;
- why it is needed;
- security implications;
- tests added/updated;
- commands used to validate the change.

By intentionally submitting a contribution, you agree that it is provided under the repository's Apache License 2.0, consistent with Section 5 of that license.
