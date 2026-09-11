# Security Policy

VAPT Sanitizer is security-sensitive software. Please report vulnerabilities responsibly and avoid publishing exploit details before a fix is available.

## Supported versions

| Version | Supported |
| --- | --- |
| 1.0.x | Yes |
| < 1.0 | No |

## What counts as a security issue

Examples include:

- a mandatory secret reaching AI Handoff unredacted;
- a bypass of `BLOCKED` or unintended automatic approval of `REVIEW`;
- vault plaintext leakage;
- redacted secrets being persisted in the mapping vault;
- cross-engagement mapping contamination;
- predictable or conflicting placeholder allocation caused by concurrency;
- unintended network transmission in the standard local-first workflow;
- Burp/CLI disagreement that can expose real values or use the wrong engagement.

## Reporting a vulnerability

Preferred method: use GitHub's private **Report a vulnerability** / Security Advisory feature for the repository if it is enabled.

If private reporting is not available, do **not** open a public issue containing vulnerability details, secrets, proof-of-concept client data, or exploit steps. Open only a minimal public issue asking the maintainer for a private reporting channel, without disclosing the vulnerability.

Include, when safe:

- affected version/commit;
- operating system and Python/Java versions;
- minimal reproduction using synthetic data only;
- expected vs actual behavior;
- impact assessment;
- suggested mitigation if known.

## Sensitive material

Never include real:

- client data;
- credentials or tokens;
- private keys;
- production hostnames or IP addresses;
- `master.key`;
- `mapping.enc`;
- engagement directories;
- decrypted mapping values.

Synthetic reproductions are strongly preferred.

## Disclosure

Please allow maintainers a reasonable opportunity to reproduce, fix, test, and release a correction before public disclosure. Security fixes should include regression coverage whenever practical.
