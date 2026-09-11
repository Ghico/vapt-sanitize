# VAPT Sanitizer v1.0.0 - Release Notes

Date: 2026-09-11

VAPT Sanitizer v1.0.0 is the first public stable release of the project. It formalizes the validated sanitizer core, installation workflow, frozen dependencies, synthetic fixtures, Burp Suite integration, encrypted engagement mapping, and release checks.

## Security boundaries

- The sanitizer does not replace operator judgment.
- Input data must originate from authorized security assessments.
- `PASS` means the implemented controls did not identify a condition requiring `REVIEW` or `BLOCKED`; it is not a mathematical guarantee of complete anonymization.
- The Engagement Mapping Vault is encrypted at rest, but the local workstation remains part of the trust boundary.

## Reference compatibility

- Python >= 3.11
- PyYAML 6.0.3
- cryptography 50.0.1
- Java >= 17
- Burp Montoya API 2026.7
- Gradle bootstrap 8.14.3

## Public release validation

- 181/181 tests OK
- Synthetic auto-detection matrix: 10/10 PASS
- `python -m vapt_sanitize --version`: `VAPT Sanitizer 1.0.0`
- Engagement Vault / Fernet runtime verified with cryptography 50.0.1
- Burp extension: BUILD SUCCESSFUL

## Dependency security refresh

Before the public `v1.0.0` tag was created, the frozen `cryptography` dependency was refreshed to 50.0.1 and the complete validation gate was rerun successfully. No sanitizer detector, policy, Security Gate, or Engagement Vault semantics were intentionally changed by this dependency refresh.

## Upgrade from an existing workspace

Do not delete the external local vault material when updating the repository:

- `~/.config/vapt-sanitize/master.key`
- `~/.local/share/vapt-sanitize/engagements/`

Those paths are outside the repository and are not part of the public release source.
