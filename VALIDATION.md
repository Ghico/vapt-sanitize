# Validation record - v1.0.0 public baseline

Date: 2026-09-11

## Automated checks

- `tests.test_sanitizer`: 108 OK
- `tests.test_cli`: 19 OK
- `tests.test_llm`: 19 OK
- `tests.test_auto_detection`: 5 OK
- `tests.test_engagement`: 14 OK
- `tests.test_burp_engagement_ui`: 9 OK
- `tests.test_release`: 7 OK
- Total: **181 OK**
- Synthetic auto-detection matrix: **10/10 PASS**

## Runtime/build validation on Kali

- `cryptography`: **50.0.1**
- Fernet import/runtime: **OK**
- CLI/Nmap -> Engagement Vault -> Burp placeholder reuse: **confirmed**
- Burp extension: **BUILD SUCCESSFUL**

## Public release gate

The public `v1.0.0` baseline must satisfy all of the following before tagging:

```bash
./scripts/install.sh
./scripts/release-check.sh
./scripts/build-burp.sh
```

Expected result:

```text
181/181 tests OK
Auto-detection: 10/10 PASS
Burp extension: BUILD SUCCESSFUL
```

## Packaging note

The public release baseline no longer relies on the earlier internal RC directory naming. GitHub clones should use the repository directory `vapt-sanitize`; release-asset checksums are published with the final GitHub Release assets.
