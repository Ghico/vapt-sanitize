# Validation record - v1.0.0 RC2

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

## Previously validated on operator Kali workspace

- 174/174 tests OK before release-only checks
- Burp extension: BUILD SUCCESSFUL
- CLI/Nmap -> Engagement Vault -> Burp placeholder reuse confirmed

## RC2 promotion gate

Before promoting this RC2 to the final v1.0.0 release, run on the target Kali workspace:

```bash
./scripts/install.sh
./scripts/release-check.sh
./scripts/build-burp.sh
```

Expected: 181 tests OK, 10/10 auto-detection, Burp BUILD SUCCESSFUL. No system Gradle installation is required.


## RC2 packaging fix

RC1 passed 180 tests and the 10/10 auto-detection matrix on Kali, but `scripts/build-burp.sh` required a system Gradle installation. RC2 adds a pinned Gradle 8.14.3 bootstrap with SHA-256 verification; sanitizer behavior, policies and detectors are unchanged.
