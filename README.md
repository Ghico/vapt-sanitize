# VAPT Sanitizer v1.0.0

[English](README.md) | [Italiano](README_IT.md)


**VAPT Sanitizer** is a local-first security gateway for authorized Vulnerability Assessment, Penetration Testing and Red Team workflows that use AI as an analysis assistant.

It sanitizes technical data **before** the operator copies it into an LLM conversation. The tool preserves useful security context, pseudonymizes values that must remain correlatable, irreversibly redacts secrets, applies a `PASS / REVIEW / BLOCKED` Security Gate and can maintain a persistent encrypted mapping per engagement.

> Primary design rule: **no automatic network transmission is performed by the standard AI Handoff workflow.** The operator reviews the sanitized result and manually pastes the generated prompt into the AI service of choice.

## Documentation

- [Technical User Guide - English (Markdown)](docs/USER_GUIDE.md)
- [Guida tecnica - Italiano (Markdown)](docs/USER_GUIDE_IT.md)

- [Technical User Guide - English (PDF)](docs/VAPT_Sanitizer_v1.0.0_User_Guide_EN.pdf)
- [Technical User Guide - English (DOCX)](docs/VAPT_Sanitizer_v1.0.0_User_Guide_EN.docx)
- [Technical User Guide - Italiano (PDF)](docs/VAPT_Sanitizer_v1.0.0_User_Guide_IT.pdf)
- [Technical User Guide - Italiano (DOCX)](docs/VAPT_Sanitizer_v1.0.0_User_Guide_IT.docx)

## Why it exists

Pentest output often contains both useful evidence and client-sensitive information:

```text
Nmap scan report for srv-app.client.local (10.20.30.45)
Authorization: Bearer eyJ...
user=m.rossi email=mario.rossi@client.example
AWS_SECRET_ACCESS_KEY=...
```

VAPT Sanitizer turns correlatable values into stable placeholders:

```text
srv-app.client.local -> [HOSTNAME_001]
10.20.30.45          -> [PRIVATE_IP_001]
mario.rossi@...       -> [EMAIL_001]
```

while secrets are redacted and intentionally **not recoverable**:

```text
password=...                  -> password=[PASSWORD_REDACTED]
Authorization: Bearer ...     -> Authorization: [BEARER_TOKEN_REDACTED]
AWS_SECRET_ACCESS_KEY=...      -> AWS_SECRET_ACCESS_KEY=[AWS_SECRET_KEY_REDACTED]
```

## Core capabilities

- Local-first sanitization of files, stdin and clipboard content.
- Automatic profile detection or explicit profile selection.
- Ten validated profiles: `GENERIC`, `NMAP`, `BURP`, `GOBUSTER`, `NUCLEI`, `WINDOWS`, `LINUX`, `AWS`, `SECRETS`, `PII`.
- Policy engine with mandatory secret protections that YAML policies cannot weaken.
- `PASS / REVIEW / BLOCKED` Security Gate before AI Handoff.
- Provider-neutral AI-ready prompt generation.
- Encrypted Engagement Mapping Vault for cross-file and cross-tool correlation.
- Placeholder resolution back to local real values.
- Burp Suite extension using the same mapping vault as the CLI.
- Synthetic regression fixtures and release validation scripts.

## Architecture

```text
Nmap / Burp / Nuclei / Gobuster / Windows / Linux / AWS / logs
                              |
                              v
                   Context / Profile Detection
                              |
                              v
                    Detectors + Policy Engine
                              |
                              v
                 Pseudonymization / Redaction
                              |
                 +------------+------------+
                 |                         |
                 v                         v
        Engagement Mapping Vault       Secrets discarded
        (encrypted, local only)         (not restorable)
                 |
                 v
              Security Gate
           PASS / REVIEW / BLOCKED
                 |
                 v
              AI Handoff
                 |
                 v
        AI-ready prompt -> clipboard
                 |
                 v
          manual browser paste
```

## Requirements

### CLI

- Linux/Kali reference environment
- Python `>= 3.11`
- Python `venv` support
- Optional clipboard helper: `xclip`, `xsel` or `wl-copy`

### Burp extension build/runtime

- Java `>= 17`
- `unzip`
- `curl` or `wget`
- Burp Suite with Montoya API support

A system Gradle installation is **not required**. The bundled `burp-extension/gradlew` bootstrap uses Gradle `8.14.3` and verifies the downloaded distribution with SHA-256.

## Installation

For a public GitHub installation:

```bash
git clone https://github.com/Ghico/vapt-sanitize.git
cd vapt-sanitize
./scripts/install.sh
```

The installer:

1. creates `.venv`;
2. installs the package in editable mode;
3. installs frozen dependencies;
4. checks for a clipboard backend;
5. runs the regression suite;
6. prints the installed version.

Frozen Python dependencies:

```text
PyYAML==6.0.3
cryptography==50.0.1
```

Verify manually:

```bash
./.venv/bin/python -m vapt_sanitize --version
# VAPT Sanitizer 1.0.0

./.venv/bin/vapt-sanitize --version
# VAPT Sanitizer 1.0.0
```

## Release validation

```bash
./scripts/release-check.sh
```

Validated Stable baseline:

```text
181 tests OK
Auto-detection: 10/10 PASS
Burp build: BUILD SUCCESSFUL
```

## CLI quick start

### Sanitize a file

```bash
./.venv/bin/vapt-sanitize scan.txt -o scan.sanitized
```

### Auto-detect the profile and build an AI-ready prompt

```bash
./.venv/bin/vapt-sanitize scan.txt \
  --ai-prompt \
  --ai-clipboard
```

No network request is made by this command.

### Force a profile

```bash
./.venv/bin/vapt-sanitize scan.txt --profile nmap
```

### Read from stdin

```bash
cat scan.txt | ./.venv/bin/vapt-sanitize -
```

### Read from the clipboard

```bash
./.venv/bin/vapt-sanitize --clipboard
```

With AI prompt generation:

```bash
./.venv/bin/vapt-sanitize --clipboard --ai-prompt
```

### Explain sanitization decisions

```bash
./.venv/bin/vapt-sanitize scan.txt --explain
```

## AI Handoff

Available tasks:

```text
analyze-security
explain-response
find-attack-surface
suggest-next-tests
custom
```

Example:

```bash
./.venv/bin/vapt-sanitize nuclei.txt \
  --ai-prompt \
  --ai-clipboard \
  --task suggest-next-tests
```

Custom analyst question:

```bash
./.venv/bin/vapt-sanitize burp.txt \
  --ai-prompt \
  --ai-clipboard \
  --task custom \
  --question "Which authorization tests should I prioritize?"
```

You can override the source label shown in the prompt:

```bash
--source "Internal web assessment"
```

## Security Gate

| State | Meaning | AI Handoff |
|---|---|---|
| `PASS` | No implemented rule requires operator intervention | Allowed |
| `REVIEW` | Manual review is required | Requires explicit approval |
| `BLOCKED` | Boundary conditions are not satisfied | Refused |

For CLI `REVIEW` handoff:

```bash
./.venv/bin/vapt-sanitize input.txt \
  --ai-prompt \
  --ai-clipboard \
  --review-approved
```

`--review-approved` never overrides `BLOCKED`.

## Policies

Included policies:

```text
policies/default.yml
policies/aggressive_pii.yml
policies/strict_llm.yml
```

Example:

```bash
./.venv/bin/vapt-sanitize input.txt \
  --policy policies/strict_llm.yml \
  --ai-prompt
```

Mandatory secret categories remain protected even if a policy attempts to weaken them.

## Engagement Mapping Vault

Use an engagement whenever multiple files/tools belong to the same authorized assessment and placeholder continuity matters.

### Create an engagement

```bash
./.venv/bin/vapt-sanitize engagement init ACME-2026-EXTERNAL
```

Engagement IDs are 1-64 characters and may contain letters, numbers, `.`, `_` and `-`.

### Use it

```bash
./.venv/bin/vapt-sanitize scan.txt \
  --engagement ACME-2026-EXTERNAL \
  --ai-prompt \
  --ai-clipboard
```

A real value receives the same placeholder across subsequent runs in the same engagement:

```text
Nmap:   10.20.30.45 -> [PRIVATE_IP_001]
Burp:   10.20.30.45 -> [PRIVATE_IP_001]
Nuclei: 10.20.30.45 -> [PRIVATE_IP_001]
```

Different engagements are isolated and may independently reuse `[PRIVATE_IP_001]` for unrelated addresses.

### Show the local map

```bash
./.venv/bin/vapt-sanitize engagement show ACME-2026-EXTERNAL
```

### Resolve placeholders

```bash
./.venv/bin/vapt-sanitize engagement resolve \
  ACME-2026-EXTERNAL \
  '[PRIVATE_IP_001]' '[HOSTNAME_001]'
```

## Vault storage and security

Default Linux/XDG paths:

```text
~/.config/vapt-sanitize/master.key
~/.local/share/vapt-sanitize/engagements/<ID>/mapping.enc
~/.local/share/vapt-sanitize/engagements/<ID>/metadata.json
~/.local/share/vapt-sanitize/engagements/<ID>/.mapping.lock
```

Important rules:

- `mapping.enc` is encrypted at rest.
- `master.key` is stored separately and created with restrictive permissions.
- Redacted secrets are never stored in the mapping.
- The vault is protected against concurrent mapping updates with a local lock.
- Losing `master.key` makes existing mappings undecryptable.
- An attacker who compromises the local account and can read both key and ciphertext is inside the local trust boundary and may decrypt the mappings.

For custom storage locations:

```bash
export VAPT_SANITIZE_CONFIG_DIR=/secure/config/vapt-sanitize
export VAPT_SANITIZE_DATA_DIR=/secure/data/vapt-sanitize
```

## Burp Suite integration

Build the JAR:

```bash
./scripts/build-burp.sh
```

Expected artifact:

```text
burp-extension/build/libs/vapt-sanitize-burp-1.0.0.jar
```

In Burp:

```text
Extensions -> Installed -> Add -> Java
```

Load the generated JAR.

The extension provides:

- `Sanitize request -> preview`
- `Sanitize response -> preview`
- `Sanitize selection -> preview`
- policy selection
- engagement selection and refresh
- detection summary
- sanitized preview
- `Copy sanitized`
- `Copy AI Prompt`

Every new Burp session starts in:

```text
(None - stateless)
```

This is deliberate to avoid accidentally carrying a client engagement into another Burp session. Select the correct engagement explicitly.

### Burp runtime path

By default the extension looks for:

```text
~/vapt-sanitize
~/vapt-sanitize/.venv/bin/python
```

If the repository is installed somewhere other than `~/vapt-sanitize`, either create an operational symlink or launch Burp with explicit paths:

```bash
export VAPT_SANITIZE_HOME="$HOME/vapt-sanitize"
export VAPT_SANITIZE_PYTHON="$VAPT_SANITIZE_HOME/.venv/bin/python"
burpsuite
```

The Burp subprocess receives the same vault config/data roots as the UI, so CLI and Burp can share the same encrypted engagement mapping.

## Recommended assessment workflow

```text
1. Create one engagement for the authorized scope.
2. Run the security tool normally.
3. Save or capture the output.
4. Sanitize using the same engagement ID.
5. Review detections and Security Gate state.
6. Build the AI-ready prompt.
7. Visually verify the prompt.
8. Paste it manually into the chosen AI service.
9. Receive analysis containing placeholders.
10. Resolve placeholders locally when needed.
11. Continue testing against the real client environment.
```

Do **not** reuse one engagement across unrelated clients.

## What VAPT Sanitizer is not

It is not:

- a vulnerability scanner;
- an exploit framework;
- a SIEM;
- a complete DLP system;
- a password manager;
- a replacement for human review;
- a mathematical guarantee that arbitrary future data formats contain no sensitive information.

`PASS` means the implemented controls did not identify a reason to require `REVIEW` or `BLOCKED`. The operator remains responsible for final inspection before data leaves the workstation.

## Troubleshooting

### `Engagement vaults require the 'cryptography' package`

Burp and the CLI must use the same correctly installed virtual environment:

```bash
./.venv/bin/python -c 'from cryptography.fernet import Fernet; print("cryptography OK")'
```

If needed:

```bash
./.venv/bin/python -m pip install -e .
```

The official `./scripts/install.sh` installs the frozen dependency automatically.

### Burp does not show an engagement

- Create it first with `engagement init`.
- Click **Refresh** in the `Engagement Mapping Vault` panel.
- Confirm Burp and CLI use the same `VAPT_SANITIZE_CONFIG_DIR` / `VAPT_SANITIZE_DATA_DIR` roots.

### CLI and Burp assign different placeholders

Confirm both are using:

- the same engagement ID;
- the same master key;
- the same engagement data directory.

### Clipboard mode fails

Install a backend appropriate for the session. On Kali/X11:

```bash
sudo apt install xclip
```

### `REVIEW` prevents AI Handoff

Inspect the sanitized content. If approved, use `--review-approved` in CLI or confirm the review dialog in Burp.

### `BLOCKED`

Do not bypass it. Correct the input/policy condition and sanitize again.

### Burp build cannot find Gradle

Use the Stable release's script:

```bash
./scripts/build-burp.sh
```

The bundled bootstrap downloads and verifies Gradle 8.14.3. Ensure Java 17+, `unzip`, and `curl` or `wget` are available.

## Files that must never be committed

The bundled `.gitignore` excludes common local artifacts. In particular, never commit or share:

```text
master.key
mapping.enc
engagements/
.venv/
client outputs
local backups
```

## Release status

Validated v1.0.0 Stable gate:

```text
181/181 tests OK
10/10 auto-detection PASS
Burp extension BUILD SUCCESSFUL
JAR: vapt-sanitize-burp-1.0.0.jar
```

Release asset SHA-256 is published alongside the GitHub Release asset after the final tagged artifact is created.

## Operational principle

```text
AI                 = analytical assistant
VAPT Sanitizer     = local security boundary
Engagement Vault   = local correlation layer
Penetration Tester = final decision maker
```

## Open-source project

VAPT Sanitizer is distributed under the [Apache License 2.0](LICENSE).

Before contributing, read:

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [SECURITY.md](SECURITY.md)
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)

For detector false positives/false negatives, use the dedicated GitHub issue template and **synthetic data only**.
