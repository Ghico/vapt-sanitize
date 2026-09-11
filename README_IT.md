# VAPT Sanitizer v1.0.0

[English](README.md) | [Italiano](README_IT.md)

**VAPT Sanitizer** è un security gateway local-first per workflow autorizzati di Vulnerability Assessment, Penetration Testing e Red Team che utilizzano sistemi di Intelligenza Artificiale come assistente analitico.

Sanitizza i dati tecnici **prima** che l'operatore li copi in una conversazione con un LLM. Il tool preserva il contesto tecnico utile, pseudonimizza i valori che devono restare correlabili, redige in modo irreversibile i secret, applica un Security Gate `PASS / REVIEW / BLOCKED` e può mantenere un mapping cifrato persistente per ogni engagement.

> Regola di design principale: **il workflow AI Handoff standard non effettua alcun invio automatico di rete.** L'operatore verifica il risultato sanitizzato e incolla manualmente il prompt generato nel servizio AI scelto.

## Documentazione

- [Technical User Guide - English (Markdown)](docs/USER_GUIDE.md)
- [Guida tecnica - Italiano (Markdown)](docs/USER_GUIDE_IT.md)

- [Technical User Guide - English (PDF)](docs/VAPT_Sanitizer_v1.0.0_User_Guide_EN.pdf)
- [Technical User Guide - English (DOCX)](docs/VAPT_Sanitizer_v1.0.0_User_Guide_EN.docx)
- [Technical User Guide - Italiano (PDF)](docs/VAPT_Sanitizer_v1.0.0_User_Guide_IT.pdf)
- [Technical User Guide - Italiano (DOCX)](docs/VAPT_Sanitizer_v1.0.0_User_Guide_IT.docx)

## Perché esiste

Gli output di un penetration test contengono spesso sia evidenze tecniche utili sia informazioni sensibili del cliente:

```text
Nmap scan report for srv-app.client.local (10.20.30.45)
Authorization: Bearer eyJ...
user=m.rossi email=mario.rossi@client.example
AWS_SECRET_ACCESS_KEY=...
```

VAPT Sanitizer trasforma i valori correlabili in placeholder stabili:

```text
srv-app.client.local -> [HOSTNAME_001]
10.20.30.45          -> [PRIVATE_IP_001]
mario.rossi@...       -> [EMAIL_001]
```

mentre i secret vengono redatti e intenzionalmente **non sono recuperabili**:

```text
password=...                  -> password=[PASSWORD_REDACTED]
Authorization: Bearer ...     -> Authorization: [BEARER_TOKEN_REDACTED]
AWS_SECRET_ACCESS_KEY=...      -> AWS_SECRET_ACCESS_KEY=[AWS_SECRET_KEY_REDACTED]
```

## Funzionalità principali

- Sanitizzazione local-first di file, stdin e clipboard.
- Auto-detection del profilo o selezione esplicita.
- Dieci profili validati: `GENERIC`, `NMAP`, `BURP`, `GOBUSTER`, `NUCLEI`, `WINDOWS`, `LINUX`, `AWS`, `SECRETS`, `PII`.
- Policy engine con protezioni mandatory secret non indebolibili dalle policy YAML.
- Security Gate `PASS / REVIEW / BLOCKED` prima dell'AI Handoff.
- Generazione provider-neutral di prompt AI-ready.
- Engagement Mapping Vault cifrato per correlazione cross-file e cross-tool.
- Risoluzione locale dei placeholder ai valori reali.
- Estensione Burp Suite che utilizza lo stesso vault della CLI.
- Fixture sintetici, test di regressione e script di validazione della release.

## Architettura

```text
Nmap / Burp / Nuclei / Gobuster / Windows / Linux / AWS / log
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

## Requisiti

### CLI

- Linux/Kali come ambiente di riferimento
- Python `>= 3.11`
- supporto Python `venv`
- helper clipboard opzionale: `xclip`, `xsel` o `wl-copy`

### Build/runtime estensione Burp

- Java `>= 17`
- `unzip`
- `curl` oppure `wget`
- Burp Suite con supporto Montoya API

Non è richiesta un'installazione di sistema di Gradle. Il bootstrap `burp-extension/gradlew` incluso usa Gradle `8.14.3` e verifica con SHA-256 la distribuzione scaricata.

## Installazione

Per una installazione pubblica da GitHub:

```bash
git clone https://github.com/Ghico/vapt-sanitize.git
cd vapt-sanitize
./scripts/install.sh
```

Lo script di installazione:

1. crea `.venv`;
2. installa il pacchetto in editable mode;
3. installa le dipendenze congelate;
4. verifica il backend clipboard;
5. esegue la suite di regressione;
6. stampa la versione installata.

Dipendenze Python congelate:

```text
PyYAML==6.0.3
cryptography==50.0.1
```

Verifica manuale:

```bash
./.venv/bin/python -m vapt_sanitize --version
# VAPT Sanitizer 1.0.0

./.venv/bin/vapt-sanitize --version
# VAPT Sanitizer 1.0.0
```

## Validazione della release

```bash
./scripts/release-check.sh
```

Baseline Stable validata:

```text
181 tests OK
Auto-detection: 10/10 PASS
Burp build: BUILD SUCCESSFUL
```

## Quick start CLI

### Sanitizzare un file

```bash
./.venv/bin/vapt-sanitize scan.txt -o scan.sanitized
```

### Generare un prompt AI-ready

```bash
./.venv/bin/vapt-sanitize scan.txt \
  --ai-prompt \
  --ai-clipboard
```

Questo comando non effettua richieste di rete.

### Forzare un profilo

```bash
./.venv/bin/vapt-sanitize scan.txt --profile nmap
```

### Leggere da stdin

```bash
cat scan.txt | ./.venv/bin/vapt-sanitize -
```

### Leggere dalla clipboard

```bash
./.venv/bin/vapt-sanitize --clipboard
```

Con generazione del prompt AI:

```bash
./.venv/bin/vapt-sanitize --clipboard --ai-prompt
```

### Spiegare le decisioni di sanitizzazione

```bash
./.venv/bin/vapt-sanitize scan.txt --explain
```

## AI Handoff

Task disponibili:

```text
analyze-security
explain-response
find-attack-surface
suggest-next-tests
custom
```

Esempio:

```bash
./.venv/bin/vapt-sanitize nuclei.txt \
  --ai-prompt \
  --ai-clipboard \
  --task suggest-next-tests
```

Domanda personalizzata:

```bash
./.venv/bin/vapt-sanitize burp.txt \
  --ai-prompt \
  --ai-clipboard \
  --task custom \
  --question "Which authorization tests should I prioritize?"
```

Il source label del prompt può essere sovrascritto con:

```bash
--source "Internal web assessment"
```

## Security Gate

| Stato | Significato | AI Handoff |
|---|---|---|
| `PASS` | Nessuna regola implementata richiede intervento | Consentito |
| `REVIEW` | È richiesta una revisione manuale | Richiede approvazione esplicita |
| `BLOCKED` | Il boundary non è soddisfatto | Rifiutato |

Per un handoff CLI in stato `REVIEW`:

```bash
./.venv/bin/vapt-sanitize input.txt \
  --ai-prompt \
  --ai-clipboard \
  --review-approved
```

`--review-approved` non può mai superare `BLOCKED`.

## Policy

Policy incluse:

```text
policies/default.yml
policies/aggressive_pii.yml
policies/strict_llm.yml
```

Esempio:

```bash
./.venv/bin/vapt-sanitize input.txt \
  --policy policies/strict_llm.yml \
  --ai-prompt
```

Le categorie mandatory secret rimangono protette anche se una policy prova a indebolirle.

## Engagement Mapping Vault

Usare un engagement quando più file o strumenti appartengono allo stesso assessment autorizzato e la continuità dei placeholder è importante.

### Creare un engagement

```bash
./.venv/bin/vapt-sanitize engagement init ACME-2026-EXTERNAL
```

Gli ID engagement devono avere 1-64 caratteri e possono contenere lettere, numeri, `.`, `_` e `-`.

### Utilizzarlo

```bash
./.venv/bin/vapt-sanitize scan.txt \
  --engagement ACME-2026-EXTERNAL \
  --ai-prompt \
  --ai-clipboard
```

Lo stesso valore reale mantiene lo stesso placeholder nelle esecuzioni successive dello stesso engagement:

```text
Nmap:   10.20.30.45 -> [PRIVATE_IP_001]
Burp:   10.20.30.45 -> [PRIVATE_IP_001]
Nuclei: 10.20.30.45 -> [PRIVATE_IP_001]
```

Engagement differenti sono isolati e possono riutilizzare indipendentemente `[PRIVATE_IP_001]` per valori non correlati.

### Mostrare il mapping locale

```bash
./.venv/bin/vapt-sanitize engagement show ACME-2026-EXTERNAL
```

### Risolvere placeholder

```bash
./.venv/bin/vapt-sanitize engagement resolve \
  ACME-2026-EXTERNAL \
  '[PRIVATE_IP_001]' '[HOSTNAME_001]'
```

## Storage e sicurezza del vault

Percorsi Linux/XDG predefiniti:

```text
~/.config/vapt-sanitize/master.key
~/.local/share/vapt-sanitize/engagements/<ID>/mapping.enc
~/.local/share/vapt-sanitize/engagements/<ID>/metadata.json
~/.local/share/vapt-sanitize/engagements/<ID>/.mapping.lock
```

Regole importanti:

- `mapping.enc` è cifrato a riposo.
- `master.key` è separata e viene creata con permessi restrittivi.
- I secret redatti non vengono mai salvati nel mapping.
- Il vault usa un lock locale per gestire update concorrenti.
- La perdita di `master.key` rende non decifrabili i mapping esistenti.
- Un attaccante che compromette l'account locale e può leggere sia chiave sia ciphertext è all'interno del trust boundary locale e può potenzialmente decifrare i mapping.

Percorsi personalizzati:

```bash
export VAPT_SANITIZE_CONFIG_DIR=/secure/config/vapt-sanitize
export VAPT_SANITIZE_DATA_DIR=/secure/data/vapt-sanitize
```

## Integrazione Burp Suite

Build del JAR:

```bash
./scripts/build-burp.sh
```

Artefatto atteso:

```text
burp-extension/build/libs/vapt-sanitize-burp-1.0.0.jar
```

In Burp:

```text
Extensions -> Installed -> Add -> Java
```

L'estensione offre:

- `Sanitize request -> preview`
- `Sanitize response -> preview`
- `Sanitize selection -> preview`
- selezione policy
- selezione e refresh engagement
- riepilogo detections
- preview sanitizzata
- `Copy sanitized`
- `Copy AI Prompt`

Ogni nuova sessione Burp parte da:

```text
(None - stateless)
```

Il comportamento è intenzionale per evitare che l'engagement di un cliente venga ereditato accidentalmente da una nuova sessione.

### Runtime path di Burp

Per default l'estensione cerca:

```text
~/vapt-sanitize
~/vapt-sanitize/.venv/bin/python
```

Se il repository e installato in una directory diversa da `~/vapt-sanitize`, usare un symlink operativo oppure avviare Burp con percorsi espliciti:

```bash
export VAPT_SANITIZE_HOME="$HOME/vapt-sanitize"
export VAPT_SANITIZE_PYTHON="$VAPT_SANITIZE_HOME/.venv/bin/python"
burpsuite
```

Il subprocess Burp riceve le stesse root config/data usate dalla UI, così CLI e Burp possono condividere lo stesso engagement cifrato.

## Workflow raccomandato

```text
1. Creare un engagement per lo scope autorizzato.
2. Eseguire normalmente lo strumento di sicurezza.
3. Salvare o catturare l'output.
4. Sanitizzare con lo stesso engagement ID.
5. Verificare detections e stato del Security Gate.
6. Generare il prompt AI-ready.
7. Controllare visivamente il prompt.
8. Incollarlo manualmente nel servizio AI scelto.
9. Ricevere l'analisi con placeholder persistenti.
10. Risolvere localmente i placeholder quando necessario.
11. Continuare i test sull'ambiente reale del cliente.
```

Non riutilizzare lo stesso engagement per clienti non correlati.

## Cosa VAPT Sanitizer non è

Non è:

- un vulnerability scanner;
- un exploit framework;
- un SIEM;
- un sistema DLP completo;
- un password manager;
- un sostituto della revisione umana;
- una garanzia matematica che qualsiasi formato futuro non possa contenere informazioni sensibili.

`PASS` significa che i controlli implementati non hanno individuato motivi per richiedere `REVIEW` o `BLOCKED`. L'operatore resta responsabile dell'ispezione finale prima che i dati lascino la workstation.

## Troubleshooting

### `Engagement vaults require the 'cryptography' package`

Burp e CLI devono utilizzare lo stesso virtual environment correttamente installato:

```bash
./.venv/bin/python -c 'from cryptography.fernet import Fernet; print("cryptography OK")'
```

Se necessario:

```bash
./.venv/bin/python -m pip install -e .
```

### Burp non mostra un engagement

- Crearlo prima con `engagement init`.
- Premere **Refresh** nel pannello `Engagement Mapping Vault`.
- Verificare che Burp e CLI usino le stesse root `VAPT_SANITIZE_CONFIG_DIR` / `VAPT_SANITIZE_DATA_DIR`.

### CLI e Burp assegnano placeholder diversi

Controllare che utilizzino:

- lo stesso engagement ID;
- la stessa master key;
- la stessa engagement data directory.

### Clipboard mode non funziona

Su Kali/X11:

```bash
sudo apt install xclip
```

### `REVIEW` impedisce l'AI Handoff

Controllare il contenuto sanitizzato. Se approvato, usare `--review-approved` nella CLI o confermare il dialog in Burp.

### `BLOCKED`

Non bypassarlo. Correggere la condizione di input/policy e sanitizzare nuovamente.

### La build Burp non trova Gradle

Usare:

```bash
./scripts/build-burp.sh
```

Il bootstrap incluso scarica e verifica Gradle 8.14.3. Sono richiesti Java 17+, `unzip` e `curl` oppure `wget`.

## File che non devono mai essere committati

Il `.gitignore` incluso esclude gli artefatti locali più comuni. In particolare non committare o condividere:

```text
master.key
mapping.enc
engagements/
.venv/
client outputs
local backups
```

## Stato della release

Gate validato v1.0.0 Stable:

```text
181/181 tests OK
10/10 auto-detection PASS
Burp extension BUILD SUCCESSFUL
JAR: vapt-sanitize-burp-1.0.0.jar
```

Lo SHA-256 dell'artefatto di release viene pubblicato insieme alla GitHub Release dopo la creazione dell'artefatto taggato finale.

## Principio operativo

```text
AI                 = assistente analitico
VAPT Sanitizer     = security boundary locale
Engagement Vault   = livello di correlazione locale
Penetration Tester = decisore finale
```

## Progetto open source

VAPT Sanitizer è distribuito con licenza [Apache License 2.0](LICENSE).

Prima di contribuire, leggere:

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [SECURITY.md](SECURITY.md)
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)

Per falsi positivi/falsi negativi dei detector usare il template GitHub dedicato e **solo dati sintetici**.
