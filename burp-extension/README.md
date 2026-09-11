# VAPT Sanitizer - Burp extension

La UI Burp invoca il bridge Python locale `vapt_sanitize.integrations.burp`. Nessun dato originale viene inviato automaticamente a un provider LLM.

Requisiti di build:
- Java 17 o superiore
- `unzip` e `curl` oppure `wget`
- nessun Gradle di sistema richiesto: `gradlew` usa Gradle 8.14.3 verificato SHA-256
- Montoya API 2026.7 (definita come `compileOnly` in `build.gradle`)

Build dalla root del repository:

```bash
./scripts/build-burp.sh
```

Al primo build il bootstrap scarica Gradle 8.14.3 dal servizio ufficiale e verifica il digest SHA-256 prima dell'estrazione.

Runtime atteso:
- `VAPT_SANITIZE_HOME` se il repository non e in `~/vapt-sanitize`
- `VAPT_SANITIZE_PYTHON` se non si usa `<home>/.venv/bin/python`
- il Mapping Vault usa le directory XDG locali; la UI passa esplicitamente data/config root al subprocess Python

Per sicurezza l'engagement attivo non viene persistito globalmente tra riavvii di Burp: ogni nuova sessione parte da `Stateless`.
