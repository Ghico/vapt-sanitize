# Changelog

## 1.0.0 - 2026-09-10

Prima baseline tecnica stabile di VAPT Sanitizer.

- 10 profili: GENERIC, NMAP, BURP, GOBUSTER, NUCLEI, WINDOWS, LINUX, AWS, SECRETS, PII.
- Auto-detection integrata e fixture sintetiche 10/10.
- Security Gate PASS / REVIEW / BLOCKED.
- AI Handoff provider-neutral, clipboard-first e senza trasmissione automatica.
- Integrazione Burp con preview e AI Prompt.
- Engagement Mapping Vault cifrato con correlazione cross-process e cross-tool.
- Lock concorrente del vault e isolamento per engagement.
- Secret redatti esclusi dal mapping persistente.
- Packaging, dipendenze congelate, release checks e build Gradle/Montoya documentati.

## 1.0.0 RC2 packaging - 2026-09-11

- Nessuna modifica ai detector, alle policy o alla semantica di sanitizzazione.
- Aggiunto bootstrap Gradle 8.14.3 verificato SHA-256 per build Burp senza Gradle installato a livello di sistema.
- Build script Burp reso riproducibile sulla workstation Kali pulita.
- Aggiunto test di release dedicato al bootstrap Gradle.
