# VAPT Sanitizer v1.0.0 - Release Notes

Data RC2: 2026-09-11

Questa release congela la baseline tecnica validata del progetto. Non introduce nuovi detector rispetto alla baseline gia testata: formalizza installazione, versioning, dipendenze, fixture, build Burp e controlli di release.

## Confini di sicurezza

- Il sanitizer non sostituisce il giudizio dell'operatore.
- I dati devono provenire da assessment autorizzati.
- Un `PASS` indica che i controlli implementati non hanno rilevato condizioni che richiedono REVIEW/BLOCKED; non e una garanzia matematica di anonimizzazione assoluta.
- Il Mapping Vault e cifrato a riposo, ma la workstation locale resta parte del trust boundary.

## Compatibilita di riferimento

- Python >= 3.11
- PyYAML 6.0.3
- cryptography 46.0.4
- Java >= 17
- Burp Montoya API 2026.7

## Upgrade da workspace esistente

Prima di sostituire file, eseguire un backup del repository. Non cancellare:

- `~/.config/vapt-sanitize/master.key`
- `~/.local/share/vapt-sanitize/engagements/`

Sono esterni al repository e non fanno parte dello ZIP di release.

## Validazione RC2

- 181 test OK (somma dei moduli di regressione)
- auto-detection fixture: 10/10 PASS
- `python -m vapt_sanitize --version`: `VAPT Sanitizer 1.0.0`
- sintassi Python e Bash verificata
- RC1 ha mostrato un difetto di packaging: mancava un Gradle bootstrap. RC2 include `burp-extension/gradlew`, fissato a Gradle 8.14.3 con verifica SHA-256; la build Burp deve essere confermata sul workspace Kali prima della promozione a release finale
