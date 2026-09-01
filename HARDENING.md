# Hardening-Fork

Fork von [lharries/whatsapp-mcp](https://github.com/lharries/whatsapp-mcp), Stand Upstream `7d6a06d` (13.07.2025).
Branch `hardening`, angelegt 21.08.2026. Seit 25.08.2026 auch der Stand von `main`.

Der Upstream ist unbetreibbar: er verbindet sich nicht mehr, und dort wo er es täte, wäre er ungeschützt.

## Änderungen

| # | Was | Warum |
|---|---|---|
| 1 | whatsmeow von `20250318` auf `20260816`, `context.Background()` an fünf Call Sites | Upstream lief in `Client outdated (405)`. Ohne diesen Patch kommt man nicht bis zum QR-Code. |
| 2 | Bind auf `127.0.0.1`, API-Key-Pflicht auf beiden Endpunkten | Bridge lauschte auf `0.0.0.0:8080` ohne Auth. Jeder im selben Netz konnte aus dem Account senden. |
| 3 | `validateMediaPath` mit Allowlist und Symlink-Auflösung | `media_path` ging ungeprüft in `os.ReadFile`. Beliebige Systemdatei liess sich an eine beliebige Nummer verschicken. |
| 4 | Query-String im DirectPath erhalten, kollisionsfreie Dateinamen | whatsmeow hängt `&hash=` an den DirectPath an. Ohne `?` antwortet Metas CDN auf jeden Download mit 403. |
| 5 | LID-Auflösung über `Store.LIDs.GetPNForLID` | Nach der LID-Migration erschien dieselbe Person als zweiter Chat mit einer rohen Zahl als Namen. |
| 6 | Sendemodus, Empfänger-Whitelist, Rate Limit, Audit-Log | Eingehende Nachrichten sind nicht vertrauenswürdiger Input. Ohne Gate kann Prompt Injection den Agenten zum Senden bringen. |
| 7 | Gesendete Nachrichten persistieren, Last-Message-JOIN korrigiert, drei Indizes | Eigene Sendungen fehlten in der DB, wodurch Auto-Reply-Schleifen dieselbe Nachricht endlos beantworteten. |
| 8 | Alle Abhängigkeiten aktualisiert | `govulncheck` meldet jetzt null erreichbare Schwachstellen. |
| 9 | Start bricht ab, wenn `SEND_MODE=confirm` ohne Terminal gesetzt ist | Sonst läuft die Bridge scheinbar normal und lehnt jeden Versand am nicht lesbaren Prompt ab. |
| 10 | Sendekontingent überlebt Neustarts | Ein In-Memory-Limit setzt sich bei jedem Absturz zurück, und genau dieses Limit schützt den einzigen belegten Ban-Pfad. |
| 11 | Audit-Log rotiert bei 5 MB, Warnung bei Bind ausserhalb Loopback | Das forensische Log wuchs unbegrenzt, und ein abweichender Bind blieb unkommentiert. |
| 12 | CI: Build, Vet, Test mit `-race`, `govulncheck`, wöchentlich | Früherkennung, wenn eine Abhängigkeit oder das Protokoll bricht. Seit 25.08.2026 grün, auf `main` und `hardening`. |
| 13 | Sende-Werkzeuge im MCP-Server hinter `WHATSAPP_MCP_ENABLE_SEND`, Vorgabe aus | Im Lesebetrieb sind sie nutzlose Angriffsflaeche. Ein Werkzeug, das dem Agenten gar nicht angeboten wird, kann eine praeparierte Nachricht auch nicht missbrauchen. |
| 14 | `pre-commit`-Hook gegen `store/`, `*.db`, `api_key`, `*.log` im Index | Das Repo ist oeffentlich, das Arbeitsverzeichnis enthaelt die komplette Historie. Ein `git add -f` oder eine verlorene Ignore-Zeile reicht sonst. |
| 15 | `run-bridge.sh`: `umask 077`, Log immer nach `store/bridge.log` | Die Bridge schreibt Nachrichteninhalte auf stdout. Jede Umleitung in eine Datei erzeugte bisher eine ungeschuetzte Zweitkopie der Historie ausserhalb von `store/`. |

## Konfiguration

Alles über Umgebungsvariablen. Die Defaults sind die sicheren Werte.

| Variable | Default | Wirkung |
|---|---|---|
| `WHATSAPP_BRIDGE_BIND` | `127.0.0.1` | Interface der REST-API. Ändern nur mit sehr gutem Grund. |
| `WHATSAPP_BRIDGE_API_KEY` | automatisch erzeugt | Liegt sonst in `store/api_key` mit Modus 0600. |
| `WHATSAPP_BRIDGE_SEND_MODE` | `off` | `off` blockiert jeden Versand, `confirm` fragt im Terminal nach, `allow` sendet ungefragt. |
| `WHATSAPP_BRIDGE_ALLOWED_JIDS` | leer | Komma-Liste erlaubter Empfänger. Leer heisst alle. |
| `WHATSAPP_BRIDGE_MAX_SENDS_PER_HOUR` | `20` | `0` schaltet das Limit ab. |
| `WHATSAPP_BRIDGE_MEDIA_ROOTS` | `store` | Doppelpunkt-Liste der Verzeichnisse, aus denen Medien gesendet werden dürfen. |
| `WHATSAPP_MCP_ENABLE_SEND` | leer | Nur der MCP-Server. Erst wenn gesetzt, erscheinen `send_message`, `send_file` und `send_audio_message` überhaupt in der Werkzeugliste. Die Bridge sperrt zusätzlich, beide Schalter müssen offen sein. |

Empfohlener Start für den Lesebetrieb: nichts setzen, und `./run-bridge.sh` statt `go run .` verwenden. Der Default blockiert Versand vollständig, auf beiden Ebenen.

**Die Ausgabe der Bridge enthält Nachrichteninhalte.** Wer sie selbst umleitet, legt eine ungeschützte Kopie der Historie an. `run-bridge.sh` setzt deshalb `umask 077` und schreibt ausschliesslich nach `store/bridge.log`.

## Nach dem Klonen einmalig

```
git config core.hooksPath .githooks
```

Git aktiviert versionierte Hooks nicht von selbst. Ohne diese Zeile ist Patch 14
wirkungslos, und zwar unbemerkt.

## Tests

`go test ./...` in `whatsapp-bridge/` deckt Path Traversal, Symlink-Ausbruch, Auth, Sendesperre, Rate Limit, Whitelist, DirectPath, Dateinamen und die Kontingent-Buchung ab. Zwölf Tests, alle grün.

## Was weiterhin offen ist

- Die SQLite-Datenbanken sind unverschlüsselt. Wer Dateizugriff hat, hat die Historie. Bewusst nicht gepatcht: SQLCipher wäre ein Umbau der gesamten Datenschicht, FileVault löst dasselbe Problem ausserhalb dieses Repos.
- Das Sende-Gate verengt Prompt Injection, es löst sie nicht. Gegated ist nur der Rückweg über WhatsApp.
- Die Nutzung verstösst gegen die WhatsApp-Nutzungsbedingungen. Das ist nicht patchbar.
- Der Upstream wird nicht gepflegt. Bricht das Protokoll, muss dieser Fork selbst nachziehen.
