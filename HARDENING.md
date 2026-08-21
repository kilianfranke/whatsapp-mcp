# Hardening-Fork

Fork von [lharries/whatsapp-mcp](https://github.com/lharries/whatsapp-mcp), Stand Upstream `7d6a06d` (13.07.2025).
Branch `hardening`, angelegt 21.08.2026.

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

Empfohlener Start für den Lesebetrieb: nichts setzen. Der Default blockiert Versand vollständig.

## Tests

`go test ./...` in `whatsapp-bridge/` deckt Path Traversal, Symlink-Ausbruch, Auth, Sendesperre, Rate Limit, Whitelist, DirectPath und Dateinamen ab. Acht Tests, alle grün.

## Was weiterhin offen ist

- Die SQLite-Datenbanken sind unverschlüsselt. Wer Dateizugriff hat, hat die Historie.
- Die Nutzung verstösst gegen die WhatsApp-Nutzungsbedingungen. Das ist nicht patchbar.
- Der Upstream wird nicht gepflegt. Bricht das Protokoll, muss dieser Fork selbst nachziehen.
