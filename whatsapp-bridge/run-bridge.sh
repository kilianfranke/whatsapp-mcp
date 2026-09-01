#!/bin/sh
# Startet die Bridge mit den sicheren Vorgaben.
#
# Hintergrund: die Bridge schreibt Nachrichteninhalte auf stdout. Jede
# Umleitung in eine Datei erzeugt damit eine zweite, ungeschuetzte Kopie der
# Chat-Historie -- ausserhalb von store/, das mit 0700 geschuetzt ist. Dieses
# Skript leitet die Ausgabe deshalb immer nach store/bridge.log und setzt
# vorher umask 077, damit die Datei nur fuer den eigenen Benutzer lesbar ist.
#
# Aufruf:            ./run-bridge.sh          (Lesebetrieb, Versand gesperrt)
# Versand erlauben:  WHATSAPP_BRIDGE_SEND_MODE=confirm ./run-bridge.sh
set -eu

cd "$(dirname "$0")"
umask 077
mkdir -p store

echo "Bridge startet. Log: $(pwd)/store/bridge.log"
echo "Sendemodus: ${WHATSAPP_BRIDGE_SEND_MODE:-off}"

# tee statt Umleitung: beim ersten Start muss der QR-Code im Terminal sichtbar
# sein. Die Logdatei entsteht unter umask 077 und ist damit 0600.
go run . 2>&1 | tee -a store/bridge.log
