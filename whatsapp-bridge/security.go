package main

// Sicherheitsschicht für die Bridge. Der Upstream hat keine davon:
// die REST-API war unauthentifiziert auf 0.0.0.0 erreichbar, Medienpfade
// gingen ungeprüft in os.ReadFile, und Senden war unbegrenzt möglich.

import (
	"bufio"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"
)

const (
	apiKeyEnv    = "WHATSAPP_BRIDGE_API_KEY"
	apiKeyFile   = "store/api_key"
	sendModeEnv  = "WHATSAPP_BRIDGE_SEND_MODE"
	allowJIDsEnv = "WHATSAPP_BRIDGE_ALLOWED_JIDS"
	mediaRootEnv = "WHATSAPP_BRIDGE_MEDIA_ROOTS"
	sendRateEnv  = "WHATSAPP_BRIDGE_MAX_SENDS_PER_HOUR"
	auditLogFile = "store/audit.log"
	sendStateFile = "store/send_history.json"

	// Ab dieser Groesse wird das Audit-Log einmal rotiert.
	auditMaxBytes = 5 << 20
)

// Sendemodus. Default ist bewusst "off": eine eingehende WhatsApp-Nachricht ist
// nicht vertrauenswürdiger Input, und ohne Gate kann ein Prompt-Injection-Angriff
// den Agenten zum Senden bringen.
const (
	sendOff     = "off"
	sendConfirm = "confirm"
	sendAllow   = "allow"
)

var (
	apiKey      string
	auditMu     sync.Mutex
	sendMu      sync.Mutex
	sendHistory []time.Time
	confirmMu   sync.Mutex
)

// loadAPIKey liest den Schlüssel aus der Umgebung oder erzeugt einen
// persistenten Zufallsschlüssel unter store/api_key (Modus 0600).
func loadAPIKey() (string, error) {
	if k := strings.TrimSpace(os.Getenv(apiKeyEnv)); k != "" {
		return k, nil
	}

	if data, err := os.ReadFile(apiKeyFile); err == nil {
		if k := strings.TrimSpace(string(data)); k != "" {
			return k, nil
		}
	}

	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("could not generate API key: %v", err)
	}
	k := hex.EncodeToString(buf)

	if err := os.MkdirAll(filepath.Dir(apiKeyFile), 0700); err != nil {
		return "", fmt.Errorf("could not create store directory: %v", err)
	}
	if err := os.WriteFile(apiKeyFile, []byte(k), 0600); err != nil {
		return "", fmt.Errorf("could not persist API key: %v", err)
	}
	fmt.Printf("Generated new API key at %s\n", apiKeyFile)
	return k, nil
}

// requireAuth schützt einen Handler mit dem API-Key. Vergleich in konstanter
// Zeit, damit der Schlüssel nicht über Laufzeitunterschiede erratbar ist.
func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		provided := r.Header.Get("X-API-Key")
		if provided == "" {
			provided = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		}
		if subtle.ConstantTimeCompare([]byte(provided), []byte(apiKey)) != 1 {
			audit("AUTH_DENIED path=%s remote=%s", r.URL.Path, r.RemoteAddr)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// mediaRoots liefert die Verzeichnisse, aus denen gesendet werden darf.
// Ohne Konfiguration ist das nur der store-Ordner der Bridge.
func mediaRoots() []string {
	roots := []string{}
	if v := strings.TrimSpace(os.Getenv(mediaRootEnv)); v != "" {
		for _, p := range strings.Split(v, ":") {
			if p = strings.TrimSpace(p); p != "" {
				roots = append(roots, p)
			}
		}
	}
	if len(roots) == 0 {
		roots = append(roots, "store")
	}

	resolved := make([]string, 0, len(roots))
	for _, r := range roots {
		abs, err := filepath.Abs(r)
		if err != nil {
			continue
		}
		// Symlinks auflösen, sonst umgeht ein Link im erlaubten Verzeichnis die Prüfung.
		if real, err := filepath.EvalSymlinks(abs); err == nil {
			abs = real
		}
		resolved = append(resolved, abs)
	}
	return resolved
}

// validateMediaPath stellt sicher, dass ein Pfad innerhalb der erlaubten Wurzeln
// liegt. Ohne diese Prüfung liest /api/send jede Datei des Systems aus
// und schickt sie an eine beliebige WhatsApp-Nummer.
func validateMediaPath(path string) (string, error) {
	if path == "" {
		return "", nil
	}

	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("invalid media path: %v", err)
	}
	// Erst den echten Pfad bestimmen, dann vergleichen. Bei noch nicht
	// existierenden Dateien fällt EvalSymlinks auf das Elternverzeichnis zurück.
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		abs = real
	} else if parent, err := filepath.EvalSymlinks(filepath.Dir(abs)); err == nil {
		abs = filepath.Join(parent, filepath.Base(abs))
	}

	for _, root := range mediaRoots() {
		rel, err := filepath.Rel(root, abs)
		if err != nil {
			continue
		}
		if rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return abs, nil
		}
	}

	audit("MEDIA_PATH_DENIED path=%s", path)
	return "", fmt.Errorf("media path %q is outside the allowed roots (%s); set %s to widen",
		path, strings.Join(mediaRoots(), ":"), mediaRootEnv)
}

// stdinIsTerminal meldet, ob eine Eingabe ueberhaupt moeglich ist.
// Eine Pruefung auf ModeCharDevice reicht nicht: /dev/null ist ebenfalls ein
// Character Device, und genau darauf zeigt stdin unter launchd. Die Pruefung
// haette also ausgerechnet den Fall verfehlt, fuer den sie gedacht ist.
func stdinIsTerminal() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

// checkSendModeUsable bricht beim Start ab, wenn "confirm" ohne Terminal
// gesetzt ist. Sonst laeuft die Bridge scheinbar normal, lehnt aber jeden
// Versand am nicht lesbaren Prompt ab, und das faellt erst im Betrieb auf.
func checkSendModeUsable() error {
	if sendMode() == sendConfirm && !stdinIsTerminal() {
		return fmt.Errorf("%s=confirm needs an interactive terminal, but stdin is not a TTY; "+
			"run the bridge in the foreground, or use %s=allow together with %s",
			sendModeEnv, sendModeEnv, allowJIDsEnv)
	}
	return nil
}

func sendMode() string {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(sendModeEnv))) {
	case sendAllow:
		return sendAllow
	case sendConfirm:
		return sendConfirm
	default:
		return sendOff
	}
}

func maxSendsPerHour() int {
	if v := strings.TrimSpace(os.Getenv(sendRateEnv)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
	}
	return 20
}

// jidAllowed prüft die optionale Empfänger-Whitelist.
func jidAllowed(recipient string) bool {
	v := strings.TrimSpace(os.Getenv(allowJIDsEnv))
	if v == "" {
		return true
	}
	for _, allowed := range strings.Split(v, ",") {
		if strings.EqualFold(strings.TrimSpace(allowed), recipient) {
			return true
		}
	}
	return false
}

// loadSendHistory stellt das Sendefenster nach einem Neustart wieder her.
// Ohne Persistenz setzt jeder Neustart das Kontingent zurueck, und genau das
// Limit schuetzt vor dem einzigen belegten Ban-Pfad.
func loadSendHistory() {
	sendMu.Lock()
	defer sendMu.Unlock()

	data, err := os.ReadFile(sendStateFile)
	if err != nil {
		return
	}
	var stamps []time.Time
	if err := json.Unmarshal(data, &stamps); err != nil {
		return
	}
	sendHistory = stamps
	pruneSendHistory()
}

// saveSendHistory schreibt das Fenster zurueck. Aufrufer hält sendMu.
func saveSendHistory() {
	if err := os.MkdirAll(filepath.Dir(sendStateFile), 0700); err != nil {
		return
	}
	data, err := json.Marshal(sendHistory)
	if err != nil {
		return
	}
	// Atomar ersetzen, damit ein Absturz keine halbe Datei hinterlaesst.
	tmp := sendStateFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return
	}
	if err := os.Rename(tmp, sendStateFile); err != nil {
		os.Remove(tmp)
	}
}

// pruneSendHistory verwirft Einträge älter als eine Stunde. Aufrufer hält sendMu.
func pruneSendHistory() {
	cutoff := time.Now().Add(-time.Hour)
	kept := sendHistory[:0]
	for _, t := range sendHistory {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	sendHistory = kept
}

// rateLimitAvailable prüft das Kontingent, ohne es zu verbrauchen.
func rateLimitAvailable() (bool, int) {
	limit := maxSendsPerHour()
	if limit == 0 {
		return true, 0
	}

	sendMu.Lock()
	defer sendMu.Unlock()

	pruneSendHistory()
	return len(sendHistory) < limit, limit
}

// rateLimitConsume bucht einen Sendevorgang. Getrennt vom Prüfen, damit eine
// am Bestätigungsprompt abgelehnte Nachricht kein Kontingent kostet.
func rateLimitConsume() {
	if maxSendsPerHour() == 0 {
		return
	}

	sendMu.Lock()
	defer sendMu.Unlock()

	pruneSendHistory()
	sendHistory = append(sendHistory, time.Now())
	saveSendHistory()
}

// confirmSend fragt im Terminal nach, bevor gesendet wird.
func confirmSend(recipient, message, mediaPath string) bool {
	confirmMu.Lock()
	defer confirmMu.Unlock()

	preview := message
	if len(preview) > 200 {
		preview = preview[:200] + "..."
	}

	fmt.Printf("\n=== SEND APPROVAL REQUIRED ===\n")
	fmt.Printf("To:    %s\n", recipient)
	fmt.Printf("Text:  %s\n", preview)
	if mediaPath != "" {
		fmt.Printf("Media: %s\n", mediaPath)
	}
	fmt.Printf("Approve? [y/N]: ")

	reader := bufio.NewReader(os.Stdin)
	answer, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("\nCould not read approval (%v), denying.\n", err)
		return false
	}
	ok := strings.EqualFold(strings.TrimSpace(answer), "y")
	if !ok {
		fmt.Printf("Denied.\n")
	}
	return ok
}

// authorizeSend bündelt alle Prüfungen vor dem Versand.
func authorizeSend(recipient, message, mediaPath string) error {
	mode := sendMode()
	if mode == sendOff {
		audit("SEND_BLOCKED_MODE_OFF recipient=%s", recipient)
		return fmt.Errorf("sending is disabled; set %s=confirm or %s=allow to enable", sendModeEnv, sendModeEnv)
	}

	if !jidAllowed(recipient) {
		audit("SEND_BLOCKED_JID recipient=%s", recipient)
		return fmt.Errorf("recipient %s is not in %s", recipient, allowJIDsEnv)
	}

	if ok, limit := rateLimitAvailable(); !ok {
		audit("SEND_BLOCKED_RATE recipient=%s limit=%d", recipient, limit)
		return fmt.Errorf("rate limit reached (%d sends per hour); raise %s to change", limit, sendRateEnv)
	}

	if mode == sendConfirm && !confirmSend(recipient, message, mediaPath) {
		audit("SEND_DENIED_BY_USER recipient=%s", recipient)
		return fmt.Errorf("send denied at the approval prompt")
	}

	// Erst jetzt buchen: alles davor kann noch scheitern.
	rateLimitConsume()

	audit("SEND_AUTHORIZED recipient=%s media=%q mode=%s", recipient, mediaPath, mode)
	return nil
}

// audit schreibt eine Zeile ins Audit-Log. Ohne dieses Log lässt sich nach
// einem Vorfall nicht rekonstruieren, was der Agent verschickt hat.
func audit(format string, args ...interface{}) {
	auditMu.Lock()
	defer auditMu.Unlock()

	if err := os.MkdirAll(filepath.Dir(auditLogFile), 0700); err != nil {
		return
	}
	// Einmalige Rotation, damit das forensische Log nicht unbegrenzt waechst.
	if info, err := os.Stat(auditLogFile); err == nil && info.Size() >= auditMaxBytes {
		os.Rename(auditLogFile, auditLogFile+".1")
	}

	f, err := os.OpenFile(auditLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()

	fmt.Fprintf(f, "%s %s\n", time.Now().Format(time.RFC3339), fmt.Sprintf(format, args...))
}

// mediaStamp erzeugt einen kollisionsfreien Namensbestandteil. Der Upstream
// benutzte reine Sekundengenauigkeit, wodurch beim Re-Sync mehrere Medien
// derselben Sekunde dieselbe Datei überschrieben.
func mediaStamp() string {
	buf := make([]byte, 4)
	if _, err := rand.Read(buf); err != nil {
		return time.Now().Format("20060102_150405.000000")
	}
	return time.Now().Format("20060102_150405") + "_" + hex.EncodeToString(buf)
}
