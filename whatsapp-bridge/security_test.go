package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateMediaPathRejectsTraversal(t *testing.T) {
	root := t.TempDir()
	t.Setenv(mediaRootEnv, root)

	inside := filepath.Join(root, "ok.jpg")
	if err := os.WriteFile(inside, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := validateMediaPath(inside); err != nil {
		t.Fatalf("path inside the root must be allowed, got %v", err)
	}

	for _, bad := range []string{
		"/etc/passwd",
		filepath.Join(root, "..", "..", "etc", "passwd"),
		filepath.Join(root, "../../../../etc/hosts"),
	} {
		if _, err := validateMediaPath(bad); err == nil {
			t.Errorf("expected %q to be rejected", bad)
		}
	}
}

func TestValidateMediaPathRejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	t.Setenv(mediaRootEnv, root)

	secret := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secret, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link.txt")
	if err := os.Symlink(secret, link); err != nil {
		t.Fatal(err)
	}

	// Ein Symlink im erlaubten Verzeichnis darf nicht aus ihm herausführen.
	if _, err := validateMediaPath(link); err == nil {
		t.Fatal("symlink pointing outside the root must be rejected")
	}
}

func TestRequireAuthRejectsMissingAndWrongKey(t *testing.T) {
	apiKey = "correct-horse"
	handler := requireAuth(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	cases := []struct {
		name string
		key  string
		want int
	}{
		{"no key", "", http.StatusUnauthorized},
		{"wrong key", "nope", http.StatusUnauthorized},
		{"right key", "correct-horse", http.StatusOK},
	}

	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodPost, "/api/send", nil)
		if tc.key != "" {
			req.Header.Set("X-API-Key", tc.key)
		}
		rec := httptest.NewRecorder()
		handler(rec, req)
		if rec.Code != tc.want {
			t.Errorf("%s: got %d, want %d", tc.name, rec.Code, tc.want)
		}
	}
}

func TestSendBlockedByDefault(t *testing.T) {
	t.Setenv(sendModeEnv, "")
	if err := authorizeSend("4915112345678@s.whatsapp.net", "hi", ""); err == nil {
		t.Fatal("sending must be disabled unless explicitly enabled")
	}
}

func TestSendRateLimit(t *testing.T) {
	t.Setenv(sendModeEnv, sendAllow)
	t.Setenv(sendRateEnv, "3")
	t.Setenv(allowJIDsEnv, "")
	sendHistory = nil

	for i := 0; i < 3; i++ {
		if err := authorizeSend("peer@s.whatsapp.net", "hi", ""); err != nil {
			t.Fatalf("send %d should pass: %v", i+1, err)
		}
	}
	err := authorizeSend("peer@s.whatsapp.net", "hi", "")
	if err == nil || !strings.Contains(err.Error(), "rate limit") {
		t.Fatalf("fourth send must hit the rate limit, got %v", err)
	}
}

func TestJIDWhitelist(t *testing.T) {
	t.Setenv(sendModeEnv, sendAllow)
	t.Setenv(sendRateEnv, "100")
	t.Setenv(allowJIDsEnv, "friend@s.whatsapp.net")
	sendHistory = nil

	if err := authorizeSend("friend@s.whatsapp.net", "hi", ""); err != nil {
		t.Fatalf("whitelisted recipient must pass: %v", err)
	}
	if err := authorizeSend("stranger@s.whatsapp.net", "hi", ""); err == nil {
		t.Fatal("recipient outside the whitelist must be rejected")
	}
}

func TestDirectPathKeepsQueryString(t *testing.T) {
	url := "https://mmg.whatsapp.net/v/t62.7118-24/13812002_698058036224062_n.enc?ccb=11-4&oh=01_Q5Aa&oe=68A&_nc_sid=5e03e0&mms3=true"
	got := extractDirectPathFromURL(url)

	if !strings.Contains(got, "?") {
		t.Fatalf("direct path must keep its query string, got %q", got)
	}
	if !strings.HasPrefix(got, "/v/t62.7118-24/") {
		t.Fatalf("unexpected direct path %q", got)
	}
}

func TestMediaStampIsUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 500; i++ {
		s := mediaStamp()
		if seen[s] {
			t.Fatalf("collision on %q", s)
		}
		seen[s] = true
	}
}
