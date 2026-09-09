package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pedro-walter/picket/agent/internal/report"
)

func TestSignMatchesServerRecipe(t *testing.T) {
	// hmac_sha256("testtoken", "1700000000." + `{"x":1}`), lowercase hex.
	// Cross-checked with: printf '%s' '1700000000.{"x":1}' |
	//   openssl dgst -sha256 -hmac testtoken
	const want = "150a3a5d49bb202e7595e6c39fee441e0c3bf3025e0ad3f9fd70ffaedf1b700d"
	got := sign("testtoken", "1700000000", []byte(`{"x":1}`))
	if got != want {
		t.Fatalf("sign() = %s, want %s", got, want)
	}
}

func TestSendReportSignsAndParses(t *testing.T) {
	var gotAuth, gotTS, gotSig string
	var gotBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/report" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		gotAuth = r.Header.Get("Authorization")
		gotTS = r.Header.Get("X-Picket-Timestamp")
		gotSig = r.Header.Get("X-Picket-Signature")
		gotBody, _ = io.ReadAll(r.Body)
		json.NewEncoder(w).Encode(report.Response{OK: true, DesiredVersion: "0.2.0", URL: "https://example/pkg"})
	}))
	defer srv.Close()

	c := New(srv.URL, "tok-abc")
	c.now = func() time.Time { return time.Unix(1700000000, 0) }

	resp, err := c.SendReport(context.Background(), &report.Payload{
		AgentName: "test", AgentVersion: "0.1.0", ChecksRun: []string{"reboot"},
	})
	if err != nil {
		t.Fatalf("SendReport: %v", err)
	}
	if resp.DesiredVersion != "0.2.0" {
		t.Errorf("desired_version = %q", resp.DesiredVersion)
	}
	if gotAuth != "Bearer tok-abc" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if gotTS != "1700000000" {
		t.Errorf("timestamp = %q", gotTS)
	}
	if want := sign("tok-abc", "1700000000", gotBody); gotSig != want {
		t.Errorf("signature = %q, want %q (over the exact bytes sent)", gotSig, want)
	}
}

func TestSendReportNon200IsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"signature mismatch"}`, http.StatusUnauthorized)
	}))
	defer srv.Close()

	_, err := New(srv.URL, "tok").SendReport(context.Background(), &report.Payload{})
	if err == nil {
		t.Fatal("expected error on 401")
	}
}
