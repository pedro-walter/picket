package selfupdate

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/pedrohardware/picket/agent/internal/report"
)

func keypair(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return priv, pubPEM
}

// serves /bin (payload) and /bin.sig (base64 DER ecdsa over sha256(payload)),
// mimicking `cosign sign-blob --key`.
func artifactServer(t *testing.T, priv *ecdsa.PrivateKey, payload []byte, mangleSig bool) *httptest.Server {
	t.Helper()
	digest := sha256.Sum256(payload)
	der, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if mangleSig {
		der[len(der)-1] ^= 0xff
	}
	sig := []byte(base64.StdEncoding.EncodeToString(der) + "\n")
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/bin":
			w.Write(payload)
		case "/bin.sig":
			w.Write(sig)
		default:
			http.NotFound(w, r)
		}
	}))
}

func newUpdater(t *testing.T, pub []byte, current string) (*Updater, string) {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "picket-agent")
	if err := os.WriteFile(bin, []byte("OLD BINARY v"+current), 0o755); err != nil {
		t.Fatal(err)
	}
	return &Updater{CurrentVersion: current, BinaryPath: bin, PublicKeyPEM: pub, HTTPClient: http.DefaultClient}, bin
}

func TestApplyHappyPath(t *testing.T) {
	priv, pub := keypair(t)
	payload := []byte("NEW BINARY v0.2.0 contents")
	srv := artifactServer(t, priv, payload, false)
	defer srv.Close()

	u, bin := newUpdater(t, pub, "0.1.0")
	sum := sha256.Sum256(payload)
	resp := &report.Response{
		DesiredVersion: "0.2.0",
		URL:            srv.URL + "/bin",
		SHA256:         hex.EncodeToString(sum[:]),
		SigURL:         srv.URL + "/bin.sig",
	}

	updated, err := u.Apply(context.Background(), resp)
	if err != nil || !updated {
		t.Fatalf("Apply = %v, %v; want true, nil", updated, err)
	}
	got, _ := os.ReadFile(bin)
	if string(got) != string(payload) {
		t.Errorf("binary not swapped: %q", got)
	}
	if fi, _ := os.Stat(bin); fi.Mode().Perm()&0o100 == 0 {
		t.Errorf("swapped binary not executable: %v", fi.Mode())
	}
	// no leftover temp files
	entries, _ := os.ReadDir(filepath.Dir(bin))
	for _, e := range entries {
		if e.Name() != "picket-agent" {
			t.Errorf("leftover file %s", e.Name())
		}
	}
}

func TestApplyRejectsBadHash(t *testing.T) {
	priv, pub := keypair(t)
	payload := []byte("payload")
	srv := artifactServer(t, priv, payload, false)
	defer srv.Close()
	u, bin := newUpdater(t, pub, "0.1.0")

	_, err := u.Apply(context.Background(), &report.Response{
		DesiredVersion: "0.2.0", URL: srv.URL + "/bin",
		SHA256: "00" + hex.EncodeToString(sha256.New().Sum(nil))[2:], SigURL: srv.URL + "/bin.sig",
	})
	if err == nil {
		t.Fatal("want error on sha256 mismatch")
	}
	if b, _ := os.ReadFile(bin); string(b) != "OLD BINARY v0.1.0" {
		t.Errorf("binary should be untouched, got %q", b)
	}
}

func TestApplyRejectsBadSignature(t *testing.T) {
	priv, pub := keypair(t)
	payload := []byte("payload-xyz")
	srv := artifactServer(t, priv, payload, true) // mangled sig
	defer srv.Close()
	u, bin := newUpdater(t, pub, "0.1.0")
	sum := sha256.Sum256(payload)

	_, err := u.Apply(context.Background(), &report.Response{
		DesiredVersion: "0.2.0", URL: srv.URL + "/bin",
		SHA256: hex.EncodeToString(sum[:]), SigURL: srv.URL + "/bin.sig",
	})
	if err == nil {
		t.Fatal("want error on signature mismatch")
	}
	if b, _ := os.ReadFile(bin); string(b) != "OLD BINARY v0.1.0" {
		t.Errorf("binary should be untouched, got %q", b)
	}
}

func TestApplyWrongKeyRejected(t *testing.T) {
	priv, _ := keypair(t)
	_, otherPub := keypair(t) // signed by priv, verified against a different key
	payload := []byte("p")
	srv := artifactServer(t, priv, payload, false)
	defer srv.Close()
	u, _ := newUpdater(t, otherPub, "0.1.0")
	sum := sha256.Sum256(payload)

	if _, err := u.Apply(context.Background(), &report.Response{
		DesiredVersion: "0.2.0", URL: srv.URL + "/bin",
		SHA256: hex.EncodeToString(sum[:]), SigURL: srv.URL + "/bin.sig",
	}); err == nil {
		t.Fatal("want error when signed by a different key")
	}
}

func TestApplyNoopCases(t *testing.T) {
	_, pub := keypair(t)
	u, _ := newUpdater(t, pub, "0.2.0")

	// same version
	if up, err := u.Apply(context.Background(), &report.Response{DesiredVersion: "0.2.0"}); up || err != nil {
		t.Errorf("same version: %v %v", up, err)
	}
	// no artifact info
	if up, err := u.Apply(context.Background(), &report.Response{DesiredVersion: "0.3.0"}); up || err != nil {
		t.Errorf("no url/sha: %v %v", up, err)
	}
	// empty key => disabled, not an error
	u.PublicKeyPEM = nil
	if up, err := u.Apply(context.Background(), &report.Response{
		DesiredVersion: "0.3.0", URL: "http://x/bin", SHA256: "ab", SigURL: "http://x/bin.sig",
	}); up || err != nil {
		t.Errorf("disabled key should no-op: %v %v", up, err)
	}
}
