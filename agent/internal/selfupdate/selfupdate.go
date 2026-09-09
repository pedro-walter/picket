// Package selfupdate downloads a newer picket-agent, verifies its SHA-256 and
// signature against the baked-in public key, atomically swaps the running
// binary, and lets the supervisor (systemd Restart=always) bring it back up.
package selfupdate

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pedro-walter/picket/agent/internal/httpdl"
	"github.com/pedro-walter/picket/agent/internal/report"
)

type Updater struct {
	CurrentVersion string
	// BinaryPath is the running binary and the swap target; the download
	// lands in the same directory so the rename is atomic.
	BinaryPath   string
	PublicKeyPEM []byte // PKIX/SPKI PEM (cosign.pub). Empty/invalid => updates disabled.
	HTTPClient   *http.Client
	Log          *slog.Logger
}

func (u *Updater) client() *http.Client {
	if u.HTTPClient != nil {
		return u.HTTPClient
	}
	return &http.Client{Timeout: 5 * time.Minute}
}

func (u *Updater) log() *slog.Logger {
	if u.Log != nil {
		return u.Log
	}
	return slog.Default()
}

// Apply performs one update if resp names a different, fully-verifiable
// version. It returns updated=true only after the binary has been swapped;
// the caller is then responsible for exiting so the supervisor restarts.
func (u *Updater) Apply(ctx context.Context, resp *report.Response) (updated bool, err error) {
	if resp == nil || resp.DesiredVersion == "" || resp.DesiredVersion == u.CurrentVersion {
		return false, nil
	}
	if resp.URL == "" || resp.SHA256 == "" || resp.SigURL == "" {
		u.log().Info("update offered but central has no verified artifact yet", "want", resp.DesiredVersion)
		return false, nil
	}
	pub, err := parsePub(u.PublicKeyPEM)
	if err != nil {
		u.log().Warn("self-update disabled: no valid signing key baked in", "err", err)
		return false, nil
	}

	dir := filepath.Dir(u.BinaryPath)
	tmp, err := os.CreateTemp(dir, ".picket-agent.new-*")
	if err != nil {
		return false, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // harmless after a successful rename

	sum, err := httpdl.ToWriter(ctx, u.client(), resp.URL, tmp)
	tmp.Close()
	if err != nil {
		return false, fmt.Errorf("downloading %s: %w", resp.URL, err)
	}
	if !hexEqual(sum, resp.SHA256) {
		return false, fmt.Errorf("sha256 mismatch: got %s want %s", hex.EncodeToString(sum), resp.SHA256)
	}

	sig, err := httpdl.Bytes(ctx, u.client(), resp.SigURL)
	if err != nil {
		return false, fmt.Errorf("fetching signature: %w", err)
	}
	if err := verify(pub, sum, sig); err != nil {
		return false, fmt.Errorf("signature verification failed: %w", err)
	}

	if err := os.Chmod(tmpName, 0o755); err != nil {
		return false, err
	}
	if err := os.Rename(tmpName, u.BinaryPath); err != nil {
		return false, fmt.Errorf("atomic swap: %w", err)
	}
	u.log().Warn("self-update applied", "from", u.CurrentVersion, "to", resp.DesiredVersion, "path", u.BinaryPath)
	return true, nil
}

func parsePub(pemBytes []byte) (*ecdsa.PublicKey, error) {
	if len(pemBytes) == 0 {
		return nil, errors.New("signing public key not configured")
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("public key is not valid PEM")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ec, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is %T, want *ecdsa.PublicKey", key)
	}
	return ec, nil
}

// verify checks an ECDSA-P256 signature over the SHA-256 digest, matching
// `cosign sign-blob --key` (base64-encoded ASN.1 DER, possibly with a
// trailing newline; raw DER also accepted).
func verify(pub *ecdsa.PublicKey, digest, sig []byte) error {
	der := sig
	if d, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig))); err == nil {
		der = d
	}
	if !ecdsa.VerifyASN1(pub, digest, der) {
		return errors.New("signature does not match the baked-in key")
	}
	return nil
}

func hexEqual(sum []byte, want string) bool {
	return hex.EncodeToString(sum) == strings.ToLower(strings.TrimSpace(want))
}
