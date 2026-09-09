// Package tools keeps the external single-binary tools the agent drives
// (crane, trivy) present and pinned in the managed bin dir. Downloads a
// release tar.gz, verifies its SHA-256, extracts the wanted member, and
// atomically installs it. Idempotent: a matching ".version" stamp skips it.
package tools

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/pedrohardware/picket/agent/internal/httpdl"
)

// Spec pins one tool. Bump version + hashes here and ship it as an agent
// release (same channel as the agent binary).
type Spec struct {
	Name        string // installed filename in the bin dir
	Version     string
	Member      string // path of the wanted file inside the tar.gz (basename match)
	URLAMD64    string
	SHA256AMD64 string
	URLARM64    string
	SHA256ARM64 string
}

// Default is the compiled-in pin set. Checksums are the vendors' published
// release checksums (crane checksums.txt, trivy *_checksums.txt).
var Default = []Spec{
	{
		Name:        "crane",
		Version:     "0.22.1",
		Member:      "crane",
		URLAMD64:    "https://github.com/google/go-containerregistry/releases/download/v0.22.1/go-containerregistry_Linux_x86_64.tar.gz",
		SHA256AMD64: "0ab7a1d6932a213aed964ce97666c3077fe691c8606413674a8b3e0b9ec4cda0",
		URLARM64:    "https://github.com/google/go-containerregistry/releases/download/v0.22.1/go-containerregistry_Linux_arm64.tar.gz",
		SHA256ARM64: "898c0cff975f898a33e8c4580bdafb0e7c02c7faa33374e946762f97c4ab7110",
	},
	{
		Name:        "trivy",
		Version:     "0.74.0",
		Member:      "trivy",
		URLAMD64:    "https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_Linux-64bit.tar.gz",
		SHA256AMD64: "2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a",
		URLARM64:    "https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_Linux-ARM64.tar.gz",
		SHA256ARM64: "b94ce1976bbf3c15b514b605ee88be7c6d94a29be2302847ff01cb794d47aad5",
	},
}

// Ensure installs/refreshes every spec into binDir for goarch. Errors are
// joined; a partial failure still installs the tools that succeeded.
func Ensure(ctx context.Context, binDir, goarch string, specs []Spec, hc *http.Client, log *slog.Logger) error {
	if hc == nil {
		hc = http.DefaultClient
	}
	if log == nil {
		log = slog.Default()
	}
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return err
	}
	var errs error
	for _, s := range specs {
		if err := ensureOne(ctx, binDir, goarch, s, hc, log); err != nil {
			errs = errors.Join(errs, fmt.Errorf("%s: %w", s.Name, err))
		}
	}
	return errs
}

func ensureOne(ctx context.Context, binDir, goarch string, s Spec, hc *http.Client, log *slog.Logger) error {
	target := filepath.Join(binDir, s.Name)
	stamp := target + ".version"

	if b, err := os.ReadFile(stamp); err == nil && strings.TrimSpace(string(b)) == s.Version {
		if _, err := os.Stat(target); err == nil {
			return nil // already at the pinned version
		}
	}

	url, want := s.URLAMD64, s.SHA256AMD64
	if goarch == "arm64" {
		url, want = s.URLARM64, s.SHA256ARM64
	}
	if url == "" {
		return fmt.Errorf("no artifact for %s/%s", goarch, s.Name)
	}

	gz, err := os.CreateTemp(binDir, ".dl-*")
	if err != nil {
		return err
	}
	gzName := gz.Name()
	defer os.Remove(gzName)

	sum, err := httpdl.ToWriter(ctx, hc, url, gz)
	gz.Close()
	if err != nil {
		return err
	}
	if hex.EncodeToString(sum) != strings.ToLower(want) {
		return fmt.Errorf("sha256 mismatch: got %s want %s", hex.EncodeToString(sum), want)
	}

	if err := extractMember(gzName, s.Member, target); err != nil {
		return err
	}
	if err := os.WriteFile(stamp, []byte(s.Version+"\n"), 0o644); err != nil {
		return err
	}
	log.Info("installed tool", "name", s.Name, "version", s.Version, "arch", goarch)
	return nil
}

func extractMember(gzPath, member, dest string) error {
	f, err := os.Open(gzPath)
	if err != nil {
		return err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer zr.Close()

	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("%q not found in archive", member)
		}
		if err != nil {
			return err
		}
		if h.Typeflag != tar.TypeReg || filepath.Base(h.Name) != member {
			continue
		}
		tmp, err := os.CreateTemp(filepath.Dir(dest), ".x-*")
		if err != nil {
			return err
		}
		if _, err := io.Copy(tmp, io.LimitReader(tr, 500<<20)); err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
			return err
		}
		tmp.Close()
		if err := os.Chmod(tmp.Name(), 0o755); err != nil {
			os.Remove(tmp.Name())
			return err
		}
		return os.Rename(tmp.Name(), dest)
	}
}
