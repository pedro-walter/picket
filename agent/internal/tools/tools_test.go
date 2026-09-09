package tools

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func makeTarGz(t *testing.T, member string, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	// a decoy dir entry + the real file, to exercise the filter
	tw.WriteHeader(&tar.Header{Name: "LICENSE", Typeflag: tar.TypeReg, Mode: 0o644, Size: 3})
	tw.Write([]byte("mit"))
	tw.WriteHeader(&tar.Header{Name: "./" + member, Typeflag: tar.TypeReg, Mode: 0o755, Size: int64(len(content))})
	tw.Write(content)
	tw.Close()
	zw.Close()
	return buf.Bytes()
}

func TestEnsureInstallsAndIsIdempotent(t *testing.T) {
	content := []byte("#!/bin/sh\necho fake-crane\n")
	archive := makeTarGz(t, "crane", content)
	sum := sha256.Sum256(archive)

	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.Write(archive)
	}))
	defer srv.Close()

	binDir := t.TempDir()
	spec := Spec{
		Name: "crane", Version: "9.9.9", Member: "crane",
		URLAMD64: srv.URL + "/crane.tgz", SHA256AMD64: hex.EncodeToString(sum[:]),
	}

	if err := Ensure(context.Background(), binDir, "amd64", []Spec{spec}, srv.Client(), nil); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(binDir, "crane"))
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("crane not installed correctly: %v", err)
	}
	if fi, _ := os.Stat(filepath.Join(binDir, "crane")); fi.Mode().Perm()&0o100 == 0 {
		t.Errorf("crane not executable: %v", fi.Mode())
	}
	if v, _ := os.ReadFile(filepath.Join(binDir, "crane.version")); string(v) != "9.9.9\n" {
		t.Errorf("stamp = %q", v)
	}

	// second call: stamp matches -> no download
	if err := Ensure(context.Background(), binDir, "amd64", []Spec{spec}, srv.Client(), nil); err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt64(&hits) != 1 {
		t.Errorf("downloaded %d times, want 1 (idempotent)", hits)
	}

	// bumped version -> re-download
	spec.Version = "9.9.10"
	if err := Ensure(context.Background(), binDir, "amd64", []Spec{spec}, srv.Client(), nil); err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt64(&hits) != 2 {
		t.Errorf("after version bump downloaded %d times, want 2", hits)
	}
}

func TestEnsureRejectsBadChecksum(t *testing.T) {
	archive := makeTarGz(t, "trivy", []byte("x"))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(archive) }))
	defer srv.Close()

	binDir := t.TempDir()
	err := Ensure(context.Background(), binDir, "amd64", []Spec{{
		Name: "trivy", Version: "1", Member: "trivy",
		URLAMD64: srv.URL + "/a.tgz", SHA256AMD64: "deadbeef",
	}}, srv.Client(), nil)
	if err == nil {
		t.Fatal("want error on checksum mismatch")
	}
	if _, statErr := os.Stat(filepath.Join(binDir, "trivy")); statErr == nil {
		t.Error("trivy should not have been installed")
	}
}

func TestExtractMemberMissing(t *testing.T) {
	f := filepath.Join(t.TempDir(), "a.tgz")
	os.WriteFile(f, makeTarGz(t, "somethingelse", []byte("x")), 0o644)
	if err := extractMember(f, "crane", filepath.Join(t.TempDir(), "crane")); err == nil {
		t.Fatal("want error when the member is absent")
	}
}

func TestDefaultSpecsWellFormed(t *testing.T) {
	for _, s := range Default {
		if s.Name == "" || s.Version == "" || s.Member == "" {
			t.Errorf("incomplete spec: %+v", s)
		}
		for _, h := range []string{s.SHA256AMD64, s.SHA256ARM64} {
			if len(h) != 64 {
				t.Errorf("%s: sha256 %q not 64 hex chars", s.Name, h)
			}
			if _, err := hex.DecodeString(h); err != nil {
				t.Errorf("%s: sha256 not hex: %v", s.Name, err)
			}
		}
	}
	_ = io.EOF
}
