package checks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRebootNoFile(t *testing.T) {
	t.Setenv("PICKET_REBOOT_REQUIRED_PATH", filepath.Join(t.TempDir(), "absent"))
	fs, err := Reboot(context.Background())
	if err != nil {
		t.Fatalf("Reboot: %v", err)
	}
	if len(fs) != 0 {
		t.Fatalf("expected no findings, got %d", len(fs))
	}
}

func TestRebootWithPkgs(t *testing.T) {
	dir := t.TempDir()
	sentinel := filepath.Join(dir, "reboot-required")
	if err := os.WriteFile(sentinel, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sentinel+".pkgs", []byte("linux-image-6.8\nlibc6\nlibc6\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PICKET_REBOOT_REQUIRED_PATH", sentinel)
	t.Setenv("PICKET_HOSTNAME", "prod-server")

	fs, err := Reboot(context.Background())
	if err != nil {
		t.Fatalf("Reboot: %v", err)
	}
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	f := fs[0]
	if f.Kind != "reboot" || f.Subject != "system" || f.Severity != "medium" {
		t.Errorf("unexpected finding shape: %+v", f)
	}
	if f.Title != "prod-server: reboot required" {
		t.Errorf("title = %q", f.Title)
	}
	if !strings.Contains(f.Detail, "libc6") || !strings.Contains(f.Detail, "linux-image-6.8") {
		t.Errorf("detail missing pkgs: %q", f.Detail)
	}
	if strings.Count(f.Detail, "libc6") != 1 {
		t.Errorf("detail should dedupe pkgs: %q", f.Detail)
	}
}
