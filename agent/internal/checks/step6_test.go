package checks

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pedrohardware/picket/agent/internal/report"
)

func byID(fs []report.Finding) map[string]report.Finding {
	m := map[string]report.Finding{}
	for _, f := range fs {
		m[f.Identifier] = f
	}
	return m
}

func bySubject(fs []report.Finding) map[string]report.Finding {
	m := map[string]report.Finding{}
	for _, f := range fs {
		m[f.Subject] = f
	}
	return m
}

// ---- Apt ----

const aptSim = `Reading package lists...
Calculating upgrade...
Inst libc6 [2.35-0ubuntu3.7] (2.35-0ubuntu3.8 Ubuntu:22.04/jammy-updates, Ubuntu:22.04/jammy-security [amd64])
Inst openssl [3.0.2-0ubuntu1.15] (3.0.2-0ubuntu1.18 Ubuntu:22.04/jammy-security [amd64])
Inst tzdata [2024a-0ubuntu0.22.04] (2024b-0ubuntu0.22.04 Ubuntu:22.04/jammy-updates [all])
Conf libc6 (2.35-0ubuntu3.8 Ubuntu:22.04/jammy-updates [amd64])
`

func TestAptSplitsSecurityVsRegular(t *testing.T) {
	a := Apt{
		APT:       fakeRunner{fn: func(string, []string) ([]byte, error) { return []byte(aptSim), nil }},
		UULog:     filepath.Join(t.TempDir(), "absent.log"),
		UUDpkgLog: filepath.Join(t.TempDir(), "absent-dpkg.log"),
	}
	got := byID(mustScan(t, a.Scan))

	sec, ok := got["security-pending"]
	if !ok || sec.Severity != "high" {
		t.Fatalf("security-pending missing/wrong: %+v", sec)
	}
	if !strings.Contains(sec.Detail, "libc6") || !strings.Contains(sec.Detail, "openssl") || strings.Contains(sec.Detail, "tzdata") {
		t.Errorf("security list wrong: %q", sec.Detail)
	}
	reg, ok := got["regular-pending"]
	if !ok || reg.Severity != "low" {
		t.Fatalf("regular-pending missing/wrong: %+v", reg)
	}
	if !strings.Contains(reg.Detail, "tzdata") || strings.Contains(reg.Detail, "libc6") {
		t.Errorf("regular list wrong: %q", reg.Detail)
	}
}

func TestAptUnattendedFailureLatestRunOnly(t *testing.T) {
	uu := filepath.Join(t.TempDir(), "uu.log")
	a := Apt{APT: fakeRunner{fn: func(string, []string) ([]byte, error) { return []byte("nothing"), nil }}, UULog: uu}

	// old failed run followed by a newer clean run -> no finding
	os.WriteFile(uu, []byte(strings.Join([]string{
		"2026-09-01 06:00:00,1 INFO Starting unattended upgrades script",
		"2026-09-01 06:00:05,2 ERROR Could not fetch archive foo",
		"2026-09-08 06:00:00,1 INFO Starting unattended upgrades script",
		"2026-09-08 06:00:09,9 INFO Packages that were upgraded: libc6",
		"",
	}, "\n")), 0o644)
	if _, bad := byID(mustScan(t, a.Scan))["unattended-upgrade-failed"]; bad {
		t.Fatal("clean latest run must not report a failure")
	}

	// latest run itself has an ERROR -> finding
	os.WriteFile(uu, []byte(strings.Join([]string{
		"2026-09-08 06:00:00,1 INFO Starting unattended upgrades script",
		"2026-09-08 06:00:06,3 ERROR dpkg returned an error code (1)",
		"",
	}, "\n")), 0o644)
	f, ok := byID(mustScan(t, a.Scan))["unattended-upgrade-failed"]
	if !ok || f.Severity != "high" || !strings.Contains(f.Detail, "dpkg returned an error") {
		t.Fatalf("expected failure finding, got %+v", f)
	}
}

func TestAptGetMissingIsError(t *testing.T) {
	a := Apt{APT: fakeRunner{fn: func(string, []string) ([]byte, error) { return nil, errors.New("apt-get not found") }}}
	if _, err := a.Scan(context.Background()); err == nil {
		t.Fatal("want error when apt-get is unavailable")
	}
}

// ---- Containers ----

func TestContainersDetectsStale(t *testing.T) {
	compose := writeCompose(t, "services:\n  api:\n    container_name: api\n    image: myrepo/api:1.4\n  db:\n    container_name: db\n    image: postgres:16\n")
	docker := fakeRunner{fn: func(_ string, args []string) ([]byte, error) {
		switch {
		case args[0] == "version":
			return []byte("27.1.1"), nil
		case args[0] == "inspect" && args[len(args)-1] == "api":
			return []byte("sha256:aaaaaaaaaaaaaaaaaaaaaaaa\n"), nil
		case args[0] == "inspect" && args[len(args)-1] == "db":
			return []byte("sha256:cccccccccccccccccccccccc\n"), nil
		case args[0] == "image" && args[len(args)-1] == "myrepo/api:1.4":
			return []byte("sha256:bbbbbbbbbbbbbbbbbbbbbbbb\n"), nil // tag moved -> stale
		case args[0] == "image" && args[len(args)-1] == "postgres:16":
			return []byte("sha256:cccccccccccccccccccccccc\n"), nil // matches
		}
		return nil, errors.New("no such object")
	}}
	fs := mustScan(t, (Containers{ComposeFiles: []string{compose}, Docker: docker}).Scan)
	if len(fs) != 1 || fs[0].Subject != "api" || fs[0].Kind != "container-stale" {
		t.Fatalf("want 1 stale finding for api, got %+v", fs)
	}
	if !strings.Contains(fs[0].Detail, "aaaaaaaaaaaa") || !strings.Contains(fs[0].Detail, "bbbbbbbbbbbb") {
		t.Errorf("detail missing short ids: %q", fs[0].Detail)
	}
}

func TestContainersDockerDownIsError(t *testing.T) {
	compose := writeCompose(t, "services:\n  api:\n    container_name: api\n    image: x:1\n")
	docker := fakeRunner{fn: func(string, []string) ([]byte, error) { return nil, errors.New("Cannot connect to the Docker daemon") }}
	if _, err := (Containers{ComposeFiles: []string{compose}, Docker: docker}).Scan(context.Background()); err == nil {
		t.Fatal("want error when the daemon is unreachable")
	}
}

// ---- CertExpiry ----

func TestCertExpiryThresholds(t *testing.T) {
	fixed := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)
	exp := map[string]time.Time{
		"ok.example":       fixed.Add(90 * 24 * time.Hour),
		"soon.example":     fixed.Add(5 * 24 * time.Hour),
		"critical.example": fixed.Add(36 * time.Hour),
	}
	c := CertExpiry{
		Domains:       []string{"ok.example", "soon.example", "critical.example", "broken.example"},
		ThresholdDays: 14,
		Now:           func() time.Time { return fixed },
		NotAfter: func(_ context.Context, d string, _ time.Duration) (time.Time, error) {
			if d == "broken.example" {
				return time.Time{}, errors.New("connection refused")
			}
			return exp[d], nil
		},
	}
	fs := mustScan(t, c.Scan)
	sub := bySubject(fs)

	if _, flagged := sub["ok.example"]; flagged {
		t.Error("ok.example (90d) should not be flagged")
	}
	if sub["soon.example"].Severity != "high" {
		t.Errorf("soon (5d) severity = %q, want high", sub["soon.example"].Severity)
	}
	if sub["critical.example"].Severity != "critical" {
		t.Errorf("critical (1.5d) severity = %q, want critical", sub["critical.example"].Severity)
	}
	if sub["soon.example"].Identifier != "expiry" {
		t.Errorf("soon identifier = %q, want expiry", sub["soon.example"].Identifier)
	}
	if sub["broken.example"].Identifier != "handshake" || sub["broken.example"].Severity != "high" {
		t.Errorf("broken should be a high handshake finding, got %+v", sub["broken.example"])
	}
}

// ---- SysHealth ----

func TestSysHealthSample(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	m, err := (SysHealth{DiskPath: "/"}).Sample(ctx)
	if err != nil {
		t.Fatalf("Sample: %v", err)
	}
	if m.DiskPct <= 0 || m.DiskPct > 100 {
		t.Errorf("disk_pct = %v", m.DiskPct)
	}
	if m.MemPct <= 0 || m.MemPct > 100 {
		t.Errorf("mem_pct = %v", m.MemPct)
	}
	if m.CPUPct < 0 || m.CPUPct > 100 {
		t.Errorf("cpu_pct = %v", m.CPUPct)
	}
}

func TestDirSizeGB(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "blob"), make([]byte, 3<<20), 0o644); err != nil {
		t.Fatal(err)
	}
	gb, err := dirSizeGB(dir)
	if err != nil {
		t.Fatal(err)
	}
	if gb < 0.0025 || gb > 0.004 { // ~3 MiB
		t.Errorf("dirSizeGB = %v, want ~0.003", gb)
	}
	if _, err := dirSizeGB(filepath.Join(dir, "nope")); err == nil {
		t.Error("want error for a missing path")
	}
}

func mustScan(t *testing.T, fn func(context.Context) ([]report.Finding, error)) []report.Finding {
	t.Helper()
	fs, err := fn(context.Background())
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	return fs
}
