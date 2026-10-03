package checks

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// fakeRunner scripts external-tool output for the image checks.
type fakeRunner struct {
	fn func(name string, args []string) ([]byte, error)
}

func (f fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	return f.fn(name, args)
}

func writeCompose(t *testing.T, body string) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "docker-compose.yml")
	if err := os.WriteFile(f, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return f
}

// ---- ImageTag ----

func TestImageTagFindsNewerWithinMajor(t *testing.T) {
	compose := writeCompose(t, "services:\n  db:\n    image: postgres:16.2-alpine\n  tr:\n    image: traefik:v3.7\n")

	crane := fakeRunner{fn: func(name string, args []string) ([]byte, error) {
		switch {
		case args[0] == "ls" && args[1] == "postgres":
			// includes a higher major (18) that must be ignored
			return []byte("13.9-alpine\n16.2-alpine\n16.4-alpine\n16.10-alpine\n18.1-alpine\nlatest\n"), nil
		case args[0] == "ls" && args[1] == "traefik":
			return []byte("v3.6\nv3.7\nv3.7.1\nv4.0\n"), nil
		case args[0] == "digest":
			// distinct digests -> real update
			return []byte("sha256:" + strings.Repeat("a", 8) + args[len(args)-1]), nil
		}
		t.Fatalf("unexpected crane call: %v", args)
		return nil, nil
	}}

	fs, err := (ImageTag{ComposeFiles: []string{compose}, Crane: crane}).Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	got := map[string]string{}
	for _, f := range fs {
		if f.Kind != "image-tag" {
			t.Errorf("kind = %q", f.Kind)
		}
		got[f.Subject] = f.Identifier
	}
	if got["postgres"] != "16.2-alpine->16.10-alpine" {
		t.Errorf("postgres: got %q, want 16.2-alpine->16.10-alpine (not 18.x)", got["postgres"])
	}
	if got["traefik"] != "v3.7->v3.7.1" {
		t.Errorf("traefik: got %q, want v3.7->v3.7.1 (not v4.0)", got["traefik"])
	}
}

func TestImageTagFloatingTagSuppressed(t *testing.T) {
	compose := writeCompose(t, "services:\n  tr:\n    image: traefik:v3.7\n")
	crane := fakeRunner{fn: func(name string, args []string) ([]byte, error) {
		if args[0] == "ls" {
			return []byte("v3.7\nv3.7.1\n"), nil
		}
		// same digest for both tags -> floating repoint, not a real update
		return []byte("sha256:identical"), nil
	}}
	fs, err := (ImageTag{ComposeFiles: []string{compose}, Crane: crane}).Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(fs) != 0 {
		t.Fatalf("expected no finding for a floating-tag repoint, got %v", fs)
	}
}

func TestImageTagLatestAndErrorsHandled(t *testing.T) {
	compose := writeCompose(t, "services:\n  a:\n    image: docker.souspike.com.br/soul-spike-web:latest\n  b:\n    image: nginx:latest\n  c:\n    image: redis:7\n")
	crane := fakeRunner{fn: func(name string, args []string) ([]byte, error) {
		return nil, os.ErrPermission // every crane call fails
	}}
	_, err := (ImageTag{ComposeFiles: []string{compose}, Crane: crane}).Scan(context.Background())
	if err == nil {
		t.Fatal("expected an error when a watched image's crane call fails (so central won't resolve)")
	}
}

// ---- ImageCVE ----

const trivyJSON = `{
  "SchemaVersion": 2,
  "ArtifactName": "postgres:16-alpine",
  "Results": [
    {
      "Target": "postgres:16-alpine (alpine 3.22.1)",
      "Class": "os-pkgs",
      "Type": "alpine",
      "Vulnerabilities": [
        {"VulnerabilityID":"CVE-2026-14456","PkgName":"libssl3","InstalledVersion":"3.5.1-r0","FixedVersion":"3.5.8-r0","Severity":"HIGH","Title":"openssl: QUIC listener DoS","PrimaryURL":"https://avd.aquasec.com/nvd/cve-2026-14456"},
        {"VulnerabilityID":"CVE-2026-14456","PkgName":"libcrypto3","InstalledVersion":"3.5.1-r0","FixedVersion":"3.5.8-r0","Severity":"HIGH","Title":"openssl: QUIC listener DoS","PrimaryURL":"https://avd.aquasec.com/nvd/cve-2026-14456"}
      ]
    },
    {
      "Target": "usr/local/bin/gosu",
      "Class": "lang-pkgs",
      "Type": "gobinary",
      "Vulnerabilities": [
        {"VulnerabilityID":"CVE-2025-22870","PkgName":"stdlib","InstalledVersion":"v1.23.1","FixedVersion":"1.23.6","Severity":"CRITICAL","Title":"golang: net/http proxy bypass"}
      ]
    },
    { "Target": "clean", "Vulnerabilities": null }
  ]
}`

func TestImageCVEParsesFindings(t *testing.T) {
	compose := writeCompose(t, "services:\n  db:\n    image: postgres:16-alpine\n")
	trivy := fakeRunner{fn: func(name string, args []string) ([]byte, error) {
		if name != "trivy" || args[0] != "image" {
			t.Fatalf("unexpected trivy call: %s %v", name, args)
		}
		if args[len(args)-1] != "postgres:16-alpine" {
			t.Errorf("scanned %q, want the pinned ref", args[len(args)-1])
		}
		return []byte(trivyJSON), nil
	}}

	fs, err := (&ImageCVE{ComposeFiles: []string{compose}, Trivy: trivy}).Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(fs) != 3 {
		t.Fatalf("got %d findings, want 3: %+v", len(fs), fs)
	}
	ids := make([]string, len(fs))
	for i, f := range fs {
		ids[i] = f.Identifier
		if f.Kind != "image-cve" || f.Subject != "postgres" {
			t.Errorf("bad shape: %+v", f)
		}
	}
	sort.Strings(ids)
	want := []string{"CVE-2025-22870|stdlib", "CVE-2026-14456|libcrypto3", "CVE-2026-14456|libssl3"}
	for i := range want {
		if ids[i] != want[i] {
			t.Errorf("ids[%d] = %q, want %q", i, ids[i], want[i])
		}
	}
	for _, f := range fs {
		if f.Identifier == "CVE-2025-22870|stdlib" && f.Severity != "critical" {
			t.Errorf("severity lowercased? got %q", f.Severity)
		}
		if f.CVE == "" {
			t.Errorf("CVE field not populated: %+v", f)
		}
	}
}

func TestImageCVETrivyFailureIsError(t *testing.T) {
	compose := writeCompose(t, "services:\n  db:\n    image: postgres:16-alpine\n")
	trivy := fakeRunner{fn: func(string, []string) ([]byte, error) { return nil, os.ErrDeadlineExceeded }}
	if _, err := (&ImageCVE{ComposeFiles: []string{compose}, Trivy: trivy}).Scan(context.Background()); err == nil {
		t.Fatal("expected error when trivy fails")
	}
}

func TestImageCVENoComposeImages(t *testing.T) {
	compose := writeCompose(t, "services:\n  a:\n    image: docker.souspike.com.br/soul-spike-web:latest\n")
	trivy := fakeRunner{fn: func(string, []string) ([]byte, error) {
		t.Fatal("trivy should not be called - only first-party images present")
		return nil, nil
	}}
	fs, err := (&ImageCVE{ComposeFiles: []string{compose}, Trivy: trivy}).Scan(context.Background())
	if err != nil || len(fs) != 0 {
		t.Fatalf("want no findings/no error, got %v / %v", fs, err)
	}
}

// ---- ImageTag: in-place rebuild of the pinned tag ----

func rebuildRunners(local, remote string, localErr error) (docker, crane fakeRunner) {
	docker = fakeRunner{fn: func(name string, args []string) ([]byte, error) {
		if localErr != nil {
			return nil, localErr
		}
		return []byte(`["mongo@` + local + `","other/x@sha256:zzz"]`), nil
	}}
	crane = fakeRunner{fn: func(name string, args []string) ([]byte, error) {
		if args[0] == "ls" {
			return []byte("8.3\n8.3.11\n"), nil
		}
		if len(args) > 1 && args[1] == "--platform" {
			return []byte("sha256:same"), nil // 8.3 vs 8.3.11 floating -> no newer-tag
		}
		return []byte(remote), nil
	}}
	return
}

func TestImageTagRebuiltInPlace(t *testing.T) {
	compose := writeCompose(t, "services:\n  db:\n    image: mongo:8.3\n  w:\n    image: nginx:latest\n")
	docker, crane := rebuildRunners("sha256:old", "sha256:new", nil)
	// nginx:latest has no local copy digest for repo nginx -> skipped; only mongo reports.
	fs, err := (ImageTag{ComposeFiles: []string{compose}, Crane: crane, Docker: docker}).Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(fs) != 1 || fs[0].Subject != "mongo" || fs[0].Identifier != "8.3->rebuilt" {
		t.Fatalf("want one mongo 8.3->rebuilt finding, got %+v", fs)
	}
}

func TestImageTagRebuiltCoversLatest(t *testing.T) {
	compose := writeCompose(t, "services:\n  j:\n    image: lscr.io/linuxserver/jellyfin:latest\n")
	docker := fakeRunner{fn: func(string, []string) ([]byte, error) {
		return []byte(`["lscr.io/linuxserver/jellyfin@sha256:old"]`), nil
	}}
	crane := fakeRunner{fn: func(string, []string) ([]byte, error) { return []byte("sha256:new"), nil }}
	fs, err := (ImageTag{ComposeFiles: []string{compose}, Crane: crane, Docker: docker}).Scan(context.Background())
	if err != nil || len(fs) != 1 || fs[0].Identifier != "latest->rebuilt" {
		t.Fatalf("got %+v, %v", fs, err)
	}
}

func TestImageTagRebuiltQuietCases(t *testing.T) {
	compose := writeCompose(t, "services:\n  db:\n    image: mongo:8.3\n")
	// up to date
	d, c := rebuildRunners("sha256:same", "sha256:same", nil)
	if fs, err := (ImageTag{ComposeFiles: []string{compose}, Crane: c, Docker: d}).Scan(context.Background()); err != nil || len(fs) != 0 {
		t.Errorf("up to date: got %+v, %v", fs, err)
	}
	// not pulled on this host
	d, c = rebuildRunners("", "sha256:new", os.ErrNotExist)
	if fs, err := (ImageTag{ComposeFiles: []string{compose}, Crane: c, Docker: d}).Scan(context.Background()); err != nil || len(fs) != 0 {
		t.Errorf("not pulled: got %+v, %v", fs, err)
	}
	// no Docker runner configured
	_, c = rebuildRunners("", "sha256:new", nil)
	if fs, err := (ImageTag{ComposeFiles: []string{compose}, Crane: c}).Scan(context.Background()); err != nil || len(fs) != 0 {
		t.Errorf("no docker: got %+v, %v", fs, err)
	}
}

func TestImageCVERecordsProvenance(t *testing.T) {
	compose := writeCompose(t, "services:\n  hc:\n    image: reg.example/hc:4.4-2\n  db:\n    image: postgres:16\n")
	trivy := fakeRunner{fn: func(_ string, args []string) ([]byte, error) {
		meta := `"Metadata":{"ImageID":"sha256:local1","RepoDigests":["reg.example/hc@sha256:feed"]}`
		if args[len(args)-1] == "postgres:16" {
			meta = `"Metadata":{"ImageID":"sha256:local2"}` // no registry digest: use the image ID
		}
		return []byte(`{` + meta + `,"Results":[{"Target":"t","Vulnerabilities":[
		  {"VulnerabilityID":"CVE-1","PkgName":"PyJWT","InstalledVersion":"2.1","FixedVersion":"2.14.0","Severity":"HIGH"},
		  {"VulnerabilityID":"CVE-2","PkgName":"libx","InstalledVersion":"1","Severity":"HIGH"}]}]}`), nil
	}}
	c := &ImageCVE{ComposeFiles: []string{compose}, Trivy: trivy}
	if got := c.Scans(); len(got) != 0 {
		t.Fatalf("scans before first scan: %+v", got)
	}
	fs, err := c.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]string{}
	for _, f := range fs {
		by[f.Subject+"/"+f.Identifier] = f.ImageRef + " " + f.ImageDigest + " " + f.FixedVersion
	}
	if by["reg.example/hc/CVE-1|PyJWT"] != "reg.example/hc:4.4-2 sha256:feed 2.14.0" {
		t.Errorf("hc fixable: %q", by["reg.example/hc/CVE-1|PyJWT"])
	}
	if by["reg.example/hc/CVE-2|libx"] != "reg.example/hc:4.4-2 sha256:feed " {
		t.Errorf("hc unfixed: %q", by["reg.example/hc/CVE-2|libx"])
	}
	if by["postgres/CVE-2|libx"] != "postgres:16 sha256:local2 " {
		t.Errorf("postgres falls back to image id: %q", by["postgres/CVE-2|libx"])
	}
	scans := c.Scans()
	if len(scans) != 2 || scans[0].Ref != "postgres:16" || scans[1].Digest != "sha256:feed" {
		t.Errorf("scans = %+v", scans)
	}
}

// A failed scan must not replace the recorded scans with a partial list.
func TestImageCVEFailureKeepsPreviousScans(t *testing.T) {
	compose := writeCompose(t, "services:\n  db:\n    image: postgres:16\n")
	fail := false
	trivy := fakeRunner{fn: func(string, []string) ([]byte, error) {
		if fail {
			return nil, os.ErrDeadlineExceeded
		}
		return []byte(`{"Metadata":{"ImageID":"sha256:a"},"Results":[]}`), nil
	}}
	c := &ImageCVE{ComposeFiles: []string{compose}, Trivy: trivy}
	if _, err := c.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	fail = true
	if _, err := c.Scan(context.Background()); err == nil {
		t.Fatal("want error")
	}
	if got := c.Scans(); len(got) != 1 || got[0].Digest != "sha256:a" {
		t.Errorf("scans after failure = %+v", got)
	}
}

// A vendored python copy (no PkgPath) and the top-level one are distinct
// findings; OS packages and a python-pkg with a path keep the plain identifier.
func TestImageCVESplitsVendoredPython(t *testing.T) {
	compose := writeCompose(t, "services:\n  hc:\n    image: reg.example/hc:4.4-2\n")
	trivy := fakeRunner{fn: func(string, []string) ([]byte, error) {
		return []byte(`{"Metadata":{"ImageID":"sha256:a"},"Results":[
		 {"Target":"os","Type":"debian","Vulnerabilities":[
		  {"VulnerabilityID":"CVE-1","PkgName":"libssl3","Severity":"HIGH"}]},
		 {"Target":"Python","Type":"python-pkg","Vulnerabilities":[
		  {"VulnerabilityID":"CVE-2","PkgName":"urllib3","PkgPath":"usr/local/lib/python3.14/site-packages/urllib3-2.7.0.dist-info/METADATA","FixedVersion":"2.8.0","Severity":"HIGH"},
		  {"VulnerabilityID":"CVE-2","PkgName":"urllib3","FixedVersion":"2.8.0","Severity":"HIGH"},
		  {"VulnerabilityID":"CVE-3","PkgName":"setuptools","Severity":"HIGH"}]}]}`), nil
	}}
	fs, err := (&ImageCVE{ComposeFiles: []string{compose}, Trivy: trivy}).Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, f := range fs {
		ids = append(ids, f.Identifier)
	}
	sort.Strings(ids)
	want := []string{"CVE-1|libssl3", "CVE-2|urllib3", "CVE-2|urllib3@vendored", "CVE-3|setuptools@vendored"}
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Errorf("identifiers = %v, want %v", ids, want)
	}
}
