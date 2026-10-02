package compose

import (
	"os"
	"path/filepath"
	"testing"
)

const sample = `
services:
  socket-proxy:
    image: tecnativa/docker-socket-proxy:v0.5.0
  traefik:
    image: "traefik:v3.7"   # quoted + trailing comment
  db:
    image: postgres:16-alpine
  zot:
    image: ghcr.io/project-zot/zot:v2.1.20
  backend:
    image: docker.souspike.com.br/soul-spike-backend:latest
  web:
    image: docker.souspike.com.br/soul-spike-web:latest
  web2:
    image: docker.souspike.com.br/soul-spike-web:latest
  # not an image line: image_pull_policy or a comment
  overlay:
    image: docker.souspike.com.br/patched-nginx:1.27
`

func TestWatchedImages(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "docker-compose.yml")
	if err := os.WriteFile(f, []byte(sample), 0o644); err != nil {
		t.Fatal(err)
	}

	imgs, err := WatchedImages([]string{f})
	if err != nil {
		t.Fatalf("WatchedImages: %v", err)
	}

	got := map[string]Image{}
	for _, im := range imgs {
		got[im.Ref] = im
	}

	want := []struct{ ref, repo, tag string }{
		{"ghcr.io/project-zot/zot:v2.1.20", "ghcr.io/project-zot/zot", "v2.1.20"},
		{"docker.souspike.com.br/patched-nginx:1.27", "docker.souspike.com.br/patched-nginx", "1.27"},
		{"postgres:16-alpine", "postgres", "16-alpine"},
		{"tecnativa/docker-socket-proxy:v0.5.0", "tecnativa/docker-socket-proxy", "v0.5.0"},
		{"traefik:v3.7", "traefik", "v3.7"},
	}
	if len(imgs) != len(want) {
		t.Fatalf("got %d images %v, want %d", len(imgs), imgs, len(want))
	}
	for _, w := range want {
		im, ok := got[w.ref]
		if !ok {
			t.Errorf("missing %s", w.ref)
			continue
		}
		if im.Repo != w.repo || im.Tag != w.tag {
			t.Errorf("%s -> repo=%q tag=%q, want repo=%q tag=%q", w.ref, im.Repo, im.Tag, w.repo, w.tag)
		}
	}

	for _, im := range imgs {
		if im.Repo == "docker.souspike.com.br/soul-spike-backend" || im.Repo == "docker.souspike.com.br/soul-spike-web" {
			t.Errorf("first-party image %s should be excluded", im.Ref)
		}
	}
}

func TestWatchedImagesRealRepoFiles(t *testing.T) {
	// the three production compose files, if the souspike repo is checked out beside this one
	files := []string{
		"../../../../souspike/production-setup/docker-compose.yml",
		"../../../../souspike/registry/docker-compose.yml",
		"../../../../souspike/monitoring/docker-compose.yml",
	}
	present := files[:0]
	for _, f := range files {
		if _, err := os.Stat(f); err == nil {
			present = append(present, f)
		}
	}
	if len(present) == 0 {
		t.Skip("souspike compose files not present")
	}
	imgs, err := WatchedImages(present)
	if err != nil {
		t.Fatalf("WatchedImages: %v", err)
	}
	for _, im := range imgs {
		if im.Tag == "" {
			t.Errorf("%s parsed with empty tag", im.Ref)
		}
		if im.Repo == "docker.souspike.com.br/soul-spike-backend" || im.Repo == "docker.souspike.com.br/soul-spike-web" {
			t.Errorf("first-party %s not excluded", im.Ref)
		}
	}
	t.Logf("watched: %v", imgs)
}

func TestServiceImages(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "dc.yml")
	os.WriteFile(f, []byte(`services:
  api:
    container_name: api
    image: myrepo/api:1.4
  worker:
    image: myrepo/worker:1.4
  db:
    container_name: db
    image: "postgres:16-alpine"
`), 0o644)
	svcs, err := ServiceImages([]string{f})
	if err != nil {
		t.Fatal(err)
	}
	if len(svcs) != 2 {
		t.Fatalf("want 2 (worker has no container_name), got %+v", svcs)
	}
	m := map[string]string{}
	for _, s := range svcs {
		m[s.Name] = s.Image
	}
	if m["api"] != "myrepo/api:1.4" || m["db"] != "postgres:16-alpine" {
		t.Errorf("wrong: %+v", m)
	}
}

func TestInputsDigest(t *testing.T) {
	write := func(body string) string {
		f := filepath.Join(t.TempDir(), "c.yml")
		if err := os.WriteFile(f, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return f
	}
	digest := func(body string) string {
		d, err := InputsDigest([]string{write(body)})
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	base := digest("services:\n  a:\n    image: hc:4.4-1\n  b:\n    image: postgres:16\n")
	// reordered, commented, quoted, with a duplicate and a first-party image: same inputs
	same := digest("# note\nservices:\n  b:\n    image: \"postgres:16\"  # db\n  a:\n    image: hc:4.4-1\n  c:\n    image: hc:4.4-1\n  w:\n    image: docker.souspike.com.br/soul-spike-web:latest\n")
	if base != same {
		t.Errorf("digest should ignore order, comments, quotes, dupes, first-party")
	}
	if base == digest("services:\n  a:\n    image: hc:4.4-2\n  b:\n    image: postgres:16\n") {
		t.Errorf("tag bump must change the digest")
	}
	if base == digest("services:\n  a:\n    image: reg.example/hc:4.4-1\n  b:\n    image: postgres:16\n") {
		t.Errorf("repo rename must change the digest")
	}
	if _, err := InputsDigest([]string{"/nonexistent/compose.yml"}); err == nil {
		t.Errorf("missing file should error")
	}
}
