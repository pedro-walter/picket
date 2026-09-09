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
