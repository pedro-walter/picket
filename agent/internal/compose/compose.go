// Package compose extracts watched image references from docker-compose
// files, porting check-images.sh's watched_images().
package compose

import (
	"bufio"
	"os"
	"regexp"
	"sort"
	"strings"
)

// Image is one watched image reference.
type Image struct {
	Repo string // "postgres", "ghcr.io/project-zot/zot", "docker.souspike.com.br/patched-x"
	Tag  string // "16-alpine", "v3.7", "latest"
	Ref  string // "<Repo>:<Tag>" exactly as pinned
}

var (
	imageLine = regexp.MustCompile(`^\s*image:\s*(\S.*)$`)
	// first-party app images - already covered by check-updates.sh / the review skill
	firstParty = regexp.MustCompile(`^docker\.souspike\.com\.br/(soul-spike-backend|soul-spike-web):`)
)

// WatchedImages returns every `image:` reference across files, with
// first-party app images removed and duplicates collapsed, sorted.
func WatchedImages(files []string) ([]Image, error) {
	seen := map[string]bool{}
	var out []Image
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			return nil, err
		}
		sc := bufio.NewScanner(fh)
		for sc.Scan() {
			m := imageLine.FindStringSubmatch(sc.Text())
			if m == nil {
				continue
			}
			ref := clean(m[1])
			if ref == "" || firstParty.MatchString(ref) || seen[ref] {
				continue
			}
			seen[ref] = true
			repo, tag := splitRef(ref)
			out = append(out, Image{Repo: repo, Tag: tag, Ref: ref})
		}
		fh.Close()
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Ref < out[j].Ref })
	return out, nil
}

func clean(s string) string {
	if i := strings.IndexByte(s, '#'); i >= 0 { // drop trailing comment
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		s = s[1 : len(s)-1]
	}
	return strings.TrimSpace(s)
}

// splitRef splits "repo:tag"; a ':' with a '/' after it is a host:port, not a
// tag separator. No tag => "latest".
func splitRef(ref string) (repo, tag string) {
	i := strings.LastIndexByte(ref, ':')
	if i < 0 || strings.Contains(ref[i+1:], "/") {
		return ref, "latest"
	}
	return ref[:i], ref[i+1:]
}

// Service is a compose service that pins both container_name and image -
// the pair the stale-container check needs. Ports check-pending-restart.sh
// service_image_map(): a service without container_name is skipped (nothing
// to `docker inspect` by name).
type Service struct {
	Name  string // container_name
	Image string // image ref as pinned
}

var (
	svcHeader    = regexp.MustCompile(`^  [A-Za-z0-9_.-]+:\s*$`)
	svcContainer = regexp.MustCompile(`^    container_name:\s*(.+)$`)
	svcImage     = regexp.MustCompile(`^    image:\s*(.+)$`)
)

// ServiceImages returns every service across files that sets both
// container_name and image, deduped by container_name (first wins).
func ServiceImages(files []string) ([]Service, error) {
	seen := map[string]bool{}
	var out []Service
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			return nil, err
		}
		var name, image string
		flush := func() {
			if name != "" && image != "" && !seen[name] {
				seen[name] = true
				out = append(out, Service{Name: name, Image: image})
			}
			name, image = "", ""
		}
		sc := bufio.NewScanner(fh)
		for sc.Scan() {
			line := sc.Text()
			switch {
			case svcHeader.MatchString(line):
				flush()
			case svcContainer.MatchString(line):
				name = clean(svcContainer.FindStringSubmatch(line)[1])
			case svcImage.MatchString(line):
				image = clean(svcImage.FindStringSubmatch(line)[1])
			}
		}
		flush()
		fh.Close()
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}
	return out, nil
}
