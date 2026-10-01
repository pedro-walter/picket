package checks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/pedro-walter/picket/agent/internal/compose"
	"github.com/pedro-walter/picket/agent/internal/report"
	"github.com/pedro-walter/picket/agent/internal/toolexec"
	"github.com/pedro-walter/picket/agent/internal/vsort"
)

// ImageTag reports (kind "image-tag") when a newer tag exists within the
// pinned tag's own major line. Ports check-images.sh latest_matching_tag():
// a major bump (postgres 16 -> 18, traefik v3 -> v4) is a deliberate human
// migration and is deliberately NOT flagged.
//
// It also reports a pinned tag that upstream rebuilt in place (same tag, new
// digest - e.g. mongo:8.3 re-cut with a patched base), including "latest":
// the locally pulled image's registry digest is compared with what the
// registry serves now. Stateless - nothing is remembered between scans, and
// the finding clears itself once the host pulls. Needs Docker; when nil (or
// the image was never pulled here) the rebuilt check is skipped.
type ImageTag struct {
	ComposeFiles []string
	Crane        toolexec.Runner
	Docker       toolexec.Runner
}

var tagCore = regexp.MustCompile(`^([0-9]+)(\.[0-9]+){0,3}(.*)$`)

func (c ImageTag) Scan(ctx context.Context) ([]report.Finding, error) {
	imgs, err := compose.WatchedImages(c.ComposeFiles)
	if err != nil {
		return nil, err
	}

	var findings []report.Finding
	var errs error
	for _, img := range imgs {
		if f, err := c.newerTag(ctx, img); err != nil {
			errs = errors.Join(errs, fmt.Errorf("%s: %w", img.Ref, err))
			continue
		} else if f != nil {
			// A newer tag means you're bumping the pin anyway; a "rebuilt"
			// finding for the old tag would only be noise.
			findings = append(findings, *f)
			continue
		}
		if f, err := c.rebuilt(ctx, img); err != nil {
			errs = errors.Join(errs, fmt.Errorf("%s: %w", img.Ref, err))
		} else if f != nil {
			findings = append(findings, *f)
		}
	}

	if errs != nil {
		// Any per-image failure drops the whole kind for this cycle so
		// central does not resolve image-tag findings on partial data.
		return nil, errs
	}
	return findings, nil
}

// newerTag returns a finding when a newer tag exists in the pin's major line.
func (c ImageTag) newerTag(ctx context.Context, img compose.Image) (*report.Finding, error) {
	if img.Tag == "" || img.Tag == "latest" {
		return nil, nil
	}
	{
		latest, err := c.latestMatchingTag(ctx, img.Repo, img.Tag)
		if err != nil {
			return nil, err
		}
		if latest == "" || latest == img.Tag {
			return nil, nil
		}
		// Floating tags (e.g. traefik repoints v3.7 -> newest v3.7.x): a
		// different tag string is only a real update if the per-platform
		// digest differs too.
		curD, e1 := c.digest(ctx, img.Repo+":"+img.Tag)
		newD, e2 := c.digest(ctx, img.Repo+":"+latest)
		if e1 == nil && e2 == nil && curD != "" && curD == newD {
			return nil, nil
		}

		return &report.Finding{
			Kind:       "image-tag",
			Subject:    img.Repo,
			Identifier: img.Tag + "->" + latest,
			Severity:   "low",
			Title:      img.Repo + ": newer tag " + img.Tag + " -> " + latest,
			Detail:     "within the " + majorOf(img.Tag) + ".x line (major bumps are not flagged)",
		}, nil
	}
}

// rebuilt returns a finding when the registry's digest for the pinned tag
// differs from the digest of the copy pulled on this host.
func (c ImageTag) rebuilt(ctx context.Context, img compose.Image) (*report.Finding, error) {
	if c.Docker == nil || img.Tag == "" {
		return nil, nil
	}
	out, err := c.Docker.Run(ctx, "docker", "image", "inspect", "--format", "{{json .RepoDigests}}", img.Ref)
	if err != nil {
		return nil, nil // not pulled on this host: nothing local to compare
	}
	var digests []string
	if json.Unmarshal(bytes.TrimSpace(out), &digests) != nil {
		return nil, nil
	}
	local := localRepoDigest(digests, img.Repo)
	if local == "" {
		return nil, nil // built/loaded locally, no registry digest recorded
	}
	// Index (manifest-list) digest, matching what `docker pull` records.
	remote, err := c.Crane.Run(ctx, "crane", "digest", img.Ref)
	if err != nil {
		return nil, err
	}
	remoteD := strings.TrimSpace(string(remote))
	if remoteD == "" || remoteD == local {
		return nil, nil
	}
	return &report.Finding{
		Kind:       "image-tag",
		Subject:    img.Repo,
		Identifier: img.Tag + "->rebuilt",
		Severity:   "low",
		Title:      img.Ref + ": rebuilt upstream, pull to update",
		Detail: fmt.Sprintf("registry now serves %s for %s, the pulled copy is %s (docker compose pull, then recreate)",
			shortDigest(remoteD), img.Ref, shortDigest(local)),
	}, nil
}

// localRepoDigest picks the digest recorded for repo out of `docker image
// inspect`'s RepoDigests ("mongo@sha256:..."), tolerating the docker.io/ and
// library/ prefixes Docker may or may not include.
func localRepoDigest(repoDigests []string, repo string) string {
	norm := func(r string) string {
		return strings.TrimPrefix(strings.TrimPrefix(r, "docker.io/"), "library/")
	}
	want := norm(repo)
	for _, rd := range repoDigests {
		name, d, ok := strings.Cut(rd, "@")
		if ok && norm(name) == want {
			return d
		}
	}
	return ""
}

func shortDigest(d string) string {
	d = strings.TrimPrefix(d, "sha256:")
	if len(d) > 12 {
		return d[:12]
	}
	return d
}

func (c ImageTag) latestMatchingTag(ctx context.Context, repo, current string) (string, error) {
	out, err := c.Crane.Run(ctx, "crane", "ls", repo)
	if err != nil {
		return "", err
	}
	tags := strings.Fields(string(out))

	vprefix, core := "", current
	if strings.HasPrefix(current, "v") {
		vprefix, core = "v", current[1:]
	}
	m := tagCore.FindStringSubmatch(core)
	if m == nil {
		return "", nil // non-numeric tag: nothing to compare against
	}
	major, suffix := m[1], m[3]
	pat, err := regexp.Compile("^" + regexp.QuoteMeta(vprefix) + major + `(\.[0-9]+){0,3}` + regexp.QuoteMeta(suffix) + "$")
	if err != nil {
		return "", err
	}

	var matches []string
	for _, t := range tags {
		if pat.MatchString(t) {
			matches = append(matches, t)
		}
	}
	if len(matches) == 0 {
		return "", nil
	}
	sort.Slice(matches, func(i, j int) bool { return vsort.Less(matches[i], matches[j]) })
	return matches[len(matches)-1], nil
}

func (c ImageTag) digest(ctx context.Context, ref string) (string, error) {
	out, err := c.Crane.Run(ctx, "crane", "digest", "--platform", "linux/amd64", ref)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func majorOf(tag string) string {
	t := strings.TrimPrefix(tag, "v")
	if m := regexp.MustCompile(`^[0-9]+`).FindString(t); m != "" {
		return m
	}
	return "same"
}
