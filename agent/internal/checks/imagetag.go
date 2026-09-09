package checks

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/pedrohardware/picket/agent/internal/compose"
	"github.com/pedrohardware/picket/agent/internal/report"
	"github.com/pedrohardware/picket/agent/internal/toolexec"
	"github.com/pedrohardware/picket/agent/internal/vsort"
)

// ImageTag reports (kind "image-tag") when a newer tag exists within the
// pinned tag's own major line. Ports check-images.sh latest_matching_tag():
// a major bump (postgres 16 -> 18, traefik v3 -> v4) is a deliberate human
// migration and is deliberately NOT flagged.
type ImageTag struct {
	ComposeFiles []string
	Crane        toolexec.Runner
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
		if img.Tag == "" || img.Tag == "latest" {
			continue
		}
		latest, err := c.latestMatchingTag(ctx, img.Repo, img.Tag)
		if err != nil {
			errs = errors.Join(errs, fmt.Errorf("%s: %w", img.Ref, err))
			continue
		}
		if latest == "" || latest == img.Tag {
			continue
		}
		// Floating tags (e.g. traefik repoints v3.7 -> newest v3.7.x): a
		// different tag string is only a real update if the per-platform
		// digest differs too.
		curD, e1 := c.digest(ctx, img.Repo+":"+img.Tag)
		newD, e2 := c.digest(ctx, img.Repo+":"+latest)
		if e1 == nil && e2 == nil && curD != "" && curD == newD {
			continue
		}

		findings = append(findings, report.Finding{
			Kind:       "image-tag",
			Subject:    img.Repo,
			Identifier: img.Tag + "->" + latest,
			Severity:   "low",
			Title:      img.Repo + ": newer tag " + img.Tag + " -> " + latest,
			Detail:     "within the " + majorOf(img.Tag) + ".x line (major bumps are not flagged)",
		})
	}

	if errs != nil {
		// Any per-image failure drops the whole kind for this cycle so
		// central does not resolve image-tag findings on partial data.
		return nil, errs
	}
	return findings, nil
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
