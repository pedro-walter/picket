package checks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/pedro-walter/picket/agent/internal/compose"
	"github.com/pedro-walter/picket/agent/internal/report"
	"github.com/pedro-walter/picket/agent/internal/toolexec"
)

// ImageCVE reports (kind "image-cve") HIGH/CRITICAL vulnerabilities in the
// pinned tag of each watched image, via `trivy image`. Ports check-images.sh
// - but sends RAW findings: ignore-list filtering lives in central so a rule
// change needs no agent redeploy.
type ImageCVE struct {
	ComposeFiles []string
	Trivy        toolexec.Runner

	mu    sync.Mutex
	scans []report.Scan
}

// Scans returns the refs and digests covered by the last fully successful Scan.
func (c *ImageCVE) Scans() []report.Scan {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]report.Scan(nil), c.scans...)
}

type trivyReport struct {
	Metadata struct {
		ImageID     string   `json:"ImageID"`
		RepoDigests []string `json:"RepoDigests"`
	} `json:"Metadata"`
	Results []struct {
		Target          string `json:"Target"`
		Type            string `json:"Type"`
		Vulnerabilities []struct {
			VulnerabilityID  string `json:"VulnerabilityID"`
			PkgName          string `json:"PkgName"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion     string `json:"FixedVersion"`
			Severity         string `json:"Severity"`
			Title            string `json:"Title"`
			PrimaryURL       string `json:"PrimaryURL"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

func (c *ImageCVE) Scan(ctx context.Context) ([]report.Finding, error) {
	imgs, err := compose.WatchedImages(c.ComposeFiles)
	if err != nil {
		return nil, err
	}

	var findings []report.Finding
	var scans []report.Scan
	var errs error
	for _, img := range imgs {
		fs, scan, err := c.scanOne(ctx, img)
		if err != nil {
			errs = errors.Join(errs, fmt.Errorf("%s: %w", img.Ref, err))
			continue
		}
		findings = append(findings, fs...)
		scans = append(scans, scan)
	}
	if errs != nil {
		return nil, errs // drop the whole kind so central does not resolve on partial data
	}
	c.mu.Lock()
	c.scans = scans
	c.mu.Unlock()
	return findings, nil
}

// digestOf prefers the registry digest of the scanned image; a locally built
// image has none, so fall back to its image ID.
func digestOf(repoDigests []string, imageID string) string {
	for _, d := range repoDigests {
		if i := strings.LastIndexByte(d, '@'); i >= 0 {
			return d[i+1:]
		}
	}
	return imageID
}

func (c *ImageCVE) scanOne(ctx context.Context, img compose.Image) ([]report.Finding, report.Scan, error) {
	out, err := c.Trivy.Run(ctx, "trivy", "image",
		"--scanners", "vuln", "--severity", "HIGH,CRITICAL",
		"--format", "json", "--quiet", img.Ref)
	if err != nil {
		return nil, report.Scan{}, err
	}

	var tr trivyReport
	if err := json.Unmarshal(out, &tr); err != nil {
		return nil, report.Scan{}, fmt.Errorf("parsing trivy json: %w", err)
	}
	scan := report.Scan{Ref: img.Ref, Digest: digestOf(tr.Metadata.RepoDigests, tr.Metadata.ImageID)}

	seen := map[string]bool{}
	var findings []report.Finding
	for _, r := range tr.Results {
		for _, v := range r.Vulnerabilities {
			id := v.VulnerabilityID + "|" + v.PkgName
			if v.VulnerabilityID == "" || seen[id] {
				continue
			}
			seen[id] = true

			detail := fmt.Sprintf("%s: %s %s", r.Target, v.PkgName, v.InstalledVersion)
			if v.FixedVersion != "" {
				detail += " -> fixed in " + v.FixedVersion
			}
			if v.Title != "" {
				detail += "; " + v.Title
			}
			if v.PrimaryURL != "" {
				detail += " (" + v.PrimaryURL + ")"
			}

			findings = append(findings, report.Finding{
				Kind:       "image-cve",
				Subject:    img.Repo, // bare repo: fingerprint survives tag bumps
				Identifier: id,
				Severity:   strings.ToLower(v.Severity),
				Title:      img.Repo + ": " + v.VulnerabilityID + " in " + v.PkgName,
				Detail:     detail,
				CVE:        v.VulnerabilityID,

				ImageRef:     scan.Ref,
				ImageDigest:  scan.Digest,
				FixedVersion: v.FixedVersion,
			})
		}
	}
	return findings, scan, nil
}
