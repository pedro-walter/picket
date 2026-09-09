package checks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

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
}

type trivyReport struct {
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

func (c ImageCVE) Scan(ctx context.Context) ([]report.Finding, error) {
	imgs, err := compose.WatchedImages(c.ComposeFiles)
	if err != nil {
		return nil, err
	}

	var findings []report.Finding
	var errs error
	for _, img := range imgs {
		fs, err := c.scanOne(ctx, img)
		if err != nil {
			errs = errors.Join(errs, fmt.Errorf("%s: %w", img.Ref, err))
			continue
		}
		findings = append(findings, fs...)
	}
	if errs != nil {
		return nil, errs // drop the whole kind so central does not resolve on partial data
	}
	return findings, nil
}

func (c ImageCVE) scanOne(ctx context.Context, img compose.Image) ([]report.Finding, error) {
	out, err := c.Trivy.Run(ctx, "trivy", "image",
		"--scanners", "vuln", "--severity", "HIGH,CRITICAL",
		"--format", "json", "--quiet", img.Ref)
	if err != nil {
		return nil, err
	}

	var tr trivyReport
	if err := json.Unmarshal(out, &tr); err != nil {
		return nil, fmt.Errorf("parsing trivy json: %w", err)
	}

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
			})
		}
	}
	return findings, nil
}
