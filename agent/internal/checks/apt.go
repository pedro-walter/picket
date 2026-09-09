package checks

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/pedro-walter/picket/agent/internal/report"
	"github.com/pedro-walter/picket/agent/internal/toolexec"
)

// Apt reports (kind "apt"):
//   - security-pending / regular-pending: updates `apt-get -s dist-upgrade`
//     says are available, split by origin.
//   - unattended-upgrade-failed: the most recent unattended-upgrades run
//     logged a WARNING/ERROR.
//
// Ports check-security-updates.sh, plus the pending-updates view the plan asks for.
type Apt struct {
	APT       toolexec.Runner
	UULog     string // default /var/log/unattended-upgrades/unattended-upgrades.log
	UUDpkgLog string // default .../unattended-upgrades-dpkg.log
}

func (a Apt) uuLog() string {
	if a.UULog != "" {
		return a.UULog
	}
	return "/var/log/unattended-upgrades/unattended-upgrades.log"
}

func (a Apt) uuDpkgLog() string {
	if a.UUDpkgLog != "" {
		return a.UUDpkgLog
	}
	return "/var/log/unattended-upgrades/unattended-upgrades-dpkg.log"
}

func (a Apt) Scan(ctx context.Context) ([]report.Finding, error) {
	out, err := a.APT.Run(ctx, "apt-get", "-s", "dist-upgrade")
	if err != nil {
		return nil, err
	}
	sec, reg := parseSimUpgrade(out)

	var findings []report.Finding
	if len(sec) > 0 {
		findings = append(findings, report.Finding{
			Kind:       "apt",
			Subject:    "system",
			Identifier: "security-pending",
			Severity:   "high",
			Title:      fmt.Sprintf("%s: %d security update(s) pending", Hostname(), len(sec)),
			Detail:     "packages: " + capList(sec, 40),
		})
	}
	if len(reg) > 0 {
		findings = append(findings, report.Finding{
			Kind:       "apt",
			Subject:    "system",
			Identifier: "regular-pending",
			Severity:   "low",
			Title:      fmt.Sprintf("%s: %d non-security update(s) pending", Hostname(), len(reg)),
			Detail:     "packages: " + capList(reg, 40),
		})
	}
	if f := a.unattendedFailure(); f != nil {
		findings = append(findings, *f)
	}
	return findings, nil
}

var instLine = regexp.MustCompile(`^Inst (\S+) .*\((.*)\)\s*$`)

// parseSimUpgrade splits `apt-get -s dist-upgrade` "Inst" lines into
// security vs regular by whether the version's origin mentions security.
func parseSimUpgrade(out []byte) (security, regular []string) {
	for _, line := range strings.Split(string(out), "\n") {
		m := instLine.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		if strings.Contains(strings.ToLower(m[2]), "security") {
			security = append(security, m[1])
		} else {
			regular = append(regular, m[1])
		}
	}
	return security, regular
}

var uuLevelLine = regexp.MustCompile(`^\S+ \S+ (WARNING|ERROR) `)

// unattendedFailure inspects the MOST RECENT unattended-upgrades run block
// (from the last "Starting unattended upgrades script" marker to EOF). A
// clean latest run => no finding => central resolves a prior failure.
func (a Apt) unattendedFailure() *report.Finding {
	b, err := os.ReadFile(a.uuLog())
	if err != nil {
		return nil // no log, or unreadable: nothing to say
	}
	lines := strings.Split(string(b), "\n")
	start := 0
	for i, l := range lines {
		if strings.Contains(l, "Starting unattended upgrades script") {
			start = i
		}
	}
	var bad []string
	for _, l := range lines[start:] {
		if uuLevelLine.MatchString(l) {
			bad = append(bad, strings.TrimSpace(l))
		}
	}
	if len(bad) == 0 {
		return nil
	}

	detail := "unattended-upgrades:\n  " + strings.Join(capN(bad, 20), "\n  ")
	if db, err := os.ReadFile(a.uuDpkgLog()); err == nil {
		var dpkg []string
		for _, l := range tailLines(string(db), 500) {
			if strings.HasPrefix(l, "E:") || strings.HasPrefix(l, "dpkg: error") {
				dpkg = append(dpkg, l)
			}
		}
		if len(dpkg) > 0 {
			detail += "\ndpkg:\n  " + strings.Join(capN(dpkg, 20), "\n  ")
		}
	}

	return &report.Finding{
		Kind:       "apt",
		Subject:    "system",
		Identifier: "unattended-upgrade-failed",
		Severity:   "high",
		Title:      Hostname() + ": last unattended-upgrades run reported errors",
		Detail:     detail,
	}
}

func capList(items []string, n int) string {
	if len(items) <= n {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:n], ", ") + fmt.Sprintf(", … (+%d more)", len(items)-n)
}

func capN(items []string, n int) []string {
	if len(items) <= n {
		return items
	}
	return append(items[:n:n], fmt.Sprintf("… (+%d more)", len(items)-n))
}

func tailLines(s string, n int) []string {
	lines := strings.Split(s, "\n")
	if len(lines) <= n {
		return lines
	}
	return lines[len(lines)-n:]
}
