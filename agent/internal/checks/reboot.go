package checks

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"sort"
	"strings"

	"github.com/pedrohardware/picket/agent/internal/report"
)

// rebootRequiredPath is the sentinel apt / unattended-upgrades touches; the
// companion ".pkgs" lists the triggering packages. Readable unprivileged.
// PICKET_REBOOT_REQUIRED_PATH overrides it for tests.
func rebootRequiredPath() string {
	if p := os.Getenv("PICKET_REBOOT_REQUIRED_PATH"); p != "" {
		return p
	}
	return "/var/run/reboot-required"
}

// Reboot reports a single finding (kind "reboot") when the host needs a
// reboot. Ports server-checks/pending-restart's reboot half.
func Reboot(context.Context) ([]report.Finding, error) {
	path := rebootRequiredPath()
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	detail := ""
	if b, err := os.ReadFile(path + ".pkgs"); err == nil {
		detail = summarizePkgs(b)
	}

	return []report.Finding{{
		Kind:       "reboot",
		Subject:    "system",
		Identifier: "",
		Severity:   "medium",
		Title:      Hostname() + ": reboot required",
		Detail:     detail,
	}}, nil
}

func summarizePkgs(b []byte) string {
	seen := map[string]bool{}
	var pkgs []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		p := strings.TrimSpace(sc.Text())
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		pkgs = append(pkgs, p)
	}
	if len(pkgs) == 0 {
		return ""
	}
	sort.Strings(pkgs)
	return "packages requiring reboot: " + strings.Join(pkgs, ", ")
}
