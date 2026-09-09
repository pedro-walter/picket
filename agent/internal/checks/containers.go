package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/pedrohardware/picket/agent/internal/compose"
	"github.com/pedrohardware/picket/agent/internal/report"
	"github.com/pedrohardware/picket/agent/internal/toolexec"
)

// Containers reports (kind "container-stale") a running container whose
// image ID differs from what its compose-pinned tag now resolves to locally
// - some earlier `docker pull` updated the tag but the container was never
// recreated. Ports check-pending-restart.sh's stale-container half.
// REPORT ONLY in v1: no recreate.
type Containers struct {
	ComposeFiles []string
	Docker       toolexec.Runner
}

func (c Containers) Scan(ctx context.Context) ([]report.Finding, error) {
	// Probe the daemon once: if docker itself is unreachable this is a real
	// error (drop the kind) rather than "no stale containers".
	if _, err := c.Docker.Run(ctx, "docker", "version", "--format", "{{.Server.Version}}"); err != nil {
		return nil, fmt.Errorf("docker not available: %w", err)
	}

	svcs, err := compose.ServiceImages(c.ComposeFiles)
	if err != nil {
		return nil, err
	}

	var findings []report.Finding
	for _, s := range svcs {
		running, err := c.id(ctx, "inspect", "--format", "{{.Image}}", s.Name)
		if err != nil || running == "" {
			continue // not running / no such container - nothing to compare
		}
		local, err := c.id(ctx, "image", "inspect", "--format", "{{.Id}}", s.Image)
		if err != nil || local == "" {
			continue // tag not present locally
		}
		if running == local {
			continue
		}
		findings = append(findings, report.Finding{
			Kind:       "container-stale",
			Subject:    s.Name,
			Identifier: s.Image,
			Severity:   "medium",
			Title:      Hostname() + ": " + s.Name + " running a stale image",
			Detail: fmt.Sprintf("%s: container is on %s, the local tag now resolves to %s (recreate to pick it up)",
				s.Image, short(running), short(local)),
		})
	}
	return findings, nil
}

func (c Containers) id(ctx context.Context, args ...string) (string, error) {
	out, err := c.Docker.Run(ctx, "docker", args...)
	return strings.TrimSpace(string(out)), err
}

func short(id string) string {
	id = strings.TrimPrefix(id, "sha256:")
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
