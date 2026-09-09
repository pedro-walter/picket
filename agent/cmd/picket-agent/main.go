// Command picket-agent is the per-server monitoring daemon: a tiered
// scheduler that runs host checks and POSTs a consolidated, authenticated
// report to the picket central service.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/pedro-walter/picket/agent/internal/checks"
	"github.com/pedro-walter/picket/agent/internal/client"
	"github.com/pedro-walter/picket/agent/internal/config"
	"github.com/pedro-walter/picket/agent/internal/report"
	"github.com/pedro-walter/picket/agent/internal/scheduler"
	"github.com/pedro-walter/picket/agent/internal/selfupdate"
	"github.com/pedro-walter/picket/agent/internal/toolexec"
	"github.com/pedro-walter/picket/agent/internal/tools"
)

// version is overridden at build time: -ldflags "-X main.version=1.2.3".
var version = "0.1.0"

func main() {
	cfgPath := flag.String("config", "/etc/picket/agent.yaml", "path to agent config")
	stateDir := flag.String("state-dir", "/var/lib/picket", "writable state directory")
	binaryPath := flag.String("binary", "/var/lib/picket/bin/picket-agent", "path to this binary (self-update swap target)")
	oneshot := flag.Bool("oneshot", false, "run every tier once and exit")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Error("load config", "err", err)
		os.Exit(1)
	}

	host := toolexec.OS{Timeout: 2 * time.Minute} // apt-get / docker, resolved from $PATH

	cheap := map[string]scheduler.CheckFunc{
		"reboot": checks.Reboot,
		"apt":    checks.Apt{APT: host}.Scan,
	}
	if len(cfg.ComposeFiles) > 0 {
		cheap["container-stale"] = checks.Containers{ComposeFiles: cfg.ComposeFiles, Docker: host}.Scan
	}

	sh := checks.SysHealth{
		DiskPath:         cfg.Paths.Disk,
		MongoDataPath:    cfg.Paths.MongoData,
		RegistryDataPath: cfg.Paths.RegistryData,
		Thresholds: &report.Thresholds{
			CPUPct:         cfg.Thresholds.CPUPct,
			MemPct:         cfg.Thresholds.MemPct,
			DiskPct:        cfg.Thresholds.DiskPct,
			MongoDataGB:    cfg.Thresholds.MongoDataGB,
			RegistryDataGB: cfg.Thresholds.RegistryDataGB,
		},
	}

	var updater scheduler.SelfUpdater
	if cfg.SelfUpdate {
		updater = &selfupdate.Updater{
			CurrentVersion: version,
			BinaryPath:     *binaryPath,
			PublicKeyPEM:   selfupdate.SigningPublicKeyPEM,
			HTTPClient:     &http.Client{Timeout: 5 * time.Minute},
			Log:            log,
		}
	}

	r := &scheduler.Runner{
		Cfg:         cfg,
		Client:      client.New(cfg.CentralURL, cfg.Token()),
		Log:         log,
		Version:     version,
		Arch:        runtime.GOARCH,
		Updater:     updater,
		StatePath:   filepath.Join(*stateDir, "state.json"),
		CheapChecks: cheap,
		Metrics:     sh.Sample,
		Sections:    buildSections(cfg, *stateDir),
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Info("picket-agent starting",
		"version", version, "agent", cfg.AgentName, "central", cfg.CentralURL,
		"report_interval", cfg.ReportInterval.Duration.String(),
		"sections", sectionNames(r.Sections), "oneshot", *oneshot)

	if *oneshot {
		if err := r.Oneshot(ctx); err != nil {
			log.Error("oneshot failed", "err", err)
			os.Exit(1)
		}
		return
	}

	if err := r.Run(ctx); err != nil && ctx.Err() == nil {
		log.Error("run failed", "err", err)
		os.Exit(1)
	}
}

func buildSections(cfg *config.Config, stateDir string) []scheduler.SectionSpec {
	var out []scheduler.SectionSpec
	binDir := filepath.Join(stateDir, "bin")

	// ensureTools downloads pinned crane/trivy into binDir if managed.
	ensureTools := func(ctx context.Context) error {
		if !cfg.Tools.AutoManage {
			return nil
		}
		return tools.Ensure(ctx, binDir, runtime.GOARCH, tools.Default, &http.Client{Timeout: 10 * time.Minute}, nil)
	}

	if len(cfg.ComposeFiles) > 0 {
		exec := toolexec.OS{BinDir: binDir, Timeout: 10 * time.Minute}
		out = append(out, scheduler.SectionSpec{
			Name:     "image-scan",
			Interval: cfg.ImageScanInterval.Duration,
			Prepare:  ensureTools,
			Checks: map[string]scheduler.CheckFunc{
				"image-cve": checks.ImageCVE{ComposeFiles: cfg.ComposeFiles, Trivy: exec}.Scan,
				"image-tag": checks.ImageTag{ComposeFiles: cfg.ComposeFiles, Crane: exec}.Scan,
			},
		})
	}

	if len(cfg.Domains) > 0 {
		out = append(out, scheduler.SectionSpec{
			Name:     "daily",
			Interval: cfg.DailyInterval.Duration,
			Prepare:  ensureTools, // daily refresh of the managed tool binaries
			Checks: map[string]scheduler.CheckFunc{
				"cert-expiry": checks.CertExpiry{Domains: cfg.Domains}.Scan,
			},
		})
	}
	return out
}

func sectionNames(s []scheduler.SectionSpec) []string {
	out := make([]string, len(s))
	for i, sec := range s {
		out[i] = sec.Name
	}
	return out
}
