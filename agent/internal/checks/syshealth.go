package checks

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/pedro-walter/picket/agent/internal/report"
)

// SysHealth samples host CPU / RAM / disk plus the two data-dir sizes and
// returns them as a metrics payload. Ports check-system-health.sh's
// readings; central stores the series and evaluates thresholds (no local
// history file). Thresholds are forwarded so central uses this host's.
type SysHealth struct {
	DiskPath         string // default "/"
	MongoDataPath    string
	RegistryDataPath string
	Thresholds       *report.Thresholds
}

func (s SysHealth) Sample(ctx context.Context) (*report.Metrics, error) {
	cpu, err := cpuPct(ctx)
	if err != nil {
		return nil, err
	}
	mem, err := memPct()
	if err != nil {
		return nil, err
	}
	disk := s.DiskPath
	if disk == "" {
		disk = "/"
	}
	dp, err := diskPct(disk)
	if err != nil {
		return nil, err
	}

	m := &report.Metrics{CPUPct: round1(cpu), MemPct: round1(mem), DiskPct: round1(dp), Thresholds: s.Thresholds}
	if s.MongoDataPath != "" {
		if gb, err := dirSizeGB(s.MongoDataPath); err == nil {
			m.MongoDataGB = round1(gb)
		}
	}
	if s.RegistryDataPath != "" {
		if gb, err := dirSizeGB(s.RegistryDataPath); err == nil {
			m.RegistryDataGB = round1(gb)
		}
	}
	return m, nil
}

func round1(f float64) float64 { return float64(int64(f*10+0.5)) / 10 }

// cpuPct samples /proc/stat over a 1s window (idle+iowait vs total).
func cpuPct(ctx context.Context) (float64, error) {
	i1, t1, err := cpuSample()
	if err != nil {
		return 0, err
	}
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-time.After(time.Second):
	}
	i2, t2, err := cpuSample()
	if err != nil {
		return 0, err
	}
	dt := t2 - t1
	if dt == 0 {
		return 0, nil
	}
	return (1 - float64(i2-i1)/float64(dt)) * 100, nil
}

func cpuSample() (idle, total uint64, err error) {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0, err
	}
	line, _, _ := strings.Cut(string(b), "\n")
	fields := strings.Fields(line) // "cpu" u n s idle iowait irq softirq steal guest guest_nice
	for i, f := range fields[1:] {
		v, _ := strconv.ParseUint(f, 10, 64)
		total += v
		if i == 3 || i == 4 { // idle, iowait
			idle += v
		}
	}
	return idle, total, nil
}

// memPct = (MemTotal - MemAvailable) / MemTotal * 100, from /proc/meminfo.
func memPct() (float64, error) {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	var total, avail float64
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "MemTotal:":
			total, _ = strconv.ParseFloat(f[1], 64)
		case "MemAvailable:":
			avail, _ = strconv.ParseFloat(f[1], 64)
		}
	}
	if total == 0 {
		return 0, nil
	}
	return (total - avail) / total * 100, nil
}

// diskPct mirrors `df` Use%: used / (used + available), reserved blocks excluded.
func diskPct(path string) (float64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	used := st.Blocks - st.Bfree
	denom := used + st.Bavail
	if denom == 0 {
		return 0, nil
	}
	return float64(used) / float64(denom) * 100, nil
}

// dirSizeGB sums regular-file apparent sizes under path (close enough to
// `du` for a threshold). Unreadable entries are skipped.
func dirSizeGB(path string) (float64, error) {
	if fi, err := os.Stat(path); err != nil || !fi.IsDir() {
		return 0, os.ErrNotExist
	}
	var total int64
	_ = filepath.WalkDir(path, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if info, err := d.Info(); err == nil {
			total += info.Size()
		}
		return nil
	})
	return float64(total) / (1 << 30), nil
}
