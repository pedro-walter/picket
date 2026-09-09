package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeConfig(t *testing.T, yaml, token string) string {
	t.Helper()
	dir := t.TempDir()
	tokPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokPath, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "agent.yaml")
	body := "token_file: " + tokPath + "\n" + yaml
	if err := os.WriteFile(cfgPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return cfgPath
}

func TestLoad(t *testing.T) {
	cfgPath := writeConfig(t, `
central_url: https://picket.souspike.com.br/
agent_name: prod-server
report_interval: 5m
image_scan_interval: 6h
update_window: "02:00-04:00"
compose_files: [/srv/compose.yml]
domains: [souspike.com.br, healthchecks.souspike.com.br]
thresholds: {disk_pct: 85, mongo_data_gb: 20}
tools: {auto_manage: true}
`, "  s3cr3t-token\n")

	c, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.CentralURL != "https://picket.souspike.com.br" {
		t.Errorf("trailing slash not trimmed: %q", c.CentralURL)
	}
	if c.Token() != "s3cr3t-token" {
		t.Errorf("token = %q (want trimmed)", c.Token())
	}
	if c.ReportInterval.Duration != 5*time.Minute {
		t.Errorf("report_interval = %v", c.ReportInterval.Duration)
	}
	if c.ImageScanInterval.Duration != 6*time.Hour {
		t.Errorf("image_scan_interval = %v", c.ImageScanInterval.Duration)
	}
	if c.DailyInterval.Duration != 24*time.Hour {
		t.Errorf("daily_interval default = %v (want 24h)", c.DailyInterval.Duration)
	}
	if !c.Tools.AutoManage || c.Thresholds.DiskPct != 85 || len(c.Domains) != 2 {
		t.Errorf("nested fields wrong: %+v", c)
	}
}

func TestLoadRequiresCoreFields(t *testing.T) {
	cfgPath := writeConfig(t, "agent_name: x\n", "tok")
	if _, err := Load(cfgPath); err == nil {
		t.Fatal("expected error when central_url missing")
	}
}

func TestLoadEmptyTokenRejected(t *testing.T) {
	cfgPath := writeConfig(t, "central_url: https://x\nagent_name: y\n", "   \n")
	if _, err := Load(cfgPath); err == nil {
		t.Fatal("expected error on empty token file")
	}
}

func TestInUpdateWindow(t *testing.T) {
	at := func(hhmm string) time.Time {
		tm, _ := time.Parse("15:04", hhmm)
		return time.Date(2026, 1, 2, tm.Hour(), tm.Minute(), 0, 0, time.UTC)
	}
	cases := []struct {
		window string
		now    string
		want   bool
	}{
		{"", "12:00", true},
		{"02:00-04:00", "03:00", true},
		{"02:00-04:00", "04:00", false}, // end exclusive
		{"02:00-04:00", "01:59", false},
		{"22:00-02:00", "23:30", true}, // wraps midnight
		{"22:00-02:00", "01:00", true},
		{"22:00-02:00", "12:00", false},
		{"garbage", "12:00", false},
	}
	for _, tc := range cases {
		c := &Config{UpdateWindow: tc.window}
		if got := c.InUpdateWindow(at(tc.now)); got != tc.want {
			t.Errorf("window %q at %s = %v, want %v", tc.window, tc.now, got, tc.want)
		}
	}
}
