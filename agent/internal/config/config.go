// Package config loads /etc/picket/agent.yaml and the separate token file.
package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration is a time.Duration that unmarshals from a Go duration string
// ("15m", "12h") in YAML.
type Duration struct{ time.Duration }

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var s string
	if err := node.Decode(&s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("bad duration %q: %w", s, err)
	}
	d.Duration = v
	return nil
}

type Thresholds struct {
	CPUPct         float64 `yaml:"cpu_pct"`
	MemPct         float64 `yaml:"mem_pct"`
	DiskPct        float64 `yaml:"disk_pct"`
	MongoDataGB    float64 `yaml:"mongo_data_gb"`
	RegistryDataGB float64 `yaml:"registry_data_gb"`
}

// Paths for the host-health check (all optional).
type Paths struct {
	Disk         string `yaml:"disk"`          // filesystem to measure, default "/"
	MongoData    string `yaml:"mongo_data"`    // size-tracked data dir (production server)
	RegistryData string `yaml:"registry_data"` // size-tracked data dir (registry server)
}

type Tools struct {
	AutoManage bool `yaml:"auto_manage"`
}

// Config mirrors PLAN.md's agent.yaml. Secrets never live here - the agent
// token is read from TokenFile (0600, git-ignored).
type Config struct {
	CentralURL        string     `yaml:"central_url"`
	AgentName         string     `yaml:"agent_name"`
	TokenFile         string     `yaml:"token_file"`
	ReportInterval    Duration   `yaml:"report_interval"`
	ImageScanInterval Duration   `yaml:"image_scan_interval"`
	DailyInterval     Duration   `yaml:"daily_interval"`
	SelfUpdate        bool       `yaml:"self_update"`
	UpdateWindow      string     `yaml:"update_window"`
	ComposeFiles      []string   `yaml:"compose_files"`
	Domains           []string   `yaml:"domains"`
	Thresholds        Thresholds `yaml:"thresholds"`
	Paths             Paths      `yaml:"paths"`
	Tools             Tools      `yaml:"tools"`

	token string // from TokenFile, not YAML
}

// Load reads and validates the config at path plus its referenced token file.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	c := &Config{
		TokenFile:         "/etc/picket/token",
		ReportInterval:    Duration{15 * time.Minute},
		ImageScanInterval: Duration{12 * time.Hour},
		DailyInterval:     Duration{24 * time.Hour},
	}
	if err := yaml.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	if c.CentralURL == "" || c.AgentName == "" {
		return nil, fmt.Errorf("%s: central_url and agent_name are required", path)
	}
	c.CentralURL = strings.TrimRight(c.CentralURL, "/")

	tb, err := os.ReadFile(c.TokenFile)
	if err != nil {
		return nil, fmt.Errorf("reading token_file %s: %w", c.TokenFile, err)
	}
	c.token = strings.TrimSpace(string(tb))
	if c.token == "" {
		return nil, fmt.Errorf("token_file %s is empty", c.TokenFile)
	}

	return c, nil
}

// Token returns the agent's bearer token.
func (c *Config) Token() string { return c.token }

// InUpdateWindow reports whether now falls inside UpdateWindow ("HH:MM-HH:MM",
// local time, may wrap midnight). An empty window means "always".
func (c *Config) InUpdateWindow(now time.Time) bool {
	if strings.TrimSpace(c.UpdateWindow) == "" {
		return true
	}
	lo, hi, ok := strings.Cut(c.UpdateWindow, "-")
	if !ok {
		return false
	}
	start, err1 := time.Parse("15:04", strings.TrimSpace(lo))
	end, err2 := time.Parse("15:04", strings.TrimSpace(hi))
	if err1 != nil || err2 != nil {
		return false
	}
	cur := now.Hour()*60 + now.Minute()
	s := start.Hour()*60 + start.Minute()
	e := end.Hour()*60 + end.Minute()
	if s <= e {
		return cur >= s && cur < e
	}
	return cur >= s || cur < e // wraps past midnight
}
