// Package report defines the wire contract between picket-agent and the
// central service. The central Worker's src/ingest.ts mirrors these shapes;
// keep them in sync.
package report

// Payload is the body of POST /api/v1/report, sent once per report_interval.
// The cheap tier's results are always fresh and inline (ChecksRun +
// Findings + Metrics). Lower-cadence tiers ride in Sections under a content
// hash - their Findings are omitted while the hash is unchanged.
type Payload struct {
	AgentName    string `json:"agent_name"`
	AgentVersion string `json:"agent_version"`
	Arch         string `json:"arch,omitempty"` // runtime.GOARCH, for arch-specific self-update
	SentAt       string `json:"sent_at"`        // RFC3339
	// ChecksRun lists the CHEAP finding kinds evaluated this cycle. Central
	// treats a stored finding of a kind that ran, but is absent here, as
	// resolved - so a check that failed/was skipped must be left out.
	ChecksRun []string           `json:"checks_run"`
	Findings  []Finding          `json:"findings"`
	Metrics   *Metrics           `json:"metrics,omitempty"`
	Sections  map[string]Section `json:"sections,omitempty"`
}

// Section is a lower-cadence group of checks (e.g. "image-scan", "daily").
// Findings is populated only when Hash differs from the hash central last
// acknowledged; otherwise Hash travels alone and central just refreshes
// freshness without re-diffing or resolving anything in ChecksRun.
type Section struct {
	Hash        string    `json:"hash"`         // sha256 hex over the canonical (kinds, findings)
	GeneratedAt string    `json:"generated_at"` // when the agent produced this scan (RFC3339)
	ChecksRun   []string  `json:"checks_run"`   // finding kinds this section covers
	Findings    []Finding `json:"findings,omitempty"`
}

// Finding is one problem instance. The (Kind, Subject, Identifier) triple,
// with the agent name, is hashed by central into a stable fingerprint - so
// Subject must NOT include a version/tag that changes on a routine bump
// (use the bare repo "postgres", not "postgres:16-alpine").
type Finding struct {
	Kind       string `json:"kind"`       // image-cve | image-tag | apt | reboot | container-stale | host-health | cert-expiry
	Subject    string `json:"subject"`    // bare repo / domain / "system"
	Identifier string `json:"identifier"` // "CVE-2026-14456|libssl3" | "16-alpine->16.14-alpine" | "" | "cpu>90%"
	Severity   string `json:"severity"`   // critical | high | medium | low | info
	Title      string `json:"title,omitempty"`
	Detail     string `json:"detail,omitempty"`
	CVE        string `json:"cve,omitempty"` // optional; else parsed from Identifier
}

// Metrics is the host-health sample; central keeps the last N and evaluates
// Thresholds server-side (no local history file). Thresholds are forwarded
// so central uses this host's numbers, which differ per server.
type Metrics struct {
	CPUPct         float64     `json:"cpu_pct"`
	MemPct         float64     `json:"mem_pct"`
	DiskPct        float64     `json:"disk_pct"`
	MongoDataGB    float64     `json:"mongo_data_gb"`
	RegistryDataGB float64     `json:"registry_data_gb"`
	Thresholds     *Thresholds `json:"thresholds,omitempty"`
}

// Thresholds are the alert cut-offs for the metrics above (percent, or GB
// for the data dirs). A zero field means "central's default".
type Thresholds struct {
	CPUPct         float64 `json:"cpu_pct,omitempty"`
	MemPct         float64 `json:"mem_pct,omitempty"`
	DiskPct        float64 `json:"disk_pct,omitempty"`
	MongoDataGB    float64 `json:"mongo_data_gb,omitempty"`
	RegistryDataGB float64 `json:"registry_data_gb,omitempty"`
}

// Response is the JSON returned by POST /api/v1/report.
type Response struct {
	OK             bool   `json:"ok"`
	DesiredVersion string `json:"desired_version"`
	URL            string `json:"url"`
	SHA256         string `json:"sha256"` // empty => agent skips the self-update swap
	SigURL         string `json:"sig_url"`
	// SectionsAck maps a section name to the hash central now holds the full
	// body for; the agent stops sending that body until the hash changes.
	SectionsAck map[string]string `json:"sections_ack,omitempty"`
	// SectionsNeedBody names sections whose hash central does not recognise
	// (fresh DB, lost report); the agent must resend the full body.
	SectionsNeedBody []string `json:"sections_need_body,omitempty"`
}
