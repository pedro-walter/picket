// Package scheduler runs the agent's tiered loop:
//
//	cheap    every ReportInterval  - fast host checks; POSTs the consolidated
//	                                 report (cheap findings fresh + a hash per
//	                                 lower-cadence section, body only on change)
//	sections each on its own Interval - image CVE / tag scan, daily cert expiry;
//	                                 results cached to disk and hash-gated
//
// The cheap report always carries current cheap findings. For each configured
// section it carries just a content hash while unchanged; when a section's
// scan produces a new hash the next cheap report(s) include the full body
// until central acknowledges it. Central never re-diffs or resolves a
// section's findings on a hash-only report.
package scheduler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pedrohardware/picket/agent/internal/client"
	"github.com/pedrohardware/picket/agent/internal/config"
	"github.com/pedrohardware/picket/agent/internal/report"
)

// CheckFunc is one check. Returning an error means "could not run" - its kind
// is then left out of the reported kinds so central will not resolve prior
// findings of that kind.
type CheckFunc func(context.Context) ([]report.Finding, error)

// MetricsFunc samples host health each cheap cycle. Central evaluates the
// thresholds and owns any host-health findings.
type MetricsFunc func(context.Context) (*report.Metrics, error)

// SelfUpdater applies a version upgrade offered in the report response.
// Returns updated=true only once the binary has been swapped.
type SelfUpdater interface {
	Apply(ctx context.Context, resp *report.Response) (updated bool, err error)
}

// SectionSpec is a lower-cadence group of checks reported under one hash.
type SectionSpec struct {
	Name     string // e.g. "image-scan", "daily"
	Interval time.Duration
	Prepare  func(context.Context) error // optional; runs before Checks each cycle (e.g. tool refresh)
	Checks   map[string]CheckFunc        // finding kind -> check
}

type Runner struct {
	Cfg     *config.Config
	Client  *client.Client
	Log     *slog.Logger
	Version string

	CheapChecks map[string]CheckFunc // run every ReportInterval, always inline
	Metrics     MetricsFunc          // optional; sampled every cheap cycle
	Sections    []SectionSpec        // run on their own intervals, hash-gated

	Updater SelfUpdater // optional; applied when central offers a new version
	Arch    string      // runtime.GOARCH, sent so central can pick the right artifact

	StatePath string // JSON file holding the per-section cache + ack state

	mu sync.Mutex // serialises state-file access across cheap + section goroutines
}

// sectionState is what the agent persists per section between runs.
type sectionState struct {
	Hash        string           `json:"hash"`         // hash of current Kinds+Findings
	GeneratedAt time.Time        `json:"generated_at"` // when this scan was produced
	Kinds       []string         `json:"kinds"`
	Findings    []report.Finding `json:"findings"`
	AckedHash   string           `json:"acked_hash"` // hash central last confirmed the body for
}

type stateFile struct {
	Sections map[string]sectionState `json:"sections"`
}

// Run primes any stale/missing sections, does an immediate cheap cycle, then
// runs the cheap ticker in this goroutine and one goroutine per section
// until ctx is cancelled.
func (r *Runner) Run(ctx context.Context) error {
	for _, s := range r.Sections {
		if r.sectionStale(s) {
			if err := r.sectionCycle(ctx, s); err != nil {
				r.Log.Warn("initial section cycle", "section", s.Name, "err", err)
			}
		}
	}
	if err := r.cheapCycle(ctx); err != nil {
		r.Log.Warn("initial cheap cycle", "err", err)
	}

	var wg sync.WaitGroup
	for _, s := range r.Sections {
		wg.Add(1)
		go func(spec SectionSpec) {
			defer wg.Done()
			t := time.NewTicker(spec.Interval)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					if err := r.sectionCycle(ctx, spec); err != nil {
						r.Log.Error("section cycle", "section", spec.Name, "err", err)
					}
				}
			}
		}(s)
	}

	cheap := time.NewTicker(r.Cfg.ReportInterval.Duration)
	defer cheap.Stop()
	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return ctx.Err()
		case <-cheap.C:
			if err := r.cheapCycle(ctx); err != nil {
				r.Log.Error("cheap cycle", "err", err)
			}
		}
	}
}

// Oneshot runs every section once, then a cheap cycle that reports. Because a
// fresh section body is sent until central acks it, a single Oneshot fully
// syncs central; a second Oneshot sends hash-only.
func (r *Runner) Oneshot(ctx context.Context) error {
	for _, s := range r.Sections {
		if err := r.sectionCycle(ctx, s); err != nil {
			r.Log.Warn("section cycle", "section", s.Name, "err", err)
		}
	}
	return r.cheapCycle(ctx)
}

func (r *Runner) cheapCycle(ctx context.Context) error {
	findings, ran := run(ctx, r.Log, "cheap", r.CheapChecks)

	r.mu.Lock()
	st, err := r.loadState()
	if err != nil {
		r.Log.Warn("reading state", "err", err)
		st = &stateFile{Sections: map[string]sectionState{}}
	}
	sections := map[string]report.Section{}
	for name, s := range st.Sections {
		if len(s.Kinds) == 0 {
			continue // never fully scanned (e.g. tools missing) - nothing to report
		}
		sec := report.Section{
			Hash:        s.Hash,
			GeneratedAt: s.GeneratedAt.UTC().Format(time.RFC3339),
			ChecksRun:   s.Kinds,
		}
		if s.Hash != s.AckedHash {
			sec.Findings = s.Findings // central does not have this body yet
		}
		sections[name] = sec
	}
	r.mu.Unlock()

	var metrics *report.Metrics
	if r.Metrics != nil {
		if m, err := r.Metrics(ctx); err != nil {
			r.Log.Warn("metrics sample failed", "err", err)
		} else {
			metrics = m
		}
	}

	p := &report.Payload{
		AgentName:    r.Cfg.AgentName,
		AgentVersion: r.Version,
		Arch:         r.Arch,
		SentAt:       time.Now().UTC().Format(time.RFC3339),
		ChecksRun:    dedupe(ran),
		Findings:     findings,
		Metrics:      metrics,
	}
	if p.Findings == nil {
		p.Findings = []report.Finding{}
	}
	if p.ChecksRun == nil {
		p.ChecksRun = []string{}
	}
	if len(sections) > 0 {
		p.Sections = sections
	}

	resp, err := r.Client.SendReport(ctx, p)
	if err != nil {
		return err
	}

	r.applyAcks(resp)

	r.Log.Info("reported",
		"findings", len(p.Findings), "checks_run", p.ChecksRun,
		"sections", sectionSummary(p.Sections),
		"desired_version", resp.DesiredVersion)
	r.maybeSelfUpdate(resp)
	return nil
}

// applyAcks records which section bodies central now holds (stop resending)
// and which it still needs (force a body next cycle).
func (r *Runner) applyAcks(resp *report.Response) {
	if len(resp.SectionsAck) == 0 && len(resp.SectionsNeedBody) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	st, err := r.loadState()
	if err != nil {
		return
	}
	changed := false
	for name, hash := range resp.SectionsAck {
		if s, ok := st.Sections[name]; ok && s.Hash == hash && s.AckedHash != hash {
			s.AckedHash = hash
			st.Sections[name] = s
			changed = true
		}
	}
	for _, name := range resp.SectionsNeedBody {
		if s, ok := st.Sections[name]; ok && s.AckedHash != "" {
			s.AckedHash = ""
			st.Sections[name] = s
			changed = true
		}
	}
	if changed {
		if err := r.writeState(st); err != nil {
			r.Log.Warn("persisting section acks", "err", err)
		}
	}
}

func (r *Runner) sectionCycle(ctx context.Context, spec SectionSpec) error {
	if len(spec.Checks) == 0 {
		return nil
	}
	if spec.Prepare != nil {
		if err := spec.Prepare(ctx); err != nil {
			// non-fatal: individual checks will still error if a tool is truly missing
			r.Log.Warn("section prepare failed", "section", spec.Name, "err", err)
		}
	}
	findings, ran := run(ctx, r.Log, spec.Name, spec.Checks)
	if len(ran) == 0 {
		// every check in this section errored - keep the previous cached
		// result rather than replacing it with an empty one.
		r.Log.Warn("section produced nothing (all checks failed)", "section", spec.Name)
		return nil
	}
	kinds := dedupe(ran)
	sortFindings(findings)
	newHash := hashSection(kinds, findings)

	r.mu.Lock()
	defer r.mu.Unlock()
	st, err := r.loadState()
	if err != nil {
		st = &stateFile{Sections: map[string]sectionState{}}
	}
	prev := st.Sections[spec.Name]
	st.Sections[spec.Name] = sectionState{
		Hash:        newHash,
		GeneratedAt: time.Now(),
		Kinds:       kinds,
		Findings:    findings,
		AckedHash:   prev.AckedHash, // cheapCycle re-sends the body if the hash moved
	}
	r.Log.Info("section scanned", "section", spec.Name,
		"kinds", kinds, "findings", len(findings), "changed", newHash != prev.Hash)
	return r.writeState(st)
}

// maybeSelfUpdate applies an offered upgrade if enabled, inside the update
// window, and the Updater verifies the artifact. On a successful swap the
// process exits so the supervisor (systemd Restart=always) runs the new binary.
func (r *Runner) maybeSelfUpdate(resp *report.Response) {
	if r.Updater == nil || !r.Cfg.SelfUpdate {
		return
	}
	if resp.DesiredVersion == "" || resp.DesiredVersion == r.Version {
		return
	}
	if !r.Cfg.InUpdateWindow(time.Now()) {
		r.Log.Info("update available, outside update_window",
			"have", r.Version, "want", resp.DesiredVersion, "window", r.Cfg.UpdateWindow)
		return
	}
	updated, err := r.Updater.Apply(context.Background(), resp)
	if err != nil {
		r.Log.Error("self-update failed", "want", resp.DesiredVersion, "err", err)
		return
	}
	if updated {
		r.Log.Warn("self-updated; exiting for supervisor restart", "to", resp.DesiredVersion)
		exit(0)
	}
}

// exit is overridable in tests.
var exit = os.Exit

// --- helpers ---

func run(ctx context.Context, log *slog.Logger, tier string, checks map[string]CheckFunc) ([]report.Finding, []string) {
	var findings []report.Finding
	var ran []string
	for _, kind := range sortedKeys(checks) {
		fs, err := checks[kind](ctx)
		if err != nil {
			log.Warn("check failed", "tier", tier, "kind", kind, "err", err)
			continue // kind stays out of the reported kinds
		}
		ran = append(ran, kind)
		findings = append(findings, fs...)
	}
	return findings, ran
}

func hashSection(kinds []string, findings []report.Finding) string {
	payload := struct {
		Kinds    []string         `json:"kinds"`
		Findings []report.Finding `json:"findings"`
	}{Kinds: kinds, Findings: findings}
	b, _ := json.Marshal(payload)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func sortFindings(fs []report.Finding) {
	sort.Slice(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.Subject != b.Subject {
			return a.Subject < b.Subject
		}
		return a.Identifier < b.Identifier
	})
}

func (r *Runner) sectionStale(spec SectionSpec) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	st, err := r.loadState()
	if err != nil || st == nil {
		return true
	}
	s, ok := st.Sections[spec.Name]
	if !ok {
		return true
	}
	return time.Since(s.GeneratedAt) >= spec.Interval
}

// loadState / writeState assume r.mu is held by the caller.
func (r *Runner) loadState() (*stateFile, error) {
	if r.StatePath == "" {
		return &stateFile{Sections: map[string]sectionState{}}, nil
	}
	b, err := os.ReadFile(r.StatePath)
	if errors.Is(err, os.ErrNotExist) {
		return &stateFile{Sections: map[string]sectionState{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var s stateFile
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	if s.Sections == nil {
		s.Sections = map[string]sectionState{}
	}
	return &s, nil
}

func (r *Runner) writeState(s *stateFile) error {
	if r.StatePath == "" {
		return nil
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(r.StatePath), 0o755); err != nil {
		return err
	}
	tmp := r.StatePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, r.StatePath)
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func sortedKeys(m map[string]CheckFunc) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sectionSummary(m map[string]report.Section) string {
	if len(m) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(m))
	for name, s := range m {
		if s.Findings != nil {
			parts = append(parts, name+"=body")
		} else {
			parts = append(parts, name+"=hash")
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}
