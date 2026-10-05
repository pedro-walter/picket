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
	"sync/atomic"
	"time"

	"github.com/pedro-walter/picket/agent/internal/client"
	"github.com/pedro-walter/picket/agent/internal/config"
	"github.com/pedro-walter/picket/agent/internal/report"
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

	// Inputs, if set, returns a cheap digest of what the section scans (no
	// network). When it differs from the digest the cached scan was made with,
	// the section is rescanned at the next cheap cycle instead of waiting for
	// its Interval.
	Inputs func() (string, error)
	// Scans, if set, reports the images the last successful scan covered. They
	// are part of the section hash, so a changed ref or digest always sends a
	// body even when the finding set is identical.
	Scans func() []report.Scan
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

	mu   sync.Mutex // serialises state-file access across cheap + section goroutines
	scan sync.Mutex // one section scan at a time (ticker and input-change rescans)
	busy atomic.Bool
	bg   sync.WaitGroup // operator-requested rescans in flight
	// rescanRunning is the request ID being worked on; rescanDone is the last
	// finished ID, echoed in reports until central stops sending the request.
	rescanRunning string
	rescanDone    string
	oneshot       bool
	tried         map[string]attempt // section -> last input-triggered rescan (in memory only)

	// RescanRetry is the minimum gap before an input-triggered rescan is
	// retried for the same inputs after it failed. Zero means one hour.
	RescanRetry time.Duration
}

type attempt struct {
	inputs string
	at     time.Time
}

// sectionState is what the agent persists per section between runs.
type sectionState struct {
	Hash        string           `json:"hash"`         // hash of current Kinds+Findings
	GeneratedAt time.Time        `json:"generated_at"` // when this scan was produced
	Kinds       []string         `json:"kinds"`
	Findings    []report.Finding `json:"findings"`
	AckedHash   string           `json:"acked_hash"`       // hash central last confirmed the body for
	Inputs      string           `json:"inputs,omitempty"` // Spec.Inputs digest the scan was made with
	Scans       []report.Scan    `json:"scans,omitempty"`  // images the scan covered
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
			r.bg.Wait()
			return ctx.Err()
		case <-cheap.C:
			if err := r.cheapCycle(ctx); err != nil {
				r.Log.Error("cheap cycle", "err", err)
			}
			r.rescanInBackground(ctx) // watched refs changed since the last scan
		}
	}
}

// Oneshot runs every section once, then a cheap cycle that reports. Because a
// fresh section body is sent until central acks it, a single Oneshot fully
// syncs central; a second Oneshot sends hash-only.
func (r *Runner) Oneshot(ctx context.Context) error {
	r.oneshot = true // every section just ran; a requested rescan is for the daemon
	for _, s := range r.Sections {
		if err := r.sectionCycle(ctx, s); err != nil {
			r.Log.Warn("section cycle", "section", s.Name, "err", err)
		}
	}
	return r.cheapCycle(ctx)
}

// rescanInBackground rescans sections whose inputs changed without blocking
// the host report (a trivy run takes minutes), then sends one extra report so
// central gets the new body now rather than a full cheap interval later.
func (r *Runner) rescanInBackground(ctx context.Context) {
	if !r.busy.CompareAndSwap(false, true) {
		return // previous rescan still running
	}
	r.bg.Add(1)
	go func() {
		defer r.bg.Done()
		defer r.busy.Store(false)
		if r.rescanChanged(ctx) {
			if err := r.cheapCycle(ctx); err != nil {
				r.Log.Error("post-rescan cheap cycle", "err", err)
			}
		}
	}()
}

// rescanChanged runs every section whose Inputs digest differs from the one
// its cached scan was made with. Returns true if any section was rescanned.
func (r *Runner) rescanChanged(ctx context.Context) bool {
	did := false
	for _, s := range r.Sections {
		cur, ok := r.changedInputs(s)
		if !ok {
			continue
		}
		if r.recentlyTried(s.Name, cur) {
			continue
		}
		r.Log.Info("section inputs changed, rescanning", "section", s.Name)
		r.markTried(s.Name, cur)
		if err := r.sectionCycle(ctx, s); err != nil {
			r.Log.Warn("rescan", "section", s.Name, "err", err)
		}
		did = true
	}
	return did
}

// changedInputs reports whether spec's inputs differ from its cached scan's.
// A cached scan with no recorded inputs (written by an older agent) counts as
// changed once, so the first run after an upgrade re-establishes provenance.
func (r *Runner) changedInputs(spec SectionSpec) (string, bool) {
	if spec.Inputs == nil || len(spec.Checks) == 0 {
		return "", false
	}
	cur, err := spec.Inputs()
	if err != nil {
		return "", false // the scan would fail the same way; leave the cache alone
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	st, err := r.loadState()
	if err != nil || st == nil {
		return cur, true
	}
	s, ok := st.Sections[spec.Name]
	if !ok {
		return cur, true
	}
	return cur, s.Inputs != cur
}

func (r *Runner) recentlyTried(section, inputs string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.tried[section]
	if !ok || a.inputs != inputs {
		return false
	}
	retry := r.RescanRetry
	if retry == 0 {
		retry = time.Hour
	}
	return time.Since(a.at) < retry
}

func (r *Runner) markTried(section, inputs string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.tried == nil {
		r.tried = map[string]attempt{}
	}
	r.tried[section] = attempt{inputs: inputs, at: time.Now()}
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
			Scans:       s.Scans,
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
	r.mu.Lock()
	p.RescanDone = r.rescanDone
	r.mu.Unlock()

	resp, err := r.Client.SendReport(ctx, p)
	if err != nil {
		return err
	}

	r.applyAcks(resp)
	r.handleRescan(ctx, resp)

	r.Log.Info("reported",
		"findings", len(p.Findings), "checks_run", p.ChecksRun,
		"sections", sectionSummary(p.Sections),
		"desired_version", resp.DesiredVersion)
	r.maybeSelfUpdate(resp)
	return nil
}

// handleRescan starts an operator-requested rescan in the background (a trivy
// run takes minutes; the host report must not wait on it). Once it finishes it
// sends an extra report carrying RescanDone so central clears the request.
func (r *Runner) handleRescan(ctx context.Context, resp *report.Response) {
	r.mu.Lock()
	defer r.mu.Unlock()
	req := resp.Rescan
	if req == nil {
		r.rescanDone = "" // central cleared it; stop echoing
		return
	}
	if r.oneshot || req.ID == r.rescanDone || req.ID == r.rescanRunning {
		return
	}
	r.rescanRunning = req.ID
	r.Log.Info("rescan requested", "id", req.ID, "sections", req.Sections)
	r.bg.Add(1)
	go func() {
		defer r.bg.Done()
		for _, s := range r.Sections {
			if !wantsSection(req.Sections, s.Name) {
				continue
			}
			if err := r.sectionCycle(ctx, s); err != nil {
				r.Log.Warn("requested rescan", "section", s.Name, "err", err)
			}
		}
		r.mu.Lock()
		r.rescanDone, r.rescanRunning = req.ID, ""
		r.mu.Unlock()
		if err := r.cheapCycle(ctx); err != nil {
			r.Log.Error("post-rescan cheap cycle", "err", err)
		}
	}()
}

func wantsSection(want []string, name string) bool {
	for _, w := range want {
		if w == "all" || w == name {
			return true
		}
	}
	return false
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
	r.scan.Lock()
	defer r.scan.Unlock()
	// sampled before scanning: a change that lands mid-scan differs from this
	// and triggers another rescan rather than being silently absorbed.
	var inputs string
	if spec.Inputs != nil {
		inputs, _ = spec.Inputs()
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
	var scans []report.Scan
	if spec.Scans != nil {
		scans = spec.Scans()
	}
	newHash := hashSection(kinds, findings, scans)

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
		Inputs:      inputs,
		Scans:       scans,
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

func hashSection(kinds []string, findings []report.Finding, scans []report.Scan) string {
	payload := struct {
		Kinds    []string         `json:"kinds"`
		Findings []report.Finding `json:"findings"`
		Scans    []report.Scan    `json:"scans,omitempty"`
	}{Kinds: kinds, Findings: findings, Scans: scans}
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
	if time.Since(s.GeneratedAt) >= spec.Interval {
		return true
	}
	if spec.Inputs != nil {
		if cur, err := spec.Inputs(); err == nil && cur != s.Inputs {
			return true
		}
	}
	return false
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
