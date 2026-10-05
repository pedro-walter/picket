package scheduler

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pedro-walter/picket/agent/internal/client"
	"github.com/pedro-walter/picket/agent/internal/config"
	"github.com/pedro-walter/picket/agent/internal/report"
)

// fakeCentral records every payload and lets a test script the response.
type fakeCentral struct {
	mu       sync.Mutex
	payloads []report.Payload
	respond  func(p report.Payload) report.Response
	srv      *httptest.Server
}

func newFakeCentral(t *testing.T) *fakeCentral {
	t.Helper()
	fc := &fakeCentral{respond: func(report.Payload) report.Response { return report.Response{OK: true} }}
	fc.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var p report.Payload
		if err := json.Unmarshal(b, &p); err != nil {
			t.Errorf("bad payload: %v", err)
		}
		fc.mu.Lock()
		fc.payloads = append(fc.payloads, p)
		resp := fc.respond(p)
		fc.mu.Unlock()
		json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(fc.srv.Close)
	return fc
}

func (fc *fakeCentral) last() report.Payload {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	return fc.payloads[len(fc.payloads)-1]
}

func (fc *fakeCentral) count() int {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	return len(fc.payloads)
}

func testRunner(t *testing.T, url string, cheap map[string]CheckFunc, sections []SectionSpec) *Runner {
	t.Helper()
	return &Runner{
		Cfg: &config.Config{
			AgentName:      "test",
			ReportInterval: config.Duration{Duration: 15 * time.Minute},
		},
		Client:      client.New(url, "tok"),
		Log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		Version:     "0.1.0",
		CheapChecks: cheap,
		Sections:    sections,
		StatePath:   filepath.Join(t.TempDir(), "state.json"),
	}
}

// The regression that bit us live: an empty report must serialize findings
// and checks_run as [], never null.
func TestCheapCycleEmptyReportSendsArrays(t *testing.T) {
	fc := newFakeCentral(t)
	var raw []byte
	fc.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ = io.ReadAll(r.Body)
		json.NewEncoder(w).Encode(report.Response{OK: true})
	})

	r := testRunner(t, fc.srv.URL, map[string]CheckFunc{}, nil)
	if err := r.cheapCycle(context.Background()); err != nil {
		t.Fatalf("cheapCycle: %v", err)
	}
	s := string(raw)
	if strings.Contains(s, `"findings":null`) || strings.Contains(s, `"checks_run":null`) {
		t.Fatalf("payload has null arrays: %s", s)
	}
	if !strings.Contains(s, `"findings":[]`) || !strings.Contains(s, `"checks_run":[]`) {
		t.Fatalf("payload missing empty arrays: %s", s)
	}
	if strings.Contains(s, `"sections"`) {
		t.Fatalf("no sections configured, should be omitted: %s", s)
	}
}

func TestCheapCycleErroredCheckExcludedFromChecksRun(t *testing.T) {
	fc := newFakeCentral(t)
	cheap := map[string]CheckFunc{
		"reboot": func(context.Context) ([]report.Finding, error) {
			return []report.Finding{{Kind: "reboot", Subject: "system", Severity: "medium", Title: "reboot"}}, nil
		},
		"apt": func(context.Context) ([]report.Finding, error) { return nil, errors.New("apt lock held") },
	}
	r := testRunner(t, fc.srv.URL, cheap, nil)
	if err := r.cheapCycle(context.Background()); err != nil {
		t.Fatalf("cheapCycle: %v", err)
	}
	p := fc.last()
	if strings.Join(p.ChecksRun, ",") != "reboot" {
		t.Errorf("checks_run = %q, want just reboot (apt errored)", p.ChecksRun)
	}
	if len(p.Findings) != 1 {
		t.Errorf("findings = %d, want 1", len(p.Findings))
	}
}

func imageScanSection(calls *int, findings *[]report.Finding) SectionSpec {
	return SectionSpec{
		Name:     "image-scan",
		Interval: 12 * time.Hour,
		Checks: map[string]CheckFunc{
			"image-cve": func(context.Context) ([]report.Finding, error) {
				*calls++
				return append([]report.Finding(nil), (*findings)...), nil
			},
		},
	}
}

// Body on first report, hash-only after central acks it.
func TestSectionBodyThenHashOnly(t *testing.T) {
	fc := newFakeCentral(t)
	fc.respond = func(p report.Payload) report.Response {
		ack := map[string]string{}
		for name, sec := range p.Sections {
			if sec.Findings != nil { // agent sent a body -> confirm it
				ack[name] = sec.Hash
			}
		}
		return report.Response{OK: true, SectionsAck: ack}
	}

	calls := 0
	findings := []report.Finding{{Kind: "image-cve", Subject: "postgres", Identifier: "CVE-1|libssl3", Severity: "high", Title: "x"}}
	r := testRunner(t, fc.srv.URL, map[string]CheckFunc{}, []SectionSpec{imageScanSection(&calls, &findings)})

	ctx := context.Background()
	if err := r.sectionCycle(ctx, r.Sections[0]); err != nil {
		t.Fatal(err)
	}

	// report 1: body present
	if err := r.cheapCycle(ctx); err != nil {
		t.Fatal(err)
	}
	if sec := fc.last().Sections["image-scan"]; sec.Findings == nil || len(sec.Findings) != 1 {
		t.Fatalf("report 1 should carry the section body, got %+v", sec)
	}

	// reports 2 and 3: hash only, no findings
	for i := 2; i <= 3; i++ {
		if err := r.cheapCycle(ctx); err != nil {
			t.Fatal(err)
		}
		sec := fc.last().Sections["image-scan"]
		if sec.Findings != nil {
			t.Fatalf("report %d should be hash-only, got body %+v", i, sec.Findings)
		}
		if sec.Hash == "" {
			t.Fatalf("report %d missing section hash", i)
		}
	}
	if calls != 1 {
		t.Errorf("heavy check ran %d times, want 1", calls)
	}
}

// central asking for the body (fresh DB / lost report) makes the agent resend.
func TestSectionNeedBodyForcesResend(t *testing.T) {
	fc := newFakeCentral(t)
	askOnce := true
	fc.respond = func(p report.Payload) report.Response {
		resp := report.Response{OK: true, SectionsAck: map[string]string{}}
		for name, sec := range p.Sections {
			if sec.Findings != nil {
				resp.SectionsAck[name] = sec.Hash
			}
		}
		if _, ok := p.Sections["image-scan"]; ok && p.Sections["image-scan"].Findings == nil && askOnce {
			askOnce = false
			resp.SectionsNeedBody = []string{"image-scan"}
		}
		return resp
	}

	calls := 0
	findings := []report.Finding{{Kind: "image-cve", Subject: "postgres", Identifier: "CVE-1|libssl3", Severity: "high", Title: "x"}}
	r := testRunner(t, fc.srv.URL, map[string]CheckFunc{}, []SectionSpec{imageScanSection(&calls, &findings)})
	ctx := context.Background()

	if err := r.sectionCycle(ctx, r.Sections[0]); err != nil {
		t.Fatal(err)
	}
	_ = r.cheapCycle(ctx) // payload[0]: body -> acked
	_ = r.cheapCycle(ctx) // payload[1]: hash-only -> central replies need_body
	_ = r.cheapCycle(ctx) // payload[2]: body again
	_ = r.cheapCycle(ctx) // payload[3]: hash-only again

	fc.mu.Lock()
	defer fc.mu.Unlock()
	bodies := 0
	for _, p := range fc.payloads {
		if p.Sections["image-scan"].Findings != nil {
			bodies++
		}
	}
	if bodies != 2 {
		t.Fatalf("expected 2 body sends (initial + after need_body), got %d", bodies)
	}
	if fc.payloads[1].Sections["image-scan"].Findings != nil {
		t.Errorf("payload[1] should be hash-only (before need_body reply is applied)")
	}
	if fc.payloads[2].Sections["image-scan"].Findings == nil {
		t.Errorf("payload[2] should resend the body after need_body")
	}
	if fc.payloads[3].Sections["image-scan"].Findings != nil {
		t.Errorf("payload[3] should be hash-only again")
	}
}

// a re-scan that changes the findings bumps the hash and resends the body.
func TestSectionRescanChangeResendsBody(t *testing.T) {
	fc := newFakeCentral(t)
	fc.respond = func(p report.Payload) report.Response {
		ack := map[string]string{}
		for name, sec := range p.Sections {
			if sec.Findings != nil {
				ack[name] = sec.Hash
			}
		}
		return report.Response{OK: true, SectionsAck: ack}
	}

	calls := 0
	findings := []report.Finding{{Kind: "image-cve", Subject: "postgres", Identifier: "CVE-1|libssl3", Severity: "high", Title: "x"}}
	spec := imageScanSection(&calls, &findings)
	r := testRunner(t, fc.srv.URL, map[string]CheckFunc{}, []SectionSpec{spec})
	ctx := context.Background()

	_ = r.sectionCycle(ctx, spec)
	_ = r.cheapCycle(ctx) // body
	_ = r.cheapCycle(ctx) // hash-only
	h1 := fc.last().Sections["image-scan"].Hash

	// new CVE shows up on the next heavy scan
	findings = append(findings, report.Finding{Kind: "image-cve", Subject: "postgres", Identifier: "CVE-2|zlib", Severity: "critical", Title: "y"})
	_ = r.sectionCycle(ctx, spec)
	_ = r.cheapCycle(ctx) // should carry the new body

	sec := fc.last().Sections["image-scan"]
	if sec.Findings == nil || len(sec.Findings) != 2 {
		t.Fatalf("re-scan change should resend body with 2 findings, got %+v", sec)
	}
	if sec.Hash == h1 {
		t.Errorf("hash should change after the finding set changed")
	}
}

// one Oneshot fully syncs; a second Oneshot sends hash-only.
func TestOneshotSyncsThenHashOnly(t *testing.T) {
	fc := newFakeCentral(t)
	fc.respond = func(p report.Payload) report.Response {
		ack := map[string]string{}
		for name, sec := range p.Sections {
			if sec.Findings != nil {
				ack[name] = sec.Hash
			}
		}
		return report.Response{OK: true, SectionsAck: ack}
	}
	calls := 0
	findings := []report.Finding{{Kind: "image-cve", Subject: "postgres", Identifier: "CVE-1|libssl3", Severity: "high", Title: "x"}}
	r := testRunner(t, fc.srv.URL, map[string]CheckFunc{"reboot": func(context.Context) ([]report.Finding, error) { return nil, nil }},
		[]SectionSpec{imageScanSection(&calls, &findings)})
	ctx := context.Background()

	if err := r.Oneshot(ctx); err != nil {
		t.Fatal(err)
	}
	if fc.payloads[0].Sections["image-scan"].Findings == nil {
		t.Fatal("first Oneshot report should carry the body")
	}
	if err := r.Oneshot(ctx); err != nil {
		t.Fatal(err)
	}
	if got := fc.payloads[fc.count()-1].Sections["image-scan"].Findings; got != nil {
		t.Fatalf("second Oneshot should be hash-only, got %+v", got)
	}
}

type fakeUpdater struct {
	updated bool
	called  int
	lastVer string
}

func (f *fakeUpdater) Apply(_ context.Context, resp *report.Response) (bool, error) {
	f.called++
	f.lastVer = resp.DesiredVersion
	return f.updated, nil
}

func TestMaybeSelfUpdateExitsOnSwap(t *testing.T) {
	fc := newFakeCentral(t)
	fc.respond = func(report.Payload) report.Response {
		return report.Response{OK: true, DesiredVersion: "0.9.0", URL: "http://x/b", SHA256: "ab", SigURL: "http://x/b.sig"}
	}
	fu := &fakeUpdater{updated: true}
	r := testRunner(t, fc.srv.URL, map[string]CheckFunc{}, nil)
	r.Cfg.SelfUpdate = true
	r.Updater = fu

	var exitCode = -1
	old := exit
	exit = func(c int) { exitCode = c; panic("exit") }
	defer func() { exit = old; recover() }()

	func() {
		defer func() { recover() }()
		_ = r.cheapCycle(context.Background())
	}()

	if fu.called != 1 || fu.lastVer != "0.9.0" {
		t.Errorf("updater called %d times, ver %q", fu.called, fu.lastVer)
	}
	if exitCode != 0 {
		t.Errorf("expected exit(0) after a swap, got %d", exitCode)
	}
}

func TestMaybeSelfUpdateSkippedOutsideWindow(t *testing.T) {
	fc := newFakeCentral(t)
	fc.respond = func(report.Payload) report.Response {
		return report.Response{OK: true, DesiredVersion: "0.9.0", URL: "http://x/b", SHA256: "ab", SigURL: "http://x/b.sig"}
	}
	fu := &fakeUpdater{updated: true}
	r := testRunner(t, fc.srv.URL, map[string]CheckFunc{}, nil)
	r.Cfg.SelfUpdate = true
	r.Cfg.UpdateWindow = "02:00-02:01" // ~never
	r.Updater = fu
	if err := r.cheapCycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fu.called != 0 {
		t.Errorf("updater should not run outside the window, called %d", fu.called)
	}
}

// ---- input-change rescans ----

// inputsSection is an image-scan whose result depends on a mutable "ref".
func inputsSection(ref *string, calls *int, ackedRefs *[]string) SectionSpec {
	return SectionSpec{
		Name:     "image-scan",
		Interval: 12 * time.Hour,
		Inputs:   func() (string, error) { return *ref, nil },
		Scans:    func() []report.Scan { return []report.Scan{{Ref: *ref, Digest: "sha256:d"}} },
		Checks: map[string]CheckFunc{
			"image-cve": func(context.Context) ([]report.Finding, error) {
				*calls++
				// same finding set whatever the ref: only the scan provenance moves
				return []report.Finding{{Kind: "image-cve", Subject: "hc", Identifier: "CVE-1|x", Severity: "high"}}, nil
			},
		},
	}
}

func TestInputsChangeTriggersRescanAndNewBody(t *testing.T) {
	fc := newFakeCentral(t)
	fc.respond = func(p report.Payload) report.Response {
		ack := map[string]string{}
		for name, sec := range p.Sections {
			if sec.Findings != nil {
				ack[name] = sec.Hash
			}
		}
		return report.Response{OK: true, SectionsAck: ack}
	}
	ref, calls := "hc:4.4-1", 0
	r := testRunner(t, fc.srv.URL, map[string]CheckFunc{}, []SectionSpec{inputsSection(&ref, &calls, nil)})
	ctx := context.Background()

	if err := r.Oneshot(ctx); err != nil { // scan + body
		t.Fatal(err)
	}
	if r.rescanChanged(ctx) {
		t.Fatal("unchanged inputs must not rescan")
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1", calls)
	}
	if err := r.cheapCycle(ctx); err != nil {
		t.Fatal(err)
	}
	if fc.last().Sections["image-scan"].Findings != nil {
		t.Fatal("acked section should be hash-only")
	}
	oldHash := fc.last().Sections["image-scan"].Hash

	ref = "hc:4.4-2" // compose repointed
	if !r.rescanChanged(ctx) {
		t.Fatal("changed inputs must rescan")
	}
	if calls != 2 {
		t.Fatalf("calls = %d, want 2", calls)
	}
	if err := r.cheapCycle(ctx); err != nil {
		t.Fatal(err)
	}
	sec := fc.last().Sections["image-scan"]
	if sec.Hash == oldHash {
		t.Error("identical finding set but new ref must still change the hash")
	}
	if sec.Findings == nil {
		t.Error("new hash must carry a body")
	}
	if len(sec.Scans) != 1 || sec.Scans[0].Ref != "hc:4.4-2" {
		t.Errorf("scans = %+v", sec.Scans)
	}
	if r.rescanChanged(ctx) {
		t.Error("rescan should settle once inputs match")
	}
}

func TestLegacyStateWithoutInputsRescansOnce(t *testing.T) {
	ref, calls := "hc:4.4-1", 0
	r := testRunner(t, "http://unused", map[string]CheckFunc{}, []SectionSpec{inputsSection(&ref, &calls, nil)})
	st := &stateFile{Sections: map[string]sectionState{"image-scan": {Hash: "h", GeneratedAt: time.Now(), Kinds: []string{"image-cve"}}}}
	r.mu.Lock()
	_ = r.writeState(st)
	r.mu.Unlock()
	if !r.rescanChanged(context.Background()) || calls != 1 {
		t.Fatalf("legacy cache should rescan once (calls=%d)", calls)
	}
	if r.rescanChanged(context.Background()) {
		t.Fatal("second pass should be quiet")
	}
}

func TestFailedRescanBacksOff(t *testing.T) {
	ref, calls := "hc:bad", 0
	spec := inputsSection(&ref, &calls, nil)
	spec.Checks["image-cve"] = func(context.Context) ([]report.Finding, error) {
		calls++
		return nil, errors.New("trivy: manifest unknown")
	}
	r := testRunner(t, "http://unused", map[string]CheckFunc{}, []SectionSpec{spec})
	ctx := context.Background()
	r.rescanChanged(ctx)
	r.rescanChanged(ctx)
	r.rescanChanged(ctx)
	if calls != 1 {
		t.Errorf("a failing ref was scanned %d times within the retry window, want 1", calls)
	}
	r.RescanRetry = time.Nanosecond
	time.Sleep(time.Millisecond)
	r.rescanChanged(ctx)
	if calls != 2 {
		t.Errorf("retry after the window: calls = %d, want 2", calls)
	}
}

func TestSectionStaleOnInputsChange(t *testing.T) {
	ref, calls := "hc:4.4-1", 0
	r := testRunner(t, "http://unused", map[string]CheckFunc{}, []SectionSpec{inputsSection(&ref, &calls, nil)})
	if err := r.sectionCycle(context.Background(), r.Sections[0]); err != nil {
		t.Fatal(err)
	}
	if r.sectionStale(r.Sections[0]) {
		t.Fatal("fresh scan with same inputs is not stale")
	}
	ref = "hc:4.4-2"
	if !r.sectionStale(r.Sections[0]) {
		t.Fatal("changed inputs make a fresh scan stale (restart path)")
	}
}

// Central re-sends the request until the agent echoes rescan_done; the agent
// must rescan once, echo the id, and stop echoing once central clears it.
func TestRequestedRescanRunsOnceAndIsEchoed(t *testing.T) {
	fc := newFakeCentral(t)
	pending := true
	fc.respond = func(p report.Payload) report.Response {
		if p.RescanDone == "r1" {
			pending = false
		}
		if pending {
			return report.Response{OK: true, Rescan: &report.Rescan{ID: "r1", Sections: []string{"image-scan"}}}
		}
		return report.Response{OK: true}
	}
	var calls int
	findings := []report.Finding{}
	r := testRunner(t, fc.srv.URL, map[string]CheckFunc{}, []SectionSpec{imageScanSection(&calls, &findings)})
	ctx := context.Background()

	if err := r.cheapCycle(ctx); err != nil { // receives the request, rescans in the background
		t.Fatal(err)
	}
	r.bg.Wait()
	if calls != 1 {
		t.Fatalf("scan calls = %d, want 1", calls)
	}
	if got := fc.last().RescanDone; got != "r1" {
		t.Fatalf("follow-up report rescan_done = %q, want r1", got)
	}
	if err := r.cheapCycle(ctx); err != nil { // central cleared it
		t.Fatal(err)
	}
	r.bg.Wait()
	if calls != 1 {
		t.Errorf("scan calls = %d after clear, want still 1", calls)
	}
	if err := r.cheapCycle(ctx); err != nil {
		t.Fatal(err)
	}
	if got := fc.last().RescanDone; got != "" {
		t.Errorf("rescan_done = %q, want it dropped once central stopped sending the request", got)
	}
}

func TestRequestedRescanSkipsOtherSections(t *testing.T) {
	fc := newFakeCentral(t)
	fc.respond = func(report.Payload) report.Response {
		return report.Response{OK: true, Rescan: &report.Rescan{ID: "r2", Sections: []string{"daily"}}}
	}
	var calls int
	findings := []report.Finding{}
	r := testRunner(t, fc.srv.URL, map[string]CheckFunc{}, []SectionSpec{imageScanSection(&calls, &findings)})
	if err := r.cheapCycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.bg.Wait()
	if calls != 0 {
		t.Errorf("image-scan ran %d times for a daily-only request", calls)
	}
}

// Regression: Run must itself notice changed inputs; rescanInBackground was
// once defined but never called from the cheap tick.
func TestRunRescansOnInputsChange(t *testing.T) {
	fc := newFakeCentral(t)
	ref, calls := "hc:4.4-1", 0
	r := testRunner(t, fc.srv.URL, map[string]CheckFunc{}, []SectionSpec{inputsSection(&ref, &calls, nil)})
	r.Cfg.ReportInterval = config.Duration{Duration: 50 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	time.Sleep(120 * time.Millisecond)
	r.mu.Lock()
	ref = "hc:4.4-2"
	r.mu.Unlock()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		n := calls
		r.mu.Unlock()
		if n >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	if calls < 2 {
		t.Fatalf("calls = %d, want a rescan after the ref changed", calls)
	}
}
