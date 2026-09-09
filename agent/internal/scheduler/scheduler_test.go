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

	"github.com/pedrohardware/picket/agent/internal/client"
	"github.com/pedrohardware/picket/agent/internal/config"
	"github.com/pedrohardware/picket/agent/internal/report"
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
