package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/osk4r8088/altlast/internal/findings"
	"github.com/osk4r8088/altlast/internal/store"
)

var eolFinding = findings.Finding{
	Type: findings.TypeEOL, Severity: findings.SeverityHigh,
	Key: "1.20", Detail: "unsupported since 2022-05-24",
}

// newStore opens a fresh database for one test.
func newStore(t *testing.T) *store.Store {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// scan records one complete scan in which each named asset produced the
// given findings, and returns the scan id.
func scan(t *testing.T, db *store.Store, assets map[string][]findings.Finding) int64 {
	t.Helper()
	ctx := context.Background()

	id, err := db.BeginScan(ctx, "testhost")
	if err != nil {
		t.Fatalf("BeginScan: %v", err)
	}

	for name, found := range assets {
		err := db.RecordObservation(ctx, id, store.Observation{
			Host: "testhost", Kind: "container", Name: name,
			Repository: "library/nginx", Tag: "1.20", Version: "1.20", VersionSource: "tag",
		})
		if err != nil {
			t.Fatalf("RecordObservation: %v", err)
		}
		if err := db.ReconcileFindings(ctx, id, "testhost", "container", name, found, nil); err != nil {
			t.Fatalf("ReconcileFindings: %v", err)
		}
	}

	if err := db.FinishScan(ctx, id, len(assets), 0); err != nil {
		t.Fatalf("FinishScan: %v", err)
	}
	return id
}

// openFinding returns the single open finding, failing if there is not
// exactly one.
func openFinding(t *testing.T, db *store.Store) store.FindingRecord {
	t.Helper()
	open, err := db.OpenFindings(context.Background())
	if err != nil {
		t.Fatalf("OpenFindings: %v", err)
	}
	if len(open) != 1 {
		t.Fatalf("got %d open findings, want 1", len(open))
	}
	return open[0]
}

func handler(t *testing.T, db *store.Store, opts Options) http.Handler {
	t.Helper()
	srv, err := NewServer(db, "test", opts)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return srv.Handler()
}

// loopbackOpts matches what serve uses on its default address.
var loopbackOpts = Options{AllowMute: true, LoopbackOnly: true}

// get and postForm build requests addressed the way a browser on this
// machine would address them. httptest defaults to Host example.com, which
// the loopback check would rightly refuse.
func get(target string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Host = "127.0.0.1:8080"
	return req
}

func postForm(target string, form url.Values) *http.Request {
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "127.0.0.1:8080"
	return req
}

func serve(h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestDashboardShowsFindings(t *testing.T) {
	db := newStore(t)
	scan(t, db, map[string][]findings.Finding{"web": {eolFinding}, "cache": nil})

	rec := serve(handler(t, db, loopbackOpts), get("/"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()
	for _, want := range []string{
		"New since the previous scan",
		"unsupported since 2022-05-24",
		`action="/findings/`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
}

// TestQuietScanHasNoAttentionPanel guards "silence is the goal": a scan that
// opened nothing must not draw attention to anything.
func TestQuietScanHasNoAttentionPanel(t *testing.T) {
	db := newStore(t)
	scan(t, db, map[string][]findings.Finding{"web": {eolFinding}})
	scan(t, db, map[string][]findings.Finding{"web": {eolFinding}})

	body := serve(handler(t, db, loopbackOpts), get("/")).Body.String()
	if strings.Contains(body, "New since the previous scan") {
		t.Error("attention panel shown for a scan that opened nothing")
	}
	if !strings.Contains(body, "unsupported since 2022-05-24") {
		t.Error("persisting finding missing from open findings")
	}
}

// TestUnobservedAssetIsLabelled covers findings on an asset the latest scan
// did not see. They stay open, and the page must say why they have no row
// in the asset table.
func TestUnobservedAssetIsLabelled(t *testing.T) {
	db := newStore(t)
	scan(t, db, map[string][]findings.Finding{"web": {eolFinding}})
	scan(t, db, map[string][]findings.Finding{"other": nil})

	body := serve(handler(t, db, loopbackOpts), get("/")).Body.String()
	if !strings.Contains(body, "no longer observed") {
		t.Error("finding on an unobserved asset is not labelled")
	}
}

func TestMute(t *testing.T) {
	tests := []struct {
		name       string
		form       url.Values
		wantStatus int
		wantMuted  bool
		wantBody   string
	}{
		{
			name:       "reason and expiry",
			form:       url.Values{"reason": {"isolated, no external access"}, "until": {"90d"}},
			wantStatus: http.StatusSeeOther,
			wantMuted:  true,
		},
		{
			name:       "missing reason",
			form:       url.Values{"reason": {"   "}, "until": {"90d"}},
			wantStatus: http.StatusUnprocessableEntity,
			wantBody:   "a reason is required",
		},
		{
			name:       "missing expiry",
			form:       url.Values{"reason": {"isolated"}},
			wantStatus: http.StatusUnprocessableEntity,
			wantBody:   "an expiry is required",
		},
		{
			name:       "unreadable expiry",
			form:       url.Values{"reason": {"isolated"}, "until": {"soon"}},
			wantStatus: http.StatusUnprocessableEntity,
			wantBody:   "cannot read",
		},
		{
			name:       "expiry in the past",
			form:       url.Values{"reason": {"isolated"}, "until": {"2020-01-01"}},
			wantStatus: http.StatusUnprocessableEntity,
			wantBody:   "in the future",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := newStore(t)
			scan(t, db, map[string][]findings.Finding{"web": {eolFinding}})
			f := openFinding(t, db)

			target := "/findings/" + strconv.FormatInt(f.ID, 10) + "/mute"
			rec := serve(handler(t, db, loopbackOpts), postForm(target, tt.form))

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if tt.wantBody != "" && !strings.Contains(rec.Body.String(), tt.wantBody) {
				t.Errorf("body missing %q", tt.wantBody)
			}
			if got := openFinding(t, db).Muted; got != tt.wantMuted {
				t.Errorf("muted = %v, want %v", got, tt.wantMuted)
			}
		})
	}
}

// TestMuteRejected covers every way a mute request must be refused without
// changing anything.
func TestMuteRejected(t *testing.T) {
	form := url.Values{"reason": {"isolated"}, "until": {"90d"}}

	tests := []struct {
		name       string
		opts       Options
		host       string // replaces the loopback Host header when set
		fetchSite  string // Sec-Fetch-Site header the browser sends, when set
		wantStatus int
	}{
		{
			// A hidden form on another site, submitted by the browser.
			name:       "cross-site request",
			opts:       loopbackOpts,
			fetchSite:  "cross-site",
			wantStatus: http.StatusForbidden,
		},
		{
			// DNS rebinding: the browser considers it same-origin, so only
			// the Host header gives it away.
			name:       "rebound hostname",
			opts:       loopbackOpts,
			host:       "attacker.example:8080",
			fetchSite:  "same-origin",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "muting disabled",
			opts:       Options{AllowMute: false},
			wantStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := newStore(t)
			scan(t, db, map[string][]findings.Finding{"web": {eolFinding}})
			f := openFinding(t, db)

			req := postForm("/findings/"+strconv.FormatInt(f.ID, 10)+"/mute", form)
			if tt.host != "" {
				req.Host = tt.host
			}
			if tt.fetchSite != "" {
				req.Header.Set("Sec-Fetch-Site", tt.fetchSite)
			}
			rec := serve(handler(t, db, tt.opts), req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if openFinding(t, db).Muted {
				t.Error("finding was muted by a request that should have been refused")
			}
		})
	}
}

func TestUnmute(t *testing.T) {
	db := newStore(t)
	scan(t, db, map[string][]findings.Finding{"web": {eolFinding}})
	ctx := context.Background()

	if err := db.MuteFinding(ctx, openFinding(t, db), "isolated", time.Now().Add(24*time.Hour)); err != nil {
		t.Fatalf("MuteFinding: %v", err)
	}
	mutes, err := db.Mutes(ctx)
	if err != nil || len(mutes) != 1 {
		t.Fatalf("Mutes = %v, %v; want one mute", mutes, err)
	}

	target := "/mutes/" + strconv.FormatInt(mutes[0].ID, 10) + "/unmute"
	rec := serve(handler(t, db, loopbackOpts), postForm(target, nil))

	if rec.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want 303", rec.Code)
	}
	if openFinding(t, db).Muted {
		t.Error("finding still muted after unmute")
	}
}

// TestDashboardLeavesLapsedMutesUnreported guards against the dashboard
// calling ExpiredMutes, which marks lapsed mutes as reported. A page load
// would then consume the one-time notice the next scan is meant to print.
func TestDashboardLeavesLapsedMutesUnreported(t *testing.T) {
	db := newStore(t)
	scan(t, db, map[string][]findings.Finding{"web": {eolFinding}})
	ctx := context.Background()

	// Expiries are stored to the second, and a mute must start in the
	// future, so the shortest honest lapse is about a second.
	if err := db.MuteFinding(ctx, openFinding(t, db), "isolated", time.Now().Add(time.Second)); err != nil {
		t.Fatalf("MuteFinding: %v", err)
	}
	time.Sleep(1100 * time.Millisecond)

	if rec := serve(handler(t, db, loopbackOpts), get("/")); rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	lapsed, err := db.ExpiredMutes(ctx)
	if err != nil {
		t.Fatalf("ExpiredMutes: %v", err)
	}
	if len(lapsed) != 1 {
		t.Errorf("got %d unreported lapsed mutes after a page load, want 1", len(lapsed))
	}
}

func TestIsLoopback(t *testing.T) {
	tests := []struct {
		hostport string
		want     bool
	}{
		{"127.0.0.1:8080", true},
		{"localhost:8080", true},
		{"LOCALHOST:8080", true},
		{"[::1]:8080", true},
		{"localhost", true},
		{"[::1]", true},
		{":8080", false},
		{"0.0.0.0:8080", false},
		{"192.168.1.20:8080", false},
		{"attacker.example:8080", false},
		// A public name that resolves to 127.0.0.1 is exactly what DNS
		// rebinding uses, so the name itself must not pass.
		{"127.0.0.1.nip.io:8080", false},
	}

	for _, tt := range tests {
		t.Run(tt.hostport, func(t *testing.T) {
			if got := IsLoopback(tt.hostport); got != tt.want {
				t.Errorf("IsLoopback(%q) = %v, want %v", tt.hostport, got, tt.want)
			}
		})
	}
}
