// Package web serves the Altlast dashboard.
//
// The server never triggers a scan and never touches what Altlast observes:
// it renders whatever the most recent scan recorded. Scanning is a separate
// command, so the dashboard never blocks on the network and needs no Docker
// access. Its only writes are mutes, which change Altlast's own records.
package web

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/osk4r8088/altlast/internal/findings"
	"github.com/osk4r8088/altlast/internal/store"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

// Options controls what the dashboard allows.
type Options struct {
	// AllowMute enables muting and unmuting from the dashboard. The server
	// has no login, so anyone who can reach it can use these actions.
	AllowMute bool

	// LoopbackOnly rejects requests whose Host header is not a loopback
	// name. Set it when listening on loopback: it defeats DNS rebinding,
	// where a hostile page points its own domain at 127.0.0.1 and becomes,
	// as far as the browser is concerned, same-origin with the dashboard.
	LoopbackOnly bool
}

// Server renders the dashboard from the database.
type Server struct {
	store   *store.Store
	tmpl    *template.Template
	version string
	opts    Options
}

// NewServer parses the embedded templates and returns a ready server.
func NewServer(st *store.Store, version string, opts Options) (*Server, error) {
	tmpl, err := template.ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("parsing templates: %w", err)
	}
	return &Server{store: st, tmpl: tmpl, version: version, opts: opts}, nil
}

// Handler returns the HTTP routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.dashboard)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	mux.Handle("GET /static/", http.FileServer(http.FS(staticFS)))

	// Unregistered rather than refusing inside the handler, so a disabled
	// action does not exist at all.
	if s.opts.AllowMute {
		mux.HandleFunc("POST /findings/{id}/mute", s.mute)
		mux.HandleFunc("POST /mutes/{id}/unmute", s.unmute)
	}

	// Rejects state-changing requests a browser marks as cross-site, so a
	// page elsewhere cannot submit a hidden form that silences a finding.
	h := http.NewCrossOriginProtection().Handler(mux)

	if s.opts.LoopbackOnly {
		h = requireLoopbackHost(h)
	}
	return h
}

// IsLoopback reports whether a host or host:port names the loopback
// interface. An empty host, as in ":8080", listens everywhere and is not.
func IsLoopback(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")

	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// requireLoopbackHost refuses requests addressed to any non-loopback name.
// It applies to reads too: a rebound page could otherwise read the register
// of everything unsupported on this host.
func requireLoopbackHost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !IsLoopback(r.Host) {
			http.Error(w, "unexpected Host header: open the dashboard via localhost or 127.0.0.1",
				http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// pageData is what every template receives. View models are built here
// rather than in the templates: display logic in Go is testable, display
// logic in a template is not.
type pageData struct {
	Title   string
	Version string
	HasScan bool
	Scan    store.Scan
	ScanAge string
	Summary summary
	Assets  []assetRow

	// New holds unmuted findings opened by the latest scan. The template
	// shows nothing when it is empty: a quiet scan is the goal.
	New      []findingRow
	Resolved int
	Open     []findingRow
	Muted    []findingRow

	MuteEnabled bool
}

type summary struct {
	Total   int
	EOL     int
	Ending  int
	Behind  int
	Unknown int
}

type assetRow struct {
	Name          string
	Repository    string
	Version       string
	Age           string
	AgeTitle      string
	NewerMajor    int64
	FromLabel     bool
	Latest        string
	Behind        int64
	HasBehind     bool
	BehindBand    string
	State         string
	ShowState     bool
	SupportState  string
	SupportText   string
	SupportDetail string
}

type findingRow struct {
	ID        int64
	Asset     string
	Label     string
	Severity  string
	Detail    string
	OpenFor   string
	OpenTitle string

	// New means the latest scan opened it.
	New bool

	// Unobserved means the asset was absent from the latest scan. Findings
	// only resolve for assets a scan sees, so a removed container's findings
	// stay open; saying so beats leaving a row with no matching asset.
	Unobserved bool

	// Set for muted findings.
	MuteID      int64
	MuteReason  string
	MuteExpires string
	MuteLeft    string

	// Set when a mute submission for this finding was rejected, so the form
	// reopens with the error and what was typed.
	FormError  string
	FormReason string
	FormUntil  string
}

// findingLabels names finding types for display.
var findingLabels = map[string]string{
	string(findings.TypeEOL):            "end of life",
	string(findings.TypeEOLApproaching): "EOL approaching",
	string(findings.TypeNewerMajor):     "newer major line",
	string(findings.TypeResolveError):   "upstream check failed",
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	data, err := s.page(ctx)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, http.StatusOK, data)
}

// page loads everything the dashboard shows.
func (s *Server) page(ctx context.Context) (pageData, error) {
	data := pageData{Title: "Dashboard", Version: s.version, MuteEnabled: s.opts.AllowMute}

	scan, err := s.store.LatestScan(ctx)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// No scan yet is an empty dashboard, not an error.
		return data, nil
	case err != nil:
		return data, err
	}

	assets, err := s.store.AssetsForScan(ctx, scan.ID)
	if err != nil {
		return data, err
	}

	data.HasScan = true
	data.Scan = scan
	data.ScanAge = humanAge(scan.StartedAt)
	data.Assets = make([]assetRow, 0, len(assets))

	observed := make(map[string]bool, len(assets))

	for _, a := range assets {
		observed[a.Name] = true

		row := buildRow(a)
		data.Assets = append(data.Assets, row)

		data.Summary.Total++
		switch a.SupportState {
		case "eol":
			data.Summary.EOL++
		case "ending":
			data.Summary.Ending++
		case "unknown":
			data.Summary.Unknown++
		}
		if row.HasBehind && row.Behind > 0 {
			data.Summary.Behind++
		}
	}

	open, err := s.store.OpenFindings(ctx)
	if err != nil {
		return data, err
	}

	// Mutes, not ExpiredMutes: that one marks lapsed mutes as reported, and
	// a page load must not use up the notice the next scan prints.
	mutes, err := s.store.Mutes(ctx)
	if err != nil {
		return data, err
	}

	resolved, err := s.store.ResolvedInScan(ctx, scan.ID)
	if err != nil {
		return data, err
	}

	data.New, data.Open, data.Muted = buildFindings(scan.ID, open, mutes, observed)
	data.Resolved = len(resolved)

	return data, nil
}

// buildFindings splits open findings into what the dashboard shows: new in
// the latest scan, open, and muted. New findings also appear in the open
// list, which is the complete register; the new panel only draws attention.
func buildFindings(
	scanID int64, open []store.FindingRecord, mutes []store.Mute, observed map[string]bool,
) (newRows, openRows, mutedRows []findingRow) {
	type identity struct {
		assetID  int64
		typ, key string
	}
	muteByIdentity := make(map[identity]store.Mute, len(mutes))
	for _, m := range mutes {
		muteByIdentity[identity{m.AssetID, m.Type, m.Key}] = m
	}

	for _, f := range open {
		row := findingRow{
			ID:         f.ID,
			Asset:      f.Asset,
			Label:      findingLabels[f.Type],
			Severity:   f.Severity,
			Detail:     f.Detail,
			New:        f.FirstScanID == scanID,
			Unobserved: !observed[f.Asset],
		}
		if row.Label == "" {
			row.Label = f.Type
		}
		if seen, err := time.Parse(time.RFC3339, f.FirstSeen); err == nil {
			row.OpenFor = humanDuration(time.Since(seen))
			row.OpenTitle = "first seen " + f.FirstSeen
		}

		if !f.Muted {
			openRows = append(openRows, row)
			if row.New {
				newRows = append(newRows, row)
			}
			continue
		}

		if m, ok := muteByIdentity[identity{f.AssetID, f.Type, f.Key}]; ok {
			row.MuteID = m.ID
			row.MuteReason = m.Reason
			row.MuteLeft = daysLeft(m.DaysLeft())
			row.MuteExpires = m.ExpiresAt
			if t, err := time.Parse(time.RFC3339, m.ExpiresAt); err == nil {
				row.MuteExpires = t.Format("2006-01-02")
			}
		}
		mutedRows = append(mutedRows, row)
	}

	return newRows, openRows, mutedRows
}

func daysLeft(n int) string {
	if n < 1 {
		return "ends today"
	}
	return fmt.Sprintf("%dd left", n)
}

// maxFormBytes bounds a mute submission. A reason is a sentence, not a
// document.
const maxFormBytes = 16 << 10

// mute handles the mute form. It enforces what the CLI enforces: a reason
// and an expiry in the future are both required.
func (s *Server) mute(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	reason := strings.TrimSpace(r.PostFormValue("reason"))
	until := strings.TrimSpace(r.PostFormValue("until"))

	reject := func(msg string) {
		s.renderMuteError(ctx, w, id, msg, reason, until)
	}

	if reason == "" {
		reject("a reason is required: a mute without one is an unexplained silence")
		return
	}
	if until == "" {
		reject("an expiry is required: a mute without one never gets reviewed")
		return
	}

	expiry, err := store.ParseDuration(until)
	if err != nil {
		reject(err.Error())
		return
	}

	f, err := s.store.OpenFinding(ctx, id)
	if errors.Is(err, store.ErrNoSuchFinding) {
		http.Error(w, "this finding is no longer open; a newer scan may have resolved it",
			http.StatusNotFound)
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}

	if err := s.store.MuteFinding(ctx, f, reason, expiry); err != nil {
		reject(err.Error())
		return
	}

	// Redirect after a successful POST, so reloading the page does not
	// submit the form again.
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// renderMuteError redraws the dashboard with the rejected form reopened.
func (s *Server) renderMuteError(ctx context.Context, w http.ResponseWriter, id int64, msg, reason, until string) {
	data, err := s.page(ctx)
	if err != nil {
		s.fail(w, err)
		return
	}

	for i := range data.Open {
		if data.Open[i].ID == id {
			data.Open[i].FormError = msg
			data.Open[i].FormReason = reason
			data.Open[i].FormUntil = until
		}
	}

	s.render(w, http.StatusUnprocessableEntity, data)
}

// unmute removes a mute. Removing one that is already gone is not an
// error: the outcome the user asked for holds either way.
func (s *Server) unmute(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	if _, err := s.store.DeleteMute(ctx, id); err != nil {
		s.fail(w, err)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// buildRow turns a database row into something a template can print
// without making decisions.
func buildRow(a store.AssetView) assetRow {
	row := assetRow{
		Name:         a.Name,
		Repository:   a.Repository,
		Version:      a.Version,
		FromLabel:    a.VersionSource == "oci-label",
		Latest:       a.Latest,
		State:        a.State,
		ShowState:    notableState(a.State),
		SupportState: a.SupportState,
	}

	if a.Behind.Valid {
		row.HasBehind = true
		row.Behind = a.Behind.Int64
		row.BehindBand = behindBand(a.Behind.Int64)
	}

	if row.Latest == "" {
		row.Latest = "–" // en dash
	}

	switch a.SupportState {
	case "eol":
		row.SupportText = "end of life"
		row.SupportDetail = a.EOLDate
	case "ending":
		row.SupportText = "ending"
		if a.EOLDays.Valid {
			row.SupportDetail = fmt.Sprintf("%d days", a.EOLDays.Int64)
		}
	case "supported":
		row.SupportText = "supported"
		// The cycle is only worth showing when it says something the
		// version does not. "cycle 2" beside version 2.11.4 is noise.
		if a.EOLCycle != "" && !strings.HasPrefix(a.Version, a.EOLCycle) {
			row.SupportDetail = "cycle " + a.EOLCycle
		}
	default:
		row.SupportText = "unknown"
	}

	// Two different durations, and the distinction matters. For an asset
	// past EOL, the useful number is how long it has been unsupported,
	// which is a fact about the software. Otherwise fall back to how long
	// we have been watching it, which is a fact about us.
	if a.SupportState == "eol" && a.EOLDate != "" {
		if eol, err := time.Parse("2006-01-02", a.EOLDate); err == nil {
			row.Age = humanDuration(time.Since(eol))
			row.AgeTitle = "unsupported since " + a.EOLDate
		}
	} else if seen, err := time.Parse(time.RFC3339, a.FirstSeen); err == nil {
		row.Age = humanDuration(time.Since(seen))
		row.AgeTitle = "first observed " + a.FirstSeen
	}

	if a.NewerMajor.Valid {
		row.NewerMajor = a.NewerMajor.Int64
	}

	return row
}

// notableState reports whether a container state is worth showing. Running
// is the norm and created is unremarkable; only states suggesting something
// went wrong earn a chip.
func notableState(state string) bool {
	switch state {
	case "exited", "dead", "paused", "restarting":
		return true
	default:
		return false
	}
}

// behindBand buckets how far behind an asset is, for colouring. The
// thresholds are deliberately coarse: the point is a glanceable ramp, not
// a precise measure.
func behindBand(n int64) string {
	switch {
	case n == 0:
		return "none"
	case n < 5:
		return "low"
	case n < 25:
		return "mid"
	default:
		return "high"
	}
}

// humanAge renders an RFC3339 timestamp as a rough interval.
func humanAge(ts string) string {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return ""
	}

	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%d min ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%d h ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%d days ago", int(d.Hours()/24))
	}
}

// humanDuration renders a duration at a coarseness suited to the scale.
// Precision beyond this is false confidence: nobody needs to know an asset
// has been unsupported for 1,384 days rather than roughly four years.
func humanDuration(d time.Duration) string {
	days := int(d.Hours() / 24)
	switch {
	case days < 1:
		return "today"
	case days < 60:
		return fmt.Sprintf("%dd", days)
	case days < 730:
		return fmt.Sprintf("%dmo", days/30)
	default:
		return fmt.Sprintf("%.1fy", float64(days)/365)
	}
}

func (s *Server) render(w http.ResponseWriter, status int, data pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := s.tmpl.ExecuteTemplate(w, "layout.html", data); err != nil {
		// The response may be partly written by now, so there is nothing
		// useful to send. Log and move on.
		fmt.Printf("template error: %v\n", err)
	}
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	http.Error(w, "internal error: "+err.Error(), http.StatusInternalServerError)
}
