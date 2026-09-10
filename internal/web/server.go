// Package web serves the Altlast dashboard.
//
// The server is read only: it renders whatever the most recent scan
// recorded and never triggers one. Scanning is a separate command, so the
// dashboard never blocks on the network and needs no Docker access.
package web

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/osk4r8088/altlast/internal/store"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

// Server renders the dashboard from the database.
type Server struct {
	store   *store.Store
	tmpl    *template.Template
	version string
}

// NewServer parses the embedded templates and returns a ready server.
func NewServer(st *store.Store, version string) (*Server, error) {
	tmpl, err := template.ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("parsing templates: %w", err)
	}
	return &Server{store: st, tmpl: tmpl, version: version}, nil
}

// Handler returns the HTTP routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.dashboard)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	mux.Handle("GET /static/", http.FileServer(http.FS(staticFS)))
	return mux
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

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	data := pageData{Title: "Dashboard", Version: s.version}

	scan, err := s.store.LatestScan(ctx)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// No scan yet is an empty dashboard, not an error.
		s.render(w, data)
		return
	case err != nil:
		s.fail(w, err)
		return
	}

	assets, err := s.store.AssetsForScan(ctx, scan.ID)
	if err != nil {
		s.fail(w, err)
		return
	}

	data.HasScan = true
	data.Scan = scan
	data.ScanAge = humanAge(scan.StartedAt)
	data.Assets = make([]assetRow, 0, len(assets))

	for _, a := range assets {
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

	s.render(w, data)
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
		row.Latest = "\u2013" // en dash
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

func (s *Server) render(w http.ResponseWriter, data pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "layout.html", data); err != nil {
		// The response may be partly written by now, so there is nothing
		// useful to send. Log and move on.
		fmt.Printf("template error: %v\n", err)
	}
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	http.Error(w, "internal error: "+err.Error(), http.StatusInternalServerError)
}
