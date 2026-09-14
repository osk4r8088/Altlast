// Command altlast reports what your self-hosted stack runs, how far behind
// it is, and what has fallen out of support.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"text/tabwriter"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/osk4r8088/altlast/internal/collect"
	"github.com/osk4r8088/altlast/internal/enrich"
	"github.com/osk4r8088/altlast/internal/findings"
	"github.com/osk4r8088/altlast/internal/resolve"
	"github.com/osk4r8088/altlast/internal/store"
	"github.com/osk4r8088/altlast/internal/web"
)

// version is overwritten at build time via -ldflags. See the Makefile.
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	var err error
	switch os.Args[1] {
	case "version":
		fmt.Printf("altlast %s\n", version)
	case "collect":
		err = runCollect(os.Args[2:])
	case "scan":
		err = runScan(os.Args[2:])
	case "findings":
		err = runFindings(os.Args[2:])
	case "mute":
		err = runMute(os.Args[2:])
	case "unmute":
		err = runUnmute(os.Args[2:])
	case "mutes":
		err = runMutes(os.Args[2:])
	case "serve":
		err = runServe(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		usage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `altlast - obsolescence register for self-hosted stacks

usage:
  altlast <command> [flags]

commands:
  collect    discover assets on this host
  scan       collect assets, check upstream, record findings
  findings   list open findings
  mute       accept a finding, with a reason and an expiry
  unmute     remove a mute
  mutes      list mutes and when they lapse
  serve      run the dashboard
  version    print the version and exit

run "altlast <command> -h" for command flags
`)
}

func runCollect(args []string) error {
	fs := flag.NewFlagSet("collect", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "emit a JSON document instead of a table")
	running := fs.Bool("running", false, "only include running containers")
	socket := fs.String("socket", "", "path to the docker socket")
	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	assets, err := collect.NewDockerCollector(*socket, !*running).Collect(ctx)
	if err != nil {
		return err
	}

	if *asJSON {
		return emitJSON(assets)
	}
	return emitTable(assets)
}

func emitJSON(assets []collect.Asset) error {
	host, _ := os.Hostname()

	doc := collect.Document{
		Schema:    collect.SchemaVersion,
		Host:      host,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Assets:    assets,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func emitTable(assets []collect.Asset) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tREGISTRY\tREPOSITORY\tTAG\tSTATE")

	for _, a := range assets {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			a.Name, a.Registry, a.Repository, a.Tag, a.State)
	}

	fmt.Fprintf(w, "\n%d assets\n", len(assets))
	return w.Flush()
}

func runScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	socket := fs.String("socket", "", "path to the docker socket")
	running := fs.Bool("running", false, "only include running containers")
	ttl := fs.Duration("cache-ttl", resolve.DefaultTTL, "how long to reuse cached tag lists")
	dbPath := fs.String("db", "", "path to the database (default: XDG data dir)")
	noStore := fs.Bool("no-store", false, "print results without recording them")
	quiet := fs.Bool("quiet", false, "print only what changed")
	// Deliberately low. Docker Hub rate limits per source IP, and behind NAT
	// that IP is shared with everyone else on the network.
	concurrency := fs.Int("concurrency", 4, "how many assets to check upstream at once")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *concurrency < 1 {
		return fmt.Errorf("--concurrency must be at least 1")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Ctrl-C cancels the context instead of killing the process, so requests
	// in flight return promptly and the scan can refuse to record itself.
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt)
	defer stop()

	host, _ := os.Hostname()

	assets, err := collect.NewDockerCollector(*socket, !*running).Collect(ctx)
	if err != nil {
		return err
	}

	resolver, err := resolve.NewRegistryResolver(*ttl)
	if err != nil {
		return err
	}

	eol, err := enrich.NewEOLClient(0)
	if err != nil {
		return err
	}

	// db stays nil when storing is disabled; every use is guarded.
	var db *store.Store
	var scanID int64
	if !*noStore {
		db, err = store.Open(*dbPath)
		if err != nil {
			return err
		}
		defer func() { _ = db.Close() }()

		scanID, err = db.BeginScan(ctx, host)
		if err != nil {
			return err
		}
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if !*quiet {
		fmt.Fprintln(w, "NAME\tIMAGE\tCURRENT\tLATEST\tBEHIND\tSUPPORT")
	}

	results := lookupAll(ctx, resolver, eol, assets, *concurrency)

	// A cancelled scan has an error for every lookup that was still in
	// flight. Recording it would resolve, by absence, findings that were
	// never actually re-checked, and reopen them next scan with their
	// history lost.
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("scan cancelled before upstream checks finished: %w", err)
	}

	var errCount int

	for i, a := range assets {
		obs := store.Observation{
			Host:          host,
			Kind:          string(a.Kind),
			Name:          a.Name,
			Registry:      a.Registry,
			Repository:    a.Repository,
			Tag:           a.Tag,
			ImageID:       a.ImageID,
			Digest:        a.Digest,
			State:         a.State,
			Version:       a.Version,
			VersionSource: a.VersionSource,
		}

		var latest string
		behind := "-"

		rel, resErr := results[i].rel, results[i].resErr
		switch {
		case resErr != nil:
			errCount++
			latest = "error"
			obs.ResolveError = resErr.Error()
			fmt.Fprintf(os.Stderr, "warning: %s: %v\n", a.Name, resErr)

		case !rel.Comparable:
			latest = "(unversioned)"
			if rel.Digest != "" {
				obs.Digest = rel.Digest
			}

		case rel.Behind == 0:
			latest = rel.Latest
			behind = "up to date"
			obs.Latest = rel.Latest
			obs.Comparable = true
			if rel.Digest != "" {
				obs.Digest = rel.Digest
			}

		default:
			latest = rel.Latest
			behind = fmt.Sprintf("%d releases", rel.Behind)
			obs.Latest = rel.Latest
			obs.Behind = rel.Behind
			obs.Comparable = true
			if rel.Digest != "" {
				obs.Digest = rel.Digest
			}
		}

		if resErr == nil && rel.NewerMajor > 0 {
			obs.NewerMajor = rel.NewerMajor
			obs.NewerMajorTag = rel.NewerMajorTag
			behind += fmt.Sprintf(" (%d.x exists)", rel.NewerMajor)
		}

		support := "-"
		lc, lcErr := results[i].lc, results[i].lcErr
		if lcErr != nil {
			obs.EOLError = lcErr.Error()
			support = "lookup failed"
		} else {
			obs.SupportState = string(lc.State)
			obs.EOLProduct = lc.Product
			obs.EOLCycle = lc.Cycle
			obs.EOLDate = lc.EOLDate
			obs.EOLDays = lc.Days

			switch lc.State {
			case enrich.SupportUnknown:
				support = "unknown"
			case enrich.SupportActive:
				support = "supported"
			case enrich.SupportEnding:
				support = fmt.Sprintf("EOL in %dd", lc.Days)
			case enrich.SupportEnded:
				support = fmt.Sprintf("EOL since %s", lc.EOLDate)
			}
		}

		current := a.Version
		if a.VersionSource == "oci-label" {
			current += " (label)"
		}

		if !*quiet {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
				a.Name, a.Repository, current, latest, behind, support)
		}

		if db == nil {
			continue
		}

		if err := db.RecordObservation(ctx, scanID, obs); err != nil {
			return err
		}

		// Findings are reconciled after the observation, because opening
		// one needs the asset identity that RecordObservation creates.
		found := findings.Evaluate(findings.Input{
			Version:       a.Version,
			SupportState:  obs.SupportState,
			EOLCycle:      obs.EOLCycle,
			EOLDate:       obs.EOLDate,
			EOLDays:       obs.EOLDays,
			NewerMajor:    obs.NewerMajor,
			NewerMajorTag: obs.NewerMajorTag,
			ResolveError:  obs.ResolveError,
		})

		if err := db.ReconcileFindings(ctx, scanID, host, string(a.Kind), a.Name, found); err != nil {
			return err
		}
	}

	if err := w.Flush(); err != nil {
		return err
	}

	if db == nil {
		return nil
	}

	if err := db.FinishScan(ctx, scanID, len(assets), errCount); err != nil {
		return err
	}

	return reportChanges(ctx, db, scanID)
}

// lookup is everything a scan learns from upstream about one asset.
type lookup struct {
	rel    resolve.Release
	resErr error
	lc     enrich.Lifecycle
	lcErr  error
}

// lookupAll checks every asset upstream, at most limit at a time, and
// returns the results in the same order as assets.
//
// Only the network round trips run concurrently. Printing and recording
// stay serial in the caller: SQLite has a single writer, tabwriter is not
// safe for concurrent use, and iterating results by index keeps the output
// order identical to a serial scan.
func lookupAll(
	ctx context.Context, resolver resolve.Resolver, eol *enrich.EOLClient,
	assets []collect.Asset, limit int,
) []lookup {
	results := make([]lookup, len(assets))

	// A plain Group, not errgroup.WithContext: that variant cancels every
	// other lookup when one fails, and one unreachable image must not stop
	// the rest of the scan.
	var g errgroup.Group
	g.SetLimit(limit)

	for i, a := range assets {
		g.Go(func() error {
			var r lookup
			r.rel, r.resErr = resolver.Resolve(ctx, a.Registry, a.Repository, a.Version)
			r.lc, r.lcErr = eol.Lookup(ctx, a.Repository, a.Version)

			// Each goroutine writes only its own element, so no lock is needed.
			results[i] = r

			// Per-asset failures are data recorded on the row, never a reason
			// to stop, so this never returns an error.
			return nil
		})
	}

	_ = g.Wait() // always nil, see above
	return results
}

// reportChanges prints what a scan changed. Silence is the goal: a scan
// that opens nothing new is the normal, healthy outcome, and a tool that
// prints a wall of text every run trains people to stop reading it.
func reportChanges(ctx context.Context, db *store.Store, scanID int64) error {
	opened, err := db.NewInScan(ctx, scanID)
	if err != nil {
		return err
	}

	resolved, err := db.ResolvedInScan(ctx, scanID)
	if err != nil {
		return err
	}

	// A lapsed mute is reported once. Otherwise a finding reappears with
	// no explanation of why it was quiet until now.
	lapsed, err := db.ExpiredMutes(ctx)
	if err != nil {
		return err
	}

	if len(opened) == 0 && len(resolved) == 0 && len(lapsed) == 0 {
		return nil
	}

	fmt.Println()

	for _, f := range opened {
		fmt.Printf("  NEW      [%s] %s: %s\n", f.Severity, f.Asset, f.Detail)
	}
	for _, f := range resolved {
		fmt.Printf("  FIXED          %s: %s\n", f.Asset, f.Detail)
	}
	for _, m := range lapsed {
		fmt.Printf("  UNMUTED        %s (%s): mute lapsed, reason was %q\n",
			m.Asset, m.Type, m.Reason)
	}

	return nil
}

func runFindings(args []string) error {
	fs := flag.NewFlagSet("findings", flag.ExitOnError)
	dbPath := fs.String("db", "", "path to the database (default: XDG data dir)")
	showMuted := fs.Bool("muted", false, "include muted findings")
	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	db, err := store.Open(*dbPath)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	all, err := db.OpenFindings(ctx)
	if err != nil {
		return err
	}

	var shown []store.FindingRecord
	var mutedCount int
	for _, f := range all {
		if f.Muted {
			mutedCount++
			if !*showMuted {
				continue
			}
		}
		shown = append(shown, f)
	}

	if len(shown) == 0 {
		if mutedCount > 0 {
			fmt.Printf("no open findings (%d muted, see --muted)\n", mutedCount)
		} else {
			fmt.Println("no open findings")
		}
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "SEVERITY\tASSET\tTYPE\tDETAIL\tOPEN FOR")

	for _, f := range shown {
		severity := f.Severity
		if f.Muted {
			severity = "muted"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			severity, f.Asset, f.Type, f.Detail, openFor(f.FirstSeen))
	}

	fmt.Fprintf(w, "\n%d shown", len(shown))
	if mutedCount > 0 && !*showMuted {
		fmt.Fprintf(w, ", %d muted", mutedCount)
	}
	fmt.Fprintln(w)

	return w.Flush()
}

// openFor renders how long a finding has been open.
func openFor(firstSeen string) string {
	t, err := time.Parse(time.RFC3339, firstSeen)
	if err != nil {
		return ""
	}
	if days := int(time.Since(t).Hours() / 24); days >= 1 {
		return fmt.Sprintf("%dd", days)
	}
	return "today"
}

// splitPositional pulls leading non-flag arguments off the front so that
// flags may follow them. Go's flag package stops parsing at the first
// non-flag argument, which would otherwise force "altlast mute --reason x
// --until y jellyfin eol" and nothing more natural.
func splitPositional(args []string, n int) (positional, rest []string) {
	for i := 0; i < n && i < len(args); i++ {
		if len(args[i]) > 0 && args[i][0] == '-' {
			break
		}
		positional = append(positional, args[i])
	}
	return positional, args[len(positional):]
}

func runMute(args []string) error {
	pos, rest := splitPositional(args, 2)

	fs := flag.NewFlagSet("mute", flag.ExitOnError)
	dbPath := fs.String("db", "", "path to the database (default: XDG data dir)")
	reason := fs.String("reason", "", "why this finding is accepted (required)")
	until := fs.String("until", "", "expiry: a date (2026-12-01) or a span (90d, 6mo, 1y)")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `usage: altlast mute <asset> <type> --reason "..." --until <when>

Accepts a finding you have judged, for a stated reason, until a stated
date. Both are required: a mute without a reason becomes a silence nobody
dares remove, and a mute without an expiry becomes permanent by accident.

The asset may be a partial name. The finding's key is resolved from what
is currently open.

example:
  altlast mute postgres eol --reason "isolated, no external access" --until 90d

`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(rest); err != nil {
		return err
	}

	// Allow the positionals to come after the flags too.
	if len(pos) < 2 {
		pos = append(pos, fs.Args()...)
	}

	if len(pos) != 2 {
		fs.Usage()
		return fmt.Errorf("expected an asset and a finding type")
	}
	if *reason == "" {
		return fmt.Errorf("--reason is required: a mute without one is an unexplained silence")
	}
	if *until == "" {
		return fmt.Errorf("--until is required: a mute without an expiry never gets reviewed")
	}

	expiry, err := store.ParseDuration(*until)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	db, err := store.Open(*dbPath)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	f, err := db.FindOpen(ctx, pos[0], pos[1])
	if err != nil {
		return err
	}

	if err := db.MuteFinding(ctx, f, *reason, expiry); err != nil {
		return err
	}

	fmt.Printf("muted %s on %s until %s\n",
		f.Type, f.Asset, expiry.Format("2006-01-02"))
	fmt.Printf("  %s\n", f.Detail)
	fmt.Printf("  reason: %s\n", *reason)
	return nil
}

func runUnmute(args []string) error {
	pos, rest := splitPositional(args, 2)

	fs := flag.NewFlagSet("unmute", flag.ExitOnError)
	dbPath := fs.String("db", "", "path to the database (default: XDG data dir)")
	if err := fs.Parse(rest); err != nil {
		return err
	}

	if len(pos) < 2 {
		pos = append(pos, fs.Args()...)
	}

	if len(pos) != 2 {
		return fmt.Errorf("usage: altlast unmute <asset> <type>")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	db, err := store.Open(*dbPath)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	n, err := db.UnmuteAsset(ctx, pos[0], pos[1])
	if err != nil {
		return err
	}

	if n == 0 {
		fmt.Printf("no %s mute found on %q\n", pos[1], pos[0])
		return nil
	}

	fmt.Printf("removed %d mute(s)\n", n)
	return nil
}

func runMutes(args []string) error {
	fs := flag.NewFlagSet("mutes", flag.ExitOnError)
	dbPath := fs.String("db", "", "path to the database (default: XDG data dir)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	db, err := store.Open(*dbPath)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	mutes, err := db.Mutes(ctx)
	if err != nil {
		return err
	}

	if len(mutes) == 0 {
		fmt.Println("no mutes")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ASSET\tTYPE\tREASON\tEXPIRES\tSTATUS")

	for _, m := range mutes {
		status := fmt.Sprintf("%dd left", m.DaysLeft())
		if !m.Active() {
			status = "lapsed"
		}

		expires := m.ExpiresAt
		if t, err := time.Parse(time.RFC3339, m.ExpiresAt); err == nil {
			expires = t.Format("2006-01-02")
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			m.Asset, m.Type, m.Reason, expires, status)
	}

	fmt.Fprintf(w, "\n%d mutes\n", len(mutes))
	return w.Flush()
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("listen", "127.0.0.1:8080", "address to listen on")
	dbPath := fs.String("db", "", "path to the database (default: XDG data dir)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	db, err := store.Open(*dbPath)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	srv, err := web.NewServer(db, version)
	if err != nil {
		return err
	}

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	fmt.Printf("altlast listening on http://%s\n", *addr)

	if err := httpSrv.ListenAndServe(); err != nil {
		return fmt.Errorf("serving: %w", err)
	}
	return nil
}
