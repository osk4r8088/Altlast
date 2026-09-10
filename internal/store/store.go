// Package store persists scan results in SQLite.
//
// The model is snapshot per scan: every scan appends a full set of
// observations rather than updating rows in place, so history is complete.
package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver

	"github.com/osk4r8088/altlast/internal/paths"
)

// migrationFS holds the numbered schema migrations. Embedding a directory
// rather than a single file means adding a migration is adding a file.
//
//go:embed migrations/*.sql
var migrationFS embed.FS

// Store is a handle on the Altlast database.
type Store struct {
	db *sql.DB

	// scanTime is the timestamp of the current scan. Every observation in
	// one scan shares it, so rows do not drift apart as the scan runs.
	scanTime string
}

// Open opens the database at the given path, creating it if needed. Pass an
// empty path to use the default location under XDG_DATA_HOME.
func Open(path string) (*Store, error) {
	if path == "" {
		dir, err := paths.Data()
		if err != nil {
			return nil, err
		}
		path = filepath.Join(dir, "altlast.db")
	}

	dsn := path + "?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)"

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the database handle.
func (s *Store) Close() error { return s.db.Close() }

// migration is one numbered schema change.
type migration struct {
	version int
	name    string
	sql     string
}

// loadMigrations reads and orders the embedded migration files. Names must
// start with a zero-padded version number, as in 001_init.sql.
func loadMigrations() ([]migration, error) {
	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return nil, fmt.Errorf("reading migrations: %w", err)
	}

	var out []migration
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".sql") {
			continue
		}

		numPart, _, found := strings.Cut(name, "_")
		if !found {
			return nil, fmt.Errorf("migration %q has no version prefix", name)
		}

		v, err := strconv.Atoi(numPart)
		if err != nil {
			return nil, fmt.Errorf("migration %q has a bad version prefix: %w", name, err)
		}

		body, err := migrationFS.ReadFile("migrations/" + name)
		if err != nil {
			return nil, fmt.Errorf("reading migration %q: %w", name, err)
		}

		out = append(out, migration{version: v, name: name, sql: string(body)})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	return out, nil
}

// migrate applies every migration newer than the recorded version.
func (s *Store) migrate() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_version (
		version    INTEGER PRIMARY KEY,
		applied_at TEXT NOT NULL
	)`)
	if err != nil {
		return fmt.Errorf("creating schema_version: %w", err)
	}

	// A database created before migrations existed has a schema_version
	// table without applied_at. CREATE TABLE IF NOT EXISTS leaves it
	// alone, so add the column explicitly. SQLite has no
	// ADD COLUMN IF NOT EXISTS, so the error is inspected instead.
	if _, err := s.db.Exec(
		`ALTER TABLE schema_version ADD COLUMN applied_at TEXT`); err != nil {
		if !strings.Contains(err.Error(), "duplicate column name") {
			return fmt.Errorf("upgrading schema_version: %w", err)
		}
	}

	// Databases created before migrations existed have a schema_version
	// table without applied_at. Tolerate that by reading only version.
	var current int
	if err := s.db.QueryRow(
		`SELECT COALESCE(MAX(version), 0) FROM schema_version`).Scan(&current); err != nil {
		return fmt.Errorf("reading schema version: %w", err)
	}

	migrations, err := loadMigrations()
	if err != nil {
		return err
	}

	for _, m := range migrations {
		if m.version <= current {
			continue
		}

		tx, err := s.db.Begin()
		if err != nil {
			return fmt.Errorf("starting migration %s: %w", m.name, err)
		}

		if _, err := tx.Exec(m.sql); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("applying migration %s: %w", m.name, err)
		}

		if _, err := tx.Exec(
			`INSERT OR REPLACE INTO schema_version (version, applied_at) VALUES (?, ?)`,
			m.version, now()); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("recording migration %s: %w", m.name, err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("committing migration %s: %w", m.name, err)
		}
	}

	return nil
}

// now returns the current time in the format we store.
func now() string { return time.Now().UTC().Format(time.RFC3339) }

// BeginScan records the start of a scan and returns its id.
func (s *Store) BeginScan(ctx context.Context, host string) (int64, error) {
	s.scanTime = now()

	res, err := s.db.ExecContext(ctx,
		`INSERT INTO scans (started_at, host) VALUES (?, ?)`, s.scanTime, host)
	if err != nil {
		return 0, fmt.Errorf("starting scan: %w", err)
	}

	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("reading scan id: %w", err)
	}
	return id, nil
}

// FinishScan records the end of a scan and its counts.
func (s *Store) FinishScan(ctx context.Context, scanID int64, assets, errors int) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE scans SET finished_at = ?, asset_count = ?, error_count = ? WHERE id = ?`,
		now(), assets, errors, scanID)
	if err != nil {
		return fmt.Errorf("finishing scan: %w", err)
	}
	return nil
}

// Observation is one asset as seen during one scan.
type Observation struct {
	Host       string
	Kind       string
	Name       string
	Registry   string
	Repository string
	Tag        string
	ImageID    string
	Digest     string
	State      string

	Version       string
	VersionSource string

	Latest        string
	Behind        int
	Comparable    bool
	NewerMajor    int
	NewerMajorTag string
	ResolveError  string

	SupportState string
	EOLProduct   string
	EOLCycle     string
	EOLDate      string
	EOLDays      int
	EOLError     string
}

// RecordObservation upserts the asset identity and appends an observation.
func (s *Store) RecordObservation(ctx context.Context, scanID int64, o Observation) error {
	ts := s.scanTime
	if ts == "" {
		ts = now()
	}

	// ON CONFLICT updates last_seen without disturbing first_seen, which
	// is the whole point of a separate assets table.
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO assets (host, kind, name, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (host, kind, name)
		DO UPDATE SET last_seen = excluded.last_seen`,
		o.Host, o.Kind, o.Name, ts, ts)
	if err != nil {
		return fmt.Errorf("recording asset %s: %w", o.Name, err)
	}

	var assetID int64
	err = s.db.QueryRowContext(ctx,
		`SELECT id FROM assets WHERE host = ? AND kind = ? AND name = ?`,
		o.Host, o.Kind, o.Name).Scan(&assetID)
	if err != nil {
		return fmt.Errorf("looking up asset %s: %w", o.Name, err)
	}

	// behind is only meaningful when a comparison happened; otherwise it
	// stays NULL so no query can mistake "unknown" for "up to date".
	var behind any
	if o.Comparable {
		behind = o.Behind
	}

	var eolDays any
	if o.EOLDate != "" {
		eolDays = o.EOLDays
	}

	// Likewise, zero means "no higher major line", not "major line 0".
	var newerMajor any
	if o.NewerMajor > 0 {
		newerMajor = o.NewerMajor
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO observations (
			scan_id, asset_id, registry, repository, tag, image_id, digest,
			state, version, version_source, latest, behind, comparable,
			resolve_error, newer_major, newer_major_tag, support_state,
			eol_product, eol_cycle, eol_date, eol_days, eol_error, observed_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		scanID, assetID, o.Registry, o.Repository, o.Tag, o.ImageID, o.Digest,
		o.State, o.Version, o.VersionSource, nullable(o.Latest), behind,
		boolToInt(o.Comparable), nullable(o.ResolveError),
		newerMajor, nullable(o.NewerMajorTag),
		nullable(o.SupportState), nullable(o.EOLProduct), nullable(o.EOLCycle),
		nullable(o.EOLDate), eolDays, nullable(o.EOLError), ts)
	if err != nil {
		return fmt.Errorf("recording observation for %s: %w", o.Name, err)
	}

	return nil
}

// nullable turns an empty string into a SQL NULL, so "unknown" and "empty"
// stay distinguishable in the database.
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Scan describes one completed scan run.
type Scan struct {
	ID         int64
	StartedAt  string
	FinishedAt string
	Host       string
	AssetCount int
	ErrorCount int
}

// LatestScan returns the most recent scan. It reports sql.ErrNoRows when no
// scan has ever run, which callers should treat as an empty dashboard
// rather than a failure.
func (s *Store) LatestScan(ctx context.Context) (Scan, error) {
	var sc Scan
	var finished sql.NullString

	err := s.db.QueryRowContext(ctx, `
		SELECT id, started_at, finished_at, host, asset_count, error_count
		FROM scans
		WHERE finished_at IS NOT NULL
		ORDER BY id DESC
		LIMIT 1`).
		Scan(&sc.ID, &sc.StartedAt, &finished, &sc.Host, &sc.AssetCount, &sc.ErrorCount)
	if err != nil {
		return Scan{}, err
	}

	sc.FinishedAt = finished.String
	return sc, nil
}

// AssetView is one asset as of a given scan, joined with its identity.
type AssetView struct {
	Name       string
	Kind       string
	Registry   string
	Repository string
	Tag        string

	Version       string
	VersionSource string

	Latest       string
	Behind       sql.NullInt64
	NewerMajor   sql.NullInt64
	Comparable   bool
	ResolveError string

	SupportState string
	EOLProduct   string
	EOLCycle     string
	EOLDate      string
	EOLDays      sql.NullInt64

	State     string
	FirstSeen string
	LastSeen  string
}

// AssetsForScan returns every asset observed during one scan, worst first:
// end of life before ending, then by how far behind.
func (s *Store) AssetsForScan(ctx context.Context, scanID int64) ([]AssetView, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT
			a.name, a.kind, a.first_seen, a.last_seen,
			o.registry, o.repository, o.tag,
			COALESCE(o.version, o.tag), COALESCE(o.version_source, 'tag'),
			COALESCE(o.latest, ''), o.behind, o.comparable,
			COALESCE(o.resolve_error, ''),
			COALESCE(o.support_state, 'unknown'),
			COALESCE(o.eol_product, ''), COALESCE(o.eol_cycle, ''),
			COALESCE(o.eol_date, ''), o.eol_days, o.newer_major,
      
			COALESCE(o.state, '')
		FROM observations o
		JOIN assets a ON a.id = o.asset_id
		WHERE o.scan_id = ?
		ORDER BY
			CASE COALESCE(o.support_state, 'unknown')
				WHEN 'eol'       THEN 0
				WHEN 'ending'    THEN 1
				WHEN 'unknown'   THEN 2
				WHEN 'supported' THEN 3
				ELSE 4
			END,
			COALESCE(o.behind, -1) DESC,
			a.name`, scanID)
	if err != nil {
		return nil, fmt.Errorf("loading assets for scan %d: %w", scanID, err)
	}
	defer func() { _ = rows.Close() }()

	var out []AssetView
	for rows.Next() {
		var v AssetView
		var comparable int

		err := rows.Scan(
			&v.Name, &v.Kind, &v.FirstSeen, &v.LastSeen,
			&v.Registry, &v.Repository, &v.Tag,
			&v.Version, &v.VersionSource,
			&v.Latest, &v.Behind, &comparable, &v.ResolveError,
			&v.SupportState, &v.EOLProduct, &v.EOLCycle,
			&v.EOLDate, &v.EOLDays, &v.NewerMajor, &v.State)
		if err != nil {
			return nil, fmt.Errorf("scanning asset row: %w", err)
		}

		v.Comparable = comparable == 1
		out = append(out, v)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating asset rows: %w", err)
	}
	return out, nil
}
