// Package store persists scan results in SQLite.
//
// The model is snapshot per scan: every scan appends a full set of
// observations rather than updating rows in place, so history is complete.
package store

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver

	"github.com/osk4r8088/altlast/internal/paths"
)

//go:embed schema.sql
var schemaSQL string

// schemaVersion is bumped whenever schema.sql changes incompatibly.
const schemaVersion = 1

// Store is a handle on the Altlast database.
type Store struct {
	db *sql.DB
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

	// _pragma parameters are driver options, not part of the filename.
	// foreign_keys enforces our REFERENCES clauses, which SQLite ignores
	// by default. journal_mode=WAL allows reads during writes.
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

// migrate applies the schema and records its version.
func (s *Store) migrate() error {
	if _, err := s.db.Exec(schemaSQL); err != nil {
		return fmt.Errorf("applying schema: %w", err)
	}

	var current int
	err := s.db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_version`).Scan(&current)
	if err != nil {
		return fmt.Errorf("reading schema version: %w", err)
	}

	if current == 0 {
		_, err := s.db.Exec(`INSERT INTO schema_version (version) VALUES (?)`, schemaVersion)
		if err != nil {
			return fmt.Errorf("recording schema version: %w", err)
		}
		return nil
	}

	if current > schemaVersion {
		return fmt.Errorf("database schema is version %d, this binary understands %d: upgrade altlast",
			current, schemaVersion)
	}

	return nil
}

// now returns the current time in the format we store.
func now() string { return time.Now().UTC().Format(time.RFC3339) }

// BeginScan records the start of a scan and returns its id.
func (s *Store) BeginScan(ctx context.Context, host string) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO scans (started_at, host) VALUES (?, ?)`, now(), host)
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

	Latest     string
	Behind     int
	Comparable bool
	Error      string
}

// RecordObservation upserts the asset identity and appends an observation.
func (s *Store) RecordObservation(ctx context.Context, scanID int64, o Observation) error {
	ts := now()

	// Upsert the asset. ON CONFLICT updates last_seen without disturbing
	// first_seen, which is the whole point of the assets table.
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

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO observations (
			scan_id, asset_id, registry, repository, tag, image_id, digest,
			state, latest, behind, comparable, resolve_error, observed_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		scanID, assetID, o.Registry, o.Repository, o.Tag, o.ImageID, o.Digest,
		o.State, nullable(o.Latest), o.Behind, boolToInt(o.Comparable),
		nullable(o.Error), ts)
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
