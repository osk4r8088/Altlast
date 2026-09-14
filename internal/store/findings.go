package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/osk4r8088/altlast/internal/findings"
)

// ErrNoSuchFinding is returned when a finding is not open, either because
// it never existed or because a later scan resolved it.
var ErrNoSuchFinding = errors.New("no such open finding")

// FindingRecord is a finding as stored, with its lifecycle timestamps.
type FindingRecord struct {
	ID       int64
	AssetID  int64
	Asset    string
	Type     string
	Key      string
	Severity string
	Detail   string

	FirstSeen  string
	LastSeen   string
	ResolvedAt sql.NullString

	FirstScanID int64
	LastScanID  int64
	Muted       bool
	MuteReason  string
	MuteExpires string
}

// Open reports whether the finding is still current.
func (f FindingRecord) Open() bool { return !f.ResolvedAt.Valid }

// ReconcileFindings brings the stored findings for one asset into line with
// what this scan produced.
//
// Three outcomes per finding: it is new and opens, it persists and its
// last_seen advances, or it is no longer produced and resolves. That last
// case is what makes time-to-resolve measurable, and it works only because
// resolution is inferred from absence rather than requiring anyone to mark
// anything as fixed.
//
// Absence is only evidence when the check actually ran. Open findings whose
// type is in unchecked are left exactly as they were, neither resolved nor
// advanced: the lookup behind them failed, and last_seen records when a
// finding was observed, not when we last tried.
func (s *Store) ReconcileFindings(
	ctx context.Context, scanID int64, host, kind, name string,
	current []findings.Finding, unchecked []findings.Type,
) error {
	assetID, err := s.assetID(ctx, host, kind, name)
	if err != nil {
		return err
	}

	ts := s.scanTime
	if ts == "" {
		ts = now()
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("starting findings transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // no-op once committed

	rows, err := tx.QueryContext(ctx,
		`SELECT id, type, key FROM findings
		 WHERE asset_id = ? AND resolved_at IS NULL`, assetID)
	if err != nil {
		return fmt.Errorf("loading open findings: %w", err)
	}

	type openKey struct{ typ, key string }
	open := make(map[openKey]int64)

	for rows.Next() {
		var id int64
		var typ, key string
		if err := rows.Scan(&id, &typ, &key); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scanning open finding: %w", err)
		}
		open[openKey{typ, key}] = id
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("iterating open findings: %w", err)
	}
	_ = rows.Close()

	seen := make(map[openKey]bool, len(current))

	for _, f := range current {
		k := openKey{string(f.Type), f.Key}
		seen[k] = true

		if id, exists := open[k]; exists {
			// Still present. Advance last_seen and refresh the detail,
			// which may have moved as days remaining count down.
			_, err := tx.ExecContext(ctx,
				`UPDATE findings
				 SET last_seen = ?, last_scan_id = ?, detail = ?, severity = ?
				 WHERE id = ?`,
				ts, scanID, f.Detail, string(f.Severity), id)
			if err != nil {
				return fmt.Errorf("updating finding %d: %w", id, err)
			}
			continue
		}

		_, err := tx.ExecContext(ctx, `
			INSERT INTO findings (
				asset_id, type, key, severity, detail,
				first_seen, last_seen, first_scan_id, last_scan_id
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			assetID, string(f.Type), f.Key, string(f.Severity), f.Detail,
			ts, ts, scanID, scanID)
		if err != nil {
			return fmt.Errorf("opening finding %s on %s: %w", f.Type, name, err)
		}
	}

	skip := make(map[string]bool, len(unchecked))
	for _, typ := range unchecked {
		skip[string(typ)] = true
	}

	// Anything open that this scan did not produce, and could have, has
	// been resolved.
	for k, id := range open {
		if seen[k] || skip[k.typ] {
			continue
		}
		_, err := tx.ExecContext(ctx,
			`UPDATE findings SET resolved_at = ?, last_scan_id = ? WHERE id = ?`,
			ts, scanID, id)
		if err != nil {
			return fmt.Errorf("resolving finding %d: %w", id, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing findings: %w", err)
	}
	return nil
}

// assetID looks up an asset's identity, which RecordObservation has already
// created by the time findings are reconciled.
func (s *Store) assetID(ctx context.Context, host, kind, name string) (int64, error) {
	var id int64
	err := s.db.QueryRowContext(ctx,
		`SELECT id FROM assets WHERE host = ? AND kind = ? AND name = ?`,
		host, kind, name).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("looking up asset %s: %w", name, err)
	}
	return id, nil
}

// OpenFindings returns every unresolved finding, most severe first, with
// mute state attached. Muting is applied at read time rather than at
// reconciliation: a muted finding still accumulates history, so unmuting
// reveals how long it has really been open.
func (s *Store) OpenFindings(ctx context.Context) ([]FindingRecord, error) {
	return s.queryFindings(ctx, `
		SELECT f.id, f.asset_id, a.name, f.type, f.key, f.severity,
		       COALESCE(f.detail, ''), f.first_seen, f.last_seen, f.resolved_at,
		       f.first_scan_id, f.last_scan_id,
		       COALESCE(m.reason, ''), COALESCE(m.expires_at, '')
		FROM findings f
		JOIN assets a ON a.id = f.asset_id
		LEFT JOIN mutes m
		       ON m.asset_id = f.asset_id AND m.type = f.type AND m.key = f.key
		      AND m.expires_at > ?
		WHERE f.resolved_at IS NULL
		ORDER BY
			CASE f.severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END,
			f.first_seen,
			a.name`, now())
}

// OpenFinding returns one open finding by id, for actions that name a
// finding exactly, such as the dashboard's mute form. Mute state is not
// loaded.
func (s *Store) OpenFinding(ctx context.Context, id int64) (FindingRecord, error) {
	matches, err := s.queryFindings(ctx, `
		SELECT f.id, f.asset_id, a.name, f.type, f.key, f.severity,
		       COALESCE(f.detail, ''), f.first_seen, f.last_seen, f.resolved_at,
		       f.first_scan_id, f.last_scan_id,
		       '', ''
		FROM findings f
		JOIN assets a ON a.id = f.asset_id
		WHERE f.id = ? AND f.resolved_at IS NULL`, id)
	if err != nil {
		return FindingRecord{}, err
	}
	if len(matches) == 0 {
		return FindingRecord{}, fmt.Errorf("finding %d: %w", id, ErrNoSuchFinding)
	}
	return matches[0], nil
}

// NewInScan returns findings that opened during a given scan. An empty
// result is the desired steady state: most scans should find nothing new.
//
// The two empty strings are the mute reason and expiry, which
// queryFindings expects as the last two columns. A newly opened finding
// has no mute state to report.
func (s *Store) NewInScan(ctx context.Context, scanID int64) ([]FindingRecord, error) {
	return s.queryFindings(ctx, `
		SELECT f.id, f.asset_id, a.name, f.type, f.key, f.severity,
		       COALESCE(f.detail, ''), f.first_seen, f.last_seen, f.resolved_at,
		       f.first_scan_id, f.last_scan_id,
		       '', ''
		FROM findings f
		JOIN assets a ON a.id = f.asset_id
		WHERE f.first_scan_id = ?
		ORDER BY
			CASE f.severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END,
			a.name`, scanID)
}

// ResolvedInScan returns findings that resolved during a given scan.
func (s *Store) ResolvedInScan(ctx context.Context, scanID int64) ([]FindingRecord, error) {
	return s.queryFindings(ctx, `
		SELECT f.id, f.asset_id, a.name, f.type, f.key, f.severity,
		       COALESCE(f.detail, ''), f.first_seen, f.last_seen, f.resolved_at,
		       f.first_scan_id, f.last_scan_id,
		       '', ''
		FROM findings f
		JOIN assets a ON a.id = f.asset_id
		WHERE f.resolved_at IS NOT NULL AND f.last_scan_id = ?
		ORDER BY a.name`, scanID)
}

// queryFindings runs a findings query and scans the rows. Queries must
// select the mute reason and expiry as their last two columns; an empty
// reason means unmuted.
func (s *Store) queryFindings(ctx context.Context, query string, args ...any) ([]FindingRecord, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying findings: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []FindingRecord
	for rows.Next() {
		var f FindingRecord
		err := rows.Scan(&f.ID, &f.AssetID, &f.Asset, &f.Type, &f.Key,
			&f.Severity, &f.Detail, &f.FirstSeen, &f.LastSeen, &f.ResolvedAt,
			&f.FirstScanID, &f.LastScanID, &f.MuteReason, &f.MuteExpires)
		if err != nil {
			return nil, fmt.Errorf("scanning finding: %w", err)
		}
		f.Muted = f.MuteReason != ""
		out = append(out, f)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating findings: %w", err)
	}
	return out, nil
}

// FindOpen locates a single open finding by asset name and type, so a mute
// can name a finding the way a person would: "mute the EOL finding on
// postgres". The key is resolved from what is actually open, since muting
// a finding you cannot currently see is not a real use case.
//
// The asset name may be a substring, as container names are long and
// mostly boilerplate. An ambiguous match is an error rather than a guess.
func (s *Store) FindOpen(ctx context.Context, assetPattern, typ string) (FindingRecord, error) {
	matches, err := s.queryFindings(ctx, `
		SELECT f.id, f.asset_id, a.name, f.type, f.key, f.severity,
		       COALESCE(f.detail, ''), f.first_seen, f.last_seen, f.resolved_at,
		       f.first_scan_id, f.last_scan_id,
		       '', ''
		FROM findings f
		JOIN assets a ON a.id = f.asset_id
		WHERE f.resolved_at IS NULL
		  AND f.type = ?
		  AND a.name LIKE '%' || ? || '%'
		ORDER BY a.name`, typ, assetPattern)
	if err != nil {
		return FindingRecord{}, err
	}

	switch len(matches) {
	case 0:
		return FindingRecord{}, fmt.Errorf(
			"no open %s finding matching %q", typ, assetPattern)
	case 1:
		return matches[0], nil
	default:
		names := make([]string, 0, len(matches))
		for _, m := range matches {
			names = append(names, m.Asset)
		}
		return FindingRecord{}, fmt.Errorf(
			"%q matches %d assets (%s): be more specific",
			assetPattern, len(matches), strings.Join(names, ", "))
	}
}

// AssetByName resolves an asset name pattern to its identity, for
// unmuting, where no open finding need exist.
func (s *Store) AssetByName(ctx context.Context, pattern string) (host, kind, name string, err error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT host, kind, name FROM assets WHERE name LIKE '%' || ? || '%' ORDER BY name`,
		pattern)
	if err != nil {
		return "", "", "", fmt.Errorf("looking up asset: %w", err)
	}
	defer func() { _ = rows.Close() }()

	type asset struct{ host, kind, name string }
	var found []asset

	for rows.Next() {
		var a asset
		if err := rows.Scan(&a.host, &a.kind, &a.name); err != nil {
			return "", "", "", fmt.Errorf("scanning asset: %w", err)
		}
		found = append(found, a)
	}
	if err := rows.Err(); err != nil {
		return "", "", "", fmt.Errorf("iterating assets: %w", err)
	}

	switch len(found) {
	case 0:
		return "", "", "", fmt.Errorf("%w matching %q", ErrNoSuchAsset, pattern)
	case 1:
		return found[0].host, found[0].kind, found[0].name, nil
	default:
		names := make([]string, 0, len(found))
		for _, a := range found {
			names = append(names, a.name)
		}
		return "", "", "", fmt.Errorf("%q matches %d assets (%s): be more specific",
			pattern, len(found), strings.Join(names, ", "))
	}
}
