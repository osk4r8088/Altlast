package store

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ErrNoSuchAsset is returned when a mute names an asset no scan has seen.
var ErrNoSuchAsset = errors.New("no such asset")

// Mute is a finding that has been judged and accepted, for a stated
// reason, until a stated date.
type Mute struct {
	ID        int64
	AssetID   int64
	Asset     string
	Type      string
	Key       string
	Reason    string
	CreatedAt string
	ExpiresAt string
}

// Active reports whether the mute is still in force.
func (m Mute) Active() bool {
	t, err := time.Parse(time.RFC3339, m.ExpiresAt)
	if err != nil {
		return false // an unparseable expiry is treated as lapsed
	}
	return time.Now().Before(t)
}

// DaysLeft returns days until expiry, negative once lapsed.
func (m Mute) DaysLeft() int {
	t, err := time.Parse(time.RFC3339, m.ExpiresAt)
	if err != nil {
		return 0
	}
	return int(time.Until(t).Hours() / 24)
}

// Mutes returns every mute, soonest to expire first.
func (s *Store) Mutes(ctx context.Context) ([]Mute, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT m.id, m.asset_id, a.name, m.type, m.key, m.reason,
		       m.created_at, m.expires_at
		FROM mutes m
		JOIN assets a ON a.id = m.asset_id
		ORDER BY m.expires_at, a.name`)
	if err != nil {
		return nil, fmt.Errorf("querying mutes: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []Mute
	for rows.Next() {
		var m Mute
		err := rows.Scan(&m.ID, &m.AssetID, &m.Asset, &m.Type, &m.Key,
			&m.Reason, &m.CreatedAt, &m.ExpiresAt)
		if err != nil {
			return nil, fmt.Errorf("scanning mute: %w", err)
		}
		out = append(out, m)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating mutes: %w", err)
	}
	return out, nil
}

// ExpiredMutes returns mutes that have lapsed since they were last
// reported, and marks them reported. A lapsing mute is a change worth
// announcing once: otherwise a finding reappears with no explanation.
func (s *Store) ExpiredMutes(ctx context.Context) ([]Mute, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT m.id, m.asset_id, a.name, m.type, m.key, m.reason,
		       m.created_at, m.expires_at
		FROM mutes m
		JOIN assets a ON a.id = m.asset_id
		WHERE m.expires_at <= ? AND m.expiry_reported_at IS NULL
		ORDER BY a.name`, now())
	if err != nil {
		return nil, fmt.Errorf("querying expired mutes: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []Mute
	for rows.Next() {
		var m Mute
		err := rows.Scan(&m.ID, &m.AssetID, &m.Asset, &m.Type, &m.Key,
			&m.Reason, &m.CreatedAt, &m.ExpiresAt)
		if err != nil {
			return nil, fmt.Errorf("scanning expired mute: %w", err)
		}
		out = append(out, m)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating expired mutes: %w", err)
	}

	for _, m := range out {
		_, err := s.db.ExecContext(ctx,
			`UPDATE mutes SET expiry_reported_at = ? WHERE id = ?`, now(), m.ID)
		if err != nil {
			return nil, fmt.Errorf("marking mute %d reported: %w", m.ID, err)
		}
	}

	return out, nil
}

// ParseDuration accepts either an absolute date (2026-12-01) or a relative
// span (90d, 6mo, 1y) and returns the resulting expiry.
func ParseDuration(s string) (time.Time, error) {
	if t, err := time.Parse("2006-01-02", s); err == nil {
		// A date means end of that day, not its first instant.
		return t.Add(24*time.Hour - time.Second), nil
	}

	var n int
	var unit string
	if _, err := fmt.Sscanf(s, "%d%s", &n, &unit); err != nil {
		return time.Time{}, fmt.Errorf("cannot read %q as a date or duration", s)
	}
	if n <= 0 {
		return time.Time{}, errors.New("duration must be positive")
	}

	switch unit {
	case "d":
		return time.Now().AddDate(0, 0, n), nil
	case "w":
		return time.Now().AddDate(0, 0, n*7), nil
	case "mo":
		return time.Now().AddDate(0, n, 0), nil
	case "y":
		return time.Now().AddDate(n, 0, 0), nil
	default:
		return time.Time{}, fmt.Errorf("unknown unit %q: use d, w, mo, or y", unit)
	}
}

// MuteFinding records a mute for an already-located finding, which is how
// the CLI works: find the open finding first, then mute exactly that.
func (s *Store) MuteFinding(ctx context.Context, f FindingRecord, reason string, until time.Time) error {
	if reason == "" {
		return errors.New("a mute needs a reason")
	}
	if until.Before(time.Now()) {
		return errors.New("a mute needs an expiry in the future")
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO mutes (asset_id, type, key, reason, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT (asset_id, type, key) DO UPDATE SET
			reason = excluded.reason,
			created_at = excluded.created_at,
			expires_at = excluded.expires_at,
			expiry_reported_at = NULL`,
		f.AssetID, f.Type, f.Key, reason, now(),
		until.UTC().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("recording mute: %w", err)
	}
	return nil
}

// UnmuteAsset removes every mute of a given type on an asset, matched by
// name pattern. It reports how many were removed.
func (s *Store) UnmuteAsset(ctx context.Context, pattern, typ string) (int, error) {
	host, kind, name, err := s.AssetByName(ctx, pattern)
	if err != nil {
		return 0, err
	}

	assetID, err := s.assetID(ctx, host, kind, name)
	if err != nil {
		return 0, err
	}

	res, err := s.db.ExecContext(ctx,
		`DELETE FROM mutes WHERE asset_id = ? AND type = ?`, assetID, typ)
	if err != nil {
		return 0, fmt.Errorf("removing mute: %w", err)
	}

	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("checking removal: %w", err)
	}
	return int(n), nil
}
