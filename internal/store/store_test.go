package store

import (
	"context"
	"path/filepath"
	"slices"
	"testing"

	"github.com/osk4r8088/altlast/internal/findings"
)

// TestRecordObservationRoundTrip guards against column and placeholder
// drift in the INSERT statement. A mismatch there compiles and runs, and
// silently writes values into the wrong columns.
func TestRecordObservationRoundTrip(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	ctx := context.Background()

	scanID, err := db.BeginScan(ctx, "testhost")
	if err != nil {
		t.Fatalf("BeginScan: %v", err)
	}

	want := Observation{
		Host:          "testhost",
		Kind:          "container",
		Name:          "widget",
		Registry:      "docker.io",
		Repository:    "library/widget",
		Tag:           "1.2.3",
		ImageID:       "sha256:aaa",
		State:         "running",
		Version:       "1.2.3",
		VersionSource: "tag",
		Latest:        "1.9.0",
		Behind:        7,
		Comparable:    true,
		NewerMajor:    2,
		NewerMajorTag: "2.0.0",
		SupportState:  "eol",
		EOLProduct:    "widget",
		EOLCycle:      "1.2",
		EOLDate:       "2025-01-01",
		EOLDays:       -300,
	}

	if err := db.RecordObservation(ctx, scanID, want); err != nil {
		t.Fatalf("RecordObservation: %v", err)
	}
	if err := db.FinishScan(ctx, scanID, 1, 0); err != nil {
		t.Fatalf("FinishScan: %v", err)
	}

	got, err := db.AssetsForScan(ctx, scanID)
	if err != nil {
		t.Fatalf("AssetsForScan: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d assets, want 1", len(got))
	}

	a := got[0]
	checks := []struct {
		field     string
		got, want any
	}{
		{"Name", a.Name, want.Name},
		{"Repository", a.Repository, want.Repository},
		{"Tag", a.Tag, want.Tag},
		{"Version", a.Version, want.Version},
		{"VersionSource", a.VersionSource, want.VersionSource},
		{"Latest", a.Latest, want.Latest},
		{"SupportState", a.SupportState, want.SupportState},
		{"EOLCycle", a.EOLCycle, want.EOLCycle},
		{"EOLDate", a.EOLDate, want.EOLDate},
		{"State", a.State, want.State},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.field, c.got, c.want)
		}
	}

	if !a.Behind.Valid || a.Behind.Int64 != 7 {
		t.Errorf("Behind = %v, want 7", a.Behind)
	}
	if !a.NewerMajor.Valid || a.NewerMajor.Int64 != 2 {
		t.Errorf("NewerMajor = %v, want 2", a.NewerMajor)
	}
}

// TestBehindIsNullWhenIncomparable checks that "we did not compare" stays
// distinguishable from "zero releases behind".
func TestBehindIsNullWhenIncomparable(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	ctx := context.Background()

	scanID, err := db.BeginScan(ctx, "testhost")
	if err != nil {
		t.Fatalf("BeginScan: %v", err)
	}

	err = db.RecordObservation(ctx, scanID, Observation{
		Host: "testhost", Kind: "container", Name: "rolling",
		Repository: "library/rolling", Tag: "latest",
		Version: "latest", VersionSource: "tag",
		Comparable: false,
	})
	if err != nil {
		t.Fatalf("RecordObservation: %v", err)
	}

	got, err := db.AssetsForScan(ctx, scanID)
	if err != nil {
		t.Fatalf("AssetsForScan: %v", err)
	}
	if got[0].Behind.Valid {
		t.Errorf("Behind = %d, want NULL for an incomparable asset", got[0].Behind.Int64)
	}
}

// TestReconcileFindingsUnchecked guards resolution by absence against failed
// lookups. A finding missing because the lookup behind it failed has not
// been fixed; resolving it would report FIXED, then reopen it as NEW on the
// next good scan with its first_seen reset.
func TestReconcileFindingsUnchecked(t *testing.T) {
	eol := findings.Finding{
		Type: findings.TypeEOL, Severity: findings.SeverityHigh,
		Key: "1.20", Detail: "unsupported since 2022-05-24",
	}
	major := findings.Finding{
		Type: findings.TypeNewerMajor, Severity: findings.SeverityLow,
		Key: "2", Detail: "a 2.x line exists but is not comparable to 1.20",
	}

	// Every case starts from a first scan that opened both findings.
	tests := []struct {
		name      string
		second    []findings.Finding // what the second scan produced
		unchecked []findings.Type    // what the second scan could not check
		wantOpen  []findings.Type
		wantFixed []findings.Type
	}{
		{
			name:      "absent after a successful check resolves",
			wantFixed: []findings.Type{findings.TypeEOL, findings.TypeNewerMajor},
		},
		{
			name:      "lifecycle lookup failed keeps eol open",
			unchecked: []findings.Type{findings.TypeEOL, findings.TypeEOLApproaching},
			wantOpen:  []findings.Type{findings.TypeEOL},
			wantFixed: []findings.Type{findings.TypeNewerMajor},
		},
		{
			name:      "registry lookup failed keeps newer major open",
			second:    []findings.Finding{eol},
			unchecked: []findings.Type{findings.TypeNewerMajor},
			wantOpen:  []findings.Type{findings.TypeEOL, findings.TypeNewerMajor},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := Open(filepath.Join(t.TempDir(), "test.db"))
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			defer func() { _ = db.Close() }()

			ctx := context.Background()

			first := reconcileScan(t, db, []findings.Finding{eol, major}, nil)
			second := reconcileScan(t, db, tt.second, tt.unchecked)

			open, err := db.OpenFindings(ctx)
			if err != nil {
				t.Fatalf("OpenFindings: %v", err)
			}
			fixed, err := db.ResolvedInScan(ctx, second)
			if err != nil {
				t.Fatalf("ResolvedInScan: %v", err)
			}

			if got, want := recordTypes(open), typeNames(tt.wantOpen); !slices.Equal(got, want) {
				t.Errorf("open = %v, want %v", got, want)
			}
			if got, want := recordTypes(fixed), typeNames(tt.wantFixed); !slices.Equal(got, want) {
				t.Errorf("resolved = %v, want %v", got, want)
			}

			for _, f := range open {
				if f.FirstScanID != first {
					t.Errorf("%s: first_scan_id = %d, want %d: history was lost",
						f.Type, f.FirstScanID, first)
				}

				// A finding the second scan could not check was not observed
				// in it, so it must not appear to have been.
				wantLast := second
				if slices.Contains(tt.unchecked, findings.Type(f.Type)) {
					wantLast = first
				}
				if f.LastScanID != wantLast {
					t.Errorf("%s: last_scan_id = %d, want %d", f.Type, f.LastScanID, wantLast)
				}
			}
		})
	}
}

// reconcileScan runs one complete scan of a single asset that produced the
// given findings, and returns the scan id.
func reconcileScan(t *testing.T, db *Store, found []findings.Finding, unchecked []findings.Type) int64 {
	t.Helper()
	ctx := context.Background()

	scanID, err := db.BeginScan(ctx, "testhost")
	if err != nil {
		t.Fatalf("BeginScan: %v", err)
	}

	err = db.RecordObservation(ctx, scanID, Observation{
		Host: "testhost", Kind: "container", Name: "web",
		Repository: "library/nginx", Tag: "1.20",
		Version: "1.20", VersionSource: "tag",
	})
	if err != nil {
		t.Fatalf("RecordObservation: %v", err)
	}

	if err := db.ReconcileFindings(ctx, scanID, "testhost", "container", "web", found, unchecked); err != nil {
		t.Fatalf("ReconcileFindings: %v", err)
	}
	if err := db.FinishScan(ctx, scanID, 1, 0); err != nil {
		t.Fatalf("FinishScan: %v", err)
	}
	return scanID
}

// recordTypes returns the sorted types of stored findings. Sorted, because
// the query orders by severity and name, not by type.
func recordTypes(rs []FindingRecord) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.Type)
	}
	slices.Sort(out)
	return out
}

func typeNames(types []findings.Type) []string {
	out := make([]string, 0, len(types))
	for _, typ := range types {
		out = append(out, string(typ))
	}
	slices.Sort(out)
	return out
}

// TestMigrationsAreIdempotent checks that reopening an existing database
// does not re-apply migrations.
func TestMigrationsAreIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	for i := range 3 {
		db, err := Open(path)
		if err != nil {
			t.Fatalf("Open attempt %d: %v", i+1, err)
		}
		if err := db.Close(); err != nil {
			t.Fatalf("Close attempt %d: %v", i+1, err)
		}
	}
}
