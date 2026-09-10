package store

import (
	"context"
	"path/filepath"
	"testing"
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
