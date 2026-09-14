// Package findings turns the facts recorded by a scan into things worth
// telling someone about.
//
// The distinction matters. An observation is what was true: this container
// runs 13.4, the newest is 18.6, the cycle ended in November. A finding is
// something that changed the risk picture. Most facts are not findings:
// being behind is the normal condition of all software, and a tool that
// reports it as a problem produces a wall of noise that trains people to
// ignore it.
package findings

import "fmt"

// Type identifies a class of finding.
type Type string

const (
	// TypeEOL means the running release cycle no longer receives fixes.
	TypeEOL Type = "eol"

	// TypeEOLApproaching means an end-of-life date is published and near.
	TypeEOLApproaching Type = "eol_approaching"

	// TypeNewerMajor means a higher major line exists that shape-aware
	// comparison cannot recommend across, so it would otherwise be
	// invisible.
	TypeNewerMajor Type = "newer_major"

	// TypeResolveError means upstream could not be checked. Not a
	// vulnerability, but a blind spot, and a blind spot that persists is
	// worth surfacing.
	TypeResolveError Type = "resolve_error"
)

// Severity ranks findings for display and for notification thresholds.
type Severity string

// Severity levels, most serious first.
const (
	SeverityHigh   Severity = "high"
	SeverityMedium Severity = "medium"
	SeverityLow    Severity = "low"
)

// Rank returns a sort order, lowest first for most severe.
func (s Severity) Rank() int {
	switch s {
	case SeverityHigh:
		return 0
	case SeverityMedium:
		return 1
	default:
		return 2
	}
}

// Finding is one thing worth telling someone about.
type Finding struct {
	Type     Type
	Severity Severity

	// Key distinguishes instances of the same type on the same asset.
	// EOL on cycle 13 and EOL on cycle 14 are different findings, so
	// upgrading resolves the first and may open the second.
	Key string

	// Detail is a human-readable summary, snapshotted when the finding
	// opens. It is display text, never something to parse.
	Detail string
}

// Input is everything the rules need from one observation. It deliberately
// duplicates fields from other packages rather than importing them: the
// rules stay a pure function of plain data, which keeps them testable and
// keeps this package free of dependencies.
type Input struct {
	Version string

	SupportState string // supported | ending | eol | unknown
	EOLCycle     string
	EOLDate      string
	EOLDays      int

	NewerMajor    int
	NewerMajorTag string

	// ResolveError and EOLError are set when a lookup failed, as distinct
	// from succeeding and finding nothing.
	ResolveError string
	EOLError     string
}

// Evaluate applies the rules to one observation.
//
// Being behind is deliberately absent. Almost everything is behind almost
// always, so reporting it as a finding would mean every scan produces a
// finding for every asset and "new since last scan" would never be empty.
// It remains a visible, sortable column; it is just not news.
func Evaluate(in Input) []Finding {
	var out []Finding

	switch in.SupportState {
	case "eol":
		detail := "no longer receives security fixes"
		if in.EOLDate != "" {
			detail = fmt.Sprintf("unsupported since %s", in.EOLDate)
		}
		out = append(out, Finding{
			Type:     TypeEOL,
			Severity: SeverityHigh,
			Key:      in.EOLCycle,
			Detail:   detail,
		})

	case "ending":
		detail := "support ends soon"
		if in.EOLDate != "" {
			detail = fmt.Sprintf("support ends %s (%d days)", in.EOLDate, in.EOLDays)
		}
		out = append(out, Finding{
			Type:     TypeEOLApproaching,
			Severity: SeverityMedium,
			Key:      in.EOLCycle,
			Detail:   detail,
		})
	}

	if in.NewerMajor > 0 {
		out = append(out, Finding{
			Type:     TypeNewerMajor,
			Severity: SeverityLow,
			Key:      fmt.Sprintf("%d", in.NewerMajor),
			Detail: fmt.Sprintf("a %d.x line exists but is not comparable to %s",
				in.NewerMajor, in.Version),
		})
	}

	if in.ResolveError != "" {
		out = append(out, Finding{
			Type:     TypeResolveError,
			Severity: SeverityLow,
			// No key: there is only ever one resolution failure per asset,
			// and keying on the message would open a new finding every
			// time the wording changed.
			Detail: "could not check upstream",
		})
	}

	return out
}

// Unchecked returns the finding types this observation could not evaluate,
// because the lookup that produces them failed.
//
// Evaluate producing no EOL finding normally means the asset is no longer
// past end of life. After a failed lifecycle lookup it means only that we do
// not know. Resolving an open finding on that basis would report it fixed,
// then reopen it as new on the next successful scan with its history gone.
func Unchecked(in Input) []Type {
	var out []Type
	if in.EOLError != "" {
		out = append(out, TypeEOL, TypeEOLApproaching)
	}
	if in.ResolveError != "" {
		out = append(out, TypeNewerMajor)
	}
	return out
}
