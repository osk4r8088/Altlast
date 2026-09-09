// Package version parses and compares container image tags.
//
// The goal is not to implement semver. Real registry tags are messier than
// semver allows, and the useful question is narrower: given the tag a user
// runs, which other tags are comparable to it, and which of those is newest.
package version

import (
	"regexp"
	"strconv"
	"strings"
)

// Tag is a parsed image tag.
type Tag struct {
	Raw string // the original string, unchanged

	Prefix string // "v" in "v1.2.3", otherwise empty
	Nums   []int  // numeric components: 1.20.2 -> [1, 20, 2]

	// Prerelease marks a pre-stable build: rc1, beta2, alpha.
	// Empty for stable releases.
	Prerelease string

	// Variant is a build flavor: alpine, bookworm, alpine3.18.
	// Two tags with different variants are never compared.
	Variant string
}

// tagPattern matches an optional "v", one or more dot-separated numbers, and
// an optional suffix introduced by "-".
var tagPattern = regexp.MustCompile(`^(v)?(\d+(?:\.\d+)*)(?:-(.+))?$`)

// prereleasePattern recognises suffixes that mean "not yet stable".
var prereleasePattern = regexp.MustCompile(`^(rc|alpha|beta|pre|dev|snapshot|nightly)[.-]?\d*$`)

// Parse turns a tag string into a Tag. The second return value is false when
// the tag carries no version information at all, such as "latest" or "stable".
func Parse(s string) (Tag, bool) {
	m := tagPattern.FindStringSubmatch(s)
	if m == nil {
		return Tag{}, false
	}

	t := Tag{Raw: s, Prefix: m[1]}

	for _, part := range strings.Split(m[2], ".") {
		n, err := strconv.Atoi(part)
		if err != nil {
			// The regex guarantees digits, so this cannot happen in
			// practice. Bail out rather than pretend we parsed it.
			return Tag{}, false
		}
		t.Nums = append(t.Nums, n)
	}

	if suffix := m[3]; suffix != "" {
		if prereleasePattern.MatchString(strings.ToLower(suffix)) {
			t.Prerelease = suffix
		} else {
			t.Variant = suffix
		}
	}

	return t, true
}

// Shape returns a key identifying which tags are comparable to each other.
// Two tags are comparable when their shapes are equal.
//
//	"1.20" and "1.25"               -> same shape, comparable
//	"1.20" and "1.25.3"             -> different precision, not comparable
//	"1.20-alpine" and "1.25-alpine" -> same shape, comparable
//	"1.20" and "1.20-alpine"        -> different variant, not comparable
func (t Tag) Shape() string {
	return t.Prefix + "|" + strconv.Itoa(len(t.Nums)) + "|" + t.Variant
}

// IsStable reports whether the tag is a stable release rather than a
// prerelease.
func (t Tag) IsStable() bool { return t.Prerelease == "" }

// Compare returns -1 if t sorts before other, +1 if after, and 0 if they are
// equivalent. Comparing tags of different shapes is meaningless; callers
// should group by Shape first.
func (t Tag) Compare(other Tag) int {
	// Compare numeric components left to right. A missing component counts
	// as zero, so "1.2" sorts before "1.2.1".
	n := max(len(t.Nums), len(other.Nums))
	for i := range n {
		a, b := at(t.Nums, i), at(other.Nums, i)
		if a != b {
			if a < b {
				return -1
			}
			return 1
		}
	}

	// Same numbers: a stable release outranks a prerelease.
	switch {
	case t.IsStable() && !other.IsStable():
		return 1
	case !t.IsStable() && other.IsStable():
		return -1
	}

	return strings.Compare(t.Prerelease, other.Prerelease)
}

// at returns nums[i], or 0 when i is out of range.
func at(nums []int, i int) int {
	if i < len(nums) {
		return nums[i]
	}
	return 0
}

// Result describes how a running tag compares to what is available.
type Result struct {
	// Current is the tag being run. Zero value when the running tag
	// carries no version, such as "latest".
	Current Tag

	// Latest is the newest tag of the same shape as Current.
	Latest Tag

	// Behind counts how many releases of the same shape sit between
	// Current and Latest. Zero means up to date.
	Behind int

	// Comparable is true when Current could be compared at all. It is
	// false for "latest", "stable", and similar unversioned tags.
	Comparable bool
}

// UpToDate reports whether the current tag is the newest of its shape.
func (r Result) UpToDate() bool { return r.Comparable && r.Behind == 0 }

// SelectLatest determines what the newest available tag is, relative to the
// tag currently in use.
//
// Only tags sharing the current tag's Shape are considered. Running "1.20"
// will never be told to move to "1.25.3" or "1.25-alpine": those are
// different release lines, and recommending across them produces noise.
//
// Prereleases are excluded unless the current tag is itself a prerelease.
func SelectLatest(current string, available []string) Result {
	cur, ok := Parse(current)
	if !ok {
		// "latest" and friends: nothing to compare against.
		return Result{Comparable: false}
	}

	shape := cur.Shape()
	wantPrerelease := !cur.IsStable()

	var candidates []Tag
	for _, raw := range available {
		t, ok := Parse(raw)
		if !ok || t.Shape() != shape {
			continue
		}
		if !t.IsStable() && !wantPrerelease {
			continue
		}
		candidates = append(candidates, t)
	}

	res := Result{Current: cur, Latest: cur, Comparable: true}

	for _, c := range candidates {
		if c.Compare(res.Latest) > 0 {
			res.Latest = c
		}
		if c.Compare(cur) > 0 {
			res.Behind++
		}
	}

	return res
}
