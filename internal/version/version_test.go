package version

import "testing"

func TestParse(t *testing.T) {
	tests := []struct {
		in         string
		ok         bool
		nums       []int
		prefix     string
		prerelease string
		variant    string
	}{
		{in: "1.20", ok: true, nums: []int{1, 20}},
		{in: "13.4", ok: true, nums: []int{13, 4}},
		{in: "10.8.0", ok: true, nums: []int{10, 8, 0}},
		{in: "1.29.0", ok: true, nums: []int{1, 29, 0}},
		{in: "3.14", ok: true, nums: []int{3, 14}},
		{in: "v1.2.3", ok: true, nums: []int{1, 2, 3}, prefix: "v"},
		{in: "2024.10.1", ok: true, nums: []int{2024, 10, 1}},
		{in: "1.20.2-alpine", ok: true, nums: []int{1, 20, 2}, variant: "alpine"},
		{in: "1.25.3-alpine3.18", ok: true, nums: []int{1, 25, 3}, variant: "alpine3.18"},
		{in: "1.20.0-rc1", ok: true, nums: []int{1, 20, 0}, prerelease: "rc1"},
		{in: "2.0.0-beta.2", ok: true, nums: []int{2, 0, 0}, prerelease: "beta.2"},

		// LinuxServer runs the suffix straight on from the digits with no
		// separator. Before this was handled, every such tag was silently
		// discarded and a whole 12.x line was invisible.
		{in: "10.11.11ubu2404-ls36", ok: true, nums: []int{10, 11, 11}, variant: "ubu2404-ls36"},
		{in: "12.0ubu2604-ls48", ok: true, nums: []int{12, 0}, variant: "ubu2604-ls48"},

		{in: "latest", ok: false},
		{in: "stable", ok: false},
		{in: "mainline", ok: false},
		{in: "stable-bookworm", ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, ok := Parse(tt.in)
			if ok != tt.ok {
				t.Fatalf("Parse(%q) ok = %v, want %v", tt.in, ok, tt.ok)
			}
			if !ok {
				return
			}
			if !equalInts(got.Nums, tt.nums) {
				t.Errorf("nums = %v, want %v", got.Nums, tt.nums)
			}
			if got.Prefix != tt.prefix {
				t.Errorf("prefix = %q, want %q", got.Prefix, tt.prefix)
			}
			if got.Prerelease != tt.prerelease {
				t.Errorf("prerelease = %q, want %q", got.Prerelease, tt.prerelease)
			}
			if got.Variant != tt.variant {
				t.Errorf("variant = %q, want %q", got.Variant, tt.variant)
			}
		})
	}
}

func TestShape(t *testing.T) {
	same := func(a, b string) {
		t.Helper()
		ta, _ := Parse(a)
		tb, _ := Parse(b)
		if ta.Shape() != tb.Shape() {
			t.Errorf("%q and %q should share a shape, got %q and %q",
				a, b, ta.Shape(), tb.Shape())
		}
	}
	differ := func(a, b string) {
		t.Helper()
		ta, _ := Parse(a)
		tb, _ := Parse(b)
		if ta.Shape() == tb.Shape() {
			t.Errorf("%q and %q should differ in shape, both %q", a, b, ta.Shape())
		}
	}

	same("1.20", "1.25")
	same("1.20.2-alpine", "1.25.3-alpine")
	same("10.8.0", "10.10.7")

	differ("1.20", "1.25.3")
	differ("1.20", "1.20-alpine")
	differ("1.2.3", "v1.2.3")
	differ("10.8.0", "2021.12.16")
}

func TestCompare(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.20", "1.25", -1},
		{"1.25", "1.20", 1},
		{"1.20", "1.20", 0},
		{"1.2", "1.10", -1}, // numeric, not lexical
		{"10.8.0", "10.10.0", -1},
		{"1.2.3", "1.2", 1},        // more components, higher
		{"1.0.0-rc1", "1.0.0", -1}, // prerelease sorts below release
		{"1.0.0", "1.0.0-rc1", 1},
		{"1.0.0-rc1", "1.0.0-rc2", -1},
	}

	for _, tt := range tests {
		t.Run(tt.a+"_vs_"+tt.b, func(t *testing.T) {
			ta, okA := Parse(tt.a)
			tb, okB := Parse(tt.b)
			if !okA || !okB {
				t.Fatalf("failed to parse %q or %q", tt.a, tt.b)
			}
			if got := ta.Compare(tb); got != tt.want {
				t.Errorf("Compare(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestSelectLatest(t *testing.T) {
	nginxTags := []string{
		"1.18", "1.20", "1.22", "1.24", "1.26", "1.28",
		"1.20.2", "1.24.0", "1.28.0",
		"1.20-alpine", "1.28-alpine",
		"1.29.0-rc1",
		"latest", "stable", "mainline", "stable-bookworm",
	}

	tests := []struct {
		name           string
		current        string
		available      []string
		wantLatest     string
		wantBehind     int
		wantCmp        bool
		wantNewerMajor int
	}{
		{
			name:       "two-component tag ignores three-component and variants",
			current:    "1.20",
			available:  nginxTags,
			wantLatest: "1.28",
			wantBehind: 4, // 1.22, 1.24, 1.26, 1.28
			wantCmp:    true,
		},
		{
			name:       "variant tags compare only among themselves",
			current:    "1.20-alpine",
			available:  nginxTags,
			wantLatest: "1.28-alpine",
			wantBehind: 1,
			wantCmp:    true,
		},
		{
			name:       "already newest",
			current:    "1.28",
			available:  nginxTags,
			wantLatest: "1.28",
			wantBehind: 0,
			wantCmp:    true,
		},
		{
			name:      "unversioned tag is not comparable",
			current:   "latest",
			available: nginxTags,
			wantCmp:   false,
		},
		{
			name:       "prereleases excluded for stable current",
			current:    "1.28.0",
			available:  nginxTags,
			wantLatest: "1.28.0",
			wantBehind: 0,
			wantCmp:    true,
		},
		{
			name:       "no comparable tags leaves current as latest",
			current:    "2.5.1",
			available:  []string{"latest", "stable"},
			wantLatest: "2.5.1",
			wantBehind: 0,
			wantCmp:    true,
		},
		{
			name:    "calendar tags never beat semver tags",
			current: "10.8.0",
			available: []string{
				"10.8.0", "10.9.11", "10.10.7",
				"2021.12.16", "2024.01.02",
			},
			wantLatest: "10.10.7",
			wantBehind: 2,
			wantCmp:    true,
		},
		{
			// A shape-filtered recommendation must never silently hide a
			// whole major line. It is reported, not recommended.
			name:    "higher major line is noted but not recommended",
			current: "10.8.0",
			available: []string{
				"10.8.0", "10.11.11", "12.0ubu2604-ls48", "latest",
			},
			wantLatest:     "10.11.11",
			wantBehind:     1,
			wantCmp:        true,
			wantNewerMajor: 12,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SelectLatest(tt.current, tt.available)

			if got.Comparable != tt.wantCmp {
				t.Fatalf("Comparable = %v, want %v", got.Comparable, tt.wantCmp)
			}
			if !tt.wantCmp {
				return
			}
			if got.Latest.Raw != tt.wantLatest {
				t.Errorf("Latest = %q, want %q", got.Latest.Raw, tt.wantLatest)
			}
			if got.Behind != tt.wantBehind {
				t.Errorf("Behind = %d, want %d", got.Behind, tt.wantBehind)
			}
			if got.NewerMajor != tt.wantNewerMajor {
				t.Errorf("NewerMajor = %d, want %d", got.NewerMajor, tt.wantNewerMajor)
			}
		})
	}
}

func TestNewerMajor(t *testing.T) {
	t.Run("notes an unreachable major line", func(t *testing.T) {
		r := SelectLatest("10.8.0", []string{"10.11.11", "12.0ubu2604-ls48"})
		if r.NewerMajor != 12 {
			t.Errorf("NewerMajor = %d, want 12", r.NewerMajor)
		}
	})

	t.Run("silent when the recommendation already covers it", func(t *testing.T) {
		r := SelectLatest("13.4", []string{"13.4", "16.2", "18.6"})
		if r.NewerMajor != 0 {
			t.Errorf("NewerMajor = %d, want 0 (18.6 is already recommended)", r.NewerMajor)
		}
	})

	t.Run("silent within one major line", func(t *testing.T) {
		r := SelectLatest("1.20", []string{"1.20", "1.28", "1.31"})
		if r.NewerMajor != 0 {
			t.Errorf("NewerMajor = %d, want 0", r.NewerMajor)
		}
	})

	t.Run("calendar tags do not count as a newer major", func(t *testing.T) {
		r := SelectLatest("10.8.0", []string{"10.11.11", "2024.01.02"})
		if r.NewerMajor != 0 {
			t.Errorf("NewerMajor = %d, want 0 (2024 is a date, not a major)", r.NewerMajor)
		}
	})

	// Every case below came from real registry data that produced a false
	// positive on the first implementation.

	t.Run("datestamp tags are not major versions", func(t *testing.T) {
		r := SelectLatest("3.14", []string{"3.24", "20260805", "20260805.1"})
		if r.NewerMajor != 0 {
			t.Errorf("NewerMajor = %d, want 0 (20260805 is a datestamp)", r.NewerMajor)
		}
	})

	t.Run("build counters are not major versions", func(t *testing.T) {
		r := SelectLatest("8.4.0", []string{"8.4.0", "667", "667.1"})
		if r.NewerMajor != 0 {
			t.Errorf("NewerMajor = %d, want 0 (667 is a build counter)", r.NewerMajor)
		}
	})

	t.Run("single-component tags never qualify", func(t *testing.T) {
		r := SelectLatest("10.8.0", []string{"10.11.11", "11", "12"})
		if r.NewerMajor != 0 {
			t.Errorf("NewerMajor = %d, want 0 (bare majors are too weak a signal)", r.NewerMajor)
		}
	})

	t.Run("a jump of more than two majors is implausible", func(t *testing.T) {
		r := SelectLatest("1.20", []string{"1.31", "9.0.1"})
		if r.NewerMajor != 0 {
			t.Errorf("NewerMajor = %d, want 0 (1 to 9 is not a next line)", r.NewerMajor)
		}
	})
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
