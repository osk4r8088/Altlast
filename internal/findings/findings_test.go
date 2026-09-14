package findings

import "testing"

func TestEvaluate(t *testing.T) {
	tests := []struct {
		name string
		in   Input
		want []Type
	}{
		{
			name: "past eol",
			in:   Input{SupportState: "eol", EOLCycle: "13", EOLDate: "2025-11-13"},
			want: []Type{TypeEOL},
		},
		{
			name: "eol approaching",
			in:   Input{SupportState: "ending", EOLCycle: "3.20", EOLDate: "2026-11-01", EOLDays: 52},
			want: []Type{TypeEOLApproaching},
		},
		{
			name: "supported produces nothing",
			in:   Input{SupportState: "supported", EOLCycle: "2"},
			want: nil,
		},
		{
			// The most important case. Unknown lifecycle is common, and
			// treating it as a problem would flag half of every fleet.
			name: "unknown lifecycle produces nothing",
			in:   Input{SupportState: "unknown"},
			want: nil,
		},
		{
			name: "newer major line",
			in:   Input{SupportState: "unknown", Version: "10.8.0", NewerMajor: 12},
			want: []Type{TypeNewerMajor},
		},
		{
			name: "eol and newer major together",
			in: Input{
				SupportState: "eol", EOLCycle: "13", EOLDate: "2025-11-13",
				Version: "13.4", NewerMajor: 15,
			},
			want: []Type{TypeEOL, TypeNewerMajor},
		},
		{
			name: "resolve error",
			in:   Input{SupportState: "unknown", ResolveError: "connection refused"},
			want: []Type{TypeResolveError},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Evaluate(tt.in)
			if len(got) != len(tt.want) {
				t.Fatalf("got %d findings %v, want %d %v",
					len(got), types(got), len(tt.want), tt.want)
			}
			for i, f := range got {
				if f.Type != tt.want[i] {
					t.Errorf("finding %d = %s, want %s", i, f.Type, tt.want[i])
				}
			}
		})
	}
}

// TestBehindIsNotAFinding guards the central noise-control decision. If
// being behind ever becomes a finding, "new since last scan" stops being
// meaningful and the whole lifecycle is pointless.
func TestBehindIsNotAFinding(t *testing.T) {
	got := Evaluate(Input{SupportState: "supported", Version: "1.20"})
	if len(got) != 0 {
		t.Errorf("got %v, want no findings for a merely outdated asset", types(got))
	}
}

func TestKeyDistinguishesCycles(t *testing.T) {
	a := Evaluate(Input{SupportState: "eol", EOLCycle: "13", EOLDate: "2025-11-13"})
	b := Evaluate(Input{SupportState: "eol", EOLCycle: "14", EOLDate: "2026-11-12"})

	if a[0].Key == b[0].Key {
		t.Error("findings on different cycles must have different keys, " +
			"otherwise upgrading never resolves anything")
	}
}

func types(fs []Finding) []Type {
	out := make([]Type, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.Type)
	}
	return out
}
