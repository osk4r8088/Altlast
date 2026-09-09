package version

import "testing"

func TestMatchCycle(t *testing.T) {
	postgres := []string{"18", "17", "16", "15", "14", "13", "12", "11"}
	alpine := []string{"3.24", "3.23", "3.22", "3.21", "3.20", "3.15", "3.14"}
	nginx := []string{"1.29", "1.28", "1.26", "1.24"}

	tests := []struct {
		name    string
		version string
		cycles  []string
		want    string
		wantOK  bool
	}{
		{"postgres patch resolves to major cycle", "13.4", postgres, "13", true},
		{"postgres bare major", "13", postgres, "13", true},
		{"alpine two-component cycle", "3.14", alpine, "3.14", true},
		{"alpine patch inside cycle", "3.14.6", alpine, "3.14", true},
		{"nginx version with no published cycle", "1.20", nginx, "", false},
		{"nginx current cycle", "1.28.1", nginx, "1.28", true},
		{"v prefix is ignored", "v13.4", postgres, "13", true},

		// The dot guard: without it "1.201" would match cycle "1.20".
		{"longer number is not a prefix match", "1.201", nginx, "", false},

		// Most specific cycle wins when both are published.
		{"most specific cycle wins", "3.14.2", []string{"3", "3.14"}, "3.14", true},

		{"no cycles at all", "1.0.0", nil, "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := MatchCycle(tt.version, tt.cycles)
			if ok != tt.wantOK {
				t.Fatalf("MatchCycle(%q) ok = %v, want %v", tt.version, ok, tt.wantOK)
			}
			if got != tt.want {
				t.Errorf("MatchCycle(%q) = %q, want %q", tt.version, got, tt.want)
			}
		})
	}
}
