package version

import "strings"

// MatchCycle finds which lifecycle release cycle a version belongs to.
//
// Lifecycle data is published per release cycle rather than per release:
// PostgreSQL has a cycle "13" covering 13.0 through 13.23, Alpine has "3.14",
// nginx has "1.28". Given a concrete version we must decide which cycle it
// falls in.
//
// A cycle matches when the version equals it exactly, or begins with it
// followed by a dot. The dot matters: version "1.201" must not match cycle
// "1.20". When several cycles match, the most specific one wins, so a
// product publishing both "3" and "3.14" resolves 3.14.2 to "3.14".
//
// The second return value is false when no cycle matches. That is a normal
// outcome, not an error: it usually means the version predates the data,
// which is itself worth reporting as unknown rather than guessed.
func MatchCycle(v string, cycles []string) (string, bool) {
	v = strings.TrimPrefix(v, "v")

	best := ""
	bestLen := -1

	for _, c := range cycles {
		trimmed := strings.TrimPrefix(c, "v")
		if v != trimmed && !strings.HasPrefix(v, trimmed+".") {
			continue
		}
		if len(trimmed) > bestLen {
			best, bestLen = c, len(trimmed)
		}
	}

	return best, bestLen >= 0
}
