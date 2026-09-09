package collect

import "strings"

// ImageRef is a parsed container image reference.
type ImageRef struct {
	Registry   string // docker.io, lscr.io, ghcr.io
	Repository string // library/nginx, linuxserver/jellyfin
	Tag        string // 1.20, latest
	Digest     string // sha256:... when the reference is digest-pinned
}

// String reassembles the reference in canonical form.
func (r ImageRef) String() string {
	s := r.Repository
	if r.Registry != "" {
		s = r.Registry + "/" + s
	}
	if r.Digest != "" {
		return s + "@" + r.Digest
	}
	return s + ":" + r.Tag
}

// ParseImage splits a container image reference into its parts.
//
// The rules are not obvious and are worth stating:
//
//   - "nginx:1.20"          -> docker.io/library/nginx:1.20
//   - "gitea/gitea:1.20.0"  -> docker.io/gitea/gitea:1.20.0
//   - "lscr.io/ls/app:1.0"  -> lscr.io/ls/app:1.0
//   - "getwud/wud"          -> docker.io/getwud/wud:latest
//   - "app@sha256:abc..."   -> digest-pinned, no tag
//
// The tricky part is deciding whether the first segment is a registry
// hostname or the start of a repository path. Docker's rule: it is a
// registry if it contains a dot or a colon, or if it is exactly
// "localhost". That is why "gitea/gitea" is a repository on Docker Hub
// while "lscr.io/x/y" has a registry.
func ParseImage(s string) ImageRef {
	var ref ImageRef

	// A digest, if present, always comes last and is separated by "@".
	if i := strings.Index(s, "@"); i >= 0 {
		ref.Digest = s[i+1:]
		s = s[:i]
	}

	// Split off a registry if the first segment looks like a hostname.
	remainder := s
	if i := strings.Index(s, "/"); i >= 0 {
		first := s[:i]
		if strings.ContainsAny(first, ".:") || first == "localhost" {
			ref.Registry = first
			remainder = s[i+1:]
		}
	}

	// A tag is separated by ":", but only in the last path segment, so
	// that a registry with a port such as "host:5000/app" is not misread.
	if i := strings.LastIndex(remainder, ":"); i >= 0 &&
		!strings.Contains(remainder[i:], "/") {
		ref.Tag = remainder[i+1:]
		remainder = remainder[:i]
	}

	ref.Repository = remainder

	// Apply Docker Hub defaults.
	if ref.Registry == "" {
		ref.Registry = "docker.io"
		// Official images live under the implicit "library" namespace.
		if !strings.Contains(ref.Repository, "/") {
			ref.Repository = "library/" + ref.Repository
		}
	}

	// An untagged, undigested reference means "latest".
	if ref.Tag == "" && ref.Digest == "" {
		ref.Tag = "latest"
	}

	return ref
}
