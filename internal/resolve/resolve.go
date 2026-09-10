// Package resolve answers "what is the newest available version" for an
// asset, by querying container registries and, later, release APIs.
package resolve

import (
	"context"
	"time"
)

// Release is what a Resolver reports back.
type Release struct {
	// Latest is the newest tag of the same shape as the current one.
	Latest        string
	NewerMajor    int
	NewerMajorTag string

	// Behind counts releases newer than the current one.
	Behind int

	// Comparable is false when the current tag carries no version
	// information, such as "latest".
	Comparable bool

	// Digest is the registry digest the current tag points at now. For
	// moving tags this is how we detect the image changed underneath us.
	Digest string

	// CheckedAt records when this answer was produced.
	CheckedAt time.Time
}

// Resolver determines the newest available release for a repository.
type Resolver interface {
	// Name identifies the resolver in logs.
	Name() string

	// Resolve reports the newest tag comparable to currentTag.
	Resolve(ctx context.Context, registry, repository, currentTag string) (Release, error)
}
