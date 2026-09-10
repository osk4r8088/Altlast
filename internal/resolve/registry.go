package resolve

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/osk4r8088/altlast/internal/version"
)

// RegistryResolver queries container registries for available tags.
type RegistryResolver struct {
	cache *tagCache
	auth  authn.Keychain
}

// NewRegistryResolver returns a resolver with an on-disk tag cache.
//
// Authentication uses the ambient Docker config, so a prior `docker login`
// is picked up automatically. That matters on Docker Hub, where anonymous
// requests are rate limited per source IP.
func NewRegistryResolver(ttl time.Duration) (*RegistryResolver, error) {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	c, err := newTagCache(ttl)
	if err != nil {
		return nil, err
	}
	return &RegistryResolver{cache: c, auth: authn.DefaultKeychain}, nil
}

// Name implements Resolver.
func (r *RegistryResolver) Name() string { return "registry" }

// Resolve implements Resolver.
func (r *RegistryResolver) Resolve(ctx context.Context, registry, repository, currentTag string) (Release, error) {
	tags, err := r.tags(ctx, registry, repository)
	if err != nil {
		return Release{}, err
	}

	sel := version.SelectLatest(currentTag, tags)

	rel := Release{
		Comparable: sel.Comparable,
		Behind:     sel.Behind,
		CheckedAt:  time.Now(),
	}
	if sel.Comparable {
		rel.NewerMajor = sel.NewerMajor
		rel.NewerMajorTag = sel.NewerMajorTag
		rel.Latest = sel.Latest.Raw
	}

	// Resolve the digest the current tag points at, so a moving tag such
	// as "latest" can still be tracked for change.
	if digest, err := r.digest(ctx, registry, repository, currentTag); err == nil {
		rel.Digest = digest
	}

	return rel, nil
}

// tags returns every tag for a repository, from cache when possible.
func (r *RegistryResolver) tags(ctx context.Context, registry, repository string) ([]string, error) {
	if cached, ok := r.cache.get(registry, repository); ok {
		return cached, nil
	}

	repo, err := name.NewRepository(registry + "/" + repository)
	if err != nil {
		return nil, fmt.Errorf("parsing repository %s/%s: %w", registry, repository, err)
	}

	tags, err := remote.List(repo,
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(r.auth),
	)
	if err != nil {
		return nil, fmt.Errorf("listing tags for %s: %w", repo, err)
	}

	if err := r.cache.put(registry, repository, tags); err != nil {
		// A failed cache write costs performance, not correctness.
		fmt.Fprintf(os.Stderr, "warning: %v\n", err)
	}

	return tags, nil
}

// digest returns the registry digest a tag currently points at.
func (r *RegistryResolver) digest(ctx context.Context, registry, repository, tag string) (string, error) {
	ref, err := name.NewTag(fmt.Sprintf("%s/%s:%s", registry, repository, tag))
	if err != nil {
		return "", fmt.Errorf("parsing reference: %w", err)
	}

	desc, err := remote.Head(ref,
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(r.auth),
	)
	if err != nil {
		return "", fmt.Errorf("fetching digest: %w", err)
	}

	return desc.Digest.String(), nil
}
