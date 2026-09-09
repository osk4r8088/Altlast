// Package collect discovers assets on a host: containers, and later the
// operating system, kernel, and firmware.
package collect

import "context"

// Kind identifies what sort of thing an Asset is.
type Kind string

// Asset kinds. Containers come first; hosts and kernels arrive at M7.
const (
	KindContainer Kind = "container"
	KindHostOS    Kind = "host_os"
	KindKernel    Kind = "kernel"
)

// Asset is one versioned thing we track. Everything Altlast knows how to
// report on reduces to this type.
type Asset struct {
	Kind Kind   `json:"kind"`
	Name string `json:"name"`

	// Registry, Repository and Tag come from parsing the image reference.
	// For non-container assets they are empty.
	Registry   string `json:"registry,omitempty"`
	Repository string `json:"repository,omitempty"`
	Tag        string `json:"tag,omitempty"`

	// ImageID is Docker's local content ID. It is stable on this host but
	// is NOT the digest the registry serves.
	ImageID string `json:"image_id,omitempty"`

	// Digest is the registry digest (RepoDigest). Populated at M4; it is
	// how we detect that a moving tag such as "latest" has changed.
	Digest string `json:"digest,omitempty"`

	// Version is what we believe the asset is running. Normally the tag,
	// but for unversioned tags such as "latest" we fall back to the OCI
	// version label baked into the image.
	Version string `json:"version,omitempty"`

	// VersionSource records where Version came from: "tag" or "oci-label".
	VersionSource string `json:"version_source,omitempty"`

	// State is the container state: running, exited, created.
	State string `json:"state,omitempty"`

	// Labels carries container labels. Compose stores the project and
	// service name here, which we use later for remediation hints.
	Labels map[string]string `json:"labels,omitempty"`
}

// Collector discovers assets of one kind from one source.
//
// This is an interface rather than a concrete type so that the Docker
// collector, the host collector, and any future source are interchangeable.
// Nothing in Go says "implements": a type satisfies this interface simply by
// having a Collect method with this signature.
type Collector interface {
	// Name identifies the collector in logs and output.
	Name() string

	// Collect returns every asset this collector can see.
	Collect(ctx context.Context) ([]Asset, error)
}

// Document is what `altlast collect` emits. Keeping it versioned means a
// future hub can read output produced by an older collector.
type Document struct {
	Schema    int     `json:"schema"`
	Host      string  `json:"host"`
	Timestamp string  `json:"timestamp"`
	Assets    []Asset `json:"assets"`
}

// SchemaVersion is the current version of Document.
const SchemaVersion = 1
