package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/osk4r8088/altlast/internal/version"
)

// DefaultDockerSocket is where the Docker daemon listens on Linux.
const DefaultDockerSocket = "/var/run/docker.sock"

// DockerCollector reads containers from a Docker daemon over its unix socket.
type DockerCollector struct {
	socket string
	client *http.Client
	all    bool // include stopped and created containers
}

// NewDockerCollector returns a collector reading from the given socket path.
// Pass an empty path to use the default. If all is true, containers that are
// not running are included too.
func NewDockerCollector(socket string, all bool) *DockerCollector {
	if socket == "" {
		socket = DefaultDockerSocket
	}

	// Docker speaks ordinary HTTP, but over a unix socket instead of TCP.
	// We keep the standard http.Client and only replace how it dials: the
	// host in the URL is ignored and every connection goes to the socket.
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
	}

	return &DockerCollector{
		socket: socket,
		all:    all,
		client: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		},
	}
}

// Name implements Collector.
func (c *DockerCollector) Name() string { return "docker" }

// dockerContainer mirrors the fields we need from Docker's /containers/json
// response. It is unexported: Docker's shape is an implementation detail and
// callers only ever see our own Asset type.
type dockerContainer struct {
	ID      string            `json:"Id"`
	Names   []string          `json:"Names"`
	Image   string            `json:"Image"`
	ImageID string            `json:"ImageID"`
	State   string            `json:"State"`
	Labels  map[string]string `json:"Labels"`
}

// Collect implements Collector.
func (c *DockerCollector) Collect(ctx context.Context) ([]Asset, error) {
	url := "http://docker/containers/json"
	if c.all {
		url += "?all=1"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("querying docker at %s: %w", c.socket, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("docker returned %s", resp.Status)
	}

	var containers []dockerContainer
	if err := json.NewDecoder(resp.Body).Decode(&containers); err != nil {
		return nil, fmt.Errorf("decoding docker response: %w", err)
	}

	assets := make([]Asset, 0, len(containers))
	for _, dc := range containers {
		assets = append(assets, dc.toAsset())
	}
	return assets, nil
}

// ociVersionLabel is the standard label carrying an image's own version.
const ociVersionLabel = "org.opencontainers.image.version"

// toAsset converts Docker's representation into ours.
func (dc dockerContainer) toAsset() Asset {
	ref := ParseImage(dc.Image)
	ver, src := resolveVersion(ref.Tag, dc.Labels)

	return Asset{
		Kind:          KindContainer,
		Name:          containerName(dc.Names),
		Registry:      ref.Registry,
		Repository:    ref.Repository,
		Tag:           ref.Tag,
		ImageID:       dc.ImageID,
		Digest:        ref.Digest,
		Version:       ver,
		VersionSource: src,
		State:         dc.State,
		Labels:        dc.Labels,
	}
}

// resolveVersion decides what version a container is running.
//
// The tag is used when it carries version information. When it does not,
// as with "latest" or "stable", the OCI version label is consulted: it
// describes the image actually on disk, so it reveals staleness that a
// moving tag hides.
func resolveVersion(tag string, labels map[string]string) (version string, source string) {
	if _, ok := parseable(tag); ok {
		return tag, "tag"
	}

	label := labels[ociVersionLabel]
	if label == "" {
		return tag, "tag"
	}

	// Strip a leading "v" so the value compares against registry tags,
	// which conventionally omit it.
	label = strings.TrimPrefix(label, "v")
	if _, ok := parseable(label); !ok {
		return tag, "tag"
	}

	return label, "oci-label"
}

// parseable reports whether s carries version information.
func parseable(s string) (version.Tag, bool) { return version.Parse(s) }

// containerName picks a usable name. Docker returns names with a leading
// slash for historical reasons, and a container can have several.
func containerName(names []string) string {
	if len(names) == 0 {
		return "<unnamed>"
	}
	return strings.TrimPrefix(names[0], "/")
}
