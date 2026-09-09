package collect

import "testing"

func TestParseImage(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want ImageRef
	}{
		{
			name: "official image with tag",
			in:   "nginx:1.20",
			want: ImageRef{Registry: "docker.io", Repository: "library/nginx", Tag: "1.20"},
		},
		{
			name: "namespaced image with tag",
			in:   "gitea/gitea:1.20.0",
			want: ImageRef{Registry: "docker.io", Repository: "gitea/gitea", Tag: "1.20.0"},
		},
		{
			name: "explicit registry",
			in:   "lscr.io/linuxserver/jellyfin:10.8.0",
			want: ImageRef{Registry: "lscr.io", Repository: "linuxserver/jellyfin", Tag: "10.8.0"},
		},
		{
			name: "no tag defaults to latest",
			in:   "getwud/wud",
			want: ImageRef{Registry: "docker.io", Repository: "getwud/wud", Tag: "latest"},
		},
		{
			name: "explicit latest",
			in:   "caddy:latest",
			want: ImageRef{Registry: "docker.io", Repository: "library/caddy", Tag: "latest"},
		},
		{
			name: "digest pinned",
			in:   "alpine@sha256:abc123",
			want: ImageRef{Registry: "docker.io", Repository: "library/alpine", Digest: "sha256:abc123"},
		},
		{
			name: "registry with port",
			in:   "registry.local:5000/team/app:2.1",
			want: ImageRef{Registry: "registry.local:5000", Repository: "team/app", Tag: "2.1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseImage(tt.in)
			if got != tt.want {
				t.Errorf("ParseImage(%q)\n got: %+v\nwant: %+v", tt.in, got, tt.want)
			}
		})
	}
}