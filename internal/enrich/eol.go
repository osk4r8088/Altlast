package enrich

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/osk4r8088/altlast/internal/version"
)

// eolBaseURL is the endoflife.date v1 API. The v1 API is documented as beta,
// so every type shaped by it lives in this file: a breaking change upstream
// should touch one file and nothing else.
const eolBaseURL = "https://endoflife.date/api/v1"

// SupportState describes where an asset sits in its support lifecycle.
type SupportState string

const (
	// SupportUnknown means no lifecycle data exists for this product, or
	// the running version matches no published cycle. Roughly half of a
	// typical stack falls here, and saying so plainly is better than
	// implying everything is fine.
	SupportUnknown SupportState = "unknown"

	// SupportActive means the release cycle is maintained.
	SupportActive SupportState = "supported"

	// SupportEnding means an end-of-life date is published and near.
	SupportEnding SupportState = "ending"

	// SupportEnded means the cycle no longer receives fixes.
	SupportEnded SupportState = "eol"
)

// EndingThreshold is how far ahead an EOL date counts as "ending".
const EndingThreshold = 180 * 24 * time.Hour

// Lifecycle is what we report about an asset's support status.
type Lifecycle struct {
	State   SupportState
	Product string // endoflife.date slug, empty when unknown
	Cycle   string // matched release cycle, empty when unmatched
	EOLDate string // RFC3339 date, empty when none published
	Days    int    // days until EOL; negative when already past
	Latest  string // newest release in this cycle
}

// apiRelease mirrors one release cycle in the v1 API response.
type apiRelease struct {
	Name         string `json:"name"`
	Label        string `json:"label"`
	ReleaseDate  string `json:"releaseDate"`
	IsLTS        bool   `json:"isLts"`
	IsEOL        bool   `json:"isEol"`
	EOLFrom      string `json:"eolFrom"`
	IsMaintained bool   `json:"isMaintained"`
	Latest       struct {
		Name string `json:"name"`
		Date string `json:"date"`
		Link string `json:"link"`
	} `json:"latest"`
}

// apiProduct mirrors the v1 product response envelope.
type apiProduct struct {
	SchemaVersion string `json:"schema_version"`
	GeneratedAt   string `json:"generated_at"`
	Result        struct {
		Name     string       `json:"name"`
		Label    string       `json:"label"`
		Releases []apiRelease `json:"releases"`
	} `json:"result"`
}

// EOLClient queries endoflife.date, caching responses on disk.
type EOLClient struct {
	http    *http.Client
	cache   *jsonCache
	catalog *Catalog
}

// NewEOLClient returns a client with an on-disk cache. Lifecycle data
// changes rarely, so the TTL is generous.
func NewEOLClient(ttl time.Duration) (*EOLClient, error) {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}

	cache, err := newJSONCache("eol", ttl)
	if err != nil {
		return nil, err
	}

	cat, err := LoadCatalog()
	if err != nil {
		return nil, err
	}

	return &EOLClient{
		http:    &http.Client{Timeout: 20 * time.Second},
		cache:   cache,
		catalog: cat,
	}, nil
}

// Lookup reports the support state of a version of a repository.
//
// An unknown result is returned, with no error, when the repository is not
// in the catalog or the version matches no published cycle. Errors are
// reserved for things that actually went wrong, such as the API being
// unreachable.
func (c *EOLClient) Lookup(ctx context.Context, repository, ver string) (Lifecycle, error) {
	product, ok := c.catalog.Product(repository)
	if !ok {
		return Lifecycle{State: SupportUnknown}, nil
	}

	releases, err := c.releases(ctx, product)
	if err != nil {
		return Lifecycle{State: SupportUnknown, Product: product}, err
	}

	names := make([]string, 0, len(releases))
	for _, r := range releases {
		names = append(names, r.Name)
	}

	cycle, ok := version.MatchCycle(ver, names)
	if !ok {
		// The version predates the published data, or is not a release
		// of this product at all. Unknown is the honest answer.
		return Lifecycle{State: SupportUnknown, Product: product}, nil
	}

	for _, r := range releases {
		if r.Name != cycle {
			continue
		}
		return lifecycleFrom(product, r), nil
	}

	return Lifecycle{State: SupportUnknown, Product: product}, nil
}

// lifecycleFrom converts an API release into our Lifecycle.
func lifecycleFrom(product string, r apiRelease) Lifecycle {
	lc := Lifecycle{
		Product: product,
		Cycle:   r.Name,
		EOLDate: r.EOLFrom,
		Latest:  r.Latest.Name,
	}

	switch {
	case r.IsEOL:
		lc.State = SupportEnded
	case r.EOLFrom == "":
		// Maintained with no announced end date.
		lc.State = SupportActive
	default:
		lc.State = SupportActive
	}

	if r.EOLFrom != "" {
		if eol, err := time.Parse("2006-01-02", r.EOLFrom); err == nil {
			lc.Days = int(time.Until(eol).Hours() / 24)
			if !r.IsEOL && time.Until(eol) < EndingThreshold {
				lc.State = SupportEnding
			}
		}
	}

	return lc
}

// releases fetches a product's release cycles, from cache when possible.
func (c *EOLClient) releases(ctx context.Context, product string) ([]apiRelease, error) {
	var cached apiProduct
	if ok := c.cache.get(product, &cached); ok {
		return cached.Result.Releases, nil
	}

	url := fmt.Sprintf("%s/products/%s/", eolBaseURL, product)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "altlast (+https://github.com/osk4r8088/altlast)")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("querying endoflife.date for %s: %w", product, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("product %q not found on endoflife.date", product)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("endoflife.date returned %s for %s", resp.Status, product)
	}

	var out apiProduct
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decoding endoflife.date response: %w", err)
	}

	if err := c.cache.put(product, out); err != nil {
		return out.Result.Releases, nil // cache failure is not fatal
	}

	return out.Result.Releases, nil
}
