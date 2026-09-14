package main

import (
	"io"
	"log"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"
)

// tracer writes diagnostic lines about a scan: every upstream HTTP request,
// and how long each asset's lookups took. It exists to find out where scan
// time goes, so it records measurements rather than conclusions.
//
// Every method is safe to call on a nil *tracer and does nothing, so call
// sites need no "if tracing" checks.
type tracer struct {
	// log.Logger serialises its writes, so goroutines can share it without
	// interleaving half-lines.
	log *log.Logger

	// requests is incremented from concurrent lookups, hence atomic.
	requests atomic.Int64
}

func newTracer(w io.Writer) *tracer {
	return &tracer{log: log.New(w, "trace ", log.Ltime|log.Lmicroseconds)}
}

func (t *tracer) printf(format string, args ...any) {
	if t == nil {
		return
	}
	t.log.Printf(format, args...)
}

// requestCount reports how many requests have been traced so far.
func (t *tracer) requestCount() int64 {
	if t == nil {
		return 0
	}
	return t.requests.Load()
}

// wrap returns base wrapped so that each request is traced. It matches the
// transport hook NewRegistryResolver and NewEOLClient accept.
func (t *tracer) wrap(base http.RoundTripper) http.RoundTripper {
	if t == nil {
		return base
	}
	return &traceTransport{base: base, t: t}
}

// traceTransport is an http.RoundTripper that logs each request it carries.
type traceTransport struct {
	base http.RoundTripper
	t    *tracer
}

// RoundTrip implements http.RoundTripper.
//
// The duration is time to response headers. Reading the body, which for a
// large tag list may be most of the cost, is not included here; it shows up
// in the per-asset lookup totals instead.
func (tt *traceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	start := time.Now()
	resp, err := tt.base.RoundTrip(req)
	elapsed := time.Since(start).Round(time.Millisecond)
	n := tt.t.requests.Add(1)

	if err != nil {
		tt.t.printf("http #%d %s %s failed after %s: %v",
			n, req.Method, traceURL(req.URL), elapsed, err)
		return resp, err
	}

	tt.t.printf("http #%d %s %d %s %s",
		n, req.Method, resp.StatusCode, elapsed, traceURL(req.URL))
	return resp, nil
}

// traceURL renders a request URL for the trace. Token requests can carry
// the account name in the query, which has no diagnostic value and does not
// belong in pasted output.
func traceURL(u *url.URL) string {
	c := *u
	c.User = nil
	if q := c.Query(); q.Has("account") {
		q.Del("account")
		c.RawQuery = q.Encode()
	}
	return c.String()
}
