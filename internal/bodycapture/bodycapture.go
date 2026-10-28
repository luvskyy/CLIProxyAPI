// Package bodycapture accumulates bounded copies of request, upstream and
// response payloads for a single inbound HTTP request. It is independent of the
// file request logger so observability sinks can receive bodies while
// request-log is disabled.
package bodycapture

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"sync"

	"github.com/gin-gonic/gin"
)

// GinContextKey stores the active *Capture on the Gin context.
const GinContextKey = "CPA_BODY_CAPTURE"

// Buffer keeps the first Limit bytes written and counts the rest.
type Buffer struct {
	data  []byte
	total int64
	limit int
}

// Write appends p up to the limit. It never fails.
func (b *Buffer) Write(p []byte) {
	if b == nil || len(p) == 0 {
		return
	}
	b.total += int64(len(p))
	remaining := b.limit - len(b.data)
	if remaining <= 0 {
		return
	}
	if len(p) > remaining {
		p = p[:remaining]
	}
	b.data = append(b.data, p...)
}

// Bytes returns the captured prefix.
func (b *Buffer) Bytes() []byte {
	if b == nil {
		return nil
	}
	return b.data
}

// Total returns the number of bytes offered, including discarded bytes.
func (b *Buffer) Total() int64 {
	if b == nil {
		return 0
	}
	return b.total
}

// Truncated reports whether bytes were discarded.
func (b *Buffer) Truncated() bool {
	return b != nil && b.total > int64(len(b.data))
}

// Capture holds bounded payload copies for one inbound request. All methods are
// safe for concurrent use and tolerate a nil receiver.
type Capture struct {
	mu               sync.Mutex
	request          Buffer
	upstreamRequest  Buffer
	upstreamResponse Buffer
	response         Buffer
	attempts         int
	redact           func(http.Header) http.Header
}

// Snapshot is an immutable copy of the captured payloads.
type Snapshot struct {
	RequestBody               []byte
	RequestBodyBytes          int64
	RequestBodyTruncated      bool
	UpstreamRequest           []byte
	UpstreamRequestBytes      int64
	UpstreamRequestTruncated  bool
	UpstreamResponse          []byte
	UpstreamResponseBytes     int64
	UpstreamResponseTruncated bool
	ResponseBody              []byte
	ResponseBodyBytes         int64
	ResponseBodyTruncated     bool
}

// New creates a capture that keeps at most maxBytes per payload field. redact
// sanitizes upstream request/response headers before they are recorded; nil
// omits headers entirely.
func New(maxBytes int, redact func(http.Header) http.Header) *Capture {
	if maxBytes < 0 {
		maxBytes = 0
	}
	return &Capture{
		request:          Buffer{limit: maxBytes},
		upstreamRequest:  Buffer{limit: maxBytes},
		upstreamResponse: Buffer{limit: maxBytes},
		response:         Buffer{limit: maxBytes},
		redact:           redact,
	}
}

// FromGin returns the capture attached to c, if any.
func FromGin(c *gin.Context) *Capture {
	if c == nil {
		return nil
	}
	value, ok := c.Get(GinContextKey)
	if !ok {
		return nil
	}
	capture, _ := value.(*Capture)
	return capture
}

// FromContext returns the capture attached to the Gin context stored under the
// "gin" key of ctx, matching the executor logging helpers.
func FromContext(ctx context.Context) *Capture {
	if ctx == nil {
		return nil
	}
	ginCtx, _ := ctx.Value("gin").(*gin.Context)
	return FromGin(ginCtx)
}

// WriteRequest appends downstream request body bytes.
func (c *Capture) WriteRequest(p []byte) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.request.Write(p)
	c.mu.Unlock()
}

// WriteResponse appends downstream response body bytes.
func (c *Capture) WriteResponse(p []byte) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.response.Write(p)
	c.mu.Unlock()
}

// RecordUpstreamRequest appends a new upstream attempt with its headers and body.
func (c *Capture) RecordUpstreamRequest(method, url string, headers http.Header, body []byte) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.attempts++
	if c.attempts > 1 {
		c.upstreamRequest.Write([]byte("\n\n"))
	}
	if method == "" {
		method = http.MethodPost
	}
	c.upstreamRequest.Write([]byte(fmt.Sprintf("=== attempt %d: %s %s ===\n", c.attempts, method, url)))
	c.writeHeadersLocked(&c.upstreamRequest, headers)
	c.upstreamRequest.Write(body)
}

// RecordUpstreamResponseMeta appends the upstream status and headers for the latest attempt.
func (c *Capture) RecordUpstreamResponseMeta(status int, headers http.Header) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.upstreamResponse.Total() > 0 {
		c.upstreamResponse.Write([]byte("\n\n"))
	}
	c.upstreamResponse.Write([]byte(fmt.Sprintf("=== attempt %d: status %d ===\n", c.attempts, status)))
	c.writeHeadersLocked(&c.upstreamResponse, headers)
}

// AppendUpstreamResponse appends an upstream response chunk followed by a newline.
func (c *Capture) AppendUpstreamResponse(chunk []byte) {
	if c == nil || len(chunk) == 0 {
		return
	}
	c.mu.Lock()
	c.upstreamResponse.Write(chunk)
	c.upstreamResponse.Write([]byte("\n"))
	c.mu.Unlock()
}

// RecordUpstreamError appends a transport-level upstream error.
func (c *Capture) RecordUpstreamError(err error) {
	if c == nil || err == nil {
		return
	}
	c.mu.Lock()
	c.upstreamResponse.Write([]byte("Error: " + err.Error() + "\n"))
	c.mu.Unlock()
}

func (c *Capture) writeHeadersLocked(buf *Buffer, headers http.Header) {
	if c.redact != nil && len(headers) > 0 {
		redacted := c.redact(headers)
		keys := make([]string, 0, len(redacted))
		for key := range redacted {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			for _, value := range redacted[key] {
				buf.Write([]byte(key + ": " + value + "\n"))
			}
		}
	}
	buf.Write([]byte("\n"))
}

// Snapshot returns a copy of all captured payloads.
func (c *Capture) Snapshot() Snapshot {
	if c == nil {
		return Snapshot{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return Snapshot{
		RequestBody:               append([]byte(nil), c.request.Bytes()...),
		RequestBodyBytes:          c.request.Total(),
		RequestBodyTruncated:      c.request.Truncated(),
		UpstreamRequest:           append([]byte(nil), c.upstreamRequest.Bytes()...),
		UpstreamRequestBytes:      c.upstreamRequest.Total(),
		UpstreamRequestTruncated:  c.upstreamRequest.Truncated(),
		UpstreamResponse:          append([]byte(nil), c.upstreamResponse.Bytes()...),
		UpstreamResponseBytes:     c.upstreamResponse.Total(),
		UpstreamResponseTruncated: c.upstreamResponse.Truncated(),
		ResponseBody:              append([]byte(nil), c.response.Bytes()...),
		ResponseBodyBytes:         c.response.Total(),
		ResponseBodyTruncated:     c.response.Truncated(),
	}
}
