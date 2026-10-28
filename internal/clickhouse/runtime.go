package clickhouse

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/bodycapture"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	internallogging "github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
	coreusage "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/usage"
	log "github.com/sirupsen/logrus"
)

const closeTimeout = 10 * time.Second

var (
	activeMu sync.RWMutex
	active   *Sink
)

func init() {
	coreusage.RegisterNamedPlugin("clickhouse", usagePlugin{})
}

func currentSink() *Sink {
	activeMu.RLock()
	defer activeMu.RUnlock()
	return active
}

// Apply starts, reconfigures or stops the global sink to match cfg. It is safe
// to call on every config reload; an unchanged configuration is a no-op.
func Apply(cfg *config.Config) {
	settings := SettingsFromConfig(cfg)
	activeMu.Lock()
	previous := active
	if previous != nil && previous.Settings() == settings {
		activeMu.Unlock()
		return
	}
	if previous == nil && !settings.Enabled {
		activeMu.Unlock()
		return
	}
	active = nil
	if settings.Enabled {
		if errValidate := settings.Validate(); errValidate != nil {
			log.WithError(errValidate).Error("clickhouse sink disabled")
		} else {
			active = NewSink(settings, nil)
			log.Infof("clickhouse sink enabled: endpoint=%s database=%s capture-bodies=%t", settings.Endpoint, settings.Database, settings.CaptureBodies)
		}
	}
	activeMu.Unlock()
	if previous != nil {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), closeTimeout)
			defer cancel()
			if errClose := previous.Close(ctx); errClose != nil {
				log.WithError(errClose).Warn("clickhouse sink: previous sink did not flush before timeout")
			}
		}()
	}
}

// Shutdown flushes and stops the global sink.
func Shutdown(ctx context.Context) error {
	activeMu.Lock()
	sink := active
	active = nil
	activeMu.Unlock()
	return sink.Close(ctx)
}

type usagePlugin struct{}

// HandleUsage converts a usage record into a usage row.
func (usagePlugin) HandleUsage(ctx context.Context, record coreusage.Record) {
	sink := currentSink()
	if sink == nil {
		return
	}
	sink.Enqueue(tableUsage, newUsageRow(ctx, record))
}

// CaptureMiddleware captures bounded request and response bodies and ships them
// to the bodies table when the sink is enabled with capture-bodies. It never
// writes files and does not depend on request-log.
func CaptureMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		sink := currentSink()
		if sink == nil || !sink.Settings().CaptureBodies || !shouldCapture(c.Request) {
			c.Next()
			return
		}
		start := time.Now()
		capture := bodycapture.New(sink.Settings().MaxBodyBytes, RedactHeaders)
		c.Set(bodycapture.GinContextKey, capture)
		if c.Request.Body != nil && c.Request.Body != http.NoBody {
			c.Request.Body = &teeReadCloser{body: c.Request.Body, capture: capture}
		}
		requestHeaders := c.Request.Header.Clone()
		writer := &captureWriter{ResponseWriter: c.Writer, capture: capture}
		c.Writer = writer

		c.Next()
		c.Writer = writer.ResponseWriter

		if writer.hijacked {
			return
		}
		requestURL := c.Request.URL.Path
		if redacted := redactQuery(c.Request.URL.Query()); redacted != "" {
			requestURL += "?" + redacted
		}
		clientKey := coreusage.APIKeyFromContext(c.Request.Context())
		if clientKey == "" {
			clientKey = c.GetString("userApiKey")
		}
		meta := BodyMeta{
			RequestedAt:     start,
			RequestID:       internallogging.GetGinRequestID(c),
			URL:             requestURL,
			Method:          c.Request.Method,
			StatusCode:      writer.Status(),
			Duration:        time.Since(start),
			ClientKey:       clientKey,
			RequestHeaders:  requestHeaders,
			ResponseHeaders: writer.Header().Clone(),
		}
		row := newBodyRow(meta, capture.Snapshot())
		sink.EnqueueSized(tableBodies, row, row.size())
	}
}

func shouldCapture(req *http.Request) bool {
	if req == nil || req.URL == nil {
		return false
	}
	if req.Method == http.MethodGet || req.Method == http.MethodOptions || req.Method == http.MethodHead {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(req.Header.Get("Upgrade")), "websocket") {
		return false
	}
	path := req.URL.Path
	// Realtime client-secret/session responses carry short-lived credentials.
	if strings.Contains(path, "/realtime/client_secrets") || strings.Contains(path, "/realtime/sessions") {
		return false
	}
	return !strings.HasPrefix(path, "/v0/management") && !strings.HasPrefix(path, "/v8/management") && !strings.HasPrefix(path, "/management")
}

// redactQuery fully replaces sensitive query values (client keys may arrive as ?key=).
func redactQuery(values url.Values) string {
	if len(values) == 0 {
		return ""
	}
	for name := range values {
		if isSensitiveHeader(name) || strings.EqualFold(name, "auth_token") {
			values[name] = []string{"[REDACTED]"}
		}
	}
	return values.Encode()
}
