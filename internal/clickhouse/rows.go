package clickhouse

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/bodycapture"
	internallogging "github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
	coreusage "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/usage"
)

const (
	tableUsage  = "usage"
	tableBodies = "bodies"

	redactedValue      = "[REDACTED]"
	maxErrorBodyBytes  = 16 << 10
	clickHouseTimeForm = "2006-01-02 15:04:05.000"
)

// ClientKeyID returns a stable, non-reversible identifier for a client API key:
// the first 12 hex characters of its SHA-256 digest. Empty keys map to "".
func ClientKeyID(key string) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])[:12]
}

var sensitiveHeaderNames = map[string]bool{
	"authorization":       true,
	"proxy-authorization": true,
	"x-api-key":           true,
	"cookie":              true,
	"set-cookie":          true,
}

// isSensitiveHeader reports whether a header value must not be stored. Headers
// whose name contains "token", "secret" or "key" are redacted, except rate-limit
// counters (e.g. anthropic-ratelimit-input-tokens-remaining), which carry
// numeric quota state rather than credentials.
func isSensitiveHeader(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	if sensitiveHeaderNames[lower] {
		return true
	}
	if strings.Contains(lower, "ratelimit") || strings.Contains(lower, "rate-limit") {
		return false
	}
	return strings.Contains(lower, "token") || strings.Contains(lower, "secret") || strings.Contains(lower, "key")
}

// RedactHeaders returns a copy of headers with credential-bearing values replaced.
func RedactHeaders(headers http.Header) http.Header {
	if len(headers) == 0 {
		return nil
	}
	out := make(http.Header, len(headers))
	for name, values := range headers {
		if isSensitiveHeader(name) {
			out[name] = []string{redactedValue}
			continue
		}
		out[name] = append([]string(nil), values...)
	}
	return out
}

// headerMap flattens redacted headers into a ClickHouse Map(String, String).
func headerMap(headers http.Header) map[string]string {
	redacted := RedactHeaders(headers)
	out := make(map[string]string, len(redacted))
	for name, values := range redacted {
		out[strings.ToLower(name)] = strings.Join(values, ", ")
	}
	return out
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		t = time.Now()
	}
	return t.UTC().Format(clickHouseTimeForm)
}

func boolToUInt8(v bool) uint8 {
	if v {
		return 1
	}
	return 0
}

func truncateString(s string, limit int) string {
	if limit > 0 && len(s) > limit {
		return s[:limit]
	}
	return s
}

type usageRow struct {
	RequestedAt          string            `json:"requested_at"`
	RequestID            string            `json:"request_id"`
	ExecutionID          string            `json:"execution_id"`
	SelectionID          string            `json:"selection_id"`
	Provider             string            `json:"provider"`
	ExecutorType         string            `json:"executor_type"`
	BaseURL              string            `json:"base_url"`
	Model                string            `json:"model"`
	Alias                string            `json:"alias"`
	ResponseModel        string            `json:"response_model"`
	AuthID               string            `json:"auth_id"`
	AuthIndex            string            `json:"auth_index"`
	AuthType             string            `json:"auth_type"`
	Source               string            `json:"source"`
	AccessProvider       string            `json:"access_provider"`
	ClientKeyID          string            `json:"client_key_id"`
	IsNativeKey          uint8             `json:"is_native_key"`
	SessionID            string            `json:"session_id"`
	ParentSessionID      string            `json:"parent_session_id"`
	Stream               uint8             `json:"stream"`
	Generate             uint8             `json:"generate"`
	ReasoningEffort      string            `json:"reasoning_effort"`
	ServiceTier          string            `json:"service_tier"`
	EffectiveServiceTier string            `json:"effective_service_tier"`
	ResponseServiceTier  string            `json:"response_service_tier"`
	LatencyMS            int64             `json:"latency_ms"`
	TTFTMS               int64             `json:"ttft_ms"`
	Failed               uint8             `json:"failed"`
	StatusCode           int               `json:"status_code"`
	ErrorCode            string            `json:"error_code"`
	ErrorBody            string            `json:"error_body"`
	InputTokens          int64             `json:"input_tokens"`
	OutputTokens         int64             `json:"output_tokens"`
	ReasoningTokens      int64             `json:"reasoning_tokens"`
	CachedTokens         int64             `json:"cached_tokens"`
	CacheReadTokens      int64             `json:"cache_read_tokens"`
	CacheCreationTokens  int64             `json:"cache_creation_tokens"`
	TotalTokens          int64             `json:"total_tokens"`
	ResponseHeaders      map[string]string `json:"response_headers"`
}

func newUsageRow(ctx context.Context, record coreusage.Record) usageRow {
	// Prefer the inbound HTTP request ID so usage rows join bodies rows.
	requestID := strings.TrimSpace(internallogging.GetRequestID(ctx))
	if requestID == "" {
		requestID = strings.TrimSpace(record.TraceID)
	}
	if requestID == "" {
		requestID = strings.TrimSpace(record.RequestID)
	}
	apiKey := record.APIKey
	if strings.TrimSpace(apiKey) == "" {
		apiKey = coreusage.APIKeyFromContext(ctx)
	}
	accessProvider := record.AccessProvider
	if strings.TrimSpace(accessProvider) == "" {
		accessProvider = coreusage.AccessProviderFromContext(ctx)
	}
	reasoningEffort := record.ReasoningEffort
	if strings.TrimSpace(reasoningEffort) == "" {
		reasoningEffort = coreusage.ReasoningEffortFromContext(ctx)
	}
	responseTier := record.ResponseServiceTier
	if responseTier == "" {
		responseTier = record.Detail.ResponseServiceTier
	}
	statusCode := record.Fail.StatusCode
	if statusCode == 0 && !record.Failed {
		statusCode = http.StatusOK
	}
	return usageRow{
		RequestedAt:          formatTime(record.RequestedAt),
		RequestID:            requestID,
		ExecutionID:          strings.TrimSpace(record.RequestID),
		SelectionID:          strings.TrimSpace(record.SelectionID),
		Provider:             strings.TrimSpace(record.Provider),
		ExecutorType:         strings.TrimSpace(record.ExecutorType),
		BaseURL:              strings.TrimSpace(record.BaseURL),
		Model:                strings.TrimSpace(record.Model),
		Alias:                strings.TrimSpace(record.Alias),
		ResponseModel:        strings.TrimSpace(record.ResponseModel),
		AuthID:               strings.TrimSpace(record.AuthID),
		AuthIndex:            strings.TrimSpace(record.AuthIndex),
		AuthType:             strings.TrimSpace(record.AuthType),
		Source:               strings.TrimSpace(record.Source),
		AccessProvider:       strings.TrimSpace(accessProvider),
		ClientKeyID:          ClientKeyID(apiKey),
		IsNativeKey:          boolToUInt8(record.IsNativeKey),
		SessionID:            strings.TrimSpace(record.SessionID),
		ParentSessionID:      strings.TrimSpace(record.ParentSessionID),
		Stream:               boolToUInt8(record.Stream),
		Generate:             boolToUInt8(coreusage.GenerateEnabled(record.Generate)),
		ReasoningEffort:      strings.TrimSpace(reasoningEffort),
		ServiceTier:          strings.TrimSpace(record.ServiceTier),
		EffectiveServiceTier: strings.TrimSpace(record.EffectiveServiceTier),
		ResponseServiceTier:  strings.TrimSpace(responseTier),
		LatencyMS:            record.Latency.Milliseconds(),
		TTFTMS:               record.TTFT.Milliseconds(),
		Failed:               boolToUInt8(record.Failed),
		StatusCode:           statusCode,
		ErrorCode:            strings.TrimSpace(record.Fail.Code),
		ErrorBody:            truncateString(record.Fail.Body, maxErrorBodyBytes),
		InputTokens:          record.Detail.InputTokens,
		OutputTokens:         record.Detail.OutputTokens,
		ReasoningTokens:      record.Detail.ReasoningTokens,
		CachedTokens:         record.Detail.CachedTokens,
		CacheReadTokens:      record.Detail.CacheReadTokens,
		CacheCreationTokens:  record.Detail.CacheCreationTokens,
		TotalTokens:          record.Detail.TotalTokens,
		ResponseHeaders:      headerMap(record.ResponseHeaders),
	}
}

type bodyRow struct {
	RequestedAt               string            `json:"requested_at"`
	RequestID                 string            `json:"request_id"`
	URL                       string            `json:"url"`
	Method                    string            `json:"method"`
	StatusCode                int               `json:"status_code"`
	DurationMS                int64             `json:"duration_ms"`
	ClientKeyID               string            `json:"client_key_id"`
	RequestHeaders            map[string]string `json:"request_headers"`
	ResponseHeaders           map[string]string `json:"response_headers"`
	RequestBody               string            `json:"request_body"`
	RequestBodyBytes          int64             `json:"request_body_bytes"`
	RequestBodyTruncated      uint8             `json:"request_body_truncated"`
	UpstreamRequest           string            `json:"upstream_request"`
	UpstreamRequestBytes      int64             `json:"upstream_request_bytes"`
	UpstreamRequestTruncated  uint8             `json:"upstream_request_truncated"`
	UpstreamResponse          string            `json:"upstream_response"`
	UpstreamResponseBytes     int64             `json:"upstream_response_bytes"`
	UpstreamResponseTruncated uint8             `json:"upstream_response_truncated"`
	ResponseBody              string            `json:"response_body"`
	ResponseBodyBytes         int64             `json:"response_body_bytes"`
	ResponseBodyTruncated     uint8             `json:"response_body_truncated"`
}

// BodyMeta describes the inbound request a body capture belongs to.
type BodyMeta struct {
	RequestedAt     time.Time
	RequestID       string
	URL             string
	Method          string
	StatusCode      int
	Duration        time.Duration
	ClientKey       string
	RequestHeaders  http.Header
	ResponseHeaders http.Header
}

// size approximates the memory held by the row.
func (r bodyRow) size() int64 {
	return int64(len(r.RequestBody) + len(r.UpstreamRequest) + len(r.UpstreamResponse) + len(r.ResponseBody) + len(r.URL))
}

func newBodyRow(meta BodyMeta, snap bodycapture.Snapshot) bodyRow {
	return bodyRow{
		RequestedAt:               formatTime(meta.RequestedAt),
		RequestID:                 meta.RequestID,
		URL:                       meta.URL,
		Method:                    meta.Method,
		StatusCode:                meta.StatusCode,
		DurationMS:                meta.Duration.Milliseconds(),
		ClientKeyID:               ClientKeyID(meta.ClientKey),
		RequestHeaders:            headerMap(meta.RequestHeaders),
		ResponseHeaders:           headerMap(meta.ResponseHeaders),
		RequestBody:               string(snap.RequestBody),
		RequestBodyBytes:          snap.RequestBodyBytes,
		RequestBodyTruncated:      boolToUInt8(snap.RequestBodyTruncated),
		UpstreamRequest:           string(snap.UpstreamRequest),
		UpstreamRequestBytes:      snap.UpstreamRequestBytes,
		UpstreamRequestTruncated:  boolToUInt8(snap.UpstreamRequestTruncated),
		UpstreamResponse:          string(snap.UpstreamResponse),
		UpstreamResponseBytes:     snap.UpstreamResponseBytes,
		UpstreamResponseTruncated: boolToUInt8(snap.UpstreamResponseTruncated),
		ResponseBody:              string(snap.ResponseBody),
		ResponseBodyBytes:         snap.ResponseBodyBytes,
		ResponseBodyTruncated:     boolToUInt8(snap.ResponseBodyTruncated),
	}
}
