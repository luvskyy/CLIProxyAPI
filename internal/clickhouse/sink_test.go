package clickhouse

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/bodycapture"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	coreusage "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/usage"
)

// fakeClickHouse records queries and JSONEachRow inserts.
type fakeClickHouse struct {
	mu       sync.Mutex
	queries  []string
	inserts  map[string][]map[string]any
	batches  map[string][]int
	users    []string
	keys     []string
	inserted chan struct{}
	server   *httptest.Server
}

func newFakeClickHouse(t *testing.T) *fakeClickHouse {
	t.Helper()
	f := &fakeClickHouse{
		inserts:  map[string][]map[string]any{},
		batches:  map[string][]int{},
		inserted: make(chan struct{}, 1024),
	}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query().Get("query")
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		defer f.mu.Unlock()
		f.queries = append(f.queries, query)
		f.users = append(f.users, r.Header.Get("X-ClickHouse-User"))
		f.keys = append(f.keys, r.Header.Get("X-ClickHouse-Key"))
		if strings.HasPrefix(query, "INSERT INTO") {
			table := strings.Trim(strings.Fields(query)[2], "`")
			table = table[strings.LastIndex(table, ".")+1:]
			table = strings.Trim(table, "`")
			count := 0
			scanner := bufio.NewScanner(bytes.NewReader(body))
			scanner.Buffer(make([]byte, 0, 1<<20), 16<<20)
			for scanner.Scan() {
				var row map[string]any
				if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				f.inserts[table] = append(f.inserts[table], row)
				count++
			}
			f.batches[table] = append(f.batches[table], count)
			f.inserted <- struct{}{}
		}
	}))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeClickHouse) rows(table string) []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]map[string]any(nil), f.inserts[table]...)
}

func testSettings(endpoint string) Settings {
	return Settings{
		Enabled:           true,
		Endpoint:          endpoint,
		Database:          "cliproxy_unit",
		Username:          "default",
		Password:          "pw-secret",
		CaptureBodies:     true,
		MaxBodyBytes:      64,
		BodyRetentionDays: 30,
		BatchSize:         3,
		FlushInterval:     time.Hour,
		QueueSize:         100,
	}
}

func TestClientKeyID(t *testing.T) {
	// sha256("sk-test") = 6f1c... first 12 hex chars.
	if got := ClientKeyID("sk-test"); len(got) != 12 || got == "sk-test" {
		t.Fatalf("ClientKeyID() = %q", got)
	}
	if ClientKeyID("sk-test") != ClientKeyID(" sk-test ") {
		t.Fatal("ClientKeyID must ignore surrounding whitespace")
	}
	if ClientKeyID("sk-test") == ClientKeyID("sk-other") {
		t.Fatal("different keys must hash differently")
	}
	if ClientKeyID("") != "" {
		t.Fatal("empty key must map to empty id")
	}
	if got, want := ClientKeyID("abc"), "ba7816bf8f01"; got != want {
		t.Fatalf("ClientKeyID(abc) = %q, want %q", got, want)
	}
}

func TestRedactHeaders(t *testing.T) {
	in := http.Header{
		"Authorization":                        {"Bearer sk-1"},
		"Proxy-Authorization":                  {"Basic x"},
		"X-Api-Key":                            {"k"},
		"Cookie":                               {"a=b"},
		"Set-Cookie":                           {"c=d"},
		"X-Goog-Api-Key":                       {"g"},
		"X-Session-Token":                      {"t"},
		"X-Client-Secret":                      {"s"},
		"Anthropic-Ratelimit-Tokens-Remaining": {"1000"},
		"X-Ratelimit-Remaining-Tokens":         {"500"},
		"Content-Type":                         {"application/json"},
		"Anthropic-Ratelimit-Unified-5h-Utilization": {"0.2"},
	}
	out := RedactHeaders(in)
	for _, name := range []string{"Authorization", "Proxy-Authorization", "X-Api-Key", "Cookie", "Set-Cookie", "X-Goog-Api-Key", "X-Session-Token", "X-Client-Secret"} {
		if got := out.Get(name); got != redactedValue {
			t.Errorf("%s = %q, want redacted", name, got)
		}
	}
	for name, want := range map[string]string{
		"Anthropic-Ratelimit-Tokens-Remaining": "1000",
		"X-Ratelimit-Remaining-Tokens":         "500",
		"Content-Type":                         "application/json",
	} {
		if got := out.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	if in.Get("Authorization") != "Bearer sk-1" {
		t.Fatal("RedactHeaders must not mutate its input")
	}
}

func TestUsageRowNeverStoresRawKey(t *testing.T) {
	record := coreusage.Record{
		RequestID: "exec-1", TraceID: "trace-1", Provider: "claude", Model: "claude-x",
		APIKey: "sk-raw-client-key", AuthID: "auth-1", AuthType: "oauth", Failed: true,
		Fail:            coreusage.Failure{StatusCode: 429, Code: "rate_limit", Body: "slow down"},
		Latency:         1500 * time.Millisecond,
		TTFT:            200 * time.Millisecond,
		Detail:          coreusage.Detail{InputTokens: 10, OutputTokens: 5, CacheReadTokens: 3, TotalTokens: 18},
		ResponseHeaders: http.Header{"Anthropic-Ratelimit-Requests-Remaining": {"9"}, "Set-Cookie": {"x"}},
	}
	row := newUsageRow(context.Background(), record)
	payload, _ := json.Marshal(row)
	if strings.Contains(string(payload), "sk-raw-client-key") {
		t.Fatalf("usage row leaks the raw client key: %s", payload)
	}
	if row.ClientKeyID != ClientKeyID("sk-raw-client-key") || row.RequestID != "trace-1" || row.ExecutionID != "exec-1" {
		t.Fatalf("unexpected identifiers: %+v", row)
	}
	if row.StatusCode != 429 || row.Failed != 1 || row.LatencyMS != 1500 || row.TTFTMS != 200 || row.CacheReadTokens != 3 {
		t.Fatalf("unexpected metrics: %+v", row)
	}
	if row.ResponseHeaders["anthropic-ratelimit-requests-remaining"] != "9" || row.ResponseHeaders["set-cookie"] != redactedValue {
		t.Fatalf("unexpected headers: %#v", row.ResponseHeaders)
	}
}

func TestSinkCreatesSchemaAndBatches(t *testing.T) {
	fake := newFakeClickHouse(t)
	sink := NewSink(testSettings(fake.server.URL), nil)
	for i := 0; i < 7; i++ {
		sink.Enqueue(tableUsage, map[string]any{"n": i})
	}
	// Two full batches of 3 are flushed by size; the remaining row waits for Close.
	for i := 0; i < 2; i++ {
		select {
		case <-fake.inserted:
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for size-triggered flush")
		}
	}
	if err := sink.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if got := len(fake.rows(tableUsage)); got != 7 {
		t.Fatalf("inserted rows = %d, want 7", got)
	}
	fake.mu.Lock()
	batches := append([]int(nil), fake.batches[tableUsage]...)
	queries := append([]string(nil), fake.queries...)
	users, keys := fake.users, fake.keys
	fake.mu.Unlock()
	if len(batches) != 3 || batches[0] != 3 || batches[1] != 3 || batches[2] != 1 {
		t.Fatalf("batches = %v, want [3 3 1]", batches)
	}
	joined := strings.Join(queries, "\n")
	for _, want := range []string{"CREATE DATABASE IF NOT EXISTS `cliproxy_unit`", "CREATE TABLE IF NOT EXISTS `cliproxy_unit`.`usage`", "CREATE TABLE IF NOT EXISTS `cliproxy_unit`.`bodies`", "TTL toDateTime(requested_at) + toIntervalDay(30)"} {
		if !strings.Contains(joined, want) {
			t.Errorf("schema statements missing %q", want)
		}
	}
	for i := range users {
		if users[i] != "default" || keys[i] != "pw-secret" {
			t.Fatalf("request %d credentials = (%q, %q)", i, users[i], keys[i])
		}
	}
	if sink.Written() != 7 || sink.Dropped() != 0 || sink.Failed() != 0 {
		t.Fatalf("counters written=%d dropped=%d failed=%d", sink.Written(), sink.Dropped(), sink.Failed())
	}
}

func TestSinkDropsWhenQueueFull(t *testing.T) {
	// A sink without a running worker never drains, making the queue bound deterministic.
	sink := &Sink{settings: testSettings("http://127.0.0.1:1"), queue: make(chan queuedRow, 2)}
	accepted := 0
	for i := 0; i < 5; i++ {
		if sink.Enqueue(tableUsage, i) {
			accepted++
		}
	}
	if accepted != 2 || sink.Dropped() != 3 {
		t.Fatalf("accepted=%d dropped=%d, want 2 and 3", accepted, sink.Dropped())
	}
}

func TestSinkDropsWhenByteBudgetExceeded(t *testing.T) {
	sink := &Sink{settings: testSettings("http://127.0.0.1:1"), queue: make(chan queuedRow, 100)}
	if !sink.EnqueueSized(tableBodies, 1, maxQueuedBytes-10) {
		t.Fatal("row within budget rejected")
	}
	if sink.EnqueueSized(tableBodies, 2, 11) {
		t.Fatal("row over byte budget accepted")
	}
	if !sink.EnqueueSized(tableBodies, 3, 10) {
		t.Fatal("row filling budget exactly rejected")
	}
	if sink.Dropped() != 1 || sink.queuedBytes.Load() != maxQueuedBytes {
		t.Fatalf("dropped=%d queuedBytes=%d", sink.Dropped(), sink.queuedBytes.Load())
	}
}

func TestSinkEnqueueNeverBlocksOnSlowServer(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer server.Close()
	defer close(release)
	settings := testSettings(server.URL)
	settings.QueueSize = 4
	settings.BatchSize = 1
	sink := NewSink(settings, nil)
	start := time.Now()
	for i := 0; i < 100; i++ {
		sink.Enqueue(tableUsage, i)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Enqueue blocked for %s", elapsed)
	}
	if sink.Dropped() == 0 {
		t.Fatal("expected drops while the server is stalled")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_ = sink.Close(ctx)
}

func TestBodyCaptureTruncation(t *testing.T) {
	capture := bodycapture.New(8, RedactHeaders)
	capture.WriteRequest([]byte("0123456789"))
	capture.WriteResponse([]byte("abc"))
	capture.RecordUpstreamRequest(http.MethodPost, "https://api.example/v1", http.Header{"Authorization": {"Bearer sk-up"}}, []byte("{}"))
	snap := capture.Snapshot()
	if string(snap.RequestBody) != "01234567" || !snap.RequestBodyTruncated || snap.RequestBodyBytes != 10 {
		t.Fatalf("request capture = %q truncated=%t total=%d", snap.RequestBody, snap.RequestBodyTruncated, snap.RequestBodyBytes)
	}
	if string(snap.ResponseBody) != "abc" || snap.ResponseBodyTruncated {
		t.Fatalf("response capture = %q truncated=%t", snap.ResponseBody, snap.ResponseBodyTruncated)
	}
	if !snap.UpstreamRequestTruncated || len(snap.UpstreamRequest) != 8 {
		t.Fatalf("upstream request capture = %q", snap.UpstreamRequest)
	}
	big := bodycapture.New(4096, RedactHeaders)
	big.RecordUpstreamRequest(http.MethodPost, "https://api.example/v1", http.Header{"Authorization": {"Bearer sk-up"}, "X-Trace": {"1"}}, []byte(`{"a":1}`))
	upstream := string(big.Snapshot().UpstreamRequest)
	if strings.Contains(upstream, "sk-up") || !strings.Contains(upstream, "Authorization: [REDACTED]") || !strings.Contains(upstream, `{"a":1}`) {
		t.Fatalf("upstream request capture = %q", upstream)
	}
}

func TestCaptureMiddlewareShipsBodies(t *testing.T) {
	gin.SetMode(gin.TestMode)
	fake := newFakeClickHouse(t)
	t.Setenv("CH_UNIT_PASSWORD", "pw-secret")
	cfg := &config.Config{}
	cfg.ClickHouse = config.ClickHouseConfig{
		Enabled: true, Endpoint: fake.server.URL, Database: "cliproxy_unit", PasswordEnv: "CH_UNIT_PASSWORD",
		CaptureBodies: true, MaxBodyBytes: 16, BatchSize: 1, FlushInterval: "1h", QueueSize: 10,
	}
	Apply(cfg)
	t.Cleanup(func() { _ = Shutdown(context.Background()) })
	if sink := currentSink(); sink == nil || sink.Settings().Password != "pw-secret" {
		t.Fatal("sink not started with env password")
	}

	engine := gin.New()
	engine.Use(CaptureMiddleware())
	engine.Use(func(c *gin.Context) {
		c.Request = c.Request.WithContext(coreusage.WithAPIKey(c.Request.Context(), "sk-client"))
		c.Next()
	})
	engine.POST("/v1/messages", func(c *gin.Context) {
		body, _ := io.ReadAll(c.Request.Body)
		capture := bodycapture.FromGin(c)
		capture.RecordUpstreamRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", http.Header{"X-Api-Key": {"sk-upstream"}}, body)
		capture.RecordUpstreamResponseMeta(http.StatusOK, http.Header{"Anthropic-Ratelimit-Requests-Remaining": {"7"}})
		capture.AppendUpstreamResponse([]byte(`{"ok":true}`))
		c.Header("Content-Type", "application/json")
		c.String(http.StatusCreated, `{"content":"hello world, this is long"}`)
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/messages?key=secret-query", strings.NewReader(`{"model":"claude","prompt":"hi"}`))
	req.Header.Set("Authorization", "Bearer sk-client")
	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusCreated || recorder.Body.String() != `{"content":"hello world, this is long"}` {
		t.Fatalf("response altered: %d %q", recorder.Code, recorder.Body.String())
	}

	select {
	case <-fake.inserted:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for bodies insert")
	}
	rows := fake.rows(tableBodies)
	if len(rows) != 1 {
		t.Fatalf("bodies rows = %d", len(rows))
	}
	row := rows[0]
	payload, _ := json.Marshal(row)
	for _, secret := range []string{"sk-client", "sk-upstream", "secret-query"} {
		if strings.Contains(string(payload), secret) {
			t.Fatalf("bodies row leaks %q: %s", secret, payload)
		}
	}
	if row["request_body"] != `{"model":"claude` || row["request_body_truncated"] != float64(1) {
		t.Fatalf("request_body = %v truncated=%v", row["request_body"], row["request_body_truncated"])
	}
	if row["response_body"] != `{"content":"hell` || row["response_body_bytes"] != float64(39) {
		t.Fatalf("response_body = %v bytes=%v", row["response_body"], row["response_body_bytes"])
	}
	if row["status_code"] != float64(http.StatusCreated) || row["method"] != http.MethodPost || row["client_key_id"] != ClientKeyID("sk-client") {
		t.Fatalf("metadata = %v %v %v", row["status_code"], row["method"], row["client_key_id"])
	}
	if headers, _ := row["request_headers"].(map[string]any); headers["authorization"] != redactedValue {
		t.Fatalf("request headers = %v", row["request_headers"])
	}
	if !strings.HasPrefix(row["url"].(string), "/v1/messages?") {
		t.Fatalf("url = %v", row["url"])
	}
}

func TestCaptureMiddlewareDisabledIsNoop(t *testing.T) {
	gin.SetMode(gin.TestMode)
	Apply(&config.Config{})
	engine := gin.New()
	engine.Use(CaptureMiddleware())
	engine.POST("/v1/chat/completions", func(c *gin.Context) {
		if bodycapture.FromGin(c) != nil {
			t.Error("capture attached while sink disabled")
		}
		c.Status(http.StatusNoContent)
	})
	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader("{}")))
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d", recorder.Code)
	}
}
