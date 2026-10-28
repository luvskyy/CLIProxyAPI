package clickhouse

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/bodycapture"
	coreusage "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/usage"
)

// TestIntegrationRealClickHouse runs against a live ClickHouse when
// CLICKHOUSE_INTEGRATION_ENDPOINT is set (e.g. http://127.0.0.1:8123). It uses
// and drops the throwaway database cliproxy_test.
func TestIntegrationRealClickHouse(t *testing.T) {
	endpoint := strings.TrimSpace(os.Getenv("CLICKHOUSE_INTEGRATION_ENDPOINT"))
	if endpoint == "" {
		t.Skip("CLICKHOUSE_INTEGRATION_ENDPOINT not set")
	}
	settings := Settings{
		Enabled:           true,
		Endpoint:          endpoint,
		Database:          "cliproxy_test",
		Username:          "default",
		Password:          os.Getenv("CLICKHOUSE_PASSWORD"),
		CaptureBodies:     true,
		MaxBodyBytes:      1024,
		BodyRetentionDays: 30,
		BatchSize:         10,
		FlushInterval:     100 * time.Millisecond,
		QueueSize:         100,
	}
	admin := &Sink{settings: settings, client: &http.Client{Timeout: 10 * time.Second}}
	query := func(q string) string {
		t.Helper()
		var out bytes.Buffer
		if err := admin.execOutput(context.Background(), q, nil, &out); err != nil {
			t.Fatalf("query %q: %v", q, err)
		}
		return strings.TrimSpace(out.String())
	}
	query("DROP DATABASE IF EXISTS cliproxy_test")
	t.Cleanup(func() { query("DROP DATABASE IF EXISTS cliproxy_test") })

	// The second round proves schema setup is idempotent and updates the bodies TTL.
	for round, retention := range []int{30, 14} {
		settings.BodyRetentionDays = retention
		sink := NewSink(settings, nil)
		record := coreusage.Record{
			RequestID: "exec-int", TraceID: "req-int", Provider: "claude", Model: "claude-int", APIKey: "sk-int-client",
			AuthID: "auth-int", AuthType: "oauth", RequestedAt: time.Now(), Latency: 1234 * time.Millisecond,
			Detail:          coreusage.Detail{InputTokens: 11, OutputTokens: 7, TotalTokens: 18},
			ResponseHeaders: http.Header{"Anthropic-Ratelimit-Unified-5h-Utilization": {"0.42"}, "Set-Cookie": {"s=1"}},
		}
		sink.Enqueue(tableUsage, newUsageRow(context.Background(), record))
		capture := bodycapture.New(settings.MaxBodyBytes, RedactHeaders)
		capture.WriteRequest([]byte(`{"model":"claude-int"}`))
		capture.RecordUpstreamRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", http.Header{"Authorization": {"Bearer sk-upstream"}}, []byte(`{"model":"claude-int"}`))
		capture.WriteResponse(bytes.Repeat([]byte("x"), 2000))
		row := newBodyRow(BodyMeta{
			RequestedAt: time.Now(), RequestID: "req-int", URL: "/v1/messages", Method: http.MethodPost, StatusCode: 200,
			ClientKey: "sk-int-client", RequestHeaders: http.Header{"Authorization": {"Bearer sk-int-client"}},
		}, capture.Snapshot())
		sink.EnqueueSized(tableBodies, row, row.size())
		if err := sink.Close(context.Background()); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
		if sink.Failed() != 0 || sink.Written() != 2 {
			t.Fatalf("round %d: written=%d failed=%d", round, sink.Written(), sink.Failed())
		}
	}
	if got := query("SELECT count() FROM cliproxy_test.usage WHERE request_id = 'req-int'"); got != "2" {
		t.Fatalf("usage rows = %s, want 2", got)
	}
	got := query("SELECT provider, model, client_key_id, latency_ms, total_tokens, response_headers['anthropic-ratelimit-unified-5h-utilization'], response_headers['set-cookie'] FROM cliproxy_test.usage LIMIT 1 FORMAT TabSeparated")
	want := strings.Join([]string{"claude", "claude-int", ClientKeyID("sk-int-client"), "1234", "18", "0.42", redactedValue}, "\t")
	if got != want {
		t.Fatalf("usage row = %q, want %q", got, want)
	}
	if strings.Contains(query("SELECT * FROM cliproxy_test.usage FORMAT JSONEachRow"), "sk-int-client") {
		t.Fatal("raw client key stored in usage table")
	}
	joined := query("SELECT u.model, b.status_code, length(b.response_body), b.response_body_truncated, b.response_body_bytes, b.request_headers['authorization'] FROM cliproxy_test.usage AS u INNER JOIN cliproxy_test.bodies AS b ON u.request_id = b.request_id LIMIT 1 FORMAT TabSeparated")
	if want := strings.Join([]string{"claude-int", "200", "1024", "1", "2000", redactedValue}, "\t"); joined != want {
		t.Fatalf("joined row = %q, want %q", joined, want)
	}
	allBodies := query("SELECT * FROM cliproxy_test.bodies FORMAT JSONEachRow")
	if strings.Contains(allBodies, "sk-int-client") || strings.Contains(allBodies, "sk-upstream") {
		t.Fatal("secret stored in bodies table")
	}
	ttl := query("SELECT engine_full FROM system.tables WHERE database = 'cliproxy_test' AND name = 'bodies' FORMAT TabSeparatedRaw")
	if !strings.Contains(ttl, "toIntervalDay(14)") {
		t.Fatalf("bodies TTL not updated to 14 days: %s", ttl)
	}
}
