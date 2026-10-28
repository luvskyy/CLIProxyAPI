package clickhouse

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestRedactQueryFullyMasksKeys(t *testing.T) {
	v := url.Values{"key": {"cpa-gen-abcdef0123456789"}, "auth_token": {"secret-tok"}, "alt": {"sse"}}
	got := redactQuery(v)
	if strings.Contains(got, "abcd") || strings.Contains(got, "6789") || strings.Contains(got, "secret-tok") {
		t.Fatalf("query leaked key material: %s", got)
	}
	if !strings.Contains(got, "alt=sse") {
		t.Fatalf("non-sensitive param dropped: %s", got)
	}
}

func TestShouldCaptureSkipsRealtimeSecrets(t *testing.T) {
	for _, p := range []string{"/v1/realtime/client_secrets", "/v1/realtime/sessions"} {
		req, _ := http.NewRequest(http.MethodPost, "http://x"+p, nil)
		if shouldCapture(req) {
			t.Fatalf("expected %s to be skipped", p)
		}
	}
}
