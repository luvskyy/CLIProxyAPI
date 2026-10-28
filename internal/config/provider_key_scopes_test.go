package config

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestProviderAllowedForKey(t *testing.T) {
	cfg := &SDKConfig{ProviderKeyScopes: map[string][]string{"Claude": {"cc-key"}, "gemini": {}}}
	cases := []struct {
		provider, key string
		want          bool
	}{
		{"claude", "cc-key", true},
		{"claude", "other", false},
		{"claude", "", false},
		{"gemini", "cc-key", false},
		{"codex", "other", true},
		{"codex", "", true},
	}
	for _, tc := range cases {
		if got := cfg.ProviderAllowedForKey(tc.provider, tc.key); got != tc.want {
			t.Errorf("ProviderAllowedForKey(%q, %q) = %t, want %t", tc.provider, tc.key, got, tc.want)
		}
	}
	var empty *SDKConfig
	if !empty.ProviderAllowedForKey("claude", "") {
		t.Error("nil config must not restrict providers")
	}
}

func TestV8ProviderKeyScopesAndClickHouseLayout(t *testing.T) {
	data := []byte(`config-version: 8
access:
  api-keys: ["cc-key", "other"]
  provider-key-scopes:
    claude: ["cc-key"]
observability:
  clickhouse:
    enabled: true
    endpoint: "http://127.0.0.1:8123"
    database: "cliproxy"
    password-env: "CLICKHOUSE_PASSWORD"
    capture-bodies: true
    max-body-bytes: 2048
    body-retention-days: 7
    batch-size: 50
    flush-interval: "1s"
    queue-size: 100
`)
	cfg, err := ParseConfigBytes(data)
	if err != nil {
		t.Fatalf("ParseConfigBytes() error = %v", err)
	}
	if got := cfg.ProviderKeyScopes["claude"]; len(got) != 1 || got[0] != "cc-key" {
		t.Fatalf("provider-key-scopes = %#v", cfg.ProviderKeyScopes)
	}
	ch := cfg.ClickHouse
	if !ch.Enabled || ch.Endpoint != "http://127.0.0.1:8123" || ch.Database != "cliproxy" || !ch.CaptureBodies ||
		ch.MaxBodyBytes != 2048 || ch.BodyRetentionDays != 7 || ch.BatchSize != 50 || ch.FlushInterval != "1s" || ch.QueueSize != 100 ||
		ch.PasswordEnv != "CLICKHOUSE_PASSWORD" {
		t.Fatalf("clickhouse config = %#v", ch)
	}

	file := filepath.Join(t.TempDir(), "config.yaml")
	if err = os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err = SaveConfigPreserveComments(file, cfg, false); err != nil {
		t.Fatalf("SaveConfigPreserveComments() error = %v", err)
	}
	out, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip, err := ParseConfigBytes(out)
	if err != nil {
		t.Fatalf("ParseConfigBytes(round trip) error = %v\n%s", err, out)
	}
	if roundTrip.ClickHouse != ch || len(roundTrip.ProviderKeyScopes["claude"]) != 1 {
		t.Fatalf("round trip lost settings:\n%s", out)
	}
	var doc map[string]any
	if err = yaml.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if _, ok := doc["clickhouse"]; ok {
		t.Fatalf("clickhouse must serialize under observability:\n%s", out)
	}
	if _, ok := doc["provider-key-scopes"]; ok {
		t.Fatalf("provider-key-scopes must serialize under access:\n%s", out)
	}
}
