package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	coreusage "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/usage"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

func TestFilterModelsForClientKey(t *testing.T) {
	gin.SetMode(gin.TestMode)
	reg := registry.GetGlobalRegistry()
	reg.RegisterClient("scope-filter-claude", "claude", []*registry.ModelInfo{{ID: "scope-filter-claude-model"}, {ID: "scope-filter-shared"}})
	reg.RegisterClient("scope-filter-codex", "codex", []*registry.ModelInfo{{ID: "scope-filter-codex-model"}, {ID: "scope-filter-shared"}})
	t.Cleanup(func() {
		reg.UnregisterClient("scope-filter-claude")
		reg.UnregisterClient("scope-filter-codex")
	})
	h := NewBaseAPIHandlers(&sdkconfig.SDKConfig{ProviderKeyScopes: map[string][]string{"claude": {"cc-key"}}}, nil)
	models := []map[string]any{
		{"id": "scope-filter-claude-model"},
		{"id": "scope-filter-codex-model"},
		{"id": "scope-filter-shared"},
		{"name": "models/scope-filter-claude-model"},
		{"id": "scope-filter-unregistered"},
	}

	ids := func(key string) []string {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(http.MethodGet, "/v1/models", nil)
		c.Request = c.Request.WithContext(coreusage.WithAPIKey(c.Request.Context(), key))
		var out []string
		for _, model := range h.FilterModelsForClientKey(c, models) {
			id, _ := model["id"].(string)
			if id == "" {
				id, _ = model["name"].(string)
			}
			out = append(out, id)
		}
		return out
	}

	if got := ids("cc-key"); len(got) != 5 {
		t.Fatalf("allowed key models = %v, want all 5", got)
	}
	got := ids("other-key")
	want := []string{"scope-filter-codex-model", "scope-filter-shared", "scope-filter-unregistered"}
	if len(got) != len(want) {
		t.Fatalf("other key models = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("other key models = %v, want %v", got, want)
		}
	}
}
