package handlers

import (
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	coreusage "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/usage"
)

// FilterModelsForClientKey removes models whose providers are all restricted
// for the requesting client key by access.provider-key-scopes. Models served by
// at least one allowed provider stay listed.
func (h *BaseAPIHandler) FilterModelsForClientKey(c *gin.Context, models []map[string]any) []map[string]any {
	cfg := h.CurrentConfig()
	if !cfg.HasProviderKeyScopes() || len(models) == 0 {
		return models
	}
	clientKey := ""
	if c != nil {
		if c.Request != nil {
			clientKey = coreusage.APIKeyFromContext(c.Request.Context())
		}
		if clientKey == "" {
			clientKey = c.GetString("userApiKey")
		}
	}
	modelRegistry := registry.GetGlobalRegistry()
	filtered := make([]map[string]any, 0, len(models))
	for _, model := range models {
		id, _ := model["id"].(string)
		if id == "" {
			name, _ := model["name"].(string)
			id = strings.TrimPrefix(name, "models/")
		}
		providers := modelRegistry.GetModelProviders(id)
		if len(providers) == 0 {
			filtered = append(filtered, model)
			continue
		}
		for _, provider := range providers {
			if cfg.ProviderAllowedForKey(provider, clientKey) {
				filtered = append(filtered, model)
				break
			}
		}
	}
	return filtered
}
