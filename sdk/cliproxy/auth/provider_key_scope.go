package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	coreusage "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/usage"
)

// ErrorCodeProviderForbidden marks requests whose client API key may not use
// credentials of any requested provider (access.provider-key-scopes).
const ErrorCodeProviderForbidden = "provider_forbidden"

type providerScopeContextKey struct{}

// providerScope captures the client key and scope config for one request.
type providerScope struct {
	cfg       *internalconfig.Config
	clientKey string
}

func (s *providerScope) allows(provider string) bool {
	if s == nil {
		return true
	}
	return s.cfg.ProviderAllowedForKey(provider, s.clientKey)
}

func providerScopeFromContext(ctx context.Context) *providerScope {
	if ctx == nil {
		return nil
	}
	scope, _ := ctx.Value(providerScopeContextKey{}).(*providerScope)
	return scope
}

// applyProviderKeyScopes removes providers the request's client key may not use
// and attaches the scope to ctx so credential selection also skips credentials
// of restricted providers. It returns a 403 error when no provider remains.
func (m *Manager) applyProviderKeyScopes(ctx context.Context, providers []string) (context.Context, []string, error) {
	if m == nil {
		return ctx, providers, nil
	}
	cfg, _ := m.runtimeConfig.Load().(*internalconfig.Config)
	if cfg == nil || !cfg.HasProviderKeyScopes() {
		return ctx, providers, nil
	}
	scope := &providerScope{cfg: cfg, clientKey: coreusage.APIKeyFromContext(ctx)}
	allowed := make([]string, 0, len(providers))
	var denied []string
	for _, provider := range providers {
		if scope.allows(provider) {
			allowed = append(allowed, provider)
		} else {
			denied = append(denied, provider)
		}
	}
	if len(allowed) == 0 && len(denied) > 0 {
		return ctx, nil, &ProviderForbiddenError{Providers: denied}
	}
	return context.WithValue(ctx, providerScopeContextKey{}, scope), allowed, nil
}

// ProviderForbiddenError is returned when access.provider-key-scopes forbids the
// client key from every requested provider. Error returns an OpenAI-style JSON
// body, which the OpenAI handlers pass through and the Claude handlers convert
// into an Anthropic permission_error.
type ProviderForbiddenError struct {
	Providers []string
}

// Message returns the human readable reason.
func (e *ProviderForbiddenError) Message() string {
	return fmt.Sprintf("this API key is not allowed to use %s credentials", strings.Join(e.Providers, ", "))
}

// Error implements error.
func (e *ProviderForbiddenError) Error() string {
	payload, errMarshal := json.Marshal(map[string]any{
		"error": map[string]any{
			"message": e.Message(),
			"type":    "permission_error",
			"code":    ErrorCodeProviderForbidden,
		},
	})
	if errMarshal != nil {
		return e.Message()
	}
	return string(payload)
}

// StatusCode implements the status accessor used by API handlers.
func (e *ProviderForbiddenError) StatusCode() int {
	return http.StatusForbidden
}
