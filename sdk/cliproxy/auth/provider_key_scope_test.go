package auth

import (
	"context"
	"errors"
	"net/http"
	"testing"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	coreusage "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/usage"
)

type scopeCountingExecutor struct {
	selectedCapabilityCaptureExecutor
}

func newScopeTestManager(t *testing.T, model string) (*Manager, map[string]*scopeCountingExecutor) {
	t.Helper()
	manager := NewManager(nil, nil, nil)
	cfg := &internalconfig.Config{}
	cfg.ProviderKeyScopes = map[string][]string{"claude": {"claude-code-key"}}
	manager.SetConfig(cfg)
	executors := map[string]*scopeCountingExecutor{}
	reg := registry.GetGlobalRegistry()
	for _, provider := range []string{"claude", "codex"} {
		executor := &scopeCountingExecutor{selectedCapabilityCaptureExecutor{provider: provider}}
		executors[provider] = executor
		manager.RegisterExecutor(executor)
		auth := &Auth{
			ID:       "scope-" + provider + "-" + model,
			Provider: provider,
			Metadata: map[string]any{"access_token": "fake-token"},
		}
		registerCapabilityTestAuth(t, manager, auth)
		reg.RegisterClient(auth.ID, provider, []*registry.ModelInfo{{ID: model}})
		authID := auth.ID
		t.Cleanup(func() { reg.UnregisterClient(authID) })
		manager.RefreshSchedulerEntry(auth.ID)
	}
	return manager, executors
}

func scopeCtx(key string) context.Context {
	return coreusage.WithAPIKey(context.Background(), key)
}

func TestProviderKeyScopes_AllowedKeyUsesRestrictedProvider(t *testing.T) {
	manager, executors := newScopeTestManager(t, "scope-claude-only")
	_, err := manager.Execute(scopeCtx("claude-code-key"), []string{"claude"}, cliproxyexecutor.Request{Model: "scope-claude-only"}, cliproxyexecutor.Options{})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if got := len(executors["claude"].requests); got != 1 {
		t.Fatalf("claude executor calls = %d, want 1", got)
	}
}

func TestProviderKeyScopes_OtherKeyForbidden(t *testing.T) {
	manager, executors := newScopeTestManager(t, "scope-claude-forbidden")
	for name, run := range map[string]func(ctx context.Context) error{
		"execute": func(ctx context.Context) error {
			_, err := manager.Execute(ctx, []string{"claude"}, cliproxyexecutor.Request{Model: "scope-claude-forbidden"}, cliproxyexecutor.Options{})
			return err
		},
		"stream": func(ctx context.Context) error {
			_, err := manager.ExecuteStream(ctx, []string{"claude"}, cliproxyexecutor.Request{Model: "scope-claude-forbidden"}, cliproxyexecutor.Options{})
			return err
		},
		"count": func(ctx context.Context) error {
			_, err := manager.ExecuteCount(ctx, []string{"claude"}, cliproxyexecutor.Request{Model: "scope-claude-forbidden"}, cliproxyexecutor.Options{})
			return err
		},
	} {
		for _, key := range []string{"other-key", ""} {
			err := run(scopeCtx(key))
			var forbidden *ProviderForbiddenError
			if !errors.As(err, &forbidden) {
				t.Fatalf("%s key=%q: error = %v, want ProviderForbiddenError", name, key, err)
			}
			if forbidden.StatusCode() != http.StatusForbidden {
				t.Fatalf("%s: status = %d, want 403", name, forbidden.StatusCode())
			}
		}
	}
	if got := len(executors["claude"].requests); got != 0 {
		t.Fatalf("claude executor calls = %d, want 0", got)
	}
}

func TestProviderKeyScopes_MixedModelFallsBackToUnrestrictedProvider(t *testing.T) {
	manager, executors := newScopeTestManager(t, "scope-mixed")
	for i := 0; i < 4; i++ {
		_, err := manager.Execute(scopeCtx("other-key"), []string{"claude", "codex"}, cliproxyexecutor.Request{Model: "scope-mixed"}, cliproxyexecutor.Options{})
		if err != nil {
			t.Fatalf("Execute() error = %v", err)
		}
	}
	if got := len(executors["claude"].requests); got != 0 {
		t.Fatalf("claude executor calls = %d, want 0", got)
	}
	if got := len(executors["codex"].requests); got != 4 {
		t.Fatalf("codex executor calls = %d, want 4", got)
	}
}

func TestProviderKeyScopes_UnlistedProviderUnaffected(t *testing.T) {
	manager, executors := newScopeTestManager(t, "scope-codex-only")
	_, err := manager.Execute(scopeCtx("other-key"), []string{"codex"}, cliproxyexecutor.Request{Model: "scope-codex-only"}, cliproxyexecutor.Options{})
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if got := len(executors["codex"].requests); got != 1 {
		t.Fatalf("codex executor calls = %d, want 1", got)
	}
}

func TestProviderKeyScopes_EligibilityExcludesRestrictedCredentials(t *testing.T) {
	cfg := &internalconfig.Config{}
	cfg.ProviderKeyScopes = map[string][]string{"claude": {"claude-code-key"}}
	eligibility := authSelectionEligibility{providerScope: &providerScope{cfg: cfg, clientKey: "other-key"}}
	if eligibility.allows(&Auth{Provider: "claude"}) {
		t.Fatal("restricted claude credential allowed for other key")
	}
	if !eligibility.allows(&Auth{Provider: "codex"}) {
		t.Fatal("unrestricted codex credential rejected")
	}
}
