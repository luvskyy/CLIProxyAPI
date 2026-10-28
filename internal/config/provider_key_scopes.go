package config

import "strings"

// ProviderAllowedForKey reports whether the client API key may use credentials
// of provider. Providers absent from ProviderKeyScopes are unrestricted. A listed
// provider is usable only by the listed keys; an empty list or an empty client
// key (e.g. unauthenticated or internal callers) denies access.
func (c *SDKConfig) ProviderAllowedForKey(provider, clientKey string) bool {
	if c == nil || len(c.ProviderKeyScopes) == 0 {
		return true
	}
	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider == "" {
		return true
	}
	var allowed []string
	listed := false
	for name, keys := range c.ProviderKeyScopes {
		if strings.ToLower(strings.TrimSpace(name)) == provider {
			allowed = append(allowed, keys...)
			listed = true
		}
	}
	if !listed {
		return true
	}
	clientKey = strings.TrimSpace(clientKey)
	if clientKey == "" {
		return false
	}
	for _, key := range allowed {
		if strings.TrimSpace(key) == clientKey {
			return true
		}
	}
	return false
}

// HasProviderKeyScopes reports whether any provider is restricted.
func (c *SDKConfig) HasProviderKeyScopes() bool {
	return c != nil && len(c.ProviderKeyScopes) > 0
}
