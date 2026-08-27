package shared

import (
	"strings"

	"github.com/cli/cli/v2/internal/gh"
)

type activeTokenResolver interface {
	ActiveTokenWithError(string) (string, string, error)
}

// ResolveActiveToken retrieves the active token while preserving the
// distinction between an unavailable credential provider and an absent token.
// Configurations that predate the error-aware method retain the legacy getter
// behavior for compatibility.
func ResolveActiveToken(authCfg gh.AuthConfig, hostname string) (string, string, error) {
	if resolver, ok := any(authCfg).(activeTokenResolver); ok {
		return resolver.ActiveTokenWithError(hostname)
	}

	token, source := authCfg.ActiveToken(hostname)
	return token, source, nil
}

// AuthTokenRefreshable reports whether the token is stored by gh and can be
// renewed with `gh auth refresh`.
func AuthTokenRefreshable(token, src string) bool {
	return token != "" && !strings.HasSuffix(src, "_TOKEN") && strings.HasPrefix(token, "gho_")
}

func AuthTokenWriteable(authCfg gh.AuthConfig, hostname string) (string, bool) {
	token, src := authCfg.ActiveToken(hostname)
	return src, (token == "" || !strings.HasSuffix(src, "_TOKEN"))
}
