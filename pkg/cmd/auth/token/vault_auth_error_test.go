package token

import (
	"errors"
	"testing"

	"github.com/cli/cli/v2/internal/config"
	"github.com/cli/cli/v2/internal/gh"
	"github.com/cli/cli/v2/pkg/iostreams"
	"github.com/stretchr/testify/require"
)

var errSyntheticTokenVaultDenied = errors.New("synthetic Vault retrieval denied for token command")

type tokenVaultAuthConfig struct {
	*config.AuthConfig
	legacyCalls   int
	resolverCalls int
}

func (c *tokenVaultAuthConfig) ActiveToken(string) (string, string) {
	c.legacyCalls++
	return "synthetic-poison-token", "synthetic-poison-source"
}

func (c *tokenVaultAuthConfig) ActiveTokenWithError(string) (string, string, error) {
	c.resolverCalls++
	return "synthetic-poison-token", "synthetic-poison-source", errSyntheticTokenVaultDenied
}

func TestTokenRunOperationalVaultFailureDoesNotPrintOrUseLegacyCredential(t *testing.T) {
	authCfg := &tokenVaultAuthConfig{AuthConfig: &config.AuthConfig{}}
	mockConfig := config.NewMockConfigFromString("")
	mockConfig.AuthenticationFunc = func() gh.AuthConfig {
		return authCfg
	}

	ios, _, stdout, stderr := iostreams.Test()
	err := tokenRun(&TokenOptions{
		IO:       ios,
		Hostname: "github.com",
		Config: func() (gh.Config, error) {
			return mockConfig, nil
		},
	})

	require.ErrorIs(t, err, errSyntheticTokenVaultDenied)
	require.Empty(t, stdout.String())
	require.Empty(t, stderr.String())
	require.Equal(t, 0, authCfg.legacyCalls)
	require.Equal(t, 1, authCfg.resolverCalls)
}
