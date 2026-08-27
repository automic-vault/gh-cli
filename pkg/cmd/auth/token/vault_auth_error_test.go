package token

import (
	"errors"
	"strings"
	"testing"

	"github.com/cli/cli/v2/internal/config"
	"github.com/cli/cli/v2/internal/gh"
	"github.com/cli/cli/v2/internal/keyring"
	"github.com/cli/cli/v2/pkg/iostreams"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errSyntheticTokenVaultDenied = errors.New("synthetic Vault retrieval denied for token command")
var errSyntheticTokenForUserVaultDenied = errors.New("synthetic Vault retrieval denied for selected token account")

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

type tokenCompatibilityAuthConfig struct {
	*config.AuthConfig
	legacyToken   string
	legacySource  string
	token         string
	source        string
	err           error
	legacyCalls   int
	resolverCalls int
}

func (c *tokenCompatibilityAuthConfig) ActiveToken(string) (string, string) {
	c.legacyCalls++
	return c.legacyToken, c.legacySource
}

func (c *tokenCompatibilityAuthConfig) ActiveTokenWithError(string) (string, string, error) {
	c.resolverCalls++
	return c.token, c.source, c.err
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

	assert.Empty(t, stdout.String())
	assert.Empty(t, stderr.String())
	assert.Equal(t, 0, authCfg.legacyCalls)
	assert.Equal(t, 1, authCfg.resolverCalls)
	combined := strings.ToLower(stdout.String() + stderr.String())
	if err != nil {
		combined += strings.ToLower(err.Error())
	}
	for _, forbidden := range []string{
		"synthetic-poison-token",
		"synthetic-poison-source",
		"synthetic-account",
		"undefined",
		"protocol=",
	} {
		assert.NotContains(t, combined, forbidden)
	}
	require.ErrorIs(t, err, errSyntheticTokenVaultDenied)
}

func TestTokenRunResolvedVaultCredentialPrintsOneTokenLine(t *testing.T) {
	authCfg := &tokenCompatibilityAuthConfig{
		legacyToken:  "synthetic-legacy-token",
		legacySource: "synthetic-legacy-source",
		token:        "synthetic-resolved-token",
		source:       "synthetic-keyring",
	}
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

	assert.NoError(t, err)
	assert.Equal(t, "synthetic-resolved-token\n", stdout.String())
	assert.Empty(t, stderr.String())
	assert.Equal(t, 0, authCfg.legacyCalls)
	assert.Equal(t, 1, authCfg.resolverCalls)
	require.NoError(t, err)
}

func TestTokenRunIntentionalAbsenceRemainsCanonical(t *testing.T) {
	authCfg := &tokenCompatibilityAuthConfig{
		legacyToken:  "synthetic-legacy-token",
		legacySource: "synthetic-legacy-source",
	}
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

	assert.Empty(t, stdout.String())
	assert.Empty(t, stderr.String())
	assert.Equal(t, 0, authCfg.legacyCalls)
	assert.Equal(t, 1, authCfg.resolverCalls)
	combined := strings.ToLower(stdout.String() + stderr.String())
	if err != nil {
		combined += strings.ToLower(err.Error())
	}
	assert.NotContains(t, combined, "synthetic-legacy-token")
	assert.NotContains(t, combined, "synthetic-legacy-source")
	assert.NotContains(t, combined, "undefined")
	assert.EqualError(t, err, "no oauth token found for github.com")
}

func TestTokenRunOperationalVaultFailureForExplicitUserModes(t *testing.T) {
	tests := []struct {
		name          string
		secureStorage bool
		username      string
	}{
		{name: "active user", username: "synthetic-account"},
		{name: "secure active slot", secureStorage: true},
		{name: "secure selected user", secureStorage: true, username: "synthetic-account"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, _ := config.NewIsolatedTestConfig(t, "")
			authCfg := cfg.Authentication()
			keyring.MockInitWithError(errSyntheticTokenForUserVaultDenied)
			t.Cleanup(keyring.MockInit)

			mockConfig := config.NewMockConfigFromString("")
			mockConfig.AuthenticationFunc = func() gh.AuthConfig {
				return authCfg
			}
			ios, _, stdout, stderr := iostreams.Test()
			err := tokenRun(&TokenOptions{
				IO:            ios,
				Hostname:      "github.com",
				Username:      tt.username,
				SecureStorage: tt.secureStorage,
				Config: func() (gh.Config, error) {
					return mockConfig, nil
				},
			})

			assert.Empty(t, stdout.String())
			assert.Empty(t, stderr.String())
			combined := strings.ToLower(stdout.String() + stderr.String())
			if err != nil {
				combined += strings.ToLower(err.Error())
			}
			for _, forbidden := range []string{
				"synthetic-token",
				"synthetic-account",
				"undefined",
				"protocol=",
			} {
				assert.NotContains(t, combined, forbidden)
			}
			var resolutionErr *config.AutomicVaultCredentialResolutionError
			require.ErrorAs(t, err, &resolutionErr)
			require.Equal(t, "Automic Vault credential resolution failed", resolutionErr.Error())
			require.ErrorIs(t, err, errSyntheticTokenForUserVaultDenied)
		})
	}
}
