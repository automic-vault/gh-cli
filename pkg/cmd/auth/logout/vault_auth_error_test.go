package logout

import (
	"errors"
	"strings"
	"testing"

	"github.com/cli/cli/v2/internal/config"
	"github.com/cli/cli/v2/internal/gh"
	"github.com/cli/cli/v2/pkg/iostreams"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errSyntheticLogoutVaultDenied = errors.New("synthetic Vault retrieval denied for logout command")

type logoutVaultAuthConfig struct {
	*config.AuthConfig
	legacyCalls   int
	resolverCalls int
	logoutCalls   int
}

func (c *logoutVaultAuthConfig) Hosts() []string {
	return []string{"github.com"}
}

func (c *logoutVaultAuthConfig) ActiveToken(string) (string, string) {
	c.legacyCalls++
	return "synthetic-poison-token", "synthetic-poison-source"
}

func (c *logoutVaultAuthConfig) ActiveTokenWithError(string) (string, string, error) {
	c.resolverCalls++
	return "synthetic-poison-token", "synthetic-poison-source", errSyntheticLogoutVaultDenied
}

func (c *logoutVaultAuthConfig) ActiveUser(string) (string, error) {
	return "synthetic-account", nil
}

func (c *logoutVaultAuthConfig) UsersForHost(string) []string {
	return []string{"synthetic-account"}
}

func (c *logoutVaultAuthConfig) Logout(string, string) error {
	c.logoutCalls++
	return nil
}

type logoutCompatibilityAuthConfig struct {
	*config.AuthConfig
	legacyToken   string
	legacySource  string
	token         string
	source        string
	err           error
	legacyCalls   int
	resolverCalls int
	logoutCalls   int
	logoutHost    string
	logoutUser    string
}

func (c *logoutCompatibilityAuthConfig) Hosts() []string {
	return []string{"github.com"}
}

func (c *logoutCompatibilityAuthConfig) ActiveToken(string) (string, string) {
	c.legacyCalls++
	return c.legacyToken, c.legacySource
}

func (c *logoutCompatibilityAuthConfig) ActiveTokenWithError(string) (string, string, error) {
	c.resolverCalls++
	return c.token, c.source, c.err
}

func (c *logoutCompatibilityAuthConfig) ActiveUser(string) (string, error) {
	return "synthetic-account", nil
}

func (c *logoutCompatibilityAuthConfig) UsersForHost(string) []string {
	return []string{"synthetic-account"}
}

func (c *logoutCompatibilityAuthConfig) Logout(hostname, username string) error {
	c.logoutCalls++
	c.logoutHost = hostname
	c.logoutUser = username
	return nil
}

func requireNoLogoutSecretMaterial(t *testing.T, err error, stdout, stderr string) {
	t.Helper()
	errText := ""
	if err != nil {
		errText = err.Error()
	}
	output := strings.ToLower(errText + stdout + stderr)
	for _, forbidden := range []string{
		"synthetic-poison-token",
		"synthetic-poison-source",
		"synthetic-account",
		"undefined",
		"protocol=",
	} {
		assert.NotContains(t, output, forbidden)
	}
}

func TestLogoutRunOperationalVaultFailureDoesNotClearOrReportSuccess(t *testing.T) {
	authCfg := &logoutVaultAuthConfig{AuthConfig: &config.AuthConfig{}}
	mockConfig := config.NewMockConfigFromString("")
	mockConfig.AuthenticationFunc = func() gh.AuthConfig {
		return authCfg
	}

	ios, _, stdout, stderr := iostreams.Test()
	err := logoutRun(&LogoutOptions{
		IO:       ios,
		Hostname: "github.com",
		Username: "synthetic-account",
		Config: func() (gh.Config, error) {
			return mockConfig, nil
		},
	})

	assert.Empty(t, stdout.String())
	assert.Empty(t, stderr.String())
	assert.Equal(t, 0, authCfg.legacyCalls)
	assert.Equal(t, 1, authCfg.resolverCalls)
	assert.Equal(t, 0, authCfg.logoutCalls)
	requireNoLogoutSecretMaterial(t, err, stdout.String(), stderr.String())
	require.ErrorIs(t, err, errSyntheticLogoutVaultDenied)
}

func TestLogoutRunResolvedCredentialLogsOutExactlyOnce(t *testing.T) {
	authCfg := &logoutCompatibilityAuthConfig{
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
	err := logoutRun(&LogoutOptions{
		IO:       ios,
		Hostname: "github.com",
		Username: "synthetic-account",
		Config: func() (gh.Config, error) {
			return mockConfig, nil
		},
	})

	assert.NoError(t, err)
	assert.Empty(t, stdout.String())
	assert.Equal(t, "✓ Logged out of github.com account synthetic-account\n", stderr.String())
	assert.Equal(t, 0, authCfg.legacyCalls)
	assert.Equal(t, 1, authCfg.resolverCalls)
	assert.Equal(t, 1, authCfg.logoutCalls)
	assert.Equal(t, "github.com", authCfg.logoutHost)
	assert.Equal(t, "synthetic-account", authCfg.logoutUser)
	require.NoError(t, err)
}

func TestLogoutRunIntentionalAbsenceStillRemovesAccount(t *testing.T) {
	authCfg := &logoutCompatibilityAuthConfig{
		legacyToken:  "synthetic-legacy-token",
		legacySource: "synthetic-legacy-source",
	}
	mockConfig := config.NewMockConfigFromString("")
	mockConfig.AuthenticationFunc = func() gh.AuthConfig {
		return authCfg
	}

	ios, _, stdout, stderr := iostreams.Test()
	err := logoutRun(&LogoutOptions{
		IO:       ios,
		Hostname: "github.com",
		Username: "synthetic-account",
		Config: func() (gh.Config, error) {
			return mockConfig, nil
		},
	})

	assert.NoError(t, err)
	assert.Empty(t, stdout.String())
	assert.Equal(t, "✓ Logged out of github.com account synthetic-account\n", stderr.String())
	assert.Equal(t, 0, authCfg.legacyCalls)
	assert.Equal(t, 1, authCfg.resolverCalls)
	assert.Equal(t, 1, authCfg.logoutCalls)
	require.NoError(t, err)
}
