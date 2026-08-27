package logout

import (
	"errors"
	"testing"

	"github.com/cli/cli/v2/internal/config"
	"github.com/cli/cli/v2/internal/gh"
	"github.com/cli/cli/v2/pkg/iostreams"
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

	require.ErrorIs(t, err, errSyntheticLogoutVaultDenied)
	require.Empty(t, stdout.String())
	require.Empty(t, stderr.String())
	require.Equal(t, 0, authCfg.legacyCalls)
	require.Equal(t, 1, authCfg.resolverCalls)
	require.Equal(t, 0, authCfg.logoutCalls)
}
