package authswitch

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

var errSyntheticSwitchCommandVaultDenied = errors.New("synthetic Vault retrieval denied for switch command")

type switchCommandVaultAuthConfig struct {
	*config.AuthConfig
	legacyCalls   int
	resolverCalls int
	switchCalls   int
}

var _ gh.AuthConfig = (*switchCommandVaultAuthConfig)(nil)

func (c *switchCommandVaultAuthConfig) Hosts() []string {
	return []string{"github.com"}
}

func (c *switchCommandVaultAuthConfig) UsersForHost(string) []string {
	return []string{"synthetic-switch-account"}
}

func (c *switchCommandVaultAuthConfig) ActiveUser(string) (string, error) {
	return "synthetic-switch-account", nil
}

func (c *switchCommandVaultAuthConfig) ActiveToken(string) (string, string) {
	c.legacyCalls++
	return "synthetic-switch-poison-token", "synthetic-switch-poison-source"
}

func (c *switchCommandVaultAuthConfig) ActiveTokenWithError(string) (string, string, error) {
	c.resolverCalls++
	return "synthetic-switch-poison-token", "synthetic-switch-poison-source", errSyntheticSwitchCommandVaultDenied
}

func (c *switchCommandVaultAuthConfig) SwitchUser(string, string) error {
	c.switchCalls++
	return nil
}

func TestSwitchRunOperationalVaultFailureStopsBeforeMutation(t *testing.T) {
	authCfg := &switchCommandVaultAuthConfig{AuthConfig: &config.AuthConfig{}}
	mockConfig := config.NewMockConfigFromString("")
	mockConfig.AuthenticationFunc = func() gh.AuthConfig {
		return authCfg
	}
	ios, _, stdout, stderr := iostreams.Test()
	err := switchRun(&SwitchOptions{
		IO:       ios,
		Hostname: "github.com",
		Username: "synthetic-switch-account",
		Config: func() (gh.Config, error) {
			return mockConfig, nil
		},
	})

	assert.Empty(t, stdout.String())
	assert.Empty(t, stderr.String(), "Vault resolution failure reported switch success or account details")
	assert.Equal(t, 0, authCfg.switchCalls, "Vault resolution failure reached SwitchUser")
	assert.Equal(t, 0, authCfg.legacyCalls, "switch used the legacy token getter")
	assert.Equal(t, 1, authCfg.resolverCalls, "switch did not attempt the error-aware resolver exactly once")
	combined := strings.ToLower(stdout.String() + stderr.String())
	if err != nil {
		combined += strings.ToLower(err.Error())
	}
	for _, forbidden := range []string{
		"synthetic-switch-poison-token",
		"synthetic-switch-poison-source",
		"synthetic-switch-account",
		"undefined",
		"logged in",
		"log in",
		"re-authenticate",
	} {
		assert.NotContains(t, combined, forbidden)
	}
	require.ErrorIs(t, err, errSyntheticSwitchCommandVaultDenied)
}
