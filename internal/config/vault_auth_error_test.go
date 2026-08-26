package config

import (
	"errors"
	"testing"

	"github.com/cli/cli/v2/internal/keyring"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type activeTokenWithError interface {
	ActiveTokenWithError(string) (string, string, error)
}

var errMissingActiveTokenWithError = errors.New("ActiveTokenWithError is not implemented")
var errSyntheticVaultDenied = errors.New("synthetic Vault access denied")

func callActiveTokenWithError(t *testing.T, authCfg *AuthConfig, hostname string) (string, string, error) {
	t.Helper()

	resolver, ok := any(authCfg).(activeTokenWithError)
	if !assert.True(t, ok, "AuthConfig must expose the error-aware token resolver") {
		return "", "", errMissingActiveTokenWithError
	}

	return resolver.ActiveTokenWithError(hostname)
}

func TestActiveTokenWithErrorOperationalAccountFailureDoesNotUseLegacyCredential(t *testing.T) {
	authCfg := newTestAuthConfig(t)
	hostname := "github.com"
	authCfg.cfg.Set([]string{hostsKey, hostname, userKey}, "synthetic-account")
	// The keyring wrapper exposes only a global mock error, so selective
	// account-slot injection is covered by the API transport dual-fake test.
	keyring.MockInitWithError(errSyntheticVaultDenied)
	t.Cleanup(keyring.MockInit)

	_, _, err := callActiveTokenWithError(t, authCfg, hostname)
	require.ErrorIs(t, err, errSyntheticVaultDenied)
}

func TestActiveTokenWithErrorAllowsLegacyOnlyForAccountNotFound(t *testing.T) {
	authCfg := newTestAuthConfig(t)
	hostname := "github.com"
	authCfg.cfg.Set([]string{hostsKey, hostname, userKey}, "synthetic-account")
	require.NoError(t, keyring.Set(keyringServiceName(hostname), "", "synthetic-legacy-token"))

	token, source, err := callActiveTokenWithError(t, authCfg, hostname)

	require.NoError(t, err)
	require.Equal(t, "synthetic-legacy-token", token)
	require.Equal(t, "keyring", source)
}

func TestActiveTokenWithErrorAllowsAnonymousUseWhenBothSlotsAreNotFound(t *testing.T) {
	authCfg := newTestAuthConfig(t)
	hostname := "github.com"
	authCfg.cfg.Set([]string{hostsKey, hostname, userKey}, "synthetic-account")

	token, source, err := callActiveTokenWithError(t, authCfg, hostname)

	require.NoError(t, err)
	require.Empty(t, token)
	require.Empty(t, source)
}

func TestActiveTokenWithErrorHonorsSetActiveTokenOverride(t *testing.T) {
	authCfg := newTestAuthConfig(t)
	authCfg.SetActiveToken("synthetic-override-token", "synthetic-override-source")

	token, source, err := callActiveTokenWithError(t, authCfg, "github.com")

	require.NoError(t, err)
	require.Equal(t, "synthetic-override-token", token)
	require.Equal(t, "synthetic-override-source", source)
}

func TestActiveTokenWithErrorPrioritizesEnvironmentToken(t *testing.T) {
	authCfg := newTestAuthConfig(t)
	hostname := "github.com"
	authCfg.cfg.Set([]string{hostsKey, hostname, userKey}, "synthetic-account")
	t.Setenv("GH_TOKEN", "synthetic-environment-token")
	keyring.MockInitWithError(errSyntheticVaultDenied)
	t.Cleanup(keyring.MockInit)

	token, source, err := callActiveTokenWithError(t, authCfg, hostname)

	require.NoError(t, err)
	require.Equal(t, "synthetic-environment-token", token)
	require.Equal(t, "GH_TOKEN", source)
}
