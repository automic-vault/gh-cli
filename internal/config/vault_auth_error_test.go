package config

import (
	"errors"
	"testing"

	"github.com/cli/cli/v2/internal/keyring"
	ghConfig "github.com/cli/go-gh/v2/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type activeTokenWithError interface {
	ActiveTokenWithError(string) (string, string, error)
}

var errMissingActiveTokenWithError = errors.New("ActiveTokenWithError is not implemented")
var errSyntheticVaultDenied = errors.New("synthetic Vault access denied")
var errSyntheticTokenForUserVaultDenied = errors.New("synthetic Vault access denied for selected account")

// vaultCredentialResolutionError is the runtime contract for the production
// error type. Keeping this as an interface lets the RED suite compile before
// internal/config exports its concrete type while still requiring errors.As
// classification and an errors.Is-preserving Unwrap method.
type vaultCredentialResolutionError interface {
	error
	Unwrap() error
	IsAutomicVaultCredentialResolution() bool
}

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

	token, source, err := callActiveTokenWithError(t, authCfg, hostname)
	if token != "" || source != "" {
		t.Errorf("operational Vault failure must not return a token or source, got token=%q source=%q", token, source)
	}
	require.ErrorIs(t, err, errSyntheticVaultDenied)
}

func TestActiveTokenWithErrorClassifiesOperationalFailureAsAutomicVaultError(t *testing.T) {
	authCfg := newTestAuthConfig(t)
	hostname := "github.com"
	authCfg.cfg.Set([]string{hostsKey, hostname, userKey}, "synthetic-account")
	keyring.MockInitWithError(errSyntheticVaultDenied)
	t.Cleanup(keyring.MockInit)

	token, source, err := callActiveTokenWithError(t, authCfg, hostname)

	// Keep the safety assertions before the classification checks so this test
	// also proves an operational failure cannot return credential material.
	require.Empty(t, token)
	require.Empty(t, source)
	require.Error(t, err)
	var classified vaultCredentialResolutionError
	require.ErrorAs(t, err, &classified)
	require.True(t, classified.IsAutomicVaultCredentialResolution())
	require.Equal(t, "Automic Vault credential resolution failed", classified.Error())
	require.ErrorIs(t, err, errSyntheticVaultDenied)
	require.NotContains(t, err.Error(), "synthetic-account")
	require.NotContains(t, err.Error(), "synthetic-poison-token")
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

func TestActiveTokenWithErrorUsesHostWideCompatibilityWhenActiveUserIsAbsent(t *testing.T) {
	authCfg := newTestAuthConfig(t)
	hostname := "github.com"
	require.NoError(t, keyring.Set(keyringServiceName(hostname), "", "synthetic-hostwide-token"))

	// ghConfig.Config.Get currently exposes only KeyNotFoundError for this
	// lookup. A non-KeyNotFound ActiveUser error needs a narrow production
	// lookup seam before it can be exercised without unsafe monkey-patching or
	// a test that merely reimplements ActiveTokenWithError.
	_, activeUserErr := authCfg.ActiveUser(hostname)
	var keyNotFoundError *ghConfig.KeyNotFoundError
	require.ErrorAs(t, activeUserErr, &keyNotFoundError)

	token, source, err := callActiveTokenWithError(t, authCfg, hostname)

	require.NoError(t, err)
	require.Equal(t, "synthetic-hostwide-token", token)
	require.Equal(t, "keyring", source)
}

func TestActiveTokenWithErrorUsesHostWideCompatibilityWhenActiveUserIsEmpty(t *testing.T) {
	authCfg := newTestAuthConfig(t)
	hostname := "github.com"
	authCfg.cfg.Set([]string{hostsKey, hostname, userKey}, "")
	require.NoError(t, keyring.Set(keyringServiceName(hostname), "", "synthetic-hostwide-token"))

	token, source, err := callActiveTokenWithError(t, authCfg, hostname)

	require.NoError(t, err)
	require.Equal(t, "synthetic-hostwide-token", token)
	require.Equal(t, "keyring", source)
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

func TestTokenForUserClassifiesOperationalKeyringFailure(t *testing.T) {
	authCfg := newTestAuthConfig(t)
	keyring.MockInitWithError(errSyntheticTokenForUserVaultDenied)
	t.Cleanup(keyring.MockInit)

	token, source, err := authCfg.TokenForUser("github.com", "synthetic-account")

	require.Empty(t, token)
	require.Empty(t, source)
	var resolutionErr *AutomicVaultCredentialResolutionError
	require.ErrorAs(t, err, &resolutionErr)
	require.Equal(t, "Automic Vault credential resolution failed", resolutionErr.Error())
	require.ErrorIs(t, err, errSyntheticTokenForUserVaultDenied)
	require.NotContains(t, err.Error(), "synthetic-account")
}

func TestTokenForUserNotFoundPreservesKeyringAbsenceIdentity(t *testing.T) {
	authCfg := newTestAuthConfig(t)

	_, _, err := authCfg.TokenForUser("github.com", "synthetic-account")

	require.ErrorIs(t, err, keyring.ErrNotFound)
	require.EqualError(t, err, "no token found for 'synthetic-account'")
}
