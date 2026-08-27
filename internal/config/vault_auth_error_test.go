package config

import (
	"bytes"
	"errors"
	"io"
	"slices"
	"strings"
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
var errSyntheticLogoutDeleteDenied = errors.New("synthetic Vault delete denied")
var errSyntheticLogoutNextGetDenied = errors.New("synthetic Vault read denied for next account")
var errSyntheticLogoutActiveSetDenied = errors.New("synthetic Vault active-slot write denied")

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

func snapshotHostsConfig(t *testing.T, readConfigs func(io.Writer, io.Writer)) []byte {
	t.Helper()
	var hosts bytes.Buffer
	readConfigs(io.Discard, &hosts)
	return append([]byte(nil), hosts.Bytes()...)
}

func requireSyntheticStringSlice(t *testing.T, want, got []string, message string) {
	t.Helper()
	require.True(t, slices.Equal(want, got), message)
}

func requireSyntheticString(t *testing.T, want, got, message string) {
	t.Helper()
	require.True(t, want == got, message)
}

func TestLogoutPreservesStateWhenKeyringDeleteFails(t *testing.T) {
	cfg, readConfigs := NewIsolatedTestConfig(t, "")
	authCfg := cfg.Authentication().(*AuthConfig)
	const hostname = "github.com"
	const username = "synthetic-account"
	_, err := authCfg.Login(hostname, username, "synthetic-logout-token", "https", true)
	require.NoError(t, err)

	beforeHosts := snapshotHostsConfig(t, readConfigs)
	resolvedToken, resolvedSource, err := authCfg.ActiveTokenWithError(hostname)
	require.NoError(t, err)
	require.NotEmpty(t, resolvedToken)
	require.Equal(t, "keyring", resolvedSource)

	var deleteCalls []string
	authCfg.keyringDelete = func(_, user string) error {
		deleteCalls = append(deleteCalls, user)
		if user == "" {
			return nil
		}
		return errSyntheticLogoutDeleteDenied
	}

	err = authCfg.Logout(hostname, username)

	// The provider failure must be transactional: no persisted or in-memory
	// account state may change before the delete succeeds.
	afterHosts := snapshotHostsConfig(t, readConfigs)
	require.True(t, bytes.Equal(beforeHosts, afterHosts), "persisted authentication state changed")
	requireSyntheticStringSlice(t, []string{username}, authCfg.UsersForHost(hostname), "account list changed")
	activeUser, activeUserErr := authCfg.ActiveUser(hostname)
	require.NoError(t, activeUserErr)
	requireSyntheticString(t, username, activeUser, "active account changed")
	requireSyntheticStringSlice(t, []string{"", username}, deleteCalls, "keyring delete sequence changed")
	if err != nil {
		require.True(t, !strings.Contains(err.Error(), "synthetic-logout-token"), "error contains credential material")
		require.True(t, !strings.Contains(err.Error(), username), "error contains account material")
	}
	require.Error(t, err)
	require.ErrorIs(t, err, errSyntheticLogoutDeleteDenied)
}

func TestLogoutPreservesStateWhenActiveAccountSwitchDeleteFails(t *testing.T) {
	cfg, readConfigs := NewIsolatedTestConfig(t, "")
	authCfg := cfg.Authentication().(*AuthConfig)
	const hostname = "github.com"
	const activeUser = "synthetic-active-account"
	const nextUser = "synthetic-next-account"
	_, err := authCfg.Login(hostname, nextUser, "synthetic-next-token", "https", true)
	require.NoError(t, err)
	_, err = authCfg.Login(hostname, activeUser, "synthetic-active-token", "https", true)
	require.NoError(t, err)

	beforeHosts := snapshotHostsConfig(t, readConfigs)
	_, resolvedSource, err := authCfg.ActiveTokenWithError(hostname)
	require.NoError(t, err)
	require.Equal(t, "keyring", resolvedSource)

	authCfg.keyringDelete = func(_, user string) error {
		if user == "" {
			return errSyntheticLogoutDeleteDenied
		}
		return nil
	}

	err = authCfg.Logout(hostname, activeUser)

	afterHosts := snapshotHostsConfig(t, readConfigs)
	require.True(t, bytes.Equal(beforeHosts, afterHosts), "persisted authentication state changed")
	requireSyntheticStringSlice(t, []string{nextUser, activeUser}, authCfg.UsersForHost(hostname), "account list changed")
	currentUser, currentUserErr := authCfg.ActiveUser(hostname)
	require.NoError(t, currentUserErr)
	requireSyntheticString(t, activeUser, currentUser, "active account changed")
	if err != nil {
		require.True(t, !strings.Contains(err.Error(), "synthetic-active-token"), "error contains credential material")
		require.True(t, !strings.Contains(err.Error(), activeUser), "error contains account material")
	}
	require.Error(t, err)
	require.ErrorIs(t, err, errSyntheticLogoutDeleteDenied)
}

func TestLogoutTreatsKeyringDeleteNotFoundAsCompatible(t *testing.T) {
	cfg, readConfigs := NewIsolatedTestConfig(t, "")
	authCfg := cfg.Authentication().(*AuthConfig)
	const hostname = "github.com"
	const username = "synthetic-account"
	_, err := authCfg.Login(hostname, username, "synthetic-logout-token", "https", true)
	require.NoError(t, err)
	authCfg.keyringDelete = func(string, string) error {
		return keyring.ErrNotFound
	}

	err = authCfg.Logout(hostname, username)

	require.NoError(t, err)
	require.Empty(t, authCfg.UsersForHost(hostname))
	require.Equal(t, []byte("{}\n"), snapshotHostsConfig(t, readConfigs))
}

func TestLogoutDeletesInactiveAccountBeforeConfigMutation(t *testing.T) {
	cfg, readConfigs := NewIsolatedTestConfig(t, "")
	authCfg := cfg.Authentication().(*AuthConfig)
	const hostname = "github.com"
	const inactiveUser = "synthetic-inactive-account"
	const activeUser = "synthetic-active-account"
	_, err := authCfg.Login(hostname, inactiveUser, "synthetic-inactive-token", "https", true)
	require.NoError(t, err)
	_, err = authCfg.Login(hostname, activeUser, "synthetic-active-token", "https", true)
	require.NoError(t, err)

	beforeHosts := snapshotHostsConfig(t, readConfigs)
	var deleteCalls []string
	authCfg.keyringDelete = func(_, user string) error {
		deleteCalls = append(deleteCalls, user)
		if user == inactiveUser {
			return errSyntheticLogoutDeleteDenied
		}
		return nil
	}

	err = authCfg.Logout(hostname, inactiveUser)

	afterHosts := snapshotHostsConfig(t, readConfigs)
	require.True(t, bytes.Equal(beforeHosts, afterHosts), "persisted authentication state changed")
	requireSyntheticStringSlice(t, []string{inactiveUser}, deleteCalls, "inactive account delete was not attempted")
	requireSyntheticStringSlice(t, []string{inactiveUser, activeUser}, authCfg.UsersForHost(hostname), "account list changed")
	currentUser, currentUserErr := authCfg.ActiveUser(hostname)
	require.NoError(t, currentUserErr)
	requireSyntheticString(t, activeUser, currentUser, "active account changed")
	if err != nil {
		require.True(t, !strings.Contains(err.Error(), inactiveUser), "error contains account material")
	}
	require.Error(t, err)
	require.ErrorIs(t, err, errSyntheticLogoutDeleteDenied)
}

func TestLogoutPreservesStateWhenNextAccountKeyringReadFails(t *testing.T) {
	cfg, readConfigs := NewIsolatedTestConfig(t, "")
	authCfg := cfg.Authentication().(*AuthConfig)
	const hostname = "github.com"
	const activeUser = "synthetic-active-account"
	const nextUser = "synthetic-next-account"
	_, err := authCfg.Login(hostname, nextUser, "synthetic-next-token", "https", true)
	require.NoError(t, err)
	_, err = authCfg.Login(hostname, activeUser, "synthetic-active-token", "https", true)
	require.NoError(t, err)

	beforeHosts := snapshotHostsConfig(t, readConfigs)
	var getCalls []string
	authCfg.keyringGet = func(service, user string) (string, error) {
		getCalls = append(getCalls, user)
		if user == nextUser {
			return "", errSyntheticLogoutNextGetDenied
		}
		return keyring.Get(service, user)
	}

	err = authCfg.Logout(hostname, activeUser)

	afterHosts := snapshotHostsConfig(t, readConfigs)
	require.True(t, bytes.Equal(beforeHosts, afterHosts), "persisted authentication state changed")
	requireSyntheticStringSlice(t, []string{nextUser}, getCalls, "next-account keyring read sequence changed")
	requireSyntheticStringSlice(t, []string{nextUser, activeUser}, authCfg.UsersForHost(hostname), "account list changed")
	currentUser, currentUserErr := authCfg.ActiveUser(hostname)
	require.NoError(t, currentUserErr)
	requireSyntheticString(t, activeUser, currentUser, "active account changed")
	if err != nil {
		require.True(t, !strings.Contains(err.Error(), activeUser), "error contains account material")
	}
	require.Error(t, err)
	require.ErrorIs(t, err, errSyntheticLogoutNextGetDenied)
}

func TestLogoutPreservesStateWhenNextAccountActiveSlotWriteFails(t *testing.T) {
	cfg, readConfigs := NewIsolatedTestConfig(t, "")
	authCfg := cfg.Authentication().(*AuthConfig)
	const hostname = "github.com"
	const activeUser = "synthetic-active-account"
	const nextUser = "synthetic-next-account"
	_, err := authCfg.Login(hostname, nextUser, "synthetic-next-token", "https", true)
	require.NoError(t, err)
	_, err = authCfg.Login(hostname, activeUser, "synthetic-active-token", "https", true)
	require.NoError(t, err)

	beforeHosts := snapshotHostsConfig(t, readConfigs)
	var getCalls []string
	var setCalls []string
	authCfg.keyringGet = func(service, user string) (string, error) {
		getCalls = append(getCalls, user)
		return keyring.Get(service, user)
	}
	authCfg.keyringSet = func(_, user, _ string) error {
		setCalls = append(setCalls, user)
		if user == "" {
			return errSyntheticLogoutActiveSetDenied
		}
		return nil
	}

	err = authCfg.Logout(hostname, activeUser)

	afterHosts := snapshotHostsConfig(t, readConfigs)
	require.True(t, bytes.Equal(beforeHosts, afterHosts), "persisted authentication state changed")
	requireSyntheticStringSlice(t, []string{nextUser}, getCalls, "next-account keyring read sequence changed")
	requireSyntheticStringSlice(t, []string{""}, setCalls, "active-slot keyring write sequence changed")
	requireSyntheticStringSlice(t, []string{nextUser, activeUser}, authCfg.UsersForHost(hostname), "account list changed")
	currentUser, currentUserErr := authCfg.ActiveUser(hostname)
	require.NoError(t, currentUserErr)
	requireSyntheticString(t, activeUser, currentUser, "active account changed")
	if err != nil {
		require.True(t, !strings.Contains(err.Error(), activeUser), "error contains account material")
	}
	require.Error(t, err)
	require.ErrorIs(t, err, errSyntheticLogoutActiveSetDenied)
}
