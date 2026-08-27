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
var errSyntheticLogoutDepartingDeleteDenied = errors.New("synthetic Vault departing-account delete denied")
var errSyntheticLogoutRollbackDenied = errors.New("synthetic Vault active-slot rollback denied")

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

func assertSyntheticStringSlice(t *testing.T, want, got []string, message string) {
	t.Helper()
	assert.True(t, slices.Equal(want, got), message)
}

func assertSyntheticString(t *testing.T, want, got, message string) {
	t.Helper()
	assert.True(t, want == got, message)
}

func requireAutomicVaultCredentialError(t *testing.T, err, cause error) {
	t.Helper()
	if !assert.Error(t, err, "credential operation did not return an error") {
		return
	}
	assert.True(t, err.Error() == "Automic Vault credential resolution failed", "credential operation error did not use the stable public diagnostic")
	var resolutionErr *AutomicVaultCredentialResolutionError
	if !assert.True(t, errors.As(err, &resolutionErr), "credential operation error was not classified") {
		return
	}
	assert.Equal(t, "Automic Vault credential resolution failed", resolutionErr.Error())
	assert.True(t, errors.Is(err, cause), "credential operation error did not preserve its cause")
}

func requireAutomicVaultCredentialErrors(t *testing.T, err error, causes ...error) {
	t.Helper()
	if !assert.Error(t, err, "credential operation did not return an error") {
		return
	}
	assert.True(t, err.Error() == "Automic Vault credential resolution failed", "credential operation error did not use the stable public diagnostic")
	var resolutionErr *AutomicVaultCredentialResolutionError
	if !assert.True(t, errors.As(err, &resolutionErr), "credential operation error was not classified") {
		return
	}
	assert.Equal(t, "Automic Vault credential resolution failed", resolutionErr.Error())
	for _, cause := range causes {
		assert.True(t, errors.Is(err, cause), "credential operation error did not preserve its cause")
	}
}

func assertLogoutProviderStateUnchanged(t *testing.T, authCfg *AuthConfig, readConfigs func(io.Writer, io.Writer), beforeHosts []byte, beforeUsers []string, beforeActive string) {
	t.Helper()
	assert.True(t, bytes.Equal(beforeHosts, snapshotHostsConfig(t, readConfigs)), "persisted authentication state changed during provider operation")
	assertSyntheticStringSlice(t, beforeUsers, authCfg.UsersForHost("github.com"), "account list changed during provider operation")
	activeUser, err := authCfg.ActiveUser("github.com")
	assert.NoError(t, err)
	assertSyntheticString(t, beforeActive, activeUser, "active account changed during provider operation")
}

func assertLogoutErrorSecretFree(t *testing.T, err error, forbidden ...string) {
	t.Helper()
	if err == nil {
		return
	}
	message := strings.ToLower(err.Error())
	for _, value := range forbidden {
		assert.False(t, strings.Contains(message, strings.ToLower(value)), "credential operation error contains secret or account material")
	}
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
		return errSyntheticLogoutDeleteDenied
	}

	err = authCfg.Logout(hostname, username)

	// The first provider failure must be fail-closed: no persisted or in-memory
	// account state may change, and no second destructive operation may run.
	afterHosts := snapshotHostsConfig(t, readConfigs)
	assert.True(t, bytes.Equal(beforeHosts, afterHosts), "persisted authentication state changed")
	assertSyntheticStringSlice(t, []string{""}, deleteCalls, "keyring delete continued after the first failure")
	assertSyntheticStringSlice(t, []string{username}, authCfg.UsersForHost(hostname), "account list changed")
	activeUser, activeUserErr := authCfg.ActiveUser(hostname)
	assert.NoError(t, activeUserErr)
	assertSyntheticString(t, username, activeUser, "active account changed")
	if err != nil {
		assert.False(t, strings.Contains(err.Error(), "synthetic-logout-token"), "error contains credential material")
		assert.False(t, strings.Contains(err.Error(), username), "error contains account material")
	}
	requireAutomicVaultCredentialError(t, err, errSyntheticLogoutDeleteDenied)
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
	assert.True(t, bytes.Equal(beforeHosts, afterHosts), "persisted authentication state changed")
	assertSyntheticStringSlice(t, []string{inactiveUser}, deleteCalls, "inactive account delete was not attempted")
	assertSyntheticStringSlice(t, []string{inactiveUser, activeUser}, authCfg.UsersForHost(hostname), "account list changed")
	currentUser, currentUserErr := authCfg.ActiveUser(hostname)
	assert.NoError(t, currentUserErr)
	assertSyntheticString(t, activeUser, currentUser, "active account changed")
	if err != nil {
		assert.False(t, strings.Contains(err.Error(), inactiveUser), "error contains account material")
	}
	requireAutomicVaultCredentialError(t, err, errSyntheticLogoutDeleteDenied)
}

func TestLogoutRemovesInactiveAccountWhenKeyringDeleteNotFound(t *testing.T) {
	cfg, _ := NewIsolatedTestConfig(t, "")
	authCfg := cfg.Authentication().(*AuthConfig)
	const hostname = "github.com"
	const inactiveUser = "synthetic-inactive-account"
	const activeUser = "synthetic-active-account"
	_, err := authCfg.Login(hostname, inactiveUser, "synthetic-inactive-token", "https", true)
	require.NoError(t, err)
	_, err = authCfg.Login(hostname, activeUser, "synthetic-active-token", "https", true)
	require.NoError(t, err)

	var deleteCalls []string
	authCfg.keyringDelete = func(_, user string) error {
		deleteCalls = append(deleteCalls, user)
		return keyring.ErrNotFound
	}

	err = authCfg.Logout(hostname, inactiveUser)

	require.NoError(t, err)
	requireSyntheticStringSlice(t, []string{inactiveUser}, deleteCalls, "inactive account delete was not attempted")
	requireSyntheticStringSlice(t, []string{activeUser}, authCfg.UsersForHost(hostname), "inactive account was not removed")
	currentUser, currentUserErr := authCfg.ActiveUser(hostname)
	require.NoError(t, currentUserErr)
	requireSyntheticString(t, activeUser, currentUser, "active account changed")
}

func TestLogoutCommitsTwoUserProviderTransactionInOrder(t *testing.T) {
	cfg, readConfigs := NewIsolatedTestConfig(t, "")
	authCfg := cfg.Authentication().(*AuthConfig)
	const hostname = "github.com"
	const nextUser = "synthetic-next-account"
	const nextToken = "synthetic-next-token"
	const activeUser = "synthetic-active-account"
	const activeToken = "synthetic-active-token"
	_, err := authCfg.Login(hostname, nextUser, nextToken, "https", true)
	require.NoError(t, err)
	_, err = authCfg.Login(hostname, activeUser, activeToken, "https", true)
	require.NoError(t, err)

	beforeHosts := snapshotHostsConfig(t, readConfigs)
	beforeUsers := append([]string(nil), authCfg.UsersForHost(hostname)...)
	beforeActive, err := authCfg.ActiveUser(hostname)
	require.NoError(t, err)

	var operations []string
	authCfg.keyringGet = func(service, user string) (string, error) {
		assert.True(t, service == keyringServiceName(hostname), "unexpected keyring service")
		assertLogoutProviderStateUnchanged(t, authCfg, readConfigs, beforeHosts, beforeUsers, beforeActive)
		switch user {
		case "":
			operations = append(operations, "get-active")
		case nextUser:
			operations = append(operations, "get-next")
		case activeUser:
			operations = append(operations, "get-departing")
		default:
			operations = append(operations, "get-unexpected")
		}
		return keyring.Get(service, user)
	}
	authCfg.keyringSet = func(service, user, secret string) error {
		assert.True(t, service == keyringServiceName(hostname), "unexpected keyring service")
		assertSyntheticString(t, "", user, "active slot was not selected for replacement")
		assertSyntheticString(t, nextToken, secret, "next credential was not selected for the active slot")
		assertLogoutProviderStateUnchanged(t, authCfg, readConfigs, beforeHosts, beforeUsers, beforeActive)
		operations = append(operations, "set")
		return keyring.Set(service, user, secret)
	}
	authCfg.keyringDelete = func(service, user string) error {
		assert.True(t, service == keyringServiceName(hostname), "unexpected keyring service")
		assertSyntheticString(t, activeUser, user, "departing account was not selected for deletion")
		assertLogoutProviderStateUnchanged(t, authCfg, readConfigs, beforeHosts, beforeUsers, beforeActive)
		operations = append(operations, "delete")
		return keyring.Delete(service, user)
	}

	err = authCfg.Logout(hostname, activeUser)

	assertSyntheticStringSlice(t, []string{"get-active", "get-next", "get-departing", "set", "delete"}, operations, "provider transaction order changed")
	assert.NoError(t, err)
	assertSyntheticStringSlice(t, []string{nextUser}, authCfg.UsersForHost(hostname), "departing account was not removed after provider commit")
	currentUser, currentUserErr := authCfg.ActiveUser(hostname)
	assert.NoError(t, currentUserErr)
	assertSyntheticString(t, nextUser, currentUser, "next account was not activated after provider commit")

	// Read the provider state through the real wrapper after clearing the test
	// hooks. The assertions intentionally disclose only synthetic-state booleans.
	authCfg.keyringGet = nil
	authCfg.keyringSet = nil
	authCfg.keyringDelete = nil
	activeSlot, activeSlotErr := keyring.Get(keyringServiceName(hostname), "")
	assert.True(t, activeSlotErr == nil && activeSlot == nextToken, "next credential was not promoted to the active slot")
	departingSlot, departingSlotErr := keyring.Get(keyringServiceName(hostname), activeUser)
	assert.True(t, errors.Is(departingSlotErr, keyring.ErrNotFound) && departingSlot == "", "departing credential was not removed")
}

func TestLogoutRollsBackTwoUserProviderAfterDepartingDeleteFails(t *testing.T) {
	cfg, readConfigs := NewIsolatedTestConfig(t, "")
	authCfg := cfg.Authentication().(*AuthConfig)
	const hostname = "github.com"
	const nextUser = "synthetic-next-account"
	const nextToken = "synthetic-next-token"
	const activeUser = "synthetic-active-account"
	const activeToken = "synthetic-active-token"
	_, err := authCfg.Login(hostname, nextUser, nextToken, "https", true)
	require.NoError(t, err)
	_, err = authCfg.Login(hostname, activeUser, activeToken, "https", true)
	require.NoError(t, err)

	beforeHosts := snapshotHostsConfig(t, readConfigs)
	beforeUsers := append([]string(nil), authCfg.UsersForHost(hostname)...)
	beforeActive, err := authCfg.ActiveUser(hostname)
	require.NoError(t, err)
	var operations []string
	var setCalls int
	authCfg.keyringGet = func(service, user string) (string, error) {
		assert.True(t, service == keyringServiceName(hostname), "unexpected keyring service")
		assertLogoutProviderStateUnchanged(t, authCfg, readConfigs, beforeHosts, beforeUsers, beforeActive)
		switch user {
		case "":
			operations = append(operations, "get-active")
		case nextUser:
			operations = append(operations, "get-next")
		case activeUser:
			operations = append(operations, "get-departing")
		default:
			operations = append(operations, "get-unexpected")
		}
		return keyring.Get(service, user)
	}
	authCfg.keyringSet = func(service, user, secret string) error {
		assert.True(t, service == keyringServiceName(hostname), "unexpected keyring service")
		assertSyntheticString(t, "", user, "active slot was not selected for provider write")
		assertLogoutProviderStateUnchanged(t, authCfg, readConfigs, beforeHosts, beforeUsers, beforeActive)
		setCalls++
		switch setCalls {
		case 1:
			assertSyntheticString(t, nextToken, secret, "next credential was not selected for the active slot")
			operations = append(operations, "set-next")
		default:
			assertSyntheticString(t, activeToken, secret, "old credential was not selected for rollback")
			operations = append(operations, "rollback-set")
		}
		return keyring.Set(service, user, secret)
	}
	authCfg.keyringDelete = func(service, user string) error {
		assert.True(t, service == keyringServiceName(hostname), "unexpected keyring service")
		assertLogoutProviderStateUnchanged(t, authCfg, readConfigs, beforeHosts, beforeUsers, beforeActive)
		if user == activeUser {
			operations = append(operations, "delete-departing")
			return errSyntheticLogoutDepartingDeleteDenied
		}
		operations = append(operations, "delete-unexpected")
		return keyring.Delete(service, user)
	}

	err = authCfg.Logout(hostname, activeUser)

	assertSyntheticStringSlice(t, []string{"get-active", "get-next", "get-departing", "set-next", "delete-departing", "rollback-set"}, operations, "provider rollback order changed")
	assertLogoutProviderStateUnchanged(t, authCfg, readConfigs, beforeHosts, beforeUsers, beforeActive)
	authCfg.keyringGet = nil
	authCfg.keyringSet = nil
	authCfg.keyringDelete = nil
	activeSlot, activeSlotErr := keyring.Get(keyringServiceName(hostname), "")
	assert.True(t, activeSlotErr == nil && activeSlot == activeToken, "active credential was not restored after provider failure")
	departingSlot, departingSlotErr := keyring.Get(keyringServiceName(hostname), activeUser)
	assert.True(t, departingSlotErr == nil && departingSlot == activeToken, "departing credential state changed after failed deletion")
	assertLogoutErrorSecretFree(t, err, nextUser, activeUser, nextToken, activeToken)
	requireAutomicVaultCredentialError(t, err, errSyntheticLogoutDepartingDeleteDenied)
}

func TestLogoutPreservesTwoUserConfigWhenProviderRollbackFails(t *testing.T) {
	cfg, readConfigs := NewIsolatedTestConfig(t, "")
	authCfg := cfg.Authentication().(*AuthConfig)
	const hostname = "github.com"
	const nextUser = "synthetic-next-account"
	const nextToken = "synthetic-next-token"
	const activeUser = "synthetic-active-account"
	const activeToken = "synthetic-active-token"
	_, err := authCfg.Login(hostname, nextUser, nextToken, "https", true)
	require.NoError(t, err)
	_, err = authCfg.Login(hostname, activeUser, activeToken, "https", true)
	require.NoError(t, err)

	beforeHosts := snapshotHostsConfig(t, readConfigs)
	beforeUsers := append([]string(nil), authCfg.UsersForHost(hostname)...)
	beforeActive, err := authCfg.ActiveUser(hostname)
	require.NoError(t, err)
	var operations []string
	var setCalls int
	authCfg.keyringGet = func(service, user string) (string, error) {
		assert.True(t, service == keyringServiceName(hostname), "unexpected keyring service")
		assertLogoutProviderStateUnchanged(t, authCfg, readConfigs, beforeHosts, beforeUsers, beforeActive)
		switch user {
		case "":
			operations = append(operations, "get-active")
		case nextUser:
			operations = append(operations, "get-next")
		case activeUser:
			operations = append(operations, "get-departing")
		default:
			operations = append(operations, "get-unexpected")
		}
		return keyring.Get(service, user)
	}
	authCfg.keyringSet = func(service, user, secret string) error {
		assert.True(t, service == keyringServiceName(hostname), "unexpected keyring service")
		assertSyntheticString(t, "", user, "active slot was not selected for provider write")
		assertLogoutProviderStateUnchanged(t, authCfg, readConfigs, beforeHosts, beforeUsers, beforeActive)
		setCalls++
		if setCalls == 1 {
			assertSyntheticString(t, nextToken, secret, "next credential was not selected for the active slot")
			operations = append(operations, "set-next")
			return keyring.Set(service, user, secret)
		}
		assertSyntheticString(t, activeToken, secret, "old credential was not selected for rollback")
		operations = append(operations, "rollback-set")
		return errSyntheticLogoutRollbackDenied
	}
	authCfg.keyringDelete = func(service, user string) error {
		assert.True(t, service == keyringServiceName(hostname), "unexpected keyring service")
		assertLogoutProviderStateUnchanged(t, authCfg, readConfigs, beforeHosts, beforeUsers, beforeActive)
		if user == activeUser {
			operations = append(operations, "delete-departing")
			return errSyntheticLogoutDepartingDeleteDenied
		}
		operations = append(operations, "delete-unexpected")
		return keyring.Delete(service, user)
	}

	err = authCfg.Logout(hostname, activeUser)

	assertSyntheticStringSlice(t, []string{"get-active", "get-next", "get-departing", "set-next", "delete-departing", "rollback-set"}, operations, "provider rollback-failure order changed")
	assertLogoutProviderStateUnchanged(t, authCfg, readConfigs, beforeHosts, beforeUsers, beforeActive)
	assertLogoutErrorSecretFree(t, err, nextUser, activeUser, nextToken, activeToken)
	requireAutomicVaultCredentialErrors(t, err, errSyntheticLogoutDepartingDeleteDenied, errSyntheticLogoutRollbackDenied)
}

func TestLogoutRestoresSingleUserProviderAfterAccountDeleteFails(t *testing.T) {
	cfg, readConfigs := NewIsolatedTestConfig(t, "")
	authCfg := cfg.Authentication().(*AuthConfig)
	const hostname = "github.com"
	const username = "synthetic-account"
	const token = "synthetic-single-token"
	_, err := authCfg.Login(hostname, username, token, "https", true)
	require.NoError(t, err)
	beforeHosts := snapshotHostsConfig(t, readConfigs)
	beforeUsers := append([]string(nil), authCfg.UsersForHost(hostname)...)
	beforeActive, err := authCfg.ActiveUser(hostname)
	require.NoError(t, err)

	var operations []string
	var deleteCalls int
	authCfg.keyringGet = func(service, user string) (string, error) {
		assert.True(t, service == keyringServiceName(hostname), "unexpected keyring service")
		assertLogoutProviderStateUnchanged(t, authCfg, readConfigs, beforeHosts, beforeUsers, beforeActive)
		switch user {
		case "":
			operations = append(operations, "get-active")
		case username:
			operations = append(operations, "get-account")
		default:
			operations = append(operations, "get-unexpected")
		}
		return keyring.Get(service, user)
	}
	authCfg.keyringSet = func(service, user, secret string) error {
		assert.True(t, service == keyringServiceName(hostname), "unexpected keyring service")
		assertSyntheticString(t, "", user, "active slot was not selected for rollback")
		assertSyntheticString(t, token, secret, "original credential was not selected for rollback")
		assertLogoutProviderStateUnchanged(t, authCfg, readConfigs, beforeHosts, beforeUsers, beforeActive)
		operations = append(operations, "rollback-set")
		return keyring.Set(service, user, secret)
	}
	authCfg.keyringDelete = func(service, user string) error {
		assert.True(t, service == keyringServiceName(hostname), "unexpected keyring service")
		assertLogoutProviderStateUnchanged(t, authCfg, readConfigs, beforeHosts, beforeUsers, beforeActive)
		deleteCalls++
		switch deleteCalls {
		case 1:
			assertSyntheticString(t, "", user, "active slot was not deleted first")
			operations = append(operations, "delete-active")
			return keyring.Delete(service, user)
		case 2:
			assertSyntheticString(t, username, user, "account credential was not deleted second")
			operations = append(operations, "delete-account")
			return errSyntheticLogoutDeleteDenied
		default:
			operations = append(operations, "delete-unexpected")
			return errSyntheticLogoutDeleteDenied
		}
	}

	err = authCfg.Logout(hostname, username)

	assertSyntheticStringSlice(t, []string{"get-active", "get-account", "delete-active", "delete-account", "rollback-set"}, operations, "single-user provider rollback order changed")
	assertLogoutProviderStateUnchanged(t, authCfg, readConfigs, beforeHosts, beforeUsers, beforeActive)
	authCfg.keyringGet = nil
	authCfg.keyringSet = nil
	authCfg.keyringDelete = nil
	activeSlot, activeSlotErr := keyring.Get(keyringServiceName(hostname), "")
	assert.True(t, activeSlotErr == nil && activeSlot == token, "active credential was not restored after account deletion failed")
	accountSlot, accountSlotErr := keyring.Get(keyringServiceName(hostname), username)
	assert.True(t, accountSlotErr == nil && accountSlot == token, "account credential changed after account deletion failed")
	assertLogoutErrorSecretFree(t, err, username, token)
	requireAutomicVaultCredentialError(t, err, errSyntheticLogoutDeleteDenied)
}

func TestLogoutPreservesSingleUserConfigWhenProviderRollbackFails(t *testing.T) {
	cfg, readConfigs := NewIsolatedTestConfig(t, "")
	authCfg := cfg.Authentication().(*AuthConfig)
	const hostname = "github.com"
	const username = "synthetic-account"
	const token = "synthetic-single-token"
	_, err := authCfg.Login(hostname, username, token, "https", true)
	require.NoError(t, err)
	beforeHosts := snapshotHostsConfig(t, readConfigs)
	beforeUsers := append([]string(nil), authCfg.UsersForHost(hostname)...)
	beforeActive, err := authCfg.ActiveUser(hostname)
	require.NoError(t, err)

	var operations []string
	var deleteCalls int
	authCfg.keyringGet = func(service, user string) (string, error) {
		assert.True(t, service == keyringServiceName(hostname), "unexpected keyring service")
		assertLogoutProviderStateUnchanged(t, authCfg, readConfigs, beforeHosts, beforeUsers, beforeActive)
		switch user {
		case "":
			operations = append(operations, "get-active")
		case username:
			operations = append(operations, "get-account")
		default:
			operations = append(operations, "get-unexpected")
		}
		return keyring.Get(service, user)
	}
	authCfg.keyringSet = func(service, user, secret string) error {
		assert.True(t, service == keyringServiceName(hostname), "unexpected keyring service")
		assertSyntheticString(t, "", user, "active slot was not selected for rollback")
		assertSyntheticString(t, token, secret, "original credential was not selected for rollback")
		assertLogoutProviderStateUnchanged(t, authCfg, readConfigs, beforeHosts, beforeUsers, beforeActive)
		operations = append(operations, "rollback-set")
		return errSyntheticLogoutRollbackDenied
	}
	authCfg.keyringDelete = func(service, user string) error {
		assert.True(t, service == keyringServiceName(hostname), "unexpected keyring service")
		assertLogoutProviderStateUnchanged(t, authCfg, readConfigs, beforeHosts, beforeUsers, beforeActive)
		deleteCalls++
		switch deleteCalls {
		case 1:
			assertSyntheticString(t, "", user, "active slot was not deleted first")
			operations = append(operations, "delete-active")
			return keyring.Delete(service, user)
		case 2:
			assertSyntheticString(t, username, user, "account credential was not deleted second")
			operations = append(operations, "delete-account")
			return errSyntheticLogoutDeleteDenied
		default:
			operations = append(operations, "delete-unexpected")
			return errSyntheticLogoutDeleteDenied
		}
	}

	err = authCfg.Logout(hostname, username)

	assertSyntheticStringSlice(t, []string{"get-active", "get-account", "delete-active", "delete-account", "rollback-set"}, operations, "single-user rollback-failure order changed")
	assertLogoutProviderStateUnchanged(t, authCfg, readConfigs, beforeHosts, beforeUsers, beforeActive)
	assertLogoutErrorSecretFree(t, err, username, token)
	requireAutomicVaultCredentialErrors(t, err, errSyntheticLogoutDeleteDenied, errSyntheticLogoutRollbackDenied)
}

func TestActivateUserPreservesStateWhenNextAccountKeyringReadFails(t *testing.T) {
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
	var deleteCalls []string
	authCfg.keyringGet = func(service, user string) (string, error) {
		getCalls = append(getCalls, user)
		if user == nextUser {
			return "", errSyntheticLogoutNextGetDenied
		}
		return keyring.Get(service, user)
	}
	authCfg.keyringSet = func(_, user, _ string) error {
		setCalls = append(setCalls, user)
		return nil
	}
	authCfg.keyringDelete = func(_, user string) error {
		deleteCalls = append(deleteCalls, user)
		return nil
	}

	err = authCfg.activateUser(hostname, nextUser)

	afterHosts := snapshotHostsConfig(t, readConfigs)
	assert.True(t, bytes.Equal(beforeHosts, afterHosts), "persisted authentication state changed")
	assertSyntheticStringSlice(t, []string{nextUser}, getCalls, "next-account keyring read sequence changed")
	assertSyntheticStringSlice(t, nil, setCalls, "active-slot keyring write ran after read failure")
	assertSyntheticStringSlice(t, nil, deleteCalls, "active-slot keyring delete ran before read succeeded")
	assertSyntheticStringSlice(t, []string{nextUser, activeUser}, authCfg.UsersForHost(hostname), "account list changed")
	currentUser, currentUserErr := authCfg.ActiveUser(hostname)
	assert.NoError(t, currentUserErr)
	assertSyntheticString(t, activeUser, currentUser, "active account changed")
	if err != nil {
		assert.False(t, strings.Contains(err.Error(), activeUser), "error contains account material")
	}
	requireAutomicVaultCredentialError(t, err, errSyntheticLogoutNextGetDenied)
}

func TestActivateUserPreservesStateWhenNextAccountActiveSlotWriteFails(t *testing.T) {
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
	var deleteCalls []string
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
	authCfg.keyringDelete = func(_, user string) error {
		deleteCalls = append(deleteCalls, user)
		return nil
	}

	err = authCfg.activateUser(hostname, nextUser)

	afterHosts := snapshotHostsConfig(t, readConfigs)
	assert.True(t, bytes.Equal(beforeHosts, afterHosts), "persisted authentication state changed")
	assertSyntheticStringSlice(t, []string{nextUser}, getCalls, "next-account keyring read sequence changed")
	assertSyntheticStringSlice(t, []string{""}, setCalls, "active-slot keyring write sequence changed")
	assertSyntheticStringSlice(t, nil, deleteCalls, "active-slot keyring delete ran before write succeeded")
	if err != nil {
		assert.False(t, strings.Contains(err.Error(), activeUser), "error contains account material")
	}
	requireAutomicVaultCredentialError(t, err, errSyntheticLogoutActiveSetDenied)
}

func TestActivateUserReadsBeforeReplacingActiveSlot(t *testing.T) {
	cfg, _ := NewIsolatedTestConfig(t, "")
	authCfg := cfg.Authentication().(*AuthConfig)
	const hostname = "github.com"
	const activeUser = "synthetic-active-account"
	const nextUser = "synthetic-next-account"
	_, err := authCfg.Login(hostname, nextUser, "synthetic-next-token", "https", true)
	require.NoError(t, err)
	_, err = authCfg.Login(hostname, activeUser, "synthetic-active-token", "https", true)
	require.NoError(t, err)

	var operations []string
	authCfg.keyringGet = func(service, user string) (string, error) {
		operations = append(operations, "get")
		return keyring.Get(service, user)
	}
	authCfg.keyringSet = func(service, user, secret string) error {
		operations = append(operations, "set")
		return keyring.Set(service, user, secret)
	}
	authCfg.keyringDelete = func(_, _ string) error {
		operations = append(operations, "delete")
		return nil
	}

	err = authCfg.activateUser(hostname, nextUser)

	assertSyntheticStringSlice(t, []string{"get", "set"}, operations, "active slot was cleared before the replacement was validated")
	assert.NoError(t, err)
	currentUser, currentUserErr := authCfg.ActiveUser(hostname)
	assert.NoError(t, currentUserErr)
	assertSyntheticString(t, nextUser, currentUser, "next account was not activated")
}
