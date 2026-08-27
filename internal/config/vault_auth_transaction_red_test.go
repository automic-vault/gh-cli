package config

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/cli/cli/v2/internal/keyring"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	errSyntheticSwitchCurrentGetDenied        = errors.New("synthetic Vault current-account read denied")
	errSyntheticSwitchTargetGetDenied         = errors.New("synthetic Vault target-account read denied")
	errSyntheticSwitchTargetSetDenied         = errors.New("synthetic Vault target active-slot write denied")
	errSyntheticSwitchTargetDeleteDenied      = errors.New("synthetic Vault target active-slot delete denied")
	errSyntheticSwitchConfigWriteDenied       = errors.New("synthetic config write denied")
	errSyntheticSwitchRollbackDenied          = errors.New("synthetic Vault switch rollback denied")
	errSyntheticLogoutActiveGetDenied         = errors.New("synthetic Vault active-slot read denied")
	errSyntheticLogoutAccountGetDenied        = errors.New("synthetic Vault account-slot read denied")
	errSyntheticLogoutConfigWriteDenied       = errors.New("synthetic config write denied")
	errSyntheticLogoutActiveRollbackDenied    = errors.New("synthetic Vault active-slot rollback denied")
	errSyntheticLogoutAccountRollbackDenied   = errors.New("synthetic Vault account-slot rollback denied")
	errSyntheticLogoutInactiveRollbackDenied  = errors.New("synthetic Vault inactive-account rollback denied")
	errSyntheticLogoutDepartingRollbackDenied = errors.New("synthetic Vault departing-account rollback denied")
)

type authSwitchFixture struct {
	authCfg      *AuthConfig
	readConfigs  func(io.Writer, io.Writer)
	hostname     string
	activeUser   string
	activeToken  string
	targetUser   string
	targetToken  string
	beforeHosts  []byte
	beforeUsers  []string
	beforeActive string
}

func newSecureAuthSwitchFixture(t *testing.T) *authSwitchFixture {
	t.Helper()
	cfg, readConfigs := NewIsolatedTestConfig(t, "")
	authCfg := cfg.Authentication().(*AuthConfig)
	const hostname = "github.com"
	const targetUser = "synthetic-target-account"
	const targetToken = "synthetic-target-token"
	const activeUser = "synthetic-current-account"
	const activeToken = "synthetic-current-token"
	_, err := authCfg.Login(hostname, targetUser, targetToken, "https", true)
	require.NoError(t, err)
	_, err = authCfg.Login(hostname, activeUser, activeToken, "https", true)
	require.NoError(t, err)

	active, err := authCfg.ActiveUser(hostname)
	require.NoError(t, err)
	return &authSwitchFixture{
		authCfg:      authCfg,
		readConfigs:  readConfigs,
		hostname:     hostname,
		activeUser:   activeUser,
		activeToken:  activeToken,
		targetUser:   targetUser,
		targetToken:  targetToken,
		beforeHosts:  snapshotHostsConfig(t, readConfigs),
		beforeUsers:  append([]string(nil), authCfg.UsersForHost(hostname)...),
		beforeActive: active,
	}
}

func newPlaintextTargetAuthSwitchFixture(t *testing.T) *authSwitchFixture {
	t.Helper()
	cfg, readConfigs := NewIsolatedTestConfig(t, "")
	authCfg := cfg.Authentication().(*AuthConfig)
	const hostname = "github.com"
	const targetUser = "synthetic-plaintext-target-account"
	const targetToken = "synthetic-plaintext-target-token"
	const activeUser = "synthetic-current-account"
	const activeToken = "synthetic-current-token"
	_, err := authCfg.Login(hostname, targetUser, targetToken, "https", false)
	require.NoError(t, err)
	_, err = authCfg.Login(hostname, activeUser, activeToken, "https", true)
	require.NoError(t, err)

	active, err := authCfg.ActiveUser(hostname)
	require.NoError(t, err)
	return &authSwitchFixture{
		authCfg:      authCfg,
		readConfigs:  readConfigs,
		hostname:     hostname,
		activeUser:   activeUser,
		activeToken:  activeToken,
		targetUser:   targetUser,
		targetToken:  targetToken,
		beforeHosts:  snapshotHostsConfig(t, readConfigs),
		beforeUsers:  append([]string(nil), authCfg.UsersForHost(hostname)...),
		beforeActive: active,
	}
}

func (f *authSwitchFixture) assertUnchanged(t *testing.T) {
	t.Helper()
	assertLogoutProviderStateUnchanged(t, f.authCfg, f.readConfigs, f.beforeHosts, f.beforeUsers, f.beforeActive)
}

func TestSwitchUserPropagatesCurrentActiveCredentialError(t *testing.T) {
	f := newSecureAuthSwitchFixture(t)
	var targetGets, sets, deletes int
	f.authCfg.keyringGet = func(service, user string) (string, error) {
		assert.True(t, service == keyringServiceName(f.hostname), "unexpected keyring service")
		switch user {
		case f.activeUser:
			return "synthetic-poison-token", errSyntheticSwitchCurrentGetDenied
		case f.targetUser:
			targetGets++
			return f.targetToken, nil
		default:
			return "", keyring.ErrNotFound
		}
	}
	f.authCfg.keyringSet = func(string, string, string) error {
		sets++
		return nil
	}
	f.authCfg.keyringDelete = func(string, string) error {
		deletes++
		return nil
	}

	err := f.authCfg.SwitchUser(f.hostname, f.targetUser)

	f.assertUnchanged(t)
	assert.Equal(t, 0, targetGets, "target credential lookup ran after current-account failure")
	assert.Equal(t, 0, sets, "provider write ran after current-account failure")
	assert.Equal(t, 0, deletes, "provider delete ran after current-account failure")
	assertLogoutErrorSecretFree(t, err, f.activeUser, f.targetUser, f.activeToken, f.targetToken)
	requireAutomicVaultCredentialError(t, err, errSyntheticSwitchCurrentGetDenied)
}

func TestSwitchUserPropagatesTargetCredentialErrorWithoutRollback(t *testing.T) {
	f := newSecureAuthSwitchFixture(t)
	keyring.MockInitWithError(errSyntheticSwitchRollbackDenied)
	t.Cleanup(keyring.MockInit)
	var sets, deletes int
	f.authCfg.keyringGet = func(service, user string) (string, error) {
		assert.True(t, service == keyringServiceName(f.hostname), "unexpected keyring service")
		switch user {
		case f.activeUser:
			return f.activeToken, nil
		case f.targetUser:
			return "synthetic-poison-token", errSyntheticSwitchTargetGetDenied
		default:
			return "", keyring.ErrNotFound
		}
	}
	f.authCfg.keyringSet = func(string, string, string) error {
		sets++
		return nil
	}
	f.authCfg.keyringDelete = func(string, string) error {
		deletes++
		return nil
	}

	err := f.authCfg.SwitchUser(f.hostname, f.targetUser)

	f.assertUnchanged(t)
	assert.Equal(t, 0, sets, "provider write ran after target credential failure")
	assert.Equal(t, 0, deletes, "provider delete ran after target credential failure")
	assert.False(t, errors.Is(err, errSyntheticSwitchRollbackDenied), "target credential failure triggered an uninstrumented provider rollback")
	assertLogoutErrorSecretFree(t, err, f.activeUser, f.targetUser, f.activeToken, f.targetToken)
	requireAutomicVaultCredentialError(t, err, errSyntheticSwitchTargetGetDenied)
}

func TestSwitchUserTargetActiveSlotSetFailureDoesNotRollbackAgain(t *testing.T) {
	f := newSecureAuthSwitchFixture(t)
	keyring.MockInitWithError(errSyntheticSwitchRollbackDenied)
	t.Cleanup(keyring.MockInit)
	var setUsers []string
	var deletes int
	f.authCfg.keyringGet = func(service, user string) (string, error) {
		assert.True(t, service == keyringServiceName(f.hostname), "unexpected keyring service")
		switch user {
		case f.activeUser:
			return f.activeToken, nil
		case f.targetUser:
			return f.targetToken, nil
		default:
			return "", keyring.ErrNotFound
		}
	}
	f.authCfg.keyringSet = func(service, user, secret string) error {
		assert.True(t, service == keyringServiceName(f.hostname), "unexpected keyring service")
		assert.True(t, user == "" && secret == f.targetToken, "unexpected target active-slot write")
		setUsers = append(setUsers, user)
		return errSyntheticSwitchTargetSetDenied
	}
	f.authCfg.keyringDelete = func(string, string) error {
		deletes++
		return nil
	}

	err := f.authCfg.SwitchUser(f.hostname, f.targetUser)

	f.assertUnchanged(t)
	assert.Equal(t, 1, len(setUsers), "target active-slot failure triggered a redundant provider write")
	assert.Equal(t, 0, deletes, "target active-slot failure triggered a provider delete")
	assert.False(t, errors.Is(err, errSyntheticSwitchRollbackDenied), "target active-slot failure triggered an uninstrumented provider rollback")
	assertLogoutErrorSecretFree(t, err, f.activeUser, f.targetUser, f.activeToken, f.targetToken)
	requireAutomicVaultCredentialError(t, err, errSyntheticSwitchTargetSetDenied)
}

func TestSwitchUserPlaintextTargetDeleteFailurePreservesState(t *testing.T) {
	f := newPlaintextTargetAuthSwitchFixture(t)
	keyring.MockInitWithError(errSyntheticSwitchRollbackDenied)
	t.Cleanup(keyring.MockInit)
	var deletes []string
	var sets int
	f.authCfg.keyringGet = func(service, user string) (string, error) {
		assert.True(t, service == keyringServiceName(f.hostname), "unexpected keyring service")
		switch user {
		case f.activeUser:
			return f.activeToken, nil
		case f.targetUser:
			return "", keyring.ErrNotFound
		default:
			return "", keyring.ErrNotFound
		}
	}
	f.authCfg.keyringSet = func(string, string, string) error {
		sets++
		return nil
	}
	f.authCfg.keyringDelete = func(service, user string) error {
		assert.True(t, service == keyringServiceName(f.hostname), "unexpected keyring service")
		deletes = append(deletes, user)
		return errSyntheticSwitchTargetDeleteDenied
	}

	err := f.authCfg.SwitchUser(f.hostname, f.targetUser)

	f.assertUnchanged(t)
	assert.True(t, len(deletes) == 1 && deletes[0] == "", "plaintext target did not attempt exactly one active-slot delete")
	assert.Equal(t, 0, sets, "plaintext target delete failure triggered an active-slot write")
	assert.False(t, errors.Is(err, errSyntheticSwitchRollbackDenied), "plaintext target delete failure triggered an uninstrumented provider rollback")
	assertLogoutErrorSecretFree(t, err, f.activeUser, f.targetUser, f.activeToken, f.targetToken)
	requireAutomicVaultCredentialError(t, err, errSyntheticSwitchTargetDeleteDenied)
}

func TestSwitchUserConfigWriteFailureRollsProviderAndConfigBack(t *testing.T) {
	f := newSecureAuthSwitchFixture(t)
	f.authCfg.configWrite = func() error {
		return errSyntheticSwitchConfigWriteDenied
	}
	var setSecrets []string
	var deletes int
	f.authCfg.keyringGet = func(service, user string) (string, error) {
		assert.True(t, service == keyringServiceName(f.hostname), "unexpected keyring service")
		switch user {
		case f.activeUser:
			return f.activeToken, nil
		case f.targetUser:
			return f.targetToken, nil
		default:
			return "", keyring.ErrNotFound
		}
	}
	f.authCfg.keyringSet = func(service, user, secret string) error {
		assert.True(t, service == keyringServiceName(f.hostname), "unexpected keyring service")
		assert.True(t, user == "", "unexpected active-slot owner")
		setSecrets = append(setSecrets, secret)
		return keyring.Set(service, user, secret)
	}
	f.authCfg.keyringDelete = func(string, string) error {
		deletes++
		return nil
	}

	err := f.authCfg.SwitchUser(f.hostname, f.targetUser)

	f.assertUnchanged(t)
	assert.Equal(t, 0, deletes, "secure switch used delete while restoring after config failure")
	assert.True(t, len(setSecrets) == 2 && setSecrets[0] == f.targetToken && setSecrets[1] == f.activeToken, "provider rollback did not use the original active credential")
	f.authCfg.keyringGet = nil
	f.authCfg.keyringSet = nil
	f.authCfg.keyringDelete = nil
	activeSlot, activeSlotErr := keyring.Get(keyringServiceName(f.hostname), "")
	assert.True(t, activeSlotErr == nil && activeSlot == f.activeToken, "active provider credential was not restored")
	assertLogoutErrorSecretFree(t, err, f.activeUser, f.targetUser, f.activeToken, f.targetToken)
	assert.ErrorIs(t, err, errSyntheticSwitchConfigWriteDenied)
}

func TestSwitchUserConfigWriteAndRollbackFailuresRemainClassified(t *testing.T) {
	f := newSecureAuthSwitchFixture(t)
	f.authCfg.configWrite = func() error {
		return errSyntheticSwitchConfigWriteDenied
	}
	var setCalls int
	f.authCfg.keyringGet = func(service, user string) (string, error) {
		assert.True(t, service == keyringServiceName(f.hostname), "unexpected keyring service")
		switch user {
		case f.activeUser:
			return f.activeToken, nil
		case f.targetUser:
			return f.targetToken, nil
		default:
			return "", keyring.ErrNotFound
		}
	}
	f.authCfg.keyringSet = func(service, user, secret string) error {
		assert.True(t, service == keyringServiceName(f.hostname), "unexpected keyring service")
		assert.True(t, user == "", "unexpected active-slot owner")
		setCalls++
		if setCalls == 1 {
			assert.True(t, secret == f.targetToken, "unexpected target credential")
			return keyring.Set(service, user, secret)
		}
		assert.True(t, secret == f.activeToken, "unexpected rollback credential")
		return errSyntheticSwitchRollbackDenied
	}

	err := f.authCfg.SwitchUser(f.hostname, f.targetUser)

	f.assertUnchanged(t)
	assert.Equal(t, 2, setCalls, "provider rollback was not attempted exactly once")
	assertLogoutErrorSecretFree(t, err, f.activeUser, f.targetUser, f.activeToken, f.targetToken)
	requireAutomicVaultCredentialErrors(t, err, errSyntheticSwitchConfigWriteDenied, errSyntheticSwitchRollbackDenied)
}

func TestLogoutFailsBeforeMutationWhenActiveCredentialReadFails(t *testing.T) {
	cfg, readConfigs := NewIsolatedTestConfig(t, "")
	authCfg := cfg.Authentication().(*AuthConfig)
	const hostname = "github.com"
	const username = "synthetic-logout-account"
	const token = "synthetic-logout-token"
	_, err := authCfg.Login(hostname, username, token, "https", true)
	require.NoError(t, err)
	beforeHosts := snapshotHostsConfig(t, readConfigs)
	beforeUsers := append([]string(nil), authCfg.UsersForHost(hostname)...)
	beforeActive, err := authCfg.ActiveUser(hostname)
	require.NoError(t, err)
	var deletes int
	authCfg.keyringGet = func(service, user string) (string, error) {
		assert.True(t, service == keyringServiceName(hostname), "unexpected keyring service")
		if user == "" {
			return "synthetic-poison-token", errSyntheticLogoutActiveGetDenied
		}
		return token, nil
	}
	authCfg.keyringDelete = func(string, string) error {
		deletes++
		return nil
	}

	err = authCfg.Logout(hostname, username)

	assert.True(t, bytes.Equal(beforeHosts, snapshotHostsConfig(t, readConfigs)), "persisted authentication state changed after active read failure")
	assertSyntheticStringSlice(t, beforeUsers, authCfg.UsersForHost(hostname), "account list changed after active read failure")
	currentUser, currentUserErr := authCfg.ActiveUser(hostname)
	assert.NoError(t, currentUserErr)
	assertSyntheticString(t, beforeActive, currentUser, "active account changed after active read failure")
	assert.Equal(t, 0, deletes, "provider deletion ran after active read failure")
	assertLogoutErrorSecretFree(t, err, username, token)
	requireAutomicVaultCredentialError(t, err, errSyntheticLogoutActiveGetDenied)
}

func TestLogoutFailsBeforeMutationWhenAccountCredentialReadFails(t *testing.T) {
	cfg, readConfigs := NewIsolatedTestConfig(t, "")
	authCfg := cfg.Authentication().(*AuthConfig)
	const hostname = "github.com"
	const username = "synthetic-logout-account"
	const token = "synthetic-logout-token"
	_, err := authCfg.Login(hostname, username, token, "https", true)
	require.NoError(t, err)
	beforeHosts := snapshotHostsConfig(t, readConfigs)
	beforeUsers := append([]string(nil), authCfg.UsersForHost(hostname)...)
	beforeActive, err := authCfg.ActiveUser(hostname)
	require.NoError(t, err)
	var deletes int
	authCfg.keyringGet = func(service, user string) (string, error) {
		assert.True(t, service == keyringServiceName(hostname), "unexpected keyring service")
		if user == "" {
			return token, nil
		}
		return "synthetic-poison-token", errSyntheticLogoutAccountGetDenied
	}
	authCfg.keyringDelete = func(string, string) error {
		deletes++
		return nil
	}

	err = authCfg.Logout(hostname, username)

	assert.True(t, bytes.Equal(beforeHosts, snapshotHostsConfig(t, readConfigs)), "persisted authentication state changed after account read failure")
	assertSyntheticStringSlice(t, beforeUsers, authCfg.UsersForHost(hostname), "account list changed after account read failure")
	currentUser, currentUserErr := authCfg.ActiveUser(hostname)
	assert.NoError(t, currentUserErr)
	assertSyntheticString(t, beforeActive, currentUser, "active account changed after account read failure")
	assert.Equal(t, 0, deletes, "provider deletion ran after account read failure")
	assertLogoutErrorSecretFree(t, err, username, token)
	requireAutomicVaultCredentialError(t, err, errSyntheticLogoutAccountGetDenied)
}

func TestLogoutWithAbsentPreviousActiveSlotRollsBackWithNotFound(t *testing.T) {
	f := newSecureAuthSwitchFixture(t)
	service := keyringServiceName(f.hostname)
	require.NoError(t, keyring.Delete(service, ""))
	var operations []string
	f.authCfg.keyringGet = func(service, user string) (string, error) {
		assert.True(t, service == keyringServiceName(f.hostname), "unexpected keyring service")
		f.assertUnchanged(t)
		switch user {
		case "":
			operations = append(operations, "get-active-absent")
			return "", keyring.ErrNotFound
		case f.targetUser:
			operations = append(operations, "get-next")
			return f.targetToken, nil
		default:
			return "", keyring.ErrNotFound
		}
	}
	f.authCfg.keyringSet = func(service, user, secret string) error {
		assert.True(t, service == keyringServiceName(f.hostname), "unexpected keyring service")
		assert.True(t, user == "" && secret == f.targetToken, "unexpected replacement credential")
		f.assertUnchanged(t)
		operations = append(operations, "set-next")
		return keyring.Set(service, user, secret)
	}
	f.authCfg.keyringDelete = func(service, user string) error {
		assert.True(t, service == keyringServiceName(f.hostname), "unexpected keyring service")
		f.assertUnchanged(t)
		switch user {
		case f.activeUser:
			operations = append(operations, "delete-departing")
			return errSyntheticLogoutDepartingDeleteDenied
		case "":
			operations = append(operations, "rollback-delete-absent")
			if deleteErr := keyring.Delete(service, user); deleteErr != nil {
				return deleteErr
			}
			return keyring.ErrNotFound
		default:
			return keyring.ErrNotFound
		}
	}

	err := f.authCfg.Logout(f.hostname, f.activeUser)

	assertSyntheticStringSlice(t, []string{"get-active-absent", "get-next", "set-next", "delete-departing", "rollback-delete-absent"}, operations, "absent-active rollback order changed")
	f.assertUnchanged(t)
	f.authCfg.keyringGet = nil
	f.authCfg.keyringSet = nil
	f.authCfg.keyringDelete = nil
	_, activeSlotErr := keyring.Get(service, "")
	assert.True(t, errors.Is(activeSlotErr, keyring.ErrNotFound), "rollback did not leave an originally absent active slot absent")
	assertLogoutErrorSecretFree(t, err, f.activeUser, f.targetUser, f.activeToken, f.targetToken)
	requireAutomicVaultCredentialError(t, err, errSyntheticLogoutDepartingDeleteDenied)
}

func TestLogoutWithAbsentPreviousActiveSlotJoinsRollbackDeleteFailure(t *testing.T) {
	f := newSecureAuthSwitchFixture(t)
	service := keyringServiceName(f.hostname)
	require.NoError(t, keyring.Delete(service, ""))
	var operations []string
	f.authCfg.keyringGet = func(service, user string) (string, error) {
		assert.True(t, service == keyringServiceName(f.hostname), "unexpected keyring service")
		f.assertUnchanged(t)
		switch user {
		case "":
			operations = append(operations, "get-active-absent")
			return "", keyring.ErrNotFound
		case f.targetUser:
			operations = append(operations, "get-next")
			return f.targetToken, nil
		default:
			return "", keyring.ErrNotFound
		}
	}
	f.authCfg.keyringSet = func(service, user, secret string) error {
		assert.True(t, service == keyringServiceName(f.hostname), "unexpected keyring service")
		assert.True(t, user == "" && secret == f.targetToken, "unexpected replacement credential")
		f.assertUnchanged(t)
		operations = append(operations, "set-next")
		return keyring.Set(service, user, secret)
	}
	f.authCfg.keyringDelete = func(service, user string) error {
		assert.True(t, service == keyringServiceName(f.hostname), "unexpected keyring service")
		f.assertUnchanged(t)
		switch user {
		case f.activeUser:
			operations = append(operations, "delete-departing")
			return errSyntheticLogoutDepartingDeleteDenied
		case "":
			operations = append(operations, "rollback-delete-failed")
			return errSyntheticLogoutRollbackDenied
		default:
			return keyring.ErrNotFound
		}
	}

	err := f.authCfg.Logout(f.hostname, f.activeUser)

	assertSyntheticStringSlice(t, []string{"get-active-absent", "get-next", "set-next", "delete-departing", "rollback-delete-failed"}, operations, "absent-active rollback failure order changed")
	f.assertUnchanged(t)
	assertLogoutErrorSecretFree(t, err, f.activeUser, f.targetUser, f.activeToken, f.targetToken)
	requireAutomicVaultCredentialErrors(t, err, errSyntheticLogoutDepartingDeleteDenied, errSyntheticLogoutRollbackDenied)
}

func TestLogoutSingleUserConfigWriteFailureRestoresProviderAndConfig(t *testing.T) {
	cfg, readConfigs := NewIsolatedTestConfig(t, "")
	authCfg := cfg.Authentication().(*AuthConfig)
	const hostname = "github.com"
	const username = "synthetic-single-write-account"
	const token = "synthetic-single-write-token"
	_, err := authCfg.Login(hostname, username, token, "https", true)
	require.NoError(t, err)

	beforeHosts := snapshotHostsConfig(t, readConfigs)
	beforeUsers := append([]string(nil), authCfg.UsersForHost(hostname)...)
	beforeActive, err := authCfg.ActiveUser(hostname)
	require.NoError(t, err)
	authCfg.configWrite = func() error {
		return errSyntheticLogoutConfigWriteDenied
	}
	var operations []string
	authCfg.keyringGet = func(service, user string) (string, error) {
		assert.True(t, service == keyringServiceName(hostname), "unexpected keyring service")
		assertLogoutProviderStateUnchanged(t, authCfg, readConfigs, beforeHosts, beforeUsers, beforeActive)
		return keyring.Get(service, user)
	}
	authCfg.keyringDelete = func(service, user string) error {
		assert.True(t, service == keyringServiceName(hostname), "unexpected keyring service")
		assertLogoutProviderStateUnchanged(t, authCfg, readConfigs, beforeHosts, beforeUsers, beforeActive)
		operations = append(operations, "delete-"+user)
		return keyring.Delete(service, user)
	}
	authCfg.keyringSet = func(service, user, secret string) error {
		assert.True(t, service == keyringServiceName(hostname), "unexpected keyring service")
		assert.True(t, (user == "" || user == username) && secret == token, "rollback used an unexpected provider value")
		operations = append(operations, "restore-"+user)
		return keyring.Set(service, user, secret)
	}

	err = authCfg.Logout(hostname, username)

	// The local write is the commit point. A failed write must leave both the
	// persisted/in-memory config and every provider slot at their prior state.
	assertSyntheticStringSlice(t, []string{"delete-", "delete-" + username, "restore-", "restore-" + username}, operations, "single-user provider transaction did not restore after config failure")
	assert.True(t, bytes.Equal(beforeHosts, snapshotHostsConfig(t, readConfigs)), "persisted authentication state changed after config write failure")
	assertSyntheticStringSlice(t, beforeUsers, authCfg.UsersForHost(hostname), "account list changed after config write failure")
	currentUser, currentUserErr := authCfg.ActiveUser(hostname)
	assert.NoError(t, currentUserErr)
	assertSyntheticString(t, beforeActive, currentUser, "active account changed after config write failure")
	authCfg.keyringGet = nil
	authCfg.keyringSet = nil
	authCfg.keyringDelete = nil
	activeSlot, activeSlotErr := keyring.Get(keyringServiceName(hostname), "")
	assert.True(t, activeSlotErr == nil && activeSlot == token, "active provider credential was not restored after config write failure")
	accountSlot, accountSlotErr := keyring.Get(keyringServiceName(hostname), username)
	assert.True(t, accountSlotErr == nil && accountSlot == token, "account provider credential was not restored after config write failure")
	assertLogoutErrorSecretFree(t, err, username, token)
	require.Same(t, errSyntheticLogoutConfigWriteDenied, err)
	assert.ErrorIs(t, err, errSyntheticLogoutConfigWriteDenied)
	var resolutionErr *AutomicVaultCredentialResolutionError
	assert.False(t, errors.As(err, &resolutionErr), "a pure config write failure must not be mislabeled as a Vault failure")
}

func TestLogoutSingleUserConfigWriteAndRollbackFailuresRemainClassified(t *testing.T) {
	cfg, readConfigs := NewIsolatedTestConfig(t, "")
	authCfg := cfg.Authentication().(*AuthConfig)
	const hostname = "github.com"
	const username = "synthetic-single-rollback-account"
	const token = "synthetic-single-rollback-token"
	_, err := authCfg.Login(hostname, username, token, "https", true)
	require.NoError(t, err)

	beforeHosts := snapshotHostsConfig(t, readConfigs)
	beforeUsers := append([]string(nil), authCfg.UsersForHost(hostname)...)
	beforeActive, err := authCfg.ActiveUser(hostname)
	require.NoError(t, err)
	authCfg.configWrite = func() error {
		return errSyntheticLogoutConfigWriteDenied
	}
	var deleteCalls int
	var restoreUsers []string
	authCfg.keyringGet = func(service, user string) (string, error) {
		assert.True(t, service == keyringServiceName(hostname), "unexpected keyring service")
		assertLogoutProviderStateUnchanged(t, authCfg, readConfigs, beforeHosts, beforeUsers, beforeActive)
		return keyring.Get(service, user)
	}
	authCfg.keyringDelete = func(service, user string) error {
		assert.True(t, service == keyringServiceName(hostname), "unexpected keyring service")
		assertLogoutProviderStateUnchanged(t, authCfg, readConfigs, beforeHosts, beforeUsers, beforeActive)
		deleteCalls++
		return keyring.Delete(service, user)
	}
	authCfg.keyringSet = func(service, user, secret string) error {
		assert.True(t, service == keyringServiceName(hostname), "unexpected keyring service")
		assert.True(t, (user == "" || user == username) && secret == token, "rollback used an unexpected provider value")
		restoreUsers = append(restoreUsers, user)
		switch user {
		case "":
			return errSyntheticLogoutActiveRollbackDenied
		case username:
			return errSyntheticLogoutAccountRollbackDenied
		default:
			return errSyntheticLogoutAccountRollbackDenied
		}
	}

	err = authCfg.Logout(hostname, username)

	assert.Equal(t, 2, deleteCalls, "single-user config failure did not complete the provider delete sequence")
	assert.True(t, len(restoreUsers) == 2 && restoreUsers[0] == "" && restoreUsers[1] == username, "single-user rollback stopped after the first failed slot restoration")
	assert.True(t, bytes.Equal(beforeHosts, snapshotHostsConfig(t, readConfigs)), "persisted authentication state changed despite rollback failure")
	assertSyntheticStringSlice(t, beforeUsers, authCfg.UsersForHost(hostname), "account list changed despite rollback failure")
	currentUser, currentUserErr := authCfg.ActiveUser(hostname)
	assert.NoError(t, currentUserErr)
	assertSyntheticString(t, beforeActive, currentUser, "active account changed despite rollback failure")
	assertLogoutErrorSecretFree(t, err, username, token)
	requireAutomicVaultCredentialErrors(t, err, errSyntheticLogoutConfigWriteDenied, errSyntheticLogoutActiveRollbackDenied, errSyntheticLogoutAccountRollbackDenied)
}

func TestLogoutInactiveUserConfigWriteFailureRestoresProviderAndConfig(t *testing.T) {
	f := newSecureAuthSwitchFixture(t)
	f.authCfg.configWrite = func() error {
		return errSyntheticLogoutConfigWriteDenied
	}
	var deletes, restores []string
	f.authCfg.keyringDelete = func(service, user string) error {
		assert.True(t, service == keyringServiceName(f.hostname), "unexpected keyring service")
		f.assertUnchanged(t)
		deletes = append(deletes, user)
		return keyring.Delete(service, user)
	}
	f.authCfg.keyringSet = func(service, user, secret string) error {
		assert.True(t, service == keyringServiceName(f.hostname), "unexpected keyring service")
		assert.True(t, user == f.targetUser && secret == f.targetToken, "inactive rollback used an unexpected provider value")
		restores = append(restores, user)
		return keyring.Set(service, user, secret)
	}

	err := f.authCfg.Logout(f.hostname, f.targetUser)

	assertSyntheticStringSlice(t, []string{f.targetUser}, deletes, "inactive account delete sequence changed")
	assertSyntheticStringSlice(t, []string{f.targetUser}, restores, "inactive account rollback was not attempted")
	f.assertUnchanged(t)
	f.authCfg.keyringGet = nil
	f.authCfg.keyringSet = nil
	f.authCfg.keyringDelete = nil
	inactiveSlot, inactiveSlotErr := keyring.Get(keyringServiceName(f.hostname), f.targetUser)
	assert.True(t, inactiveSlotErr == nil && inactiveSlot == f.targetToken, "inactive provider credential was not restored after config write failure")
	assertLogoutErrorSecretFree(t, err, f.activeUser, f.targetUser, f.activeToken, f.targetToken)
	require.Same(t, errSyntheticLogoutConfigWriteDenied, err)
	assert.ErrorIs(t, err, errSyntheticLogoutConfigWriteDenied)
	var resolutionErr *AutomicVaultCredentialResolutionError
	assert.False(t, errors.As(err, &resolutionErr), "a pure config write failure must not be mislabeled as a Vault failure")
}

func TestLogoutInactiveUserConfigWriteAndRollbackFailureRemainClassified(t *testing.T) {
	f := newSecureAuthSwitchFixture(t)
	f.authCfg.configWrite = func() error {
		return errSyntheticLogoutConfigWriteDenied
	}
	var deletes, restores []string
	f.authCfg.keyringDelete = func(service, user string) error {
		assert.True(t, service == keyringServiceName(f.hostname), "unexpected keyring service")
		f.assertUnchanged(t)
		deletes = append(deletes, user)
		return keyring.Delete(service, user)
	}
	f.authCfg.keyringSet = func(service, user, secret string) error {
		assert.True(t, service == keyringServiceName(f.hostname), "unexpected keyring service")
		assert.True(t, user == f.targetUser && secret == f.targetToken, "inactive rollback used an unexpected provider value")
		restores = append(restores, user)
		return errSyntheticLogoutInactiveRollbackDenied
	}

	err := f.authCfg.Logout(f.hostname, f.targetUser)

	assertSyntheticStringSlice(t, []string{f.targetUser}, deletes, "inactive account delete sequence changed")
	assertSyntheticStringSlice(t, []string{f.targetUser}, restores, "inactive account rollback was not attempted")
	f.assertUnchanged(t)
	assertLogoutErrorSecretFree(t, err, f.activeUser, f.targetUser, f.activeToken, f.targetToken)
	requireAutomicVaultCredentialErrors(t, err, errSyntheticLogoutConfigWriteDenied, errSyntheticLogoutInactiveRollbackDenied)
}

func TestLogoutActiveUserConfigWriteFailureRestoresTwoUserProviderAndConfig(t *testing.T) {
	f := newSecureAuthSwitchFixture(t)
	f.authCfg.configWrite = func() error {
		return errSyntheticLogoutConfigWriteDenied
	}
	var setUsers, setSecrets, deletes []string
	f.authCfg.keyringGet = func(service, user string) (string, error) {
		assert.True(t, service == keyringServiceName(f.hostname), "unexpected keyring service")
		f.assertUnchanged(t)
		return keyring.Get(service, user)
	}
	f.authCfg.keyringSet = func(service, user, secret string) error {
		assert.True(t, service == keyringServiceName(f.hostname), "unexpected keyring service")
		setUsers = append(setUsers, user)
		setSecrets = append(setSecrets, secret)
		return keyring.Set(service, user, secret)
	}
	f.authCfg.keyringDelete = func(service, user string) error {
		assert.True(t, service == keyringServiceName(f.hostname), "unexpected keyring service")
		f.assertUnchanged(t)
		deletes = append(deletes, user)
		return keyring.Delete(service, user)
	}

	err := f.authCfg.Logout(f.hostname, f.activeUser)

	assert.Equal(t, []string{"", "", f.activeUser}, setUsers, "active two-user rollback did not restore active and departing slots")
	assert.True(t, len(setSecrets) == 3 && setSecrets[0] == f.targetToken && setSecrets[1] == f.activeToken && setSecrets[2] == f.activeToken, "active two-user rollback used unexpected provider credentials")
	assertSyntheticStringSlice(t, []string{f.activeUser}, deletes, "active two-user delete sequence changed")
	f.assertUnchanged(t)
	f.authCfg.keyringGet = nil
	f.authCfg.keyringSet = nil
	f.authCfg.keyringDelete = nil
	activeSlot, activeSlotErr := keyring.Get(keyringServiceName(f.hostname), "")
	assert.True(t, activeSlotErr == nil && activeSlot == f.activeToken, "active provider credential was not restored after config write failure")
	departingSlot, departingSlotErr := keyring.Get(keyringServiceName(f.hostname), f.activeUser)
	assert.True(t, departingSlotErr == nil && departingSlot == f.activeToken, "departing provider credential was not restored after config write failure")
	assertLogoutErrorSecretFree(t, err, f.activeUser, f.targetUser, f.activeToken, f.targetToken)
	require.Same(t, errSyntheticLogoutConfigWriteDenied, err)
	assert.ErrorIs(t, err, errSyntheticLogoutConfigWriteDenied)
	var resolutionErr *AutomicVaultCredentialResolutionError
	assert.False(t, errors.As(err, &resolutionErr), "a pure config write failure must not be mislabeled as a Vault failure")
}

func TestLogoutActiveUserConfigWriteAndRollbackFailuresRemainClassified(t *testing.T) {
	f := newSecureAuthSwitchFixture(t)
	f.authCfg.configWrite = func() error {
		return errSyntheticLogoutConfigWriteDenied
	}
	var setUsers, setSecrets, deletes []string
	f.authCfg.keyringGet = func(service, user string) (string, error) {
		assert.True(t, service == keyringServiceName(f.hostname), "unexpected keyring service")
		f.assertUnchanged(t)
		return keyring.Get(service, user)
	}
	f.authCfg.keyringSet = func(service, user, secret string) error {
		assert.True(t, service == keyringServiceName(f.hostname), "unexpected keyring service")
		setUsers = append(setUsers, user)
		setSecrets = append(setSecrets, secret)
		switch len(setUsers) {
		case 1:
			assert.True(t, user == "" && secret == f.targetToken, "active replacement used an unexpected provider value")
			return keyring.Set(service, user, secret)
		case 2:
			assert.True(t, user == "" && secret == f.activeToken, "active rollback used an unexpected provider value")
			return errSyntheticLogoutActiveRollbackDenied
		case 3:
			assert.True(t, user == f.activeUser && secret == f.activeToken, "departing rollback used an unexpected provider value")
			return errSyntheticLogoutDepartingRollbackDenied
		default:
			return errSyntheticLogoutDepartingRollbackDenied
		}
	}
	f.authCfg.keyringDelete = func(service, user string) error {
		assert.True(t, service == keyringServiceName(f.hostname), "unexpected keyring service")
		f.assertUnchanged(t)
		deletes = append(deletes, user)
		return keyring.Delete(service, user)
	}

	err := f.authCfg.Logout(f.hostname, f.activeUser)

	assert.True(t, len(setUsers) == 3 && setUsers[0] == "" && setUsers[1] == "" && setUsers[2] == f.activeUser, "active rollback did not attempt every mutated provider slot")
	assert.True(t, len(setSecrets) == 3 && setSecrets[0] == f.targetToken && setSecrets[1] == f.activeToken && setSecrets[2] == f.activeToken, "active rollback used unexpected provider credentials")
	assertSyntheticStringSlice(t, []string{f.activeUser}, deletes, "active two-user delete sequence changed")
	f.assertUnchanged(t)
	assertLogoutErrorSecretFree(t, err, f.activeUser, f.targetUser, f.activeToken, f.targetToken)
	requireAutomicVaultCredentialErrors(t, err, errSyntheticLogoutConfigWriteDenied, errSyntheticLogoutActiveRollbackDenied, errSyntheticLogoutDepartingRollbackDenied)
}
