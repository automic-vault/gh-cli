package config

import (
	"bytes"
	"errors"
	"io"
	"maps"
	"testing"

	"github.com/cli/cli/v2/internal/keyring"
	ghConfig "github.com/cli/go-gh/v2/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	errSyntheticFollowupInitialRepairWrite = errors.New("synthetic local initial config write denied")
	errSyntheticFollowupRepairWrite        = errors.New("synthetic local repair config write denied")
	errSyntheticFollowupRepairRollback     = errors.New("synthetic Vault repair rollback denied")
	errSyntheticFollowupDepartingRollback  = errors.New("synthetic Vault departing repair rollback denied")
	errSyntheticFollowupHostwideGet        = errors.New("synthetic Vault host-wide active read denied")
	errSyntheticFollowupDriftWrite         = errors.New("synthetic local drift config write denied")
	errSyntheticFollowupAbsentWrite        = errors.New("synthetic local absent config write denied")
	errSyntheticFollowupTargetGet          = errors.New("synthetic Vault target read denied in multi-host fixture")
	errSyntheticFollowupTargetSet          = errors.New("synthetic Vault target active-slot write denied in multi-host fixture")
	errSyntheticFollowupTargetDelete       = errors.New("synthetic Vault target active-slot delete denied in multi-host fixture")
	errSyntheticFollowupMultiHostWrite     = errors.New("synthetic local multi-host config write denied")
)

type followupProvider struct {
	values    map[string]string
	getErrors map[string]error
	setErrors map[string]error
	delErrors map[string]error
}

func newFollowupProvider() *followupProvider {
	return &followupProvider{
		values:    map[string]string{},
		getErrors: map[string]error{},
		setErrors: map[string]error{},
		delErrors: map[string]error{},
	}
}

func followupProviderKey(service, user string) string {
	return service + "\x00" + user
}

func (p *followupProvider) get(service, user string) (string, error) {
	if err := p.getErrors[followupProviderKey(service, user)]; err != nil {
		return "", err
	}
	token, ok := p.values[followupProviderKey(service, user)]
	if !ok {
		return "", keyring.ErrNotFound
	}
	return token, nil
}

func (p *followupProvider) set(service, user, token string) error {
	if err := p.setErrors[followupProviderKey(service, user)]; err != nil {
		return err
	}
	p.values[followupProviderKey(service, user)] = token
	return nil
}

func (p *followupProvider) delete(service, user string) error {
	if err := p.delErrors[followupProviderKey(service, user)]; err != nil {
		return err
	}
	key := followupProviderKey(service, user)
	if _, ok := p.values[key]; !ok {
		return keyring.ErrNotFound
	}
	delete(p.values, key)
	return nil
}

func setupFollowupMultiHostConfig(t *testing.T, targetPlaintext bool) (*AuthConfig, func(io.Writer, io.Writer), *followupProvider) {
	t.Helper()
	isolated, readConfigs := NewIsolatedTestConfig(t, "")
	authCfg := isolated.Authentication().(*AuthConfig)
	const switchedHost = "github.com"
	const activeUser = "synthetic-followup-active-account"
	const targetUser = "synthetic-followup-target-account"

	// Insert the switched host between two unrelated hosts so a subtree
	// remove-and-recreate can be observed as a host-order change.
	for _, host := range []string{"alpha.example", switchedHost, "zulu.example"} {
		isolated.cfg.Set([]string{hostsKey, host, userKey}, "synthetic-unrelated-account")
		isolated.cfg.Set([]string{hostsKey, host, usersKey, "synthetic-unrelated-account"}, "")
	}
	isolated.cfg.Set([]string{hostsKey, switchedHost, userKey}, activeUser)
	isolated.cfg.Set([]string{hostsKey, switchedHost, usersKey, activeUser}, "")
	isolated.cfg.Set([]string{hostsKey, switchedHost, usersKey, targetUser}, "")
	if targetPlaintext {
		isolated.cfg.Set([]string{hostsKey, switchedHost, usersKey, targetUser, oauthTokenKey}, "synthetic-followup-target-token")
	}
	require.NoError(t, isolated.Write())

	provider := newFollowupProvider()
	service := keyringServiceName(switchedHost)
	provider.values[followupProviderKey(service, activeUser)] = "synthetic-followup-account-token"
	if !targetPlaintext {
		provider.values[followupProviderKey(service, targetUser)] = "synthetic-followup-target-token"
	}
	authCfg.keyringGet = provider.get
	authCfg.keyringSet = provider.set
	authCfg.keyringDelete = provider.delete
	return authCfg, readConfigs, provider
}

func assertFollowupHostsUnchanged(t *testing.T, authCfg *AuthConfig, readConfigs func(io.Writer, io.Writer), beforeKeys []string, beforeBytes []byte) {
	t.Helper()
	afterKeys, err := authCfg.cfg.Keys([]string{hostsKey})
	require.NoError(t, err)
	assert.Equal(t, beforeKeys, afterKeys, "host key order changed")
	assert.True(t, bytes.Equal(beforeBytes, snapshotHostsConfig(t, readConfigs)), "serialized hosts state changed")
}

func assertFollowupSerializedHostsUnchanged(t *testing.T, authCfg *AuthConfig, readConfigs func(io.Writer, io.Writer), beforeKeys []string, beforeBytes []byte) {
	t.Helper()
	require.NoError(t, ghConfig.Write(authCfg.cfg))
	afterKeys, err := authCfg.cfg.Keys([]string{hostsKey})
	require.NoError(t, err)
	assert.Equal(t, beforeKeys, afterKeys, "serialized repair changed host key order")
	assert.True(t, bytes.Equal(beforeBytes, snapshotHostsConfig(t, readConfigs)), "serialized repair changed hosts state")
}

func snapshotFollowupKeyring(t *testing.T, service string, users ...string) map[string]string {
	t.Helper()
	state := make(map[string]string, len(users))
	for _, user := range users {
		token, err := keyring.Get(service, user)
		if errors.Is(err, keyring.ErrNotFound) {
			continue
		}
		require.NoError(t, err)
		state[followupProviderKey(service, user)] = token
	}
	return state
}

func assertFollowupErrorSecretFree(t *testing.T, err error, forbidden ...string) {
	t.Helper()
	if err == nil {
		return
	}
	for _, value := range forbidden {
		assert.NotContains(t, err.Error(), value, "credential operation error contains synthetic credential or account material")
	}
}

func TestConfigRepairWriteFailureRemainsLocalWhenProviderRollbackSucceeds(t *testing.T) {
	f := newSecureAuthSwitchFixture(t)
	service := keyringServiceName(f.hostname)
	beforeProvider := snapshotFollowupKeyring(t, service, "", f.activeUser, f.targetUser)
	var repairCalls int
	f.authCfg.configWrite = func() error {
		return errSyntheticFollowupInitialRepairWrite
	}
	f.authCfg.configRepairWrite = func() error {
		repairCalls++
		return errSyntheticFollowupRepairWrite
	}

	err := f.authCfg.Logout(f.hostname, f.activeUser)

	assert.Equal(t, 1, repairCalls, "config repair was not attempted exactly once")
	f.assertUnchanged(t)
	afterProvider := snapshotFollowupKeyring(t, service, "", f.activeUser, f.targetUser)
	assert.Equal(t, beforeProvider, afterProvider, "provider state was not fully restored after local repair failure")
	assertLogoutErrorSecretFree(t, err, f.activeUser, f.targetUser, f.activeToken, f.targetToken)
	require.ErrorIs(t, err, errSyntheticFollowupInitialRepairWrite)
	require.ErrorIs(t, err, errSyntheticFollowupRepairWrite)
	assert.Equal(t, errors.Join(errSyntheticFollowupInitialRepairWrite, errSyntheticFollowupRepairWrite).Error(), err.Error(), "fully local repair failure was not returned as the local error join")
	var resolutionErr *AutomicVaultCredentialResolutionError
	assert.False(t, errors.As(err, &resolutionErr), "local config repair failure was mislabeled as a Vault failure")
}

func TestConfigRepairAndProviderRollbackFailuresAreClassifiedOnce(t *testing.T) {
	f := newSecureAuthSwitchFixture(t)
	var setCalls int
	f.authCfg.configWrite = func() error {
		return errSyntheticFollowupInitialRepairWrite
	}
	f.authCfg.configRepairWrite = func() error {
		return errSyntheticFollowupRepairWrite
	}
	f.authCfg.keyringSet = func(service, user, token string) error {
		setCalls++
		if setCalls == 1 {
			return keyring.Set(service, user, token)
		}
		if setCalls == 2 {
			return errSyntheticFollowupRepairRollback
		}
		return errSyntheticFollowupDepartingRollback
	}

	err := f.authCfg.Logout(f.hostname, f.activeUser)

	assert.Equal(t, 3, setCalls, "provider rollback did not continue after the first rollback failure")
	f.assertUnchanged(t)
	assertLogoutErrorSecretFree(t, err, f.activeUser, f.targetUser, f.activeToken, f.targetToken)
	requireAutomicVaultCredentialErrors(t, err, errSyntheticFollowupInitialRepairWrite, errSyntheticFollowupRepairWrite, errSyntheticFollowupRepairRollback, errSyntheticFollowupDepartingRollback)
}

func TestSwitchUserWriteFailureRestoresActualDriftedHostwideCredential(t *testing.T) {
	authCfg, _, provider := setupFollowupMultiHostConfig(t, false)
	const host = "github.com"
	const activeUser = "synthetic-followup-active-account"
	const targetUser = "synthetic-followup-target-account"
	service := keyringServiceName(host)
	provider.values[followupProviderKey(service, "")] = "synthetic-followup-hostwide-token"
	beforeProvider := maps.Clone(provider.values)
	authCfg.configWrite = func() error {
		return errSyntheticFollowupDriftWrite
	}

	err := authCfg.SwitchUser(host, targetUser)

	assert.Equal(t, beforeProvider, maps.Clone(provider.values), "provider state was not fully restored after host-wide drift rollback")
	assert.Equal(t, "synthetic-followup-hostwide-token", provider.values[followupProviderKey(service, "")], "rollback restored the account token instead of the actual host-wide token")
	assert.Equal(t, "synthetic-followup-account-token", provider.values[followupProviderKey(service, activeUser)], "active account credential changed")
	assert.Equal(t, "synthetic-followup-target-token", provider.values[followupProviderKey(service, targetUser)], "target account credential changed")
	assert.Same(t, errSyntheticFollowupDriftWrite, err, "host-wide drift write failure was not returned unchanged")
	assertFollowupErrorSecretFree(t, err, activeUser, targetUser, "synthetic-followup-account-token", "synthetic-followup-target-token", "synthetic-followup-hostwide-token")
	var resolutionErr *AutomicVaultCredentialResolutionError
	assert.False(t, errors.As(err, &resolutionErr), "local host-wide drift write failure was mislabeled as a Vault failure")
	require.ErrorIs(t, err, errSyntheticFollowupDriftWrite)
}

func TestSwitchUserWriteFailureLeavesHostwideCredentialAbsent(t *testing.T) {
	authCfg, _, provider := setupFollowupMultiHostConfig(t, false)
	const host = "github.com"
	const targetUser = "synthetic-followup-target-account"
	service := keyringServiceName(host)
	beforeProvider := maps.Clone(provider.values)
	authCfg.configWrite = func() error {
		return errSyntheticFollowupAbsentWrite
	}

	err := authCfg.SwitchUser(host, targetUser)

	assert.Equal(t, beforeProvider, maps.Clone(provider.values), "provider state was not fully restored after absent host-wide rollback")
	_, present := provider.values[followupProviderKey(service, "")]
	assert.False(t, present, "rollback created a host-wide credential that was originally absent")
	assert.Same(t, errSyntheticFollowupAbsentWrite, err, "absent host-wide write failure was not returned unchanged")
	assertFollowupErrorSecretFree(t, err, targetUser, "synthetic-followup-account-token", "synthetic-followup-target-token")
	var resolutionErr *AutomicVaultCredentialResolutionError
	assert.False(t, errors.As(err, &resolutionErr), "local absent host-wide write failure was mislabeled as a Vault failure")
	require.ErrorIs(t, err, errSyntheticFollowupAbsentWrite)
}

func TestSwitchUserHostwideReadFailureStopsBeforeTargetResolution(t *testing.T) {
	authCfg, readConfigs, provider := setupFollowupMultiHostConfig(t, false)
	const host = "github.com"
	const targetUser = "synthetic-followup-target-account"
	service := keyringServiceName(host)
	provider.getErrors[followupProviderKey(service, "")] = errSyntheticFollowupHostwideGet
	beforeKeys, err := authCfg.cfg.Keys([]string{hostsKey})
	require.NoError(t, err)
	beforeBytes := snapshotHostsConfig(t, readConfigs)
	beforeProvider := maps.Clone(provider.values)
	var hostwideGets, targetGets, sets, deletes, writes int
	originalGet := provider.get
	authCfg.keyringGet = func(service, user string) (string, error) {
		if user == "" {
			hostwideGets++
		}
		if user == targetUser {
			targetGets++
		}
		return originalGet(service, user)
	}
	authCfg.keyringSet = func(service, user, token string) error {
		sets++
		return provider.set(service, user, token)
	}
	authCfg.keyringDelete = func(service, user string) error {
		deletes++
		return provider.delete(service, user)
	}
	authCfg.configWrite = func() error {
		writes++
		return nil
	}

	err = authCfg.SwitchUser(host, targetUser)

	assert.Equal(t, beforeProvider, maps.Clone(provider.values), "provider state changed after host-wide read failure")
	assert.Equal(t, 1, hostwideGets, "host-wide active slot was not read before switching")
	assert.Equal(t, 0, targetGets, "target resolution ran after an unhandled host-wide read failure")
	assert.Equal(t, 0, sets, "provider write ran after an unhandled host-wide read failure")
	assert.Equal(t, 0, deletes, "provider delete ran after an unhandled host-wide read failure")
	assert.Equal(t, 0, writes, "config write ran after an unhandled host-wide read failure")
	assertFollowupHostsUnchanged(t, authCfg, readConfigs, beforeKeys, beforeBytes)
	assertFollowupSerializedHostsUnchanged(t, authCfg, readConfigs, beforeKeys, beforeBytes)
	assertFollowupErrorSecretFree(t, err, targetUser, "synthetic-followup-account-token", "synthetic-followup-target-token")
	requireAutomicVaultCredentialError(t, err, errSyntheticFollowupHostwideGet)
}

func TestSwitchUserPreMutationFailuresPreserveMultiHostState(t *testing.T) {
	tests := []struct {
		name       string
		targetMode string
		cause      error
	}{
		{name: "target-get", targetMode: "get", cause: errSyntheticFollowupTargetGet},
		{name: "target-set", targetMode: "set", cause: errSyntheticFollowupTargetSet},
		{name: "target-delete", targetMode: "delete", cause: errSyntheticFollowupTargetDelete},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authCfg, readConfigs, provider := setupFollowupMultiHostConfig(t, tt.targetMode == "delete")
			const host = "github.com"
			const targetUser = "synthetic-followup-target-account"
			service := keyringServiceName(host)
			beforeKeys, err := authCfg.cfg.Keys([]string{hostsKey})
			require.NoError(t, err)
			beforeBytes := snapshotHostsConfig(t, readConfigs)
			beforeProvider := maps.Clone(provider.values)
			var writes, repairs int
			authCfg.configWrite = func() error {
				writes++
				return nil
			}
			authCfg.configRepairWrite = func() error {
				repairs++
				return nil
			}
			switch tt.targetMode {
			case "get":
				provider.getErrors[followupProviderKey(service, targetUser)] = tt.cause
			case "set":
				provider.setErrors[followupProviderKey(service, "")] = tt.cause
			case "delete":
				provider.delErrors[followupProviderKey(service, "")] = tt.cause
			}

			err = authCfg.SwitchUser(host, targetUser)

			assertFollowupHostsUnchanged(t, authCfg, readConfigs, beforeKeys, beforeBytes)
			assert.Equal(t, 0, writes, "config write ran during a pre-mutation provider failure")
			assert.Equal(t, 0, repairs, "config repair ran during a pre-mutation provider failure")
			assert.Equal(t, beforeProvider, maps.Clone(provider.values), "provider state changed during a pre-mutation failure")
			assertFollowupSerializedHostsUnchanged(t, authCfg, readConfigs, beforeKeys, beforeBytes)
			assertFollowupErrorSecretFree(t, err, targetUser, "synthetic-followup-account-token", "synthetic-followup-target-token")
			requireAutomicVaultCredentialError(t, err, tt.cause)
		})
	}
}

func TestSwitchUserMultiHostWriteFailurePreservesHostOrder(t *testing.T) {
	authCfg, readConfigs, provider := setupFollowupMultiHostConfig(t, false)
	const host = "github.com"
	const targetUser = "synthetic-followup-target-account"
	service := keyringServiceName(host)
	provider.values[followupProviderKey(service, "")] = "synthetic-followup-hostwide-token"
	beforeProvider := maps.Clone(provider.values)
	beforeKeys, err := authCfg.cfg.Keys([]string{hostsKey})
	require.NoError(t, err)
	beforeBytes := snapshotHostsConfig(t, readConfigs)
	authCfg.configWrite = func() error {
		return errSyntheticFollowupMultiHostWrite
	}

	err = authCfg.SwitchUser(host, targetUser)

	assertFollowupHostsUnchanged(t, authCfg, readConfigs, beforeKeys, beforeBytes)
	assert.Equal(t, beforeProvider, maps.Clone(provider.values), "provider state was not fully restored after multi-host write failure")
	assert.Same(t, errSyntheticFollowupMultiHostWrite, err, "multi-host local write failure was not returned unchanged")
	assertFollowupErrorSecretFree(t, err, targetUser, "synthetic-followup-account-token", "synthetic-followup-target-token", "synthetic-followup-hostwide-token")
	var resolutionErr *AutomicVaultCredentialResolutionError
	assert.False(t, errors.As(err, &resolutionErr), "multi-host local write failure was mislabeled as a Vault failure")
	require.ErrorIs(t, err, errSyntheticFollowupMultiHostWrite)
	// Force the in-memory tree through the real isolated writer as a second
	// serialization check; this does not contact a live service.
	assertFollowupSerializedHostsUnchanged(t, authCfg, readConfigs, beforeKeys, beforeBytes)
}
