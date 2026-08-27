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

func TestConfigRepairWriteFailureRemainsLocalWhenProviderRollbackSucceeds(t *testing.T) {
	f := newSecureAuthSwitchFixture(t)
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
	authCfg.configWrite = func() error {
		return errSyntheticFollowupDriftWrite
	}

	err := authCfg.SwitchUser(host, targetUser)

	assert.Equal(t, "synthetic-followup-hostwide-token", provider.values[followupProviderKey(service, "")], "rollback restored the account token instead of the actual host-wide token")
	assert.Equal(t, "synthetic-followup-account-token", provider.values[followupProviderKey(service, activeUser)], "active account credential changed")
	assert.Equal(t, "synthetic-followup-target-token", provider.values[followupProviderKey(service, targetUser)], "target account credential changed")
	require.ErrorIs(t, err, errSyntheticFollowupDriftWrite)
}

func TestSwitchUserWriteFailureLeavesHostwideCredentialAbsent(t *testing.T) {
	authCfg, _, provider := setupFollowupMultiHostConfig(t, false)
	const host = "github.com"
	const targetUser = "synthetic-followup-target-account"
	service := keyringServiceName(host)
	authCfg.configWrite = func() error {
		return errSyntheticFollowupAbsentWrite
	}

	err := authCfg.SwitchUser(host, targetUser)

	_, present := provider.values[followupProviderKey(service, "")]
	assert.False(t, present, "rollback created a host-wide credential that was originally absent")
	require.ErrorIs(t, err, errSyntheticFollowupAbsentWrite)
}

func TestSwitchUserHostwideReadFailureStopsBeforeTargetResolution(t *testing.T) {
	authCfg, _, provider := setupFollowupMultiHostConfig(t, false)
	const host = "github.com"
	const targetUser = "synthetic-followup-target-account"
	service := keyringServiceName(host)
	provider.getErrors[followupProviderKey(service, "")] = errSyntheticFollowupHostwideGet
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

	err := authCfg.SwitchUser(host, targetUser)

	assert.Equal(t, 1, hostwideGets, "host-wide active slot was not read before switching")
	assert.Equal(t, 0, targetGets, "target resolution ran after an unhandled host-wide read failure")
	assert.Equal(t, 0, sets, "provider write ran after an unhandled host-wide read failure")
	assert.Equal(t, 0, deletes, "provider delete ran after an unhandled host-wide read failure")
	assert.Equal(t, 0, writes, "config write ran after an unhandled host-wide read failure")
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
	beforeKeys, err := authCfg.cfg.Keys([]string{hostsKey})
	require.NoError(t, err)
	beforeBytes := snapshotHostsConfig(t, readConfigs)
	authCfg.configWrite = func() error {
		return errSyntheticFollowupMultiHostWrite
	}

	err = authCfg.SwitchUser(host, targetUser)

	assertFollowupHostsUnchanged(t, authCfg, readConfigs, beforeKeys, beforeBytes)
	require.ErrorIs(t, err, errSyntheticFollowupMultiHostWrite)
	// Force the in-memory tree through the real isolated writer as a second
	// serialization check; this does not contact a live service.
	require.NoError(t, ghConfig.Write(authCfg.cfg))
	assert.Equal(t, beforeKeys, func() []string {
		keys, keyErr := authCfg.cfg.Keys([]string{hostsKey})
		require.NoError(t, keyErr)
		return keys
	}(), "host key order changed after serialized repair")
	assert.True(t, bytes.Equal(beforeBytes, snapshotHostsConfig(t, readConfigs)), "serialized multi-host tree changed after repair")
}
