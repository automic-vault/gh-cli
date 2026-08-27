package config

import (
	"bytes"
	"errors"
	"io"
	"maps"
	"strings"
	"testing"

	"github.com/cli/cli/v2/internal/keyring"
	ghConfig "github.com/cli/go-gh/v2/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	errSyntheticLoginAccountSetDenied      = errors.New("synthetic Vault login account write denied")
	errSyntheticLoginActiveSetDenied       = errors.New("synthetic Vault login active-slot write denied")
	errSyntheticLoginActiveRollbackDenied  = errors.New("synthetic Vault login active-slot rollback denied")
	errSyntheticLoginAccountRollbackDenied = errors.New("synthetic Vault login account rollback denied")
	errSyntheticLoginConfigWriteDenied     = errors.New("synthetic local login config write denied")
)

type loginTransactionProvider struct {
	values      map[string]string
	getCalls    []string
	setUsers    []string
	deleteUsers []string
	operations  []loginTransactionOperation
	setHook     func(service, user, token string, call int) error
	deleteHook  func(service, user string, call int) error
}

type loginTransactionOperation struct {
	kind  string
	user  string
	token string
}

type loginConfigEntry struct {
	keys  []string
	value string
}

func newLoginTransactionProvider() *loginTransactionProvider {
	return &loginTransactionProvider{values: map[string]string{}}
}

func loginProviderKey(service, user string) string {
	return service + "\x00" + user
}

func (p *loginTransactionProvider) get(service, user string) (string, error) {
	p.getCalls = append(p.getCalls, user)
	p.operations = append(p.operations, loginTransactionOperation{kind: "get", user: user})
	token, ok := p.values[loginProviderKey(service, user)]
	if !ok {
		return "", keyring.ErrNotFound
	}
	return token, nil
}

func (p *loginTransactionProvider) set(service, user, token string) error {
	p.setUsers = append(p.setUsers, user)
	p.operations = append(p.operations, loginTransactionOperation{kind: "set", user: user, token: token})
	call := len(p.setUsers)
	if p.setHook != nil {
		if err := p.setHook(service, user, token, call); err != nil {
			return err
		}
	}
	p.values[loginProviderKey(service, user)] = token
	return nil
}

func (p *loginTransactionProvider) delete(service, user string) error {
	p.deleteUsers = append(p.deleteUsers, user)
	p.operations = append(p.operations, loginTransactionOperation{kind: "delete", user: user})
	call := len(p.deleteUsers)
	if p.deleteHook != nil {
		if err := p.deleteHook(service, user, call); err != nil {
			return err
		}
	}
	key := loginProviderKey(service, user)
	if _, ok := p.values[key]; !ok {
		return keyring.ErrNotFound
	}
	delete(p.values, key)
	return nil
}

func setupLoginTransactionFixture(t *testing.T) (*AuthConfig, func(io.Writer, io.Writer), *loginTransactionProvider, []string, []loginConfigEntry, []byte) {
	t.Helper()
	cfg, readConfigs := NewIsolatedTestConfig(t, "")
	authCfg := cfg.Authentication().(*AuthConfig)
	for _, host := range []string{"alpha.example", "github.com", "zulu.example"} {
		cfg.cfg.Set([]string{hostsKey, host, userKey}, "synthetic-unrelated-account")
		cfg.cfg.Set([]string{hostsKey, host, usersKey, "synthetic-unrelated-account"}, "")
	}
	const host = "github.com"
	const activeUser = "synthetic-login-active-account"
	cfg.cfg.Set([]string{hostsKey, host, userKey}, activeUser)
	cfg.cfg.Set([]string{hostsKey, host, usersKey, activeUser}, "")
	require.NoError(t, cfg.Write())

	provider := newLoginTransactionProvider()
	service := keyringServiceName(host)
	provider.values[loginProviderKey(service, "")] = "synthetic-login-hostwide-token"
	provider.values[loginProviderKey(service, activeUser)] = "synthetic-login-active-token"
	authCfg.keyringGet = provider.get
	authCfg.keyringSet = provider.set
	authCfg.keyringDelete = provider.delete
	keys, err := cfg.cfg.Keys([]string{hostsKey})
	require.NoError(t, err)
	return authCfg, readConfigs, provider, keys, snapshotLoginConfig(t, cfg.cfg), snapshotHostsConfig(t, readConfigs)
}

func snapshotLoginConfig(t *testing.T, cfg *ghConfig.Config) []loginConfigEntry {
	t.Helper()
	var entries []loginConfigEntry
	var visit func([]string)
	visit = func(keys []string) {
		childKeys, err := cfg.Keys(keys)
		if err != nil || len(childKeys) == 0 {
			value, valueErr := cfg.Get(keys)
			require.NoError(t, valueErr)
			entries = append(entries, loginConfigEntry{keys: append([]string(nil), keys...), value: value})
			return
		}
		for _, childKey := range childKeys {
			visit(append(append([]string(nil), keys...), childKey))
		}
	}
	visit([]string{hostsKey})
	return entries
}

func assertLoginTransactionStateUnchanged(t *testing.T, authCfg *AuthConfig, readConfigs func(io.Writer, io.Writer), provider *loginTransactionProvider, beforeProvider map[string]string, beforeKeys []string, beforeConfig []loginConfigEntry, beforeBytes []byte) {
	t.Helper()
	keys, err := authCfg.cfg.Keys([]string{hostsKey})
	require.NoError(t, err)
	assert.Equal(t, beforeKeys, keys, "host order changed during failed login")
	assert.Equal(t, beforeConfig, snapshotLoginConfig(t, authCfg.cfg), "in-memory authentication config changed during failed login")
	assert.True(t, bytes.Equal(beforeBytes, snapshotHostsConfig(t, readConfigs)), "persisted authentication state changed during failed login")
	assert.Equal(t, beforeProvider, maps.Clone(provider.values), "provider state changed during failed login")
}

func assertLoginErrorSecretFree(t *testing.T, err error, forbidden ...string) {
	t.Helper()
	if err == nil {
		return
	}
	message := strings.ToLower(err.Error())
	for _, value := range forbidden {
		assert.NotContains(t, message, strings.ToLower(value), "login error contains credential or account material")
	}
}

func TestLoginSecureStorageAccountSetFailureIsTypedAndAtomic(t *testing.T) {
	authCfg, readConfigs, provider, beforeKeys, beforeConfig, beforeBytes := setupLoginTransactionFixture(t)
	beforeProvider := maps.Clone(provider.values)
	var setCalls int
	authCfg.keyringSet = func(_, _, _ string) error {
		setCalls++
		return errSyntheticLoginAccountSetDenied
	}

	_, err := authCfg.Login("github.com", "synthetic-login-new-account", "synthetic-login-new-token", "https", true)

	assert.Equal(t, 1, setCalls, "account provider write was not attempted exactly once")
	assertLoginTransactionStateUnchanged(t, authCfg, readConfigs, provider, beforeProvider, beforeKeys, beforeConfig, beforeBytes)
	assertLoginErrorSecretFree(t, err, "synthetic-login-new-account", "synthetic-login-new-token")
	requireAutomicVaultCredentialError(t, err, errSyntheticLoginAccountSetDenied)
}

func TestLoginSecureStorageActiveSetFailureRollsBackNewAccount(t *testing.T) {
	authCfg, readConfigs, provider, beforeKeys, beforeConfig, beforeBytes := setupLoginTransactionFixture(t)
	beforeProvider := maps.Clone(provider.values)
	provider.setHook = func(_, user, _ string, call int) error {
		if call == 2 && user == "" {
			return errSyntheticLoginActiveSetDenied
		}
		return nil
	}

	_, err := authCfg.Login("github.com", "synthetic-login-new-account", "synthetic-login-new-token", "https", true)

	assert.Equal(t, []string{"synthetic-login-new-account", ""}, provider.setUsers, "login did not attempt the account write and active-slot write")
	assert.Equal(t, []string{"synthetic-login-new-account"}, provider.deleteUsers, "failed active write did not remove the new account slot")
	assertLoginTransactionStateUnchanged(t, authCfg, readConfigs, provider, beforeProvider, beforeKeys, beforeConfig, beforeBytes)
	assertLoginErrorSecretFree(t, err, "synthetic-login-new-account", "synthetic-login-new-token")
	requireAutomicVaultCredentialError(t, err, errSyntheticLoginActiveSetDenied)
}

func TestLoginSecureStorageActiveSetAndAccountRollbackFailuresAreClassifiedOnce(t *testing.T) {
	authCfg, readConfigs, provider, beforeKeys, beforeConfig, beforeBytes := setupLoginTransactionFixture(t)
	beforeProvider := maps.Clone(provider.values)
	provider.setHook = func(_, user, _ string, call int) error {
		if call == 2 && user == "" {
			return errSyntheticLoginActiveSetDenied
		}
		return nil
	}
	provider.deleteHook = func(_, user string, _ int) error {
		if user == "synthetic-login-new-account" {
			return errSyntheticLoginAccountRollbackDenied
		}
		return nil
	}

	_, err := authCfg.Login("github.com", "synthetic-login-new-account", "synthetic-login-new-token", "https", true)

	assert.Equal(t, []string{"synthetic-login-new-account", ""}, provider.setUsers, "failed active write did not attempt the account write and active-slot write")
	assert.Equal(t, []string{"synthetic-login-new-account"}, provider.deleteUsers, "failed active write did not attempt account rollback")
	assert.Equal(t, beforeKeys, mustConfigKeys(t, authCfg), "login host order changed despite provider rollback failure")
	assert.Equal(t, beforeConfig, snapshotLoginConfig(t, authCfg.cfg), "login config changed despite provider rollback failure")
	assert.True(t, bytes.Equal(beforeBytes, snapshotHostsConfig(t, readConfigs)), "persisted config changed despite provider rollback failure")
	assert.NotEqual(t, beforeProvider, maps.Clone(provider.values), "test fixture unexpectedly restored provider state after injected rollback failure")
	assertLoginErrorSecretFree(t, err, "synthetic-login-new-account", "synthetic-login-new-token")
	requireAutomicVaultCredentialErrors(t, err, errSyntheticLoginActiveSetDenied, errSyntheticLoginAccountRollbackDenied)
}

func TestLoginSecureStorageConfigWriteFailureRestoresProviderAndMultiHostConfig(t *testing.T) {
	authCfg, readConfigs, provider, beforeKeys, beforeConfig, beforeBytes := setupLoginTransactionFixture(t)
	beforeProvider := maps.Clone(provider.values)
	authCfg.configWrite = func() error {
		return errSyntheticLoginConfigWriteDenied
	}

	_, err := authCfg.Login("github.com", "synthetic-login-new-account", "synthetic-login-new-token", "https", true)

	assert.Equal(t, []loginTransactionOperation{
		{kind: "get", user: "synthetic-login-new-account"},
		{kind: "get", user: ""},
		{kind: "set", user: "synthetic-login-new-account", token: "synthetic-login-new-token"},
		{kind: "set", user: "", token: "synthetic-login-new-token"},
		{kind: "set", user: "", token: "synthetic-login-hostwide-token"},
		{kind: "delete", user: "synthetic-login-new-account"},
	}, provider.operations, "config failure did not use inverse provider operation order")
	assert.Equal(t, []string{"synthetic-login-new-account", "", ""}, provider.setUsers, "config failure did not restore the active provider slot")
	assert.Equal(t, []string{"synthetic-login-new-account"}, provider.deleteUsers, "config failure did not remove the new account slot")
	assertLoginTransactionStateUnchanged(t, authCfg, readConfigs, provider, beforeProvider, beforeKeys, beforeConfig, beforeBytes)
	assertLoginErrorSecretFree(t, err, "synthetic-login-new-account", "synthetic-login-new-token")
	require.Same(t, errSyntheticLoginConfigWriteDenied, err)
	assert.False(t, errors.As(err, new(*AutomicVaultCredentialResolutionError)), "pure local login config failure was classified as a Vault failure")
}

func TestLoginSecureStorageConfigAndProviderRollbackFailuresAreClassifiedOnce(t *testing.T) {
	authCfg, readConfigs, provider, beforeKeys, beforeConfig, beforeBytes := setupLoginTransactionFixture(t)
	authCfg.configWrite = func() error {
		return errSyntheticLoginConfigWriteDenied
	}
	provider.setHook = func(_, user, _ string, call int) error {
		if call == 3 && user == "" {
			return errSyntheticLoginActiveRollbackDenied
		}
		return nil
	}
	provider.deleteHook = func(_, user string, _ int) error {
		if user == "synthetic-login-new-account" {
			return errSyntheticLoginAccountRollbackDenied
		}
		return nil
	}

	_, err := authCfg.Login("github.com", "synthetic-login-new-account", "synthetic-login-new-token", "https", true)

	assert.Equal(t, []loginTransactionOperation{
		{kind: "get", user: "synthetic-login-new-account"},
		{kind: "get", user: ""},
		{kind: "set", user: "synthetic-login-new-account", token: "synthetic-login-new-token"},
		{kind: "set", user: "", token: "synthetic-login-new-token"},
		{kind: "set", user: "", token: "synthetic-login-hostwide-token"},
		{kind: "delete", user: "synthetic-login-new-account"},
	}, provider.operations, "config and provider rollback did not attempt each inverse operation in LIFO order")
	assert.Equal(t, []string{"synthetic-login-new-account", "", ""}, provider.setUsers, "config failure did not continue active-slot rollback")
	assert.Equal(t, []string{"synthetic-login-new-account"}, provider.deleteUsers, "config failure did not continue account rollback")
	assert.Equal(t, beforeKeys, mustConfigKeys(t, authCfg), "login host order changed despite provider rollback failures")
	assert.Equal(t, beforeConfig, snapshotLoginConfig(t, authCfg.cfg), "login config changed despite provider rollback failures")
	assert.True(t, bytes.Equal(beforeBytes, snapshotHostsConfig(t, readConfigs)), "persisted config changed despite provider rollback failures")
	assertLoginErrorSecretFree(t, err, "synthetic-login-new-account", "synthetic-login-new-token")
	requireAutomicVaultCredentialErrors(t, err, errSyntheticLoginConfigWriteDenied, errSyntheticLoginActiveRollbackDenied, errSyntheticLoginAccountRollbackDenied)
}

func mustConfigKeys(t *testing.T, authCfg *AuthConfig) []string {
	t.Helper()
	keys, err := authCfg.cfg.Keys([]string{hostsKey})
	require.NoError(t, err)
	return keys
}
