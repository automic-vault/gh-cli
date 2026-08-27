package config

import (
	"bytes"
	"errors"
	"io"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/cli/cli/v2/internal/keyring"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	errSyntheticLoginPreflightAccountReadDenied = errors.New("synthetic Vault login account read denied")
	errSyntheticLoginPreflightActiveReadDenied  = errors.New("synthetic Vault login active-slot read denied")
	errSyntheticLoginPreflightActiveSetDenied   = errors.New("synthetic Vault login active-slot write denied")
	errSyntheticLoginPreflightConfigWrite       = errors.New("synthetic local login config write denied")
)

type loginPreflightOperation struct {
	kind  string
	user  string
	token string
}

type loginPreflightFailure struct {
	token string
	err   error
}

type loginPreflightProvider struct {
	values          map[string]string
	operations      []loginPreflightOperation
	getFailures     map[string]loginPreflightFailure
	beforeOperation func(loginPreflightOperation)
	setHook         func(loginPreflightOperation) error
	deleteHook      func(loginPreflightOperation) error
}

func newLoginPreflightProvider() *loginPreflightProvider {
	return &loginPreflightProvider{
		values:      map[string]string{},
		getFailures: map[string]loginPreflightFailure{},
	}
}

func (p *loginPreflightProvider) get(service, user string) (string, error) {
	op := loginPreflightOperation{kind: "get", user: user}
	p.operations = append(p.operations, op)
	if p.beforeOperation != nil {
		p.beforeOperation(op)
	}
	if failure, ok := p.getFailures[user]; ok {
		return failure.token, failure.err
	}
	token, ok := p.values[loginProviderKey(service, user)]
	if !ok {
		return "", keyring.ErrNotFound
	}
	return token, nil
}

func (p *loginPreflightProvider) set(service, user, token string) error {
	op := loginPreflightOperation{kind: "set", user: user, token: token}
	p.operations = append(p.operations, op)
	if p.beforeOperation != nil {
		p.beforeOperation(op)
	}
	if p.setHook != nil {
		if err := p.setHook(op); err != nil {
			return err
		}
	}
	p.values[loginProviderKey(service, user)] = token
	return nil
}

func (p *loginPreflightProvider) delete(service, user string) error {
	op := loginPreflightOperation{kind: "delete", user: user}
	p.operations = append(p.operations, op)
	if p.beforeOperation != nil {
		p.beforeOperation(op)
	}
	if p.deleteHook != nil {
		if err := p.deleteHook(op); err != nil {
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

type loginPreflightFixture struct {
	authCfg      *AuthConfig
	readConfigs  func(io.Writer, io.Writer)
	provider     *loginPreflightProvider
	hostname     string
	account      string
	active       string
	newToken     string
	oldAccount   string
	activeToken  string
	oldActive    string
	beforeKeys   []string
	beforeConfig []loginConfigEntry
	beforeBytes  []byte
	beforeValues map[string]string
}

func newLoginPreflightFixture(t *testing.T, activeSlotPresent bool) *loginPreflightFixture {
	t.Helper()
	cfg, readConfigs := NewIsolatedTestConfig(t, "")
	authCfg := cfg.Authentication().(*AuthConfig)
	for _, host := range []string{"alpha.example", "github.com", "zulu.example"} {
		cfg.cfg.Set([]string{hostsKey, host, userKey}, "synthetic-login-preflight-unrelated")
		cfg.cfg.Set([]string{hostsKey, host, usersKey, "synthetic-login-preflight-unrelated"}, "")
	}

	const (
		host        = "github.com"
		active      = "synthetic-login-preflight-active-account"
		account     = "synthetic-login-preflight-existing-account"
		oldAccount  = "synthetic-login-preflight-old-account-token"
		activeToken = "synthetic-login-preflight-active-account-token"
		oldActive   = "synthetic-login-preflight-old-active-slot-token"
		newToken    = "synthetic-login-preflight-new-token"
	)
	cfg.cfg.Set([]string{hostsKey, host, userKey}, active)
	cfg.cfg.Set([]string{hostsKey, host, usersKey, active}, "")
	cfg.cfg.Set([]string{hostsKey, host, usersKey, account}, "")
	require.NoError(t, cfg.Write())

	provider := newLoginPreflightProvider()
	service := keyringServiceName(host)
	provider.values[loginProviderKey(service, account)] = oldAccount
	provider.values[loginProviderKey(service, active)] = activeToken
	if activeSlotPresent {
		provider.values[loginProviderKey(service, "")] = oldActive
	}
	authCfg.keyringGet = provider.get
	authCfg.keyringSet = provider.set
	authCfg.keyringDelete = provider.delete

	keys, err := cfg.cfg.Keys([]string{hostsKey})
	require.NoError(t, err)
	fixture := &loginPreflightFixture{
		authCfg:      authCfg,
		readConfigs:  readConfigs,
		provider:     provider,
		hostname:     host,
		account:      account,
		active:       active,
		newToken:     newToken,
		oldAccount:   oldAccount,
		activeToken:  activeToken,
		oldActive:    oldActive,
		beforeKeys:   append([]string(nil), keys...),
		beforeConfig: snapshotLoginConfig(t, cfg.cfg),
		beforeBytes:  snapshotHostsConfig(t, readConfigs),
		beforeValues: maps.Clone(provider.values),
	}
	provider.beforeOperation = func(op loginPreflightOperation) {
		fixture.assertConfigUnchanged(t, op.kind+" callback ran after local mutation")
	}
	return fixture
}

func (f *loginPreflightFixture) assertConfigUnchanged(t *testing.T, message string) {
	t.Helper()
	keys, err := f.authCfg.cfg.Keys([]string{hostsKey})
	require.NoError(t, err)
	assert.True(t, slices.Equal(f.beforeKeys, keys), message+": host order changed")
	assert.Equal(t, f.beforeConfig, snapshotLoginConfig(t, f.authCfg.cfg), message+": in-memory config changed")
	assert.True(t, bytes.Equal(f.beforeBytes, snapshotHostsConfig(t, f.readConfigs)), message+": persisted config changed")
}

func (f *loginPreflightFixture) assertProviderUnchanged(t *testing.T, message string) {
	t.Helper()
	assert.Equal(t, f.beforeValues, maps.Clone(f.provider.values), message)
}

func (f *loginPreflightFixture) assertPreflightPrefix(t *testing.T, message string) {
	t.Helper()
	want := []loginPreflightOperation{
		{kind: "get", user: f.account},
		{kind: "get", user: ""},
		{kind: "set", user: f.account, token: f.newToken},
		{kind: "set", user: "", token: f.newToken},
	}
	if len(f.provider.operations) < len(want) {
		assert.Fail(t, message, "provider operation sequence is shorter than the preflight contract: got %#v", f.provider.operations)
		return
	}
	assert.Equal(t, want, f.provider.operations[:len(want)], message)
}

func (f *loginPreflightFixture) assertNoProviderReadAfterSets(t *testing.T, message string) {
	t.Helper()
	lastSet := -1
	for i, op := range f.provider.operations {
		if op.kind == "set" {
			lastSet = i
		}
	}
	if lastSet < 0 {
		return
	}
	for _, op := range f.provider.operations[lastSet+1:] {
		assert.NotEqual(t, "get", op.kind, message)
	}
}

func (f *loginPreflightFixture) assertErrorSecretFree(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	message := strings.ToLower(err.Error())
	for _, forbidden := range []string{f.account, f.active, f.newToken, f.oldAccount, f.activeToken, f.oldActive} {
		assert.NotContains(t, message, strings.ToLower(forbidden), "login error contains credential or account material")
	}
}

func TestLoginSecureStoragePreflightAccountReadFailureIsAtomic(t *testing.T) {
	f := newLoginPreflightFixture(t, true)
	f.provider.getFailures[f.account] = loginPreflightFailure{
		token: "synthetic-login-preflight-poison-token",
		err:   errSyntheticLoginPreflightAccountReadDenied,
	}

	_, err := f.authCfg.Login(f.hostname, f.account, f.newToken, "", true)

	assert.Equal(t, []loginPreflightOperation{{kind: "get", user: f.account}}, f.provider.operations, "account read failure did not stop before any provider write")
	f.assertProviderUnchanged(t, "account read failure changed provider state")
	f.assertConfigUnchanged(t, "account read failure changed authentication state")
	f.assertErrorSecretFree(t, err)
	requireAutomicVaultCredentialError(t, err, errSyntheticLoginPreflightAccountReadDenied)
}

func TestLoginSecureStoragePreflightActiveReadFailureIsAtomic(t *testing.T) {
	f := newLoginPreflightFixture(t, true)
	f.provider.getFailures[""] = loginPreflightFailure{
		token: "synthetic-login-preflight-poison-active-token",
		err:   errSyntheticLoginPreflightActiveReadDenied,
	}

	_, err := f.authCfg.Login(f.hostname, f.account, f.newToken, "", true)

	assert.Equal(t, []loginPreflightOperation{
		{kind: "get", user: f.account},
		{kind: "get", user: ""},
	}, f.provider.operations, "active-slot read failure did not stop before provider mutation")
	f.assertProviderUnchanged(t, "active-slot read failure changed provider state")
	f.assertConfigUnchanged(t, "active-slot read failure changed authentication state")
	f.assertErrorSecretFree(t, err)
	requireAutomicVaultCredentialError(t, err, errSyntheticLoginPreflightActiveReadDenied)
}

func TestLoginSecureStoragePreflightReadsOldSlotsBeforeWrites(t *testing.T) {
	f := newLoginPreflightFixture(t, true)

	_, err := f.authCfg.Login(f.hostname, f.account, f.newToken, "", true)

	require.NoError(t, err)
	f.assertPreflightPrefix(t, "login did not preflight old account and active credentials before writing")
	f.assertNoProviderReadAfterSets(t, "login reread provider state after beginning writes")
	assert.Equal(t, f.newToken, f.provider.values[loginProviderKey(keyringServiceName(f.hostname), f.account)])
	assert.Equal(t, f.newToken, f.provider.values[loginProviderKey(keyringServiceName(f.hostname), "")])
}

func TestLoginSecureStorageExistingAccountActiveWriteFailureRestoresOldAccount(t *testing.T) {
	f := newLoginPreflightFixture(t, true)
	f.provider.setHook = func(op loginPreflightOperation) error {
		if op.user == "" && op.token == f.newToken {
			return errSyntheticLoginPreflightActiveSetDenied
		}
		return nil
	}

	_, err := f.authCfg.Login(f.hostname, f.account, f.newToken, "", true)

	f.assertPreflightPrefix(t, "active-slot failure did not use the required preflight sequence")
	assert.Contains(t, f.provider.operations, loginPreflightOperation{kind: "set", user: f.account, token: f.oldAccount}, "active-slot failure did not restore the overwritten account credential")
	assert.Equal(t, f.oldAccount, f.provider.values[loginProviderKey(keyringServiceName(f.hostname), f.account)], "active-slot failure did not restore the exact old account credential")
	f.assertProviderUnchanged(t, "active-slot failure did not restore the complete provider map")
	f.assertConfigUnchanged(t, "active-slot failure changed authentication state")
	f.assertErrorSecretFree(t, err)
	requireAutomicVaultCredentialError(t, err, errSyntheticLoginPreflightActiveSetDenied)
}

func TestLoginSecureStorageExistingAccountConfigFailureRestoresAllProviderState(t *testing.T) {
	f := newLoginPreflightFixture(t, true)
	f.authCfg.configWrite = func() error {
		return errSyntheticLoginPreflightConfigWrite
	}

	_, err := f.authCfg.Login(f.hostname, f.account, f.newToken, "", true)

	f.assertPreflightPrefix(t, "config failure did not preflight old credentials")
	f.assertNoProviderReadAfterSets(t, "config failure performed a provider reread after mutation")
	assert.Equal(t, f.beforeValues, maps.Clone(f.provider.values), "config failure did not restore the complete provider map")
	f.assertConfigUnchanged(t, "config failure did not restore the complete multi-host config")
	f.assertErrorSecretFree(t, err)
	require.Same(t, errSyntheticLoginPreflightConfigWrite, err)
	var resolutionErr *AutomicVaultCredentialResolutionError
	assert.False(t, errors.As(err, &resolutionErr), "a local config write failure was mislabeled as a Vault failure")
}

func TestLoginSecureStorageAbsentActiveSlotConfigFailureDeletesCreatedSlot(t *testing.T) {
	f := newLoginPreflightFixture(t, false)
	f.authCfg.configWrite = func() error {
		return errSyntheticLoginPreflightConfigWrite
	}

	_, err := f.authCfg.Login(f.hostname, f.account, f.newToken, "", true)

	f.assertPreflightPrefix(t, "absent active slot did not preflight before writing")
	assert.Contains(t, f.provider.operations, loginPreflightOperation{kind: "delete", user: ""}, "config failure did not delete the newly created active slot")
	assert.Equal(t, f.beforeValues, maps.Clone(f.provider.values), "config failure did not restore the provider map when active slot was originally absent")
	f.assertConfigUnchanged(t, "config failure did not restore config when active slot was originally absent")
	f.assertErrorSecretFree(t, err)
	require.Same(t, errSyntheticLoginPreflightConfigWrite, err)
	var resolutionErr *AutomicVaultCredentialResolutionError
	assert.False(t, errors.As(err, &resolutionErr), "a local config write failure was mislabeled as a Vault failure")
}
