package get

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/cli/cli/v2/internal/gh"
	ghmock "github.com/cli/cli/v2/internal/gh/mock"
	"github.com/cli/cli/v2/pkg/iostreams"
	"github.com/stretchr/testify/require"
)

var errSyntheticConfigGetVaultDenied = errors.New("synthetic config get Vault denial")

type configGetOuterVaultError struct {
	cause error
}

func (e *configGetOuterVaultError) Error() string { return e.cause.Error() }
func (e *configGetOuterVaultError) Unwrap() error { return e.cause }

type configGetMarkedVaultError struct {
	cause error
}

func (e *configGetMarkedVaultError) Error() string {
	return "Automic Vault credential resolution failed"
}
func (e *configGetMarkedVaultError) Unwrap() error                          { return e.cause }
func (*configGetMarkedVaultError) IsAutomicVaultCredentialResolution() bool { return true }

type configGetErrorAwareAuthConfig struct {
	gh.AuthConfig
	legacyToken   string
	legacySource  string
	token         string
	source        string
	err           error
	legacyCalls   int
	resolverCalls int
}

var _ gh.AuthConfig = (*configGetErrorAwareAuthConfig)(nil)

func (c *configGetErrorAwareAuthConfig) ActiveToken(string) (string, string) {
	c.legacyCalls++
	return c.legacyToken, c.legacySource
}

func (c *configGetErrorAwareAuthConfig) ActiveTokenWithError(string) (string, string, error) {
	c.resolverCalls++
	return c.token, c.source, c.err
}

type configGetLegacyOnlyAuthConfig struct {
	gh.AuthConfig
	legacyCalls int
}

var _ gh.AuthConfig = (*configGetLegacyOnlyAuthConfig)(nil)

func (c *configGetLegacyOnlyAuthConfig) ActiveToken(string) (string, string) {
	c.legacyCalls++
	return "synthetic-legacy-oauth-token", "oauth_token"
}

type configGetEnvironmentAuthConfig struct {
	gh.AuthConfig
	legacyCalls   int
	resolverCalls int
	keyringCalls  int
}

var _ gh.AuthConfig = (*configGetEnvironmentAuthConfig)(nil)

func (c *configGetEnvironmentAuthConfig) ActiveToken(string) (string, string) {
	c.legacyCalls++
	return os.Getenv("GH_TOKEN"), "GH_TOKEN"
}

func (c *configGetEnvironmentAuthConfig) ActiveTokenWithError(string) (string, string, error) {
	c.resolverCalls++
	if token := os.Getenv("GH_TOKEN"); token != "" {
		return token, "GH_TOKEN", nil
	}
	return "", "", nil
}

func (c *configGetEnvironmentAuthConfig) TokenFromKeyring(string) (string, error) {
	c.keyringCalls++
	return "", nil
}

func configGetOptions(t *testing.T, authCfg gh.AuthConfig) (*GetOptions, *bytes.Buffer, *bytes.Buffer, *ghmock.ConfigMock) {
	t.Helper()
	mockConfig := &ghmock.ConfigMock{
		AuthenticationFunc: func() gh.AuthConfig { return authCfg },
		SetFunc:            func(string, string, string) {},
		WriteFunc:          func() error { return nil },
	}
	ios, _, stdout, stderr := iostreams.Test()
	return &GetOptions{
		IO:       ios,
		Config:   mockConfig,
		Hostname: "github.com",
		Key:      "oauth_token",
	}, stdout, stderr, mockConfig
}

func TestGetRunOAuthTokenOperationalVaultFailureIsLocalAndSilent(t *testing.T) {
	authCfg := &configGetErrorAwareAuthConfig{
		legacyToken:  "synthetic-poison-legacy-token",
		legacySource: "synthetic-poison-legacy-source",
		token:        "synthetic-poison-token",
		source:       "synthetic-poison-source",
		err:          &configGetOuterVaultError{cause: &configGetMarkedVaultError{cause: errSyntheticConfigGetVaultDenied}},
	}
	opts, stdout, stderr, mockConfig := configGetOptions(t, authCfg)

	err := getRun(opts)

	require.Empty(t, stdout.String())
	require.Empty(t, stderr.String())
	require.Equal(t, 1, authCfg.resolverCalls)
	require.Equal(t, 0, authCfg.legacyCalls)
	require.Empty(t, mockConfig.SetCalls(), "credential retrieval must not mutate configuration")
	require.Empty(t, mockConfig.WriteCalls(), "credential retrieval must not write configuration")
	require.EqualError(t, err, "Automic Vault credential resolution failed")
	require.ErrorIs(t, err, errSyntheticConfigGetVaultDenied)
	var marker interface{ IsAutomicVaultCredentialResolution() bool }
	require.ErrorAs(t, err, &marker)
	require.True(t, marker.IsAutomicVaultCredentialResolution())
	for _, forbidden := range []string{"synthetic-poison", "oauth_token", "not found", "undefined"} {
		require.NotContains(t, strings.ToLower(err.Error()), forbidden)
	}
}

func TestGetRunOAuthTokenUsesErrorAwareResolver(t *testing.T) {
	authCfg := &configGetErrorAwareAuthConfig{
		legacyToken:  "synthetic-poison-legacy-token",
		legacySource: "synthetic-poison-legacy-source",
		token:        "synthetic-resolved-oauth-token",
		source:       "keyring",
	}
	opts, stdout, stderr, _ := configGetOptions(t, authCfg)

	err := getRun(opts)

	require.NoError(t, err)
	require.Equal(t, "synthetic-resolved-oauth-token\n", stdout.String())
	require.Empty(t, stderr.String())
	require.Equal(t, 1, authCfg.resolverCalls)
	require.Equal(t, 0, authCfg.legacyCalls)
}

func TestGetRunOAuthTokenIntentionalAbsenceRemainsCanonical(t *testing.T) {
	authCfg := &configGetErrorAwareAuthConfig{
		legacyToken:  "synthetic-poison-legacy-token",
		legacySource: "synthetic-poison-legacy-source",
	}
	opts, stdout, stderr, _ := configGetOptions(t, authCfg)

	err := getRun(opts)

	require.Empty(t, stdout.String())
	require.Empty(t, stderr.String())
	require.EqualError(t, err, `could not find key "oauth_token"`)
	require.Equal(t, 1, authCfg.resolverCalls)
	require.Equal(t, 0, authCfg.legacyCalls)
	require.NotContains(t, strings.ToLower(err.Error()), "vault")
}

func TestGetRunOAuthTokenKeepsLegacyOnlyCompatibility(t *testing.T) {
	authCfg := &configGetLegacyOnlyAuthConfig{}
	if _, ok := any(authCfg).(interface {
		ActiveTokenWithError(string) (string, string, error)
	}); ok {
		t.Fatal("legacy-only fixture must not implement the resolver")
	}
	opts, stdout, stderr, _ := configGetOptions(t, authCfg)

	err := getRun(opts)

	require.NoError(t, err)
	require.Equal(t, "synthetic-legacy-oauth-token\n", stdout.String())
	require.Empty(t, stderr.String())
	require.Equal(t, 1, authCfg.legacyCalls)
}

func TestGetRunOAuthTokenEnvironmentPrecedenceAvoidsKeyringAndMutation(t *testing.T) {
	t.Setenv("GH_TOKEN", "synthetic-environment-oauth-token")
	authCfg := &configGetEnvironmentAuthConfig{}
	opts, stdout, stderr, mockConfig := configGetOptions(t, authCfg)

	err := getRun(opts)

	require.NoError(t, err)
	require.Equal(t, "synthetic-environment-oauth-token\n", stdout.String())
	require.Empty(t, stderr.String())
	require.Equal(t, 1, authCfg.resolverCalls, "environment precedence must use the error-aware resolver")
	require.Equal(t, 0, authCfg.legacyCalls, "environment precedence must not use the legacy getter")
	require.Equal(t, 0, authCfg.keyringCalls, "environment precedence must not consult keyring storage")
	require.Empty(t, mockConfig.SetCalls(), "environment retrieval must not mutate configuration")
	require.Empty(t, mockConfig.WriteCalls(), "environment retrieval must not write configuration")
}
