package agent

import (
	"errors"
	"net/http"
	"testing"

	"github.com/cli/cli/v2/internal/gh"
	ghmock "github.com/cli/cli/v2/internal/gh/mock"
	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/stretchr/testify/require"
)

var errSyntheticAgentVaultDenied = errors.New("synthetic agent Vault denial")

// The outer wrapper models callers which add context while preserving the
// marker and cause that the command must inspect with errors.As/errors.Is.
type agentOuterVaultError struct {
	cause error
}

func (e *agentOuterVaultError) Error() string { return e.cause.Error() }
func (e *agentOuterVaultError) Unwrap() error { return e.cause }

type agentMarkedVaultError struct {
	cause error
}

func (e *agentMarkedVaultError) Error() string                          { return "Automic Vault credential resolution failed" }
func (e *agentMarkedVaultError) Unwrap() error                          { return e.cause }
func (*agentMarkedVaultError) IsAutomicVaultCredentialResolution() bool { return true }

type agentErrorAwareAuthConfig struct {
	gh.AuthConfig
	legacyToken   string
	legacySource  string
	token         string
	source        string
	err           error
	legacyCalls   int
	resolverCalls int
}

var _ gh.AuthConfig = (*agentErrorAwareAuthConfig)(nil)

func (c *agentErrorAwareAuthConfig) DefaultHost() (string, string) {
	return "github.com", "synthetic-test"
}

func (c *agentErrorAwareAuthConfig) ActiveToken(string) (string, string) {
	c.legacyCalls++
	return c.legacyToken, c.legacySource
}

func (c *agentErrorAwareAuthConfig) ActiveTokenWithError(string) (string, string, error) {
	c.resolverCalls++
	return c.token, c.source, c.err
}

type agentLegacyOnlyAuthConfig struct {
	gh.AuthConfig
	legacyCalls int
}

var _ gh.AuthConfig = (*agentLegacyOnlyAuthConfig)(nil)

func (c *agentLegacyOnlyAuthConfig) DefaultHost() (string, string) {
	return "github.com", "synthetic-test"
}

func (c *agentLegacyOnlyAuthConfig) ActiveToken(string) (string, string) {
	c.legacyCalls++
	return "gho_synthetic-legacy-token", "keyring"
}

func agentFactoryForAuth(authCfg gh.AuthConfig) *cmdutil.Factory {
	return &cmdutil.Factory{
		Config: func() (gh.Config, error) {
			return &ghmock.ConfigMock{
				AuthenticationFunc: func() gh.AuthConfig { return authCfg },
			}, nil
		},
	}
}

func TestRequireOAuthTokenOperationalVaultFailureIsLocalAndDoesNotUseLegacyOrRunCommand(t *testing.T) {
	authCfg := &agentErrorAwareAuthConfig{
		legacyToken:  "gho_synthetic-legacy-token",
		legacySource: "legacy-host-slot",
		token:        "gho_synthetic-poison-token",
		source:       "synthetic-poison-source",
		err:          &agentOuterVaultError{cause: &agentMarkedVaultError{cause: errSyntheticAgentVaultDenied}},
	}
	if _, ok := any(authCfg).(interface {
		ActiveTokenWithError(string) (string, string, error)
	}); !ok {
		t.Fatal("operational fixture must expose the error-aware resolver")
	}

	commandExecuted := false
	f := agentFactoryForAuth(authCfg)
	f.HttpClient = func() (*http.Client, error) {
		commandExecuted = true
		return nil, errors.New("synthetic HTTP construction must not occur")
	}

	err := requireOAuthToken(f)
	require.False(t, commandExecuted, "credential failure must stop before command/client execution")
	require.Equal(t, 0, authCfg.legacyCalls, "operational Vault failure must not use the legacy getter")
	require.Equal(t, 1, authCfg.resolverCalls, "operational Vault failure must use the resolver once")
	require.EqualError(t, err, "Automic Vault credential resolution failed")
	require.ErrorIs(t, err, errSyntheticAgentVaultDenied)
	var marker interface{ IsAutomicVaultCredentialResolution() bool }
	require.ErrorAs(t, err, &marker)
	require.True(t, marker.IsAutomicVaultCredentialResolution())
	require.NotContains(t, err.Error(), "synthetic-poison")
	require.NotContains(t, err.Error(), "log in")
	require.NotContains(t, err.Error(), "re-authenticate")
}

func TestRequireOAuthTokenUsesErrorAwareKeyringSource(t *testing.T) {
	authCfg := &agentErrorAwareAuthConfig{
		legacyToken:  "synthetic-invalid-legacy-token",
		legacySource: "legacy-host-slot",
		token:        "gho_synthetic-resolved-token",
		source:       "keyring",
	}

	err := requireOAuthToken(agentFactoryForAuth(authCfg))
	require.NoError(t, err)
	require.Equal(t, 0, authCfg.legacyCalls)
	require.Equal(t, 1, authCfg.resolverCalls)
}

func TestRequireOAuthTokenPreservesOrdinaryAbsenceGuidance(t *testing.T) {
	authCfg := &agentErrorAwareAuthConfig{
		legacyToken:  "synthetic-invalid-legacy-token",
		legacySource: "legacy-host-slot",
	}

	err := requireOAuthToken(agentFactoryForAuth(authCfg))
	require.EqualError(t, err, "this command requires an OAuth token. Re-authenticate with: gh auth login")
	require.Equal(t, 0, authCfg.legacyCalls, "absence must not fall back after selecting the error-aware resolver")
	require.Equal(t, 1, authCfg.resolverCalls)
}

func TestRequireOAuthTokenKeepsLegacyOnlyCompatibility(t *testing.T) {
	authCfg := &agentLegacyOnlyAuthConfig{}
	if _, ok := any(authCfg).(interface {
		ActiveTokenWithError(string) (string, string, error)
	}); ok {
		t.Fatal("legacy-only fixture must not accidentally implement the resolver")
	}

	err := requireOAuthToken(agentFactoryForAuth(authCfg))
	require.NoError(t, err)
	require.Equal(t, 1, authCfg.legacyCalls)
}
