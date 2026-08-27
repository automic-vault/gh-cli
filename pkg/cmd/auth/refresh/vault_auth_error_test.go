package refresh

import (
	"errors"
	"net/http"
	"testing"

	"github.com/cli/cli/v2/internal/config"
	"github.com/cli/cli/v2/internal/gh"
	"github.com/cli/cli/v2/internal/prompter"
	"github.com/cli/cli/v2/pkg/iostreams"
	"github.com/stretchr/testify/require"
)

var errSyntheticRefreshVaultDenied = errors.New("synthetic Vault retrieval denied for refresh command")

type refreshVaultAuthConfig struct {
	*config.AuthConfig
	legacyCalls   int
	resolverCalls int
	loginCalls    int
}

func (c *refreshVaultAuthConfig) Hosts() []string {
	return []string{"github.com"}
}

func (c *refreshVaultAuthConfig) ActiveToken(string) (string, string) {
	c.legacyCalls++
	return "synthetic-poison-token", "synthetic-poison-source"
}

func (c *refreshVaultAuthConfig) ActiveTokenWithError(string) (string, string, error) {
	c.resolverCalls++
	return "synthetic-poison-token", "synthetic-poison-source", errSyntheticRefreshVaultDenied
}

func (c *refreshVaultAuthConfig) ActiveUser(string) (string, error) {
	return "synthetic-account", nil
}

func (c *refreshVaultAuthConfig) Login(string, string, string, string, bool) (bool, error) {
	c.loginCalls++
	return false, nil
}

type refreshRejectingTransport struct {
	calls int
}

func (t *refreshRejectingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	t.calls++
	return nil, errors.New("synthetic refresh transport must not be reached")
}

func TestRefreshRunOperationalVaultFailureStopsBeforeAuthFlowOrNetwork(t *testing.T) {
	authCfg := &refreshVaultAuthConfig{AuthConfig: &config.AuthConfig{}}
	mockConfig := config.NewMockConfigFromString("")
	mockConfig.AuthenticationFunc = func() gh.AuthConfig {
		return authCfg
	}

	transport := &refreshRejectingTransport{}
	ios, _, stdout, stderr := iostreams.Test()
	authFlowCalls := 0
	err := refreshRun(&RefreshOptions{
		IO:          ios,
		Hostname:    "github.com",
		ResetScopes: true,
		Prompter:    &prompter.PrompterMock{},
		Config: func() (gh.Config, error) {
			return mockConfig, nil
		},
		PlainHttpClient: func() (*http.Client, error) {
			return &http.Client{Transport: transport}, nil
		},
		AuthFlow: func(*http.Client, *iostreams.IOStreams, string, []string, bool, bool) (token, username, error) {
			authFlowCalls++
			return token("synthetic-flow-token"), username("synthetic-account"), nil
		},
	})

	require.ErrorIs(t, err, errSyntheticRefreshVaultDenied)
	require.Empty(t, stdout.String())
	require.Empty(t, stderr.String())
	require.Equal(t, 0, transport.calls)
	require.Equal(t, 0, authCfg.legacyCalls)
	require.Equal(t, 1, authCfg.resolverCalls)
	require.Equal(t, 0, authFlowCalls)
	require.Equal(t, 0, authCfg.loginCalls)
}
