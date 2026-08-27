package refresh

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/cli/cli/v2/internal/config"
	"github.com/cli/cli/v2/internal/gh"
	"github.com/cli/cli/v2/internal/prompter"
	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/cli/cli/v2/pkg/iostreams"
	"github.com/stretchr/testify/assert"
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

type refreshCompatibilityAuthConfig struct {
	*config.AuthConfig
	legacyToken   string
	legacySource  string
	token         string
	source        string
	err           error
	legacyCalls   int
	resolverCalls int
	loginCalls    int
	loginHost     string
	loginUser     string
	loginToken    string
	loginSecure   bool
}

func (c *refreshCompatibilityAuthConfig) Hosts() []string {
	return []string{"github.com"}
}

func (c *refreshCompatibilityAuthConfig) ActiveToken(string) (string, string) {
	c.legacyCalls++
	return c.legacyToken, c.legacySource
}

func (c *refreshCompatibilityAuthConfig) ActiveTokenWithError(string) (string, string, error) {
	c.resolverCalls++
	return c.token, c.source, c.err
}

func (c *refreshCompatibilityAuthConfig) ActiveUser(string) (string, error) {
	return "synthetic-account", nil
}

func (c *refreshCompatibilityAuthConfig) Login(hostname, user, token, _ string, secureStorage bool) (bool, error) {
	c.loginCalls++
	c.loginHost = hostname
	c.loginUser = user
	c.loginToken = token
	c.loginSecure = secureStorage
	return false, nil
}

type refreshScopeTransport struct {
	calls         int
	authorization string
}

func (t *refreshScopeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.calls++
	t.authorization = req.Header.Get("Authorization")
	return &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"X-Oauth-Scopes": []string{"repo, read:org"},
		},
		Body:    io.NopCloser(strings.NewReader("")),
		Request: req,
	}, nil
}

func refreshOutput(err error, stdout, stderr string) string {
	errText := ""
	if err != nil {
		errText = err.Error()
	}
	return strings.ToLower(errText + stdout + stderr)
}

func requireNoRefreshSecretMaterial(t *testing.T, output string) {
	t.Helper()
	for _, forbidden := range []string{
		"synthetic-poison-token",
		"synthetic-poison-source",
		"synthetic-account",
		"synthetic-flow-token",
		"undefined",
		"protocol=",
	} {
		assert.NotContains(t, output, forbidden)
	}
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
	plainHTTPClientCalls := 0
	err := refreshRun(&RefreshOptions{
		IO:          ios,
		Hostname:    "github.com",
		ResetScopes: true,
		Prompter:    &prompter.PrompterMock{},
		Config: func() (gh.Config, error) {
			return mockConfig, nil
		},
		PlainHttpClient: func() (*http.Client, error) {
			plainHTTPClientCalls++
			return &http.Client{Transport: transport}, nil
		},
		AuthFlow: func(*http.Client, *iostreams.IOStreams, string, []string, bool, bool) (token, username, error) {
			authFlowCalls++
			return token("synthetic-flow-token"), username("synthetic-account"), nil
		},
	})

	assert.Empty(t, stdout.String())
	assert.Empty(t, stderr.String())
	assert.Equal(t, 0, plainHTTPClientCalls)
	assert.Equal(t, 0, transport.calls)
	assert.Equal(t, 0, authCfg.legacyCalls)
	assert.Equal(t, 1, authCfg.resolverCalls)
	assert.Equal(t, 0, authFlowCalls)
	assert.Equal(t, 0, authCfg.loginCalls)
	requireNoRefreshSecretMaterial(t, refreshOutput(err, stdout.String(), stderr.String()))
	require.ErrorIs(t, err, errSyntheticRefreshVaultDenied)
}

func TestRefreshRunResolvedCredentialPreservesScopesAndAuthFlow(t *testing.T) {
	authCfg := &refreshCompatibilityAuthConfig{
		legacyToken:  "synthetic-legacy-token",
		legacySource: "synthetic-legacy-source",
		token:        "synthetic-resolved-token",
		source:       "synthetic-keyring",
	}
	mockConfig := config.NewMockConfigFromString("")
	mockConfig.AuthenticationFunc = func() gh.AuthConfig {
		return authCfg
	}

	transport := &refreshScopeTransport{}
	ios, _, stdout, stderr := iostreams.Test()
	authFlowCalls := 0
	var gotScopes []string
	err := refreshRun(&RefreshOptions{
		IO:       ios,
		Hostname: "github.com",
		Prompter: &prompter.PrompterMock{},
		Config: func() (gh.Config, error) {
			return mockConfig, nil
		},
		PlainHttpClient: func() (*http.Client, error) {
			return &http.Client{Transport: transport}, nil
		},
		AuthFlow: func(_ *http.Client, _ *iostreams.IOStreams, hostname string, scopes []string, interactive bool, clipboard bool) (token, username, error) {
			authFlowCalls++
			gotScopes = append([]string(nil), scopes...)
			if hostname != "github.com" || interactive || clipboard {
				t.Errorf("unexpected auth-flow context: host=%q interactive=%v clipboard=%v", hostname, interactive, clipboard)
			}
			return token("synthetic-refreshed-token"), username("synthetic-account"), nil
		},
	})

	assert.NoError(t, err)
	assert.Equal(t, "✓ Authentication complete.\n", stderr.String())
	assert.Empty(t, stdout.String())
	assert.Equal(t, 1, transport.calls)
	assert.Equal(t, "token synthetic-resolved-token", transport.authorization)
	assert.ElementsMatch(t, []string{"repo", "read:org"}, gotScopes)
	assert.Equal(t, 1, authFlowCalls)
	assert.Equal(t, 1, authCfg.loginCalls)
	assert.Equal(t, "github.com", authCfg.loginHost)
	assert.Equal(t, "synthetic-account", authCfg.loginUser)
	assert.Equal(t, "synthetic-refreshed-token", authCfg.loginToken)
	assert.True(t, authCfg.loginSecure)
	assert.Equal(t, 0, authCfg.legacyCalls)
	assert.Equal(t, 1, authCfg.resolverCalls)
	require.NoError(t, err)
}

func TestRefreshRunIntentionalAbsenceStillStartsAuthFlow(t *testing.T) {
	authCfg := &refreshCompatibilityAuthConfig{
		legacyToken:  "synthetic-legacy-token",
		legacySource: "synthetic-legacy-source",
	}
	mockConfig := config.NewMockConfigFromString("")
	mockConfig.AuthenticationFunc = func() gh.AuthConfig {
		return authCfg
	}

	transport := &refreshScopeTransport{}
	ios, _, stdout, stderr := iostreams.Test()
	authFlowCalls := 0
	err := refreshRun(&RefreshOptions{
		IO:       ios,
		Hostname: "github.com",
		// Reset avoids an old-scope request when the resolver reports no
		// configured credential; the auth flow remains the normal path.
		ResetScopes: true,
		Prompter:    &prompter.PrompterMock{},
		Config: func() (gh.Config, error) {
			return mockConfig, nil
		},
		PlainHttpClient: func() (*http.Client, error) {
			return &http.Client{Transport: transport}, nil
		},
		AuthFlow: func(_ *http.Client, _ *iostreams.IOStreams, _ string, _ []string, _ bool, _ bool) (token, username, error) {
			authFlowCalls++
			return token("synthetic-refreshed-token"), username("synthetic-account"), nil
		},
	})

	assert.NoError(t, err)
	assert.Equal(t, "✓ Authentication complete.\n", stderr.String())
	assert.Empty(t, stdout.String())
	assert.Equal(t, 0, transport.calls)
	assert.Equal(t, 1, authFlowCalls)
	assert.Equal(t, 1, authCfg.loginCalls)
	assert.Equal(t, 0, authCfg.legacyCalls)
	assert.Equal(t, 1, authCfg.resolverCalls)
	require.NoError(t, err)
}

func TestRefreshRunEnvironmentCredentialRemainsNonWritable(t *testing.T) {
	t.Setenv("GH_TOKEN", "synthetic-env-token")
	authCfg := &refreshCompatibilityAuthConfig{
		legacyToken:  "synthetic-env-token",
		legacySource: "GH_TOKEN",
		token:        "synthetic-env-token",
		source:       "GH_TOKEN",
	}
	mockConfig := config.NewMockConfigFromString("")
	mockConfig.AuthenticationFunc = func() gh.AuthConfig {
		return authCfg
	}

	transport := &refreshScopeTransport{}
	ios, _, stdout, stderr := iostreams.Test()
	authFlowCalls := 0
	err := refreshRun(&RefreshOptions{
		IO:       ios,
		Hostname: "github.com",
		Prompter: &prompter.PrompterMock{},
		Config: func() (gh.Config, error) {
			return mockConfig, nil
		},
		PlainHttpClient: func() (*http.Client, error) {
			return &http.Client{Transport: transport}, nil
		},
		AuthFlow: func(*http.Client, *iostreams.IOStreams, string, []string, bool, bool) (token, username, error) {
			authFlowCalls++
			return token("synthetic-refreshed-token"), username("synthetic-account"), nil
		},
	})

	assert.Empty(t, stdout.String())
	assert.Equal(t, "The value of the GH_TOKEN environment variable is being used for authentication.\nTo refresh credentials stored in GitHub CLI, first clear the value from the environment.\n", stderr.String())
	assert.Equal(t, 0, transport.calls)
	assert.Equal(t, 0, authFlowCalls)
	assert.Equal(t, 0, authCfg.loginCalls)
	assert.Equal(t, 0, authCfg.legacyCalls)
	assert.Equal(t, 1, authCfg.resolverCalls)
	require.ErrorIs(t, err, cmdutil.SilentError)
}
