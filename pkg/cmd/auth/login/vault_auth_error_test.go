package login

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/cli/cli/v2/internal/config"
	"github.com/cli/cli/v2/internal/gh"
	"github.com/cli/cli/v2/pkg/iostreams"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errSyntheticLoginCommandVaultDenied = errors.New("synthetic Vault retrieval denied for login command")

type loginCommandVaultAuthConfig struct {
	*config.AuthConfig
	legacyCalls   int
	resolverCalls int
	loginCalls    int
}

var _ gh.AuthConfig = (*loginCommandVaultAuthConfig)(nil)

func (c *loginCommandVaultAuthConfig) ActiveToken(string) (string, string) {
	c.legacyCalls++
	return "synthetic-login-poison-token", "synthetic-login-poison-source"
}

func (c *loginCommandVaultAuthConfig) ActiveTokenWithError(string) (string, string, error) {
	c.resolverCalls++
	return "synthetic-login-poison-token", "synthetic-login-poison-source", errSyntheticLoginCommandVaultDenied
}

func (c *loginCommandVaultAuthConfig) Login(string, string, string, string, bool) (bool, error) {
	c.loginCalls++
	return false, nil
}

type loginCommandCountingTransport struct {
	calls int
}

func (t *loginCommandCountingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.calls++
	body := ""
	if req.Method == http.MethodPost {
		body = `{"data":{"viewer":{"login":"synthetic-login-user"}}}`
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}, nil
}

func TestLoginRunOperationalVaultFailureStopsBeforeHTTPAndMutation(t *testing.T) {
	authCfg := &loginCommandVaultAuthConfig{AuthConfig: &config.AuthConfig{}}
	mockConfig := config.NewMockConfigFromString("")
	mockConfig.AuthenticationFunc = func() gh.AuthConfig {
		return authCfg
	}
	transport := &loginCommandCountingTransport{}
	plainClientCalls := 0
	httpClientCalls := 0
	ios, _, stdout, stderr := iostreams.Test()
	err := loginRun(&LoginOptions{
		IO:       ios,
		Hostname: "github.com",
		Token:    "synthetic-login-token",
		Config: func() (gh.Config, error) {
			return mockConfig, nil
		},
		PlainHttpClient: func() (*http.Client, error) {
			plainClientCalls++
			return &http.Client{Transport: transport}, nil
		},
		HttpClient: func() (*http.Client, error) {
			httpClientCalls++
			return &http.Client{Transport: transport}, nil
		},
	})

	assert.Equal(t, 0, plainClientCalls, "Vault resolution failure occurred after constructing the plain HTTP client")
	assert.Equal(t, 0, httpClientCalls, "Vault resolution failure occurred after constructing the authenticated HTTP client")
	assert.Equal(t, 0, transport.calls, "Vault resolution failure reached the HTTP transport")
	assert.Equal(t, 0, authCfg.loginCalls, "Vault resolution failure reached credential mutation")
	assert.Empty(t, stdout.String())
	assert.Empty(t, stderr.String())
	assert.Equal(t, 0, authCfg.legacyCalls, "login used the legacy token getter")
	assert.Equal(t, 1, authCfg.resolverCalls, "login did not attempt the error-aware resolver exactly once")
	combined := strings.ToLower(stdout.String() + stderr.String())
	if err != nil {
		combined += strings.ToLower(err.Error())
	}
	for _, forbidden := range []string{
		"synthetic-login-poison-token",
		"synthetic-login-poison-source",
		"synthetic-login-token",
		"synthetic-login-user",
		"undefined",
		"logged in",
		"log in",
		"re-authenticate",
	} {
		assert.NotContains(t, combined, forbidden)
	}
	require.ErrorIs(t, err, errSyntheticLoginCommandVaultDenied)
}
