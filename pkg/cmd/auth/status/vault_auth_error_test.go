package status

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/cli/cli/v2/internal/config"
	"github.com/cli/cli/v2/internal/gh"
	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/cli/cli/v2/pkg/iostreams"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errSyntheticVaultStatus = errors.New("synthetic Vault retrieval denied")

type statusVaultAuthConfig struct {
	*config.AuthConfig
}

var _ gh.AuthConfig = (*statusVaultAuthConfig)(nil)

func (c *statusVaultAuthConfig) Hosts() []string {
	return []string{"github.com"}
}

func (c *statusVaultAuthConfig) ActiveToken(string) (string, string) {
	return "synthetic-legacy-token", "legacy-host-slot"
}

func (c *statusVaultAuthConfig) ActiveTokenWithError(string) (string, string, error) {
	return "", "", errSyntheticVaultStatus
}

func (c *statusVaultAuthConfig) ActiveUser(string) (string, error) {
	return "synthetic-account", nil
}

func (c *statusVaultAuthConfig) UsersForHost(string) []string {
	return nil
}

type statusCountingTransport struct {
	calls int
}

func (t *statusCountingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.calls++
	return &http.Response{
		StatusCode: http.StatusNoContent,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("")),
		Request:    req,
	}, nil
}

func TestStatusRunReportsVaultRetrievalFailureBeforeNetwork(t *testing.T) {
	authCfg := &statusVaultAuthConfig{AuthConfig: &config.AuthConfig{}}
	mockConfig := config.NewMockConfigFromString("")
	mockConfig.AuthenticationFunc = func() gh.AuthConfig {
		return authCfg
	}
	mockConfig.GitProtocolFunc = func(string) gh.ConfigEntry {
		return gh.ConfigEntry{Value: "https"}
	}

	transport := &statusCountingTransport{}
	ios, _, stdout, stderr := iostreams.Test()
	err := statusRun(&StatusOptions{
		Hostname: "github.com",
		IO:       ios,
		Config: func() (gh.Config, error) {
			return mockConfig, nil
		},
		HttpClient: func() (*http.Client, error) {
			return &http.Client{Transport: transport}, nil
		},
	})

	assert.Empty(t, stdout.String(), "Vault retrieval failure must not emit a successful status on stdout")
	assert.Equal(t, 0, transport.calls, "Vault retrieval failure must prevent all HTTP requests")
	output := strings.ToLower(stdout.String() + stderr.String())
	assert.Contains(t, output, "vault")
	assert.Contains(t, output, "retrieval")
	assert.NotContains(t, output, "invalid")
	assert.NotContains(t, output, "logged out")
	assert.NotContains(t, output, "logged in")
	assert.NotContains(t, output, "not logged in")
	assert.NotContains(t, output, "signed out")
	assert.NotContains(t, output, "re-authenticate")
	assert.NotContains(t, output, "reauthenticate")
	assert.NotContains(t, output, "authenticate again")
	assert.NotContains(t, output, "log in")
	assert.NotContains(t, output, "login")
	assert.NotContains(t, output, "gh auth login")
	require.ErrorIs(t, err, cmdutil.SilentError)
}
