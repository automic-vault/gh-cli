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
	legacyCalls   int
	resolverCalls int
}

var _ gh.AuthConfig = (*statusVaultAuthConfig)(nil)

func (c *statusVaultAuthConfig) Hosts() []string {
	return []string{"github.com"}
}

func (c *statusVaultAuthConfig) ActiveToken(string) (string, string) {
	c.legacyCalls++
	return "synthetic-poison-token", "synthetic-poison-source"
}

func (c *statusVaultAuthConfig) ActiveTokenWithError(string) (string, string, error) {
	c.resolverCalls++
	return "synthetic-poison-token", "synthetic-poison-source", errSyntheticVaultStatus
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
	assert.Equal(t, 0, authCfg.legacyCalls, "Vault retrieval failure must not use the legacy token getter")
	assert.Equal(t, 1, authCfg.resolverCalls, "Vault retrieval failure must use the error-aware token resolver once")
	assert.Equal(t, "github.com\n  X Vault retrieval unavailable.\n  - Active account: true\n", stderr.String())
	output := strings.ToLower(stdout.String() + stderr.String())
	assert.Contains(t, output, "vault")
	assert.Contains(t, output, "retrieval")
	for _, forbidden := range []string{
		"invalid",
		"logged out",
		"logged in",
		"not logged in",
		"signed out",
		"re-authenticate",
		"reauthenticate",
		"authenticate again",
		"authenticate",
		"authorize",
		"sign in",
		"signin",
		"gh auth login",
		"gh auth refresh",
		"login",
		"token expired",
		"credential expired",
		"undefined",
		"synthetic-poison-token",
		"synthetic-poison-source",
	} {
		assert.NotContains(t, output, forbidden)
	}
	require.ErrorIs(t, err, cmdutil.SilentError)
}

func TestStatusRunOperationalVaultFailureJSONFailsClosed(t *testing.T) {
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
	exporter := cmdutil.NewJSONExporter()
	exporter.SetFields([]string{"hosts"})
	err := statusRun(&StatusOptions{
		Hostname: "github.com",
		IO:       ios,
		Exporter: exporter,
		Config: func() (gh.Config, error) {
			return mockConfig, nil
		},
		HttpClient: func() (*http.Client, error) {
			return &http.Client{Transport: transport}, nil
		},
	})

	require.ErrorIs(t, err, cmdutil.SilentError)
	require.Empty(t, stdout.String(), "operational Vault failure must not emit successful JSON")
	require.Equal(t, "github.com\n  X Vault retrieval unavailable.\n  - Active account: true\n", stderr.String())
	require.Equal(t, 0, transport.calls)
	require.Equal(t, 0, authCfg.legacyCalls)
	require.Equal(t, 1, authCfg.resolverCalls)
	require.NotContains(t, strings.ToLower(stdout.String()+stderr.String()), "undefined")
}

type statusValidAuthConfig struct {
	*config.AuthConfig
	legacyCalls   int
	resolverCalls int
}

func (c *statusValidAuthConfig) Hosts() []string {
	return []string{"github.com"}
}

func (c *statusValidAuthConfig) ActiveToken(string) (string, string) {
	c.legacyCalls++
	return "synthetic-valid-token", "synthetic-keyring"
}

func (c *statusValidAuthConfig) ActiveTokenWithError(string) (string, string, error) {
	c.resolverCalls++
	return "synthetic-valid-token", "synthetic-keyring", nil
}

func (c *statusValidAuthConfig) ActiveUser(string) (string, error) {
	return "synthetic-account", nil
}

func (c *statusValidAuthConfig) UsersForHost(string) []string {
	return nil
}

type statusUnauthorizedTransport struct {
	calls         int
	authorization string
}

func (t *statusUnauthorizedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.calls++
	t.authorization = req.Header.Get("Authorization")
	return &http.Response{
		StatusCode: http.StatusUnauthorized,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("")),
		Request:    req,
	}, nil
}

func TestStatusRunPreservesProviderHTTP401AsInvalidCredential(t *testing.T) {
	authCfg := &statusValidAuthConfig{AuthConfig: &config.AuthConfig{}}
	mockConfig := config.NewMockConfigFromString("")
	mockConfig.AuthenticationFunc = func() gh.AuthConfig {
		return authCfg
	}
	mockConfig.GitProtocolFunc = func(string) gh.ConfigEntry {
		return gh.ConfigEntry{Value: "https"}
	}

	transport := &statusUnauthorizedTransport{}
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

	require.ErrorIs(t, err, cmdutil.SilentError)
	require.Empty(t, stdout.String())
	output := strings.ToLower(stderr.String())
	require.Contains(t, output, "invalid")
	require.NotContains(t, output, "vault")
	require.NotContains(t, output, "retrieval")
	require.Equal(t, 1, transport.calls)
	require.Equal(t, "token synthetic-valid-token", transport.authorization)
	require.Equal(t, 0, authCfg.legacyCalls)
	require.Equal(t, 1, authCfg.resolverCalls)
}

func TestStatusRunOperationalVaultFailureCoversInactiveAccounts(t *testing.T) {
	authCfg := &statusVaultAuthConfig{AuthConfig: &config.AuthConfig{}}
	mockConfig := config.NewMockConfigFromString("")
	mockConfig.AuthenticationFunc = func() gh.AuthConfig {
		return authCfg
	}
	mockConfig.GitProtocolFunc = func(string) gh.ConfigEntry {
		return gh.ConfigEntry{Value: "https"}
	}

	// Use a distinct wrapper for the multi-account fixture so the active and
	// inactive account list is explicit without changing production interfaces.
	multiAccountAuthCfg := &multiAccountStatusVaultAuthConfig{statusVaultAuthConfig: authCfg}
	mockConfig.AuthenticationFunc = func() gh.AuthConfig {
		return multiAccountAuthCfg
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

	require.ErrorIs(t, err, cmdutil.SilentError)
	require.Empty(t, stdout.String())
	require.Equal(t, 0, transport.calls)
	require.Equal(t, 0, multiAccountAuthCfg.legacyCalls)
	require.Equal(t, 2, multiAccountAuthCfg.resolverCalls)
	require.Equal(t, 2, strings.Count(stderr.String(), "Vault retrieval unavailable."))
	output := strings.ToLower(stdout.String() + stderr.String())
	require.NotContains(t, output, "invalid")
	require.NotContains(t, output, "login")
}

type multiAccountStatusVaultAuthConfig struct {
	*statusVaultAuthConfig
}

func (c *multiAccountStatusVaultAuthConfig) UsersForHost(string) []string {
	return []string{"synthetic-secondary-account"}
}
