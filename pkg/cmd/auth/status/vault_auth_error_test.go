package status

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/cli/cli/v2/internal/config"
	"github.com/cli/cli/v2/internal/gh"
	"github.com/cli/cli/v2/internal/keyring"
	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/cli/cli/v2/pkg/iostreams"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errSyntheticVaultStatus = errors.New("synthetic Vault retrieval denied")
var errSyntheticInactiveVaultStatus = errors.New("synthetic Vault retrieval denied for inactive account")
var errSyntheticExcludedVaultStatus = errors.New("synthetic Vault retrieval denied for excluded host")
var errSyntheticInactiveStatusNotFound = &syntheticStatusNotFoundError{cause: keyring.ErrNotFound}

type markedStatusVaultError struct {
	cause error
}

func (e *markedStatusVaultError) Error() string {
	return e.cause.Error()
}

func (e *markedStatusVaultError) Unwrap() error {
	return e.cause
}

func (*markedStatusVaultError) IsAutomicVaultCredentialResolution() bool {
	return true
}

type outerStatusVaultError struct {
	cause error
}

func (e *outerStatusVaultError) Error() string {
	return "synthetic outer Vault retrieval failure: " + e.cause.Error()
}

func (e *outerStatusVaultError) Unwrap() error {
	return e.cause
}

func markStatusVaultError(cause error) error {
	return &outerStatusVaultError{cause: &markedStatusVaultError{cause: cause}}
}

type statusVaultResolutionMarker interface {
	IsAutomicVaultCredentialResolution() bool
}

var _ statusVaultResolutionMarker = (*markedStatusVaultError)(nil)

type syntheticStatusNotFoundError struct {
	cause error
}

func (e *syntheticStatusNotFoundError) Error() string {
	return "synthetic inactive credential absence"
}

func (e *syntheticStatusNotFoundError) Unwrap() error {
	return e.cause
}

func TestMarkedStatusVaultErrorPreservesMarkerAndCauseThroughOuterWrapper(t *testing.T) {
	err := markStatusVaultError(errSyntheticVaultStatus)
	_, directlyMarked := err.(statusVaultResolutionMarker)
	assert.False(t, directlyMarked)

	var marker statusVaultResolutionMarker
	assert.True(t, errors.As(err, &marker))
	assert.True(t, marker.IsAutomicVaultCredentialResolution())
	assert.ErrorIs(t, err, errSyntheticVaultStatus)
}

type statusResolutionCall struct {
	kind     string
	hostname string
	username string
}

type statusVaultAuthConfig struct {
	*config.AuthConfig
	legacyCalls   int
	resolverCalls int
	resolution    []statusResolutionCall
}

var _ gh.AuthConfig = (*statusVaultAuthConfig)(nil)

func (c *statusVaultAuthConfig) Hosts() []string {
	return []string{"github.com"}
}

func (c *statusVaultAuthConfig) ActiveToken(hostname string) (string, string) {
	c.legacyCalls++
	c.resolution = append(c.resolution, statusResolutionCall{kind: "legacy", hostname: hostname})
	return "synthetic-poison-token", "synthetic-poison-source"
}

func (c *statusVaultAuthConfig) ActiveTokenWithError(hostname string) (string, string, error) {
	c.resolverCalls++
	c.resolution = append(c.resolution, statusResolutionCall{kind: "active", hostname: hostname})
	return "synthetic-poison-token", "synthetic-poison-source", markStatusVaultError(errSyntheticVaultStatus)
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
	httpClientCalls := 0
	err := statusRun(&StatusOptions{
		Hostname: "github.com",
		IO:       ios,
		Config: func() (gh.Config, error) {
			return mockConfig, nil
		},
		HttpClient: func() (*http.Client, error) {
			httpClientCalls++
			return &http.Client{Transport: transport}, nil
		},
	})

	assert.Empty(t, stdout.String(), "Vault retrieval failure must not emit a successful status on stdout")
	assert.Equal(t, 0, httpClientCalls, "Vault retrieval failure must prevent HTTP client construction")
	assert.Equal(t, 0, transport.calls, "Vault retrieval failure must prevent all HTTP requests")
	assert.Equal(t, 0, authCfg.legacyCalls, "Vault retrieval failure must not use the legacy token getter")
	assert.Equal(t, 1, authCfg.resolverCalls, "Vault retrieval failure must use the error-aware token resolver once")
	assert.Equal(t, []statusResolutionCall{{kind: "active", hostname: "github.com"}}, authCfg.resolution)
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
	httpClientCalls := 0
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
			httpClientCalls++
			return &http.Client{Transport: transport}, nil
		},
	})

	assert.Empty(t, stdout.String(), "operational Vault failure must not emit successful JSON")
	assert.Equal(t, "github.com\n  X Vault retrieval unavailable.\n  - Active account: true\n", stderr.String())
	assert.Equal(t, 0, httpClientCalls)
	assert.Equal(t, 0, transport.calls)
	assert.Equal(t, 0, authCfg.legacyCalls)
	assert.Equal(t, 1, authCfg.resolverCalls)
	assert.Equal(t, []statusResolutionCall{{kind: "active", hostname: "github.com"}}, authCfg.resolution)
	output := strings.ToLower(stdout.String() + stderr.String())
	assert.NotContains(t, output, "undefined")
	assert.NotContains(t, output, "synthetic-poison-token")
	assert.NotContains(t, output, "synthetic-poison-source")
	assert.NotContains(t, output, "synthetic-account")
	require.ErrorIs(t, err, cmdutil.SilentError)
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
	httpClientCalls := 0
	err := statusRun(&StatusOptions{
		Hostname: "github.com",
		IO:       ios,
		Config: func() (gh.Config, error) {
			return mockConfig, nil
		},
		HttpClient: func() (*http.Client, error) {
			httpClientCalls++
			return &http.Client{Transport: transport}, nil
		},
	})

	require.ErrorIs(t, err, cmdutil.SilentError)
	require.Empty(t, stdout.String())
	output := strings.ToLower(stderr.String())
	require.Contains(t, output, "invalid")
	require.Contains(t, output, "active account: true")
	require.NotContains(t, output, "vault")
	require.NotContains(t, output, "retrieval")
	require.Equal(t, 1, httpClientCalls)
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
	httpClientCalls := 0
	err := statusRun(&StatusOptions{
		Hostname: "github.com",
		IO:       ios,
		Config: func() (gh.Config, error) {
			return mockConfig, nil
		},
		HttpClient: func() (*http.Client, error) {
			httpClientCalls++
			return &http.Client{Transport: transport}, nil
		},
	})

	assert.Empty(t, stdout.String())
	assert.Equal(t, 0, httpClientCalls, "inactive Vault retrieval failure must prevent HTTP client construction")
	assert.Equal(t, 0, transport.calls, "all selected credential errors must be resolved before any HTTP request")
	assert.Equal(t, 0, multiAccountAuthCfg.legacyCalls)
	assert.Equal(t, 1, multiAccountAuthCfg.activeResolverCalls)
	assert.Equal(t, 1, multiAccountAuthCfg.perUserCalls)
	assert.Equal(t, "github.com", multiAccountAuthCfg.activeResolverHost)
	assert.Equal(t, "github.com", multiAccountAuthCfg.perUserHost)
	assert.Equal(t, "synthetic-secondary-account", multiAccountAuthCfg.perUser)
	assert.Equal(t, []statusResolutionCall{
		{kind: "active", hostname: "github.com"},
		{kind: "inactive", hostname: "github.com", username: "synthetic-secondary-account"},
	}, multiAccountAuthCfg.resolution)
	assert.Equal(t, "github.com\n  X Vault retrieval unavailable.\n  - Active account: false\n", stderr.String())
	output := strings.ToLower(stdout.String() + stderr.String())
	assert.NotContains(t, output, "invalid")
	assert.NotContains(t, output, "login")
	assert.NotContains(t, output, "refresh")
	assert.NotContains(t, output, "synthetic-active-token")
	assert.NotContains(t, output, "synthetic-poison-token")
	assert.NotContains(t, output, "synthetic-poison-source")
	assert.NotContains(t, output, "synthetic-keyring")
	assert.NotContains(t, output, "synthetic-account")
	assert.NotContains(t, output, "synthetic-secondary-account")
	require.ErrorIs(t, err, cmdutil.SilentError)
}

type multiAccountStatusVaultAuthConfig struct {
	*statusVaultAuthConfig
	activeResolverCalls int
	activeResolverHost  string
	perUserCalls        int
	perUserHost         string
	perUser             string
}

func (c *multiAccountStatusVaultAuthConfig) ActiveTokenWithError(hostname string) (string, string, error) {
	c.activeResolverCalls++
	c.activeResolverHost = hostname
	c.resolution = append(c.resolution, statusResolutionCall{kind: "active", hostname: hostname})
	return "synthetic-active-token", "synthetic-keyring", nil
}

func (c *multiAccountStatusVaultAuthConfig) TokenForUser(hostname, username string) (string, string, error) {
	c.perUserCalls++
	c.perUserHost = hostname
	c.perUser = username
	c.resolution = append(c.resolution, statusResolutionCall{kind: "inactive", hostname: hostname, username: username})
	return "synthetic-poison-token", "synthetic-poison-source", markStatusVaultError(errSyntheticInactiveVaultStatus)
}

func (c *multiAccountStatusVaultAuthConfig) UsersForHost(string) []string {
	return []string{"synthetic-secondary-account"}
}

type orderedStatusAuthConfig struct {
	*config.AuthConfig
	legacyCalls    int
	resolution     []statusResolutionCall
	activeUserHost []string
	usersHost      []string
}

var _ gh.AuthConfig = (*orderedStatusAuthConfig)(nil)

func (c *orderedStatusAuthConfig) Hosts() []string {
	return []string{"alpha.example.com", "github.com", "zulu.example.com"}
}

func (c *orderedStatusAuthConfig) ActiveToken(hostname string) (string, string) {
	c.legacyCalls++
	c.resolution = append(c.resolution, statusResolutionCall{kind: "legacy", hostname: hostname})
	return "synthetic-ordered-poison-token", "synthetic-ordered-poison-source"
}

func (c *orderedStatusAuthConfig) ActiveTokenWithError(hostname string) (string, string, error) {
	c.resolution = append(c.resolution, statusResolutionCall{kind: "active", hostname: hostname})
	switch hostname {
	case "alpha.example.com":
		return "synthetic-alpha-active-token", "synthetic-alpha-source", nil
	case "github.com":
		return "synthetic-github-active-token", "synthetic-github-source", nil
	case "zulu.example.com":
		return "synthetic-zulu-active-token", "synthetic-zulu-source", nil
	default:
		return "synthetic-unexpected-token", "synthetic-unexpected-source", nil
	}
}

func (c *orderedStatusAuthConfig) ActiveUser(hostname string) (string, error) {
	c.activeUserHost = append(c.activeUserHost, hostname)
	switch hostname {
	case "alpha.example.com":
		return "synthetic-alpha-active-account", nil
	case "github.com":
		return "synthetic-github-active-account", nil
	case "zulu.example.com":
		return "synthetic-zulu-active-account", nil
	default:
		return "synthetic-unexpected-account", nil
	}
}

func (c *orderedStatusAuthConfig) UsersForHost(hostname string) []string {
	c.usersHost = append(c.usersHost, hostname)
	switch hostname {
	case "alpha.example.com":
		return []string{"synthetic-alpha-inactive-account"}
	case "github.com":
		return []string{"synthetic-github-inactive-account"}
	case "zulu.example.com":
		return []string{"synthetic-zulu-inactive-account"}
	default:
		return nil
	}
}

func (c *orderedStatusAuthConfig) TokenForUser(hostname, username string) (string, string, error) {
	c.resolution = append(c.resolution, statusResolutionCall{kind: "inactive", hostname: hostname, username: username})
	switch {
	case hostname == "alpha.example.com" && username == "synthetic-alpha-inactive-account":
		return "synthetic-alpha-inactive-token", "synthetic-alpha-source", nil
	case hostname == "github.com" && username == "synthetic-github-inactive-account":
		return "synthetic-github-inactive-poison-token", "synthetic-github-inactive-poison-source", markStatusVaultError(errSyntheticInactiveVaultStatus)
	case hostname == "zulu.example.com" && username == "synthetic-zulu-inactive-account":
		return "synthetic-zulu-inactive-token", "synthetic-zulu-source", nil
	default:
		return "synthetic-unexpected-token", "synthetic-unexpected-source", nil
	}
}

type statusOrderedRunResult struct {
	auth        *orderedStatusAuthConfig
	transport   *statusCountingTransport
	clientCalls int
	stdout      string
	stderr      string
	err         error
}

func runOrderedStatus(t *testing.T, exporter cmdutil.Exporter, showToken bool) statusOrderedRunResult {
	t.Helper()
	authCfg := &orderedStatusAuthConfig{AuthConfig: &config.AuthConfig{}}
	mockConfig := config.NewMockConfigFromString("")
	mockConfig.AuthenticationFunc = func() gh.AuthConfig {
		return authCfg
	}
	mockConfig.GitProtocolFunc = func(string) gh.ConfigEntry {
		return gh.ConfigEntry{Value: "https"}
	}

	transport := &statusCountingTransport{}
	ios, _, stdout, stderr := iostreams.Test()
	httpClientCalls := 0
	statusExporter := exporter
	if statusExporter == nil && showToken {
		jsonExporter := cmdutil.NewJSONExporter()
		jsonExporter.SetFields([]string{"hosts"})
		statusExporter = jsonExporter
	}
	err := statusRun(&StatusOptions{
		IO:        ios,
		ShowToken: showToken,
		Exporter:  statusExporter,
		Config: func() (gh.Config, error) {
			return mockConfig, nil
		},
		HttpClient: func() (*http.Client, error) {
			httpClientCalls++
			return &http.Client{Transport: transport}, nil
		},
	})

	return statusOrderedRunResult{
		auth:        authCfg,
		transport:   transport,
		clientCalls: httpClientCalls,
		stdout:      stdout.String(),
		stderr:      stderr.String(),
		err:         err,
	}
}

func requireNoOrderedStatusCredentialMaterial(t *testing.T, output string) {
	t.Helper()
	output = strings.ToLower(output)
	for _, forbidden := range []string{
		"synthetic-alpha-active-token",
		"synthetic-alpha-inactive-token",
		"synthetic-alpha-active-account",
		"synthetic-alpha-inactive-account",
		"synthetic-github-active-token",
		"synthetic-github-inactive-poison-token",
		"synthetic-github-active-account",
		"synthetic-github-inactive-account",
		"synthetic-zulu-active-token",
		"synthetic-zulu-active-account",
		"synthetic-ordered-poison-token",
		"synthetic-ordered-poison-source",
		"undefined",
	} {
		assert.NotContains(t, output, forbidden)
	}
}

func TestStatusRunPreflightsOrderedHostsAndAccountsBeforeAnyOutputOrNetwork(t *testing.T) {
	result := runOrderedStatus(t, nil, false)

	assert.Empty(t, result.stdout)
	assert.Equal(t, 0, result.clientCalls, "selected credential failure must occur before HTTP client construction")
	assert.Equal(t, 0, result.transport.calls, "selected credential failure must occur before HTTP requests")
	assert.Equal(t, 0, result.auth.legacyCalls)
	assert.Equal(t, []statusResolutionCall{
		{kind: "active", hostname: "alpha.example.com"},
		{kind: "inactive", hostname: "alpha.example.com", username: "synthetic-alpha-inactive-account"},
		{kind: "active", hostname: "github.com"},
		{kind: "inactive", hostname: "github.com", username: "synthetic-github-inactive-account"},
	}, result.auth.resolution)
	assert.NotContains(t, result.auth.activeUserHost, "zulu.example.com")
	assert.NotContains(t, result.auth.usersHost, "zulu.example.com")
	assert.Equal(t, "github.com\n  X Vault retrieval unavailable.\n  - Active account: false\n", result.stderr)
	requireNoOrderedStatusCredentialMaterial(t, result.stdout+result.stderr)
	output := strings.ToLower(result.stdout + result.stderr)
	assert.NotContains(t, output, "invalid")
	assert.NotContains(t, output, "logged in")
	assert.NotContains(t, output, "not logged in")
	assert.NotContains(t, output, "signed out")
	assert.NotContains(t, output, "re-authenticate")
	assert.NotContains(t, output, "authenticate")
	assert.NotContains(t, output, "authorize")
	assert.NotContains(t, output, "sign in")
	assert.NotContains(t, output, "login")
	assert.NotContains(t, output, "refresh")
	require.ErrorIs(t, result.err, cmdutil.SilentError)
}

func TestStatusRunPreflightsOrderedHostsAndAccountsBeforeJSONOutput(t *testing.T) {
	exporter := cmdutil.NewJSONExporter()
	exporter.SetFields([]string{"hosts"})
	result := runOrderedStatus(t, exporter, true)

	assert.Empty(t, result.stdout, "operational credential failure must not emit partial JSON")
	assert.Equal(t, 0, result.clientCalls, "selected credential failure must occur before HTTP client construction")
	assert.Equal(t, 0, result.transport.calls)
	assert.Equal(t, 0, result.auth.legacyCalls)
	assert.Equal(t, []statusResolutionCall{
		{kind: "active", hostname: "alpha.example.com"},
		{kind: "inactive", hostname: "alpha.example.com", username: "synthetic-alpha-inactive-account"},
		{kind: "active", hostname: "github.com"},
		{kind: "inactive", hostname: "github.com", username: "synthetic-github-inactive-account"},
	}, result.auth.resolution)
	assert.NotContains(t, result.auth.activeUserHost, "zulu.example.com")
	assert.NotContains(t, result.auth.usersHost, "zulu.example.com")
	assert.Equal(t, "github.com\n  X Vault retrieval unavailable.\n  - Active account: false\n", result.stderr)
	requireNoOrderedStatusCredentialMaterial(t, result.stdout+result.stderr)
	require.ErrorIs(t, result.err, cmdutil.SilentError)
}

type legacyOnlyStatusAuthConfig struct {
	gh.AuthConfig
	legacyCalls int
}

var _ gh.AuthConfig = (*legacyOnlyStatusAuthConfig)(nil)

type statusActiveTokenResolver interface {
	ActiveTokenWithError(string) (string, string, error)
}

func (c *legacyOnlyStatusAuthConfig) Hosts() []string {
	return []string{"github.com"}
}

func (c *legacyOnlyStatusAuthConfig) ActiveToken(string) (string, string) {
	c.legacyCalls++
	return "synthetic-legacy-status-token", "synthetic-legacy-status-source"
}

func (c *legacyOnlyStatusAuthConfig) ActiveUser(string) (string, error) {
	return "synthetic-legacy-status-account", nil
}

func (c *legacyOnlyStatusAuthConfig) UsersForHost(string) []string {
	return nil
}

type statusSuccessTransport struct {
	calls         int
	authorization string
}

func (t *statusSuccessTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.calls++
	t.authorization = req.Header.Get("Authorization")
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("")),
		Request:    req,
	}, nil
}

func TestStatusRunLegacyOnlyAuthConfigRemainsCompatible(t *testing.T) {
	authCfg := &legacyOnlyStatusAuthConfig{}
	_, implementsResolver := any(authCfg).(statusActiveTokenResolver)
	assert.False(t, implementsResolver, "legacy-only fixture must not gain a promoted error-aware resolver")
	mockConfig := config.NewMockConfigFromString("")
	mockConfig.AuthenticationFunc = func() gh.AuthConfig {
		return authCfg
	}
	mockConfig.GitProtocolFunc = func(string) gh.ConfigEntry {
		return gh.ConfigEntry{Value: "https"}
	}

	transport := &statusSuccessTransport{}
	ios, _, stdout, stderr := iostreams.Test()
	httpClientCalls := 0
	err := statusRun(&StatusOptions{
		IO: ios,
		Config: func() (gh.Config, error) {
			return mockConfig, nil
		},
		HttpClient: func() (*http.Client, error) {
			httpClientCalls++
			return &http.Client{Transport: transport}, nil
		},
	})

	require.NoError(t, err)
	assert.Equal(t, 1, authCfg.legacyCalls)
	assert.Equal(t, 1, httpClientCalls)
	assert.Equal(t, 1, transport.calls)
	assert.Equal(t, "token synthetic-legacy-status-token", transport.authorization)
	assert.Contains(t, stdout.String(), "Logged in to github.com account synthetic-legacy-status-account (synthetic-legacy-status-source)")
	assert.Empty(t, stderr.String())
}

type statusAbsentAuthConfig struct {
	*config.AuthConfig
	legacyCalls   int
	resolverCalls int
}

var _ gh.AuthConfig = (*statusAbsentAuthConfig)(nil)

func (c *statusAbsentAuthConfig) Hosts() []string {
	return []string{"github.com"}
}

func (c *statusAbsentAuthConfig) ActiveToken(string) (string, string) {
	c.legacyCalls++
	return "synthetic-absence-poison-token", "synthetic-absence-poison-source"
}

func (c *statusAbsentAuthConfig) ActiveTokenWithError(string) (string, string, error) {
	c.resolverCalls++
	return "", "", nil
}

func (c *statusAbsentAuthConfig) ActiveUser(string) (string, error) {
	return "synthetic-absence-account", nil
}

func (c *statusAbsentAuthConfig) UsersForHost(string) []string {
	return nil
}

func TestStatusRunErrorAwareAbsenceRetainsProvider401Behavior(t *testing.T) {
	authCfg := &statusAbsentAuthConfig{AuthConfig: &config.AuthConfig{}}
	mockConfig := config.NewMockConfigFromString("")
	mockConfig.AuthenticationFunc = func() gh.AuthConfig {
		return authCfg
	}
	mockConfig.GitProtocolFunc = func(string) gh.ConfigEntry {
		return gh.ConfigEntry{Value: "https"}
	}

	transport := &statusUnauthorizedTransport{}
	ios, _, stdout, stderr := iostreams.Test()
	httpClientCalls := 0
	err := statusRun(&StatusOptions{
		IO: ios,
		Config: func() (gh.Config, error) {
			return mockConfig, nil
		},
		HttpClient: func() (*http.Client, error) {
			httpClientCalls++
			return &http.Client{Transport: transport}, nil
		},
	})

	output := strings.ToLower(stdout.String() + stderr.String())
	require.ErrorIs(t, err, cmdutil.SilentError)
	assert.Empty(t, stdout.String())
	assert.Contains(t, output, "invalid")
	assert.Contains(t, output, "re-authenticate")
	assert.Contains(t, output, "gh auth login")
	assert.NotContains(t, output, "vault")
	assert.NotContains(t, output, "retrieval")
	assert.NotContains(t, output, "synthetic-absence-poison-token")
	assert.NotContains(t, output, "synthetic-absence-poison-source")
	assert.NotContains(t, output, "undefined")
	assert.Equal(t, 1, authCfg.resolverCalls)
	assert.Equal(t, 0, authCfg.legacyCalls)
	assert.Equal(t, 1, httpClientCalls)
	assert.Equal(t, 1, transport.calls)
	assert.Equal(t, "token ", transport.authorization)
}

type inactiveAbsenceStatusAuthConfig struct {
	*config.AuthConfig
	legacyCalls       int
	resolverCalls     int
	inactiveCalls     int
	resolution        []statusResolutionCall
	lastInactiveError error
}

var _ gh.AuthConfig = (*inactiveAbsenceStatusAuthConfig)(nil)

func (c *inactiveAbsenceStatusAuthConfig) Hosts() []string {
	return []string{"github.com"}
}

func (c *inactiveAbsenceStatusAuthConfig) ActiveToken(string) (string, string) {
	c.legacyCalls++
	return "synthetic-inactive-absence-poison-token", "synthetic-inactive-absence-poison-source"
}

func (c *inactiveAbsenceStatusAuthConfig) ActiveTokenWithError(hostname string) (string, string, error) {
	c.resolverCalls++
	c.resolution = append(c.resolution, statusResolutionCall{kind: "active", hostname: hostname})
	return "synthetic-inactive-absence-active-token", "synthetic-inactive-absence-source", nil
}

func (c *inactiveAbsenceStatusAuthConfig) ActiveUser(string) (string, error) {
	return "synthetic-inactive-absence-active-account", nil
}

func (c *inactiveAbsenceStatusAuthConfig) UsersForHost(string) []string {
	return []string{"synthetic-inactive-absence-account"}
}

func (c *inactiveAbsenceStatusAuthConfig) TokenForUser(hostname, username string) (string, string, error) {
	c.inactiveCalls++
	c.resolution = append(c.resolution, statusResolutionCall{kind: "inactive", hostname: hostname, username: username})
	c.lastInactiveError = errSyntheticInactiveStatusNotFound
	return "", "default", c.lastInactiveError
}

type statusActiveThenUnauthorizedTransport struct {
	calls          int
	authorizations []string
}

func (t *statusActiveThenUnauthorizedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.calls++
	t.authorizations = append(t.authorizations, req.Header.Get("Authorization"))
	statusCode := http.StatusUnauthorized
	if t.calls == 1 {
		statusCode = http.StatusOK
	}
	return &http.Response{
		StatusCode: statusCode,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("")),
		Request:    req,
	}, nil
}

func TestStatusRunInactiveCredentialAbsenceRetainsInvalidCredentialBehavior(t *testing.T) {
	authCfg := &inactiveAbsenceStatusAuthConfig{AuthConfig: &config.AuthConfig{}}
	mockConfig := config.NewMockConfigFromString("")
	mockConfig.AuthenticationFunc = func() gh.AuthConfig {
		return authCfg
	}
	mockConfig.GitProtocolFunc = func(string) gh.ConfigEntry {
		return gh.ConfigEntry{Value: "https"}
	}

	transport := &statusActiveThenUnauthorizedTransport{}
	ios, _, stdout, stderr := iostreams.Test()
	httpClientCalls := 0
	err := statusRun(&StatusOptions{
		IO: ios,
		Config: func() (gh.Config, error) {
			return mockConfig, nil
		},
		HttpClient: func() (*http.Client, error) {
			httpClientCalls++
			return &http.Client{Transport: transport}, nil
		},
	})

	output := strings.ToLower(stdout.String() + stderr.String())
	require.ErrorIs(t, err, cmdutil.SilentError)
	assert.Empty(t, stdout.String())
	assert.Contains(t, output, "synthetic-inactive-absence-active-account")
	assert.Contains(t, output, "synthetic-inactive-absence-account")
	assert.Contains(t, output, "default")
	assert.Contains(t, output, "active account: false")
	assert.Contains(t, output, "invalid")
	assert.Contains(t, output, "re-authenticate")
	assert.Contains(t, output, "gh auth login")
	for _, forbidden := range []string{
		"vault",
		"retrieval",
		"synthetic-inactive-absence-poison-token",
		"synthetic-inactive-absence-poison-source",
		"synthetic inactive credential absence",
		"undefined",
	} {
		assert.NotContains(t, output, forbidden)
	}
	var marker statusVaultResolutionMarker
	assert.ErrorIs(t, authCfg.lastInactiveError, keyring.ErrNotFound)
	assert.False(t, errors.As(authCfg.lastInactiveError, &marker))
	assert.Equal(t, []statusResolutionCall{
		{kind: "active", hostname: "github.com"},
		{kind: "inactive", hostname: "github.com", username: "synthetic-inactive-absence-account"},
	}, authCfg.resolution)
	assert.Equal(t, 1, authCfg.resolverCalls)
	assert.Equal(t, 1, authCfg.inactiveCalls)
	assert.Equal(t, 0, authCfg.legacyCalls)
	assert.Equal(t, 1, httpClientCalls)
	assert.Equal(t, 2, transport.calls)
	assert.Equal(t, []string{"token synthetic-inactive-absence-active-token", "token "}, transport.authorizations)
}

type filterStatusAuthConfig struct {
	*config.AuthConfig
	legacyCalls       int
	resolverCalls     int
	inactiveCalls     int
	resolution        []statusResolutionCall
	activeErrorHost   string
	inactiveErrorHost string
	ignoredError      error
}

var _ gh.AuthConfig = (*filterStatusAuthConfig)(nil)

func (c *filterStatusAuthConfig) Hosts() []string {
	return []string{"alpha.example.com", "github.com"}
}

func (c *filterStatusAuthConfig) ActiveToken(hostname string) (string, string) {
	c.legacyCalls++
	c.resolution = append(c.resolution, statusResolutionCall{kind: "legacy", hostname: hostname})
	return "synthetic-filter-poison-token", "synthetic-filter-poison-source"
}

func (c *filterStatusAuthConfig) ActiveTokenWithError(hostname string) (string, string, error) {
	c.resolverCalls++
	c.resolution = append(c.resolution, statusResolutionCall{kind: "active", hostname: hostname})
	if hostname == c.activeErrorHost {
		return "synthetic-filter-active-poison-token", "synthetic-filter-active-poison-source", markStatusVaultError(errSyntheticExcludedVaultStatus)
	}
	return "synthetic-filter-active-token", "synthetic-filter-source", nil
}

func (c *filterStatusAuthConfig) ActiveUser(hostname string) (string, error) {
	return "synthetic-filter-active-account-" + hostname, nil
}

func (c *filterStatusAuthConfig) UsersForHost(hostname string) []string {
	return []string{"synthetic-filter-inactive-account-" + hostname}
}

func (c *filterStatusAuthConfig) TokenForUser(hostname, username string) (string, string, error) {
	c.inactiveCalls++
	c.resolution = append(c.resolution, statusResolutionCall{kind: "inactive", hostname: hostname, username: username})
	if hostname == c.inactiveErrorHost {
		return "synthetic-filter-inactive-poison-token", "synthetic-filter-inactive-poison-source", markStatusVaultError(c.ignoredError)
	}
	return "synthetic-filter-inactive-token-" + hostname, "synthetic-filter-source-" + hostname, nil
}

func runFilterStatus(t *testing.T, opts StatusOptions, authCfg *filterStatusAuthConfig) (stdout, stderr string, clientCalls, transportCalls int, err error) {
	t.Helper()
	mockConfig := config.NewMockConfigFromString("")
	mockConfig.AuthenticationFunc = func() gh.AuthConfig {
		return authCfg
	}
	mockConfig.GitProtocolFunc = func(string) gh.ConfigEntry {
		return gh.ConfigEntry{Value: "https"}
	}
	transport := &statusSuccessTransport{}
	ios, _, out, errOut := iostreams.Test()
	opts.IO = ios
	opts.Config = func() (gh.Config, error) {
		return mockConfig, nil
	}
	clientCalls = 0
	opts.HttpClient = func() (*http.Client, error) {
		clientCalls++
		return &http.Client{Transport: transport}, nil
	}
	err = statusRun(&opts)
	return out.String(), errOut.String(), clientCalls, transport.calls, err
}

func TestStatusRunActiveFilterDoesNotResolveIgnoredInactiveAccounts(t *testing.T) {
	authCfg := &filterStatusAuthConfig{
		AuthConfig:        &config.AuthConfig{},
		inactiveErrorHost: "github.com",
		ignoredError:      errSyntheticInactiveVaultStatus,
	}
	stdout, stderr, clientCalls, transportCalls, err := runFilterStatus(t, StatusOptions{Active: true}, authCfg)

	require.NoError(t, err)
	assert.Empty(t, stderr)
	assert.NotEmpty(t, stdout)
	assert.Equal(t, 2, authCfg.resolverCalls)
	assert.Equal(t, 0, authCfg.legacyCalls)
	assert.Equal(t, 0, authCfg.inactiveCalls)
	assert.Equal(t, []statusResolutionCall{
		{kind: "active", hostname: "alpha.example.com"},
		{kind: "active", hostname: "github.com"},
	}, authCfg.resolution)
	assert.Equal(t, 1, clientCalls)
	assert.Equal(t, 2, transportCalls)
	output := strings.ToLower(stdout + stderr)
	assert.Contains(t, output, "synthetic-filter-active-account")
	assert.NotContains(t, output, "synthetic-filter-inactive")
}

func TestStatusRunHostnameFilterDoesNotResolveExcludedHost(t *testing.T) {
	authCfg := &filterStatusAuthConfig{
		AuthConfig:        &config.AuthConfig{},
		activeErrorHost:   "github.com",
		inactiveErrorHost: "github.com",
		ignoredError:      errSyntheticExcludedVaultStatus,
	}
	stdout, stderr, clientCalls, transportCalls, err := runFilterStatus(t, StatusOptions{Hostname: "alpha.example.com"}, authCfg)

	require.NoError(t, err)
	assert.Empty(t, stderr)
	assert.NotEmpty(t, stdout)
	assert.Equal(t, 1, authCfg.resolverCalls)
	assert.Equal(t, 0, authCfg.legacyCalls)
	assert.Equal(t, 1, authCfg.inactiveCalls)
	assert.Equal(t, []statusResolutionCall{
		{kind: "active", hostname: "alpha.example.com"},
		{kind: "inactive", hostname: "alpha.example.com", username: "synthetic-filter-inactive-account-alpha.example.com"},
	}, authCfg.resolution)
	assert.Equal(t, 1, clientCalls)
	assert.Equal(t, 2, transportCalls)
	output := strings.ToLower(stdout + stderr)
	assert.Contains(t, output, "synthetic-filter-active-account-alpha.example.com")
	assert.Contains(t, output, "synthetic-filter-inactive-account-alpha.example.com")
	for _, forbidden := range []string{
		"github.com",
		"synthetic-filter-active-poison-token",
		"synthetic-filter-active-poison-source",
		"synthetic-filter-inactive-poison-token",
		"synthetic-filter-inactive-poison-source",
		"synthetic vault retrieval denied",
	} {
		assert.NotContains(t, output, forbidden)
	}
}
