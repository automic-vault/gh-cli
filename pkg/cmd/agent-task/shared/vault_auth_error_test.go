package shared

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/cli/cli/v2/api"
	"github.com/cli/cli/v2/internal/gh"
	ghmock "github.com/cli/cli/v2/internal/gh/mock"
	"github.com/cli/cli/v2/pkg/cmdutil"
	ghAPI "github.com/cli/go-gh/v2/pkg/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errSyntheticCapiVaultDenied = errors.New("synthetic CAPI Vault denial")

type capiOuterVaultError struct {
	cause error
}

func (e *capiOuterVaultError) Error() string { return e.cause.Error() }
func (e *capiOuterVaultError) Unwrap() error { return e.cause }

type capiMarkedVaultError struct {
	cause error
}

func (e *capiMarkedVaultError) Error() string                          { return "Automic Vault credential resolution failed" }
func (e *capiMarkedVaultError) Unwrap() error                          { return e.cause }
func (*capiMarkedVaultError) IsAutomicVaultCredentialResolution() bool { return true }

type capiResolutionAuthConfig struct {
	gh.AuthConfig
	legacyToken   string
	legacySource  string
	legacyCalls   int
	token         string
	source        string
	err           error
	resolverCalls int
	trace         *[]string
	sequence      []capiResolution
}

type capiResolution struct {
	token  string
	source string
	err    error
}

var _ gh.AuthConfig = (*capiResolutionAuthConfig)(nil)

func (c *capiResolutionAuthConfig) DefaultHost() (string, string) {
	if c.trace != nil {
		*c.trace = append(*c.trace, "default-host")
	}
	return "github.com", "synthetic-test"
}

func (c *capiResolutionAuthConfig) ActiveToken(string) (string, string) {
	c.legacyCalls++
	if c.trace != nil {
		*c.trace = append(*c.trace, "legacy")
	}
	return c.legacyToken, c.legacySource
}

func (c *capiResolutionAuthConfig) ActiveTokenWithError(string) (string, string, error) {
	c.resolverCalls++
	if c.trace != nil {
		*c.trace = append(*c.trace, "resolver")
	}
	if len(c.sequence) > 0 {
		result := c.sequence[0]
		c.sequence = c.sequence[1:]
		return result.token, result.source, result.err
	}
	return c.token, c.source, c.err
}

type capiLegacyOnlyAuthConfig struct {
	gh.AuthConfig
	legacyCalls int
}

var _ gh.AuthConfig = (*capiLegacyOnlyAuthConfig)(nil)

func (c *capiLegacyOnlyAuthConfig) DefaultHost() (string, string) {
	return "github.com", "synthetic-test"
}

func (c *capiLegacyOnlyAuthConfig) ActiveToken(string) (string, string) {
	c.legacyCalls++
	return "synthetic-legacy-capi-token", "oauth_token"
}

type capiRecordingTransport struct {
	calls          int
	trace          *[]string
	graphQLStatus  int
	authorizations []string
}

func (t *capiRecordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.calls++
	t.authorizations = append(t.authorizations, req.Header.Get("Authorization"))
	if t.trace != nil {
		if req.URL.Host == "api.github.com" {
			*t.trace = append(*t.trace, "graphql")
		} else {
			*t.trace = append(*t.trace, "capi")
		}
	}

	status := t.graphQLStatus
	if status == 0 {
		status = http.StatusOK
	}
	body := `{"data":{"viewer":{"copilotEndpoints":{"api":"https://api.githubcopilot.com"}}}}`
	if req.URL.Host != "api.github.com" {
		body = `{"sessions":[]}`
	}
	if status == http.StatusUnauthorized {
		if req.URL.Host == "api.github.com" {
			return nil, &ghAPI.HTTPError{
				StatusCode: http.StatusUnauthorized,
				Headers:    req.Header,
				RequestURL: req.URL,
				Message:    "synthetic provider unauthorized",
			}
		}
		body = `{"message":"synthetic provider unauthorized"}`
	}
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}, nil
}

func capiFactory(authCfg gh.AuthConfig, transport http.RoundTripper, trace *[]string, clientCalls *int) *cmdutil.Factory {
	return &cmdutil.Factory{
		Config: func() (gh.Config, error) {
			return &ghmock.ConfigMock{
				AuthenticationFunc: func() gh.AuthConfig { return authCfg },
			}, nil
		},
		HttpClient: func() (*http.Client, error) {
			*clientCalls++
			if trace != nil {
				*trace = append(*trace, "http-factory")
			}
			return &http.Client{Transport: transport}, nil
		},
	}
}

func requireCapiVaultError(t *testing.T, err error, cause error) {
	t.Helper()
	require.EqualError(t, err, "Automic Vault credential resolution failed")
	require.ErrorIs(t, err, cause)
	var marker interface{ IsAutomicVaultCredentialResolution() bool }
	require.ErrorAs(t, err, &marker)
	require.True(t, marker.IsAutomicVaultCredentialResolution())
	require.NotContains(t, err.Error(), "synthetic-poison")
}

func TestCapiClientFuncOperationalVaultFailureStopsBeforeClientAndGraphQL(t *testing.T) {
	trace := []string{}
	transport := &capiRecordingTransport{trace: &trace}
	authCfg := &capiResolutionAuthConfig{
		legacyToken:  "synthetic-legacy-capi-token",
		legacySource: "legacy-host-slot",
		token:        "synthetic-poison-capi-token",
		source:       "synthetic-poison-capi-source",
		err:          &capiOuterVaultError{cause: &capiMarkedVaultError{cause: errSyntheticCapiVaultDenied}},
		trace:        &trace,
	}
	clientCalls := 0
	f := capiFactory(authCfg, transport, &trace, &clientCalls)

	client, err := CapiClientFunc(f)()

	assert.Nil(t, client, "operational credential failure must not construct a CAPI client")
	assert.Equal(t, 0, clientCalls, "credential resolution must precede HTTP client construction")
	assert.Equal(t, 0, transport.calls, "credential resolution must precede GraphQL")
	assert.Equal(t, 0, authCfg.legacyCalls, "operational failure must not use the legacy getter")
	assert.Equal(t, 1, authCfg.resolverCalls)
	assert.Equal(t, []string{"default-host", "resolver"}, trace)
	requireCapiVaultError(t, err, errSyntheticCapiVaultDenied)
}

func TestCapiClientFuncResolvedCredentialOrderAndHeaders(t *testing.T) {
	trace := []string{}
	transport := &capiRecordingTransport{trace: &trace}
	authCfg := &capiResolutionAuthConfig{
		legacyToken:  "synthetic-poison-capi-token",
		legacySource: "synthetic-poison-capi-source",
		token:        "synthetic-resolved-capi-token",
		source:       "keyring",
		trace:        &trace,
	}
	clientCalls := 0
	client, err := CapiClientFunc(capiFactory(authCfg, transport, &trace, &clientCalls))()
	require.NoError(t, err)
	require.NotNil(t, client)

	_, err = client.ListLatestSessionsForViewer(context.Background(), 1)
	require.NoError(t, err)
	assert.Equal(t, []string{"default-host", "resolver", "http-factory", "graphql", "capi"}, trace)
	assert.Equal(t, 1, clientCalls)
	assert.Equal(t, 2, transport.calls)
	assert.Equal(t, []string{"token synthetic-resolved-capi-token", "Bearer synthetic-resolved-capi-token"}, transport.authorizations)
	assert.Equal(t, 0, authCfg.legacyCalls)
	assert.Equal(t, 1, authCfg.resolverCalls)
}

func TestCapiClientFuncRecoversOnFreshInvocationAfterVaultFailure(t *testing.T) {
	trace := []string{}
	transport := &capiRecordingTransport{trace: &trace}
	authCfg := &capiResolutionAuthConfig{
		legacyToken:  "synthetic-poison-capi-token",
		legacySource: "synthetic-poison-capi-source",
		trace:        &trace,
		sequence: []capiResolution{
			{err: &capiOuterVaultError{cause: &capiMarkedVaultError{cause: errSyntheticCapiVaultDenied}}},
			{token: "synthetic-recovered-capi-token", source: "keyring"},
		},
	}
	clientCalls := 0
	f := capiFactory(authCfg, transport, &trace, &clientCalls)
	clientFunc := CapiClientFunc(f)

	first, firstErr := clientFunc()
	assert.Nil(t, first)
	assert.Equal(t, 0, clientCalls)
	assert.Equal(t, 0, transport.calls)
	assert.Equal(t, 0, authCfg.legacyCalls)
	assert.Equal(t, []string{"default-host", "resolver"}, trace)

	trace = trace[:0]
	second, secondErr := clientFunc()
	require.NoError(t, secondErr)
	require.NotNil(t, second)
	_, secondErr = second.ListLatestSessionsForViewer(context.Background(), 1)
	require.NoError(t, secondErr)
	assert.Equal(t, []string{"default-host", "resolver", "http-factory", "graphql", "capi"}, trace)
	assert.Equal(t, 1, clientCalls)
	assert.Equal(t, 2, transport.calls)
	require.Len(t, transport.authorizations, 2)
	assert.Equal(t, "Bearer synthetic-recovered-capi-token", transport.authorizations[1])
	assert.Equal(t, 0, authCfg.legacyCalls)
	assert.Equal(t, 2, authCfg.resolverCalls)
	requireCapiVaultError(t, firstErr, errSyntheticCapiVaultDenied)
}

func TestCapiClientFuncProvider401RemainsHTTPErrorAfterSuccessfulResolution(t *testing.T) {
	trace := []string{}
	transport := &capiRecordingTransport{trace: &trace, graphQLStatus: http.StatusUnauthorized}
	authCfg := &capiResolutionAuthConfig{
		legacyToken:  "synthetic-poison-capi-token",
		legacySource: "synthetic-poison-capi-source",
		token:        "synthetic-valid-capi-token",
		source:       "keyring",
		trace:        &trace,
	}
	clientCalls := 0
	client, err := CapiClientFunc(capiFactory(authCfg, transport, &trace, &clientCalls))()
	require.Nil(t, client)
	var httpErr api.HTTPError
	require.ErrorAs(t, err, &httpErr)
	require.Equal(t, http.StatusUnauthorized, httpErr.StatusCode)
	require.Equal(t, 1, clientCalls)
	require.Equal(t, 1, transport.calls)
	assert.Equal(t, "token synthetic-valid-capi-token", transport.authorizations[0])
	assert.Equal(t, 0, authCfg.legacyCalls)
	assert.Equal(t, 1, authCfg.resolverCalls)
	assert.NotContains(t, strings.ToLower(err.Error()), "vault")
}

func TestCapiClientFuncKeepsLegacyOnlyCompatibility(t *testing.T) {
	trace := []string{}
	transport := &capiRecordingTransport{trace: &trace}
	authCfg := &capiLegacyOnlyAuthConfig{}
	if _, ok := any(authCfg).(interface {
		ActiveTokenWithError(string) (string, string, error)
	}); ok {
		t.Fatal("legacy-only fixture must not implement the error-aware resolver")
	}
	clientCalls := 0
	client, err := CapiClientFunc(capiFactory(authCfg, transport, &trace, &clientCalls))()
	require.NoError(t, err)
	require.NotNil(t, client)
	_, err = client.ListLatestSessionsForViewer(context.Background(), 1)
	require.NoError(t, err)
	require.Equal(t, 1, clientCalls)
	require.Equal(t, 2, transport.calls)
	require.Equal(t, 1, authCfg.legacyCalls)
	require.Len(t, transport.authorizations, 2)
	require.Equal(t, []string{
		"token synthetic-legacy-capi-token",
		"Bearer synthetic-legacy-capi-token",
	}, transport.authorizations)
	require.NotContains(t, strings.ToLower(strings.Join(transport.authorizations, " ")), "undefined")
}
