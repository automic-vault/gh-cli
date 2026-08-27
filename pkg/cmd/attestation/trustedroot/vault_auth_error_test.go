package trustedroot

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	ghapi "github.com/cli/cli/v2/api"
	"github.com/cli/cli/v2/internal/gh"
	ghmock "github.com/cli/cli/v2/internal/gh/mock"
	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/cli/cli/v2/pkg/iostreams"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errSyntheticTrustedRootVaultDenied = errors.New("synthetic trusted-root Vault denial")

type trustedRootOuterVaultError struct {
	cause error
}

func (e *trustedRootOuterVaultError) Error() string { return e.cause.Error() }
func (e *trustedRootOuterVaultError) Unwrap() error { return e.cause }

type trustedRootMarkedVaultError struct {
	cause error
}

func (e *trustedRootMarkedVaultError) Error() string {
	return "Automic Vault credential resolution failed"
}
func (e *trustedRootMarkedVaultError) Unwrap() error { return e.cause }
func (*trustedRootMarkedVaultError) IsAutomicVaultCredentialResolution() bool {
	return true
}

type trustedRootErrorAwareAuthConfig struct {
	gh.AuthConfig
	hasActiveToken      bool
	hasActiveTokenCalls int
	legacyCalls         int
	resolverCalls       int
	legacyToken         string
	legacySource        string
	token               string
	source              string
	err                 error
	trace               *[]string
}

var _ gh.AuthConfig = (*trustedRootErrorAwareAuthConfig)(nil)

func (c *trustedRootErrorAwareAuthConfig) HasActiveToken(string) bool {
	c.hasActiveTokenCalls++
	if c.trace != nil {
		*c.trace = append(*c.trace, "has-active")
	}
	return c.hasActiveToken
}

func (c *trustedRootErrorAwareAuthConfig) ActiveToken(string) (string, string) {
	c.legacyCalls++
	if c.trace != nil {
		*c.trace = append(*c.trace, "legacy")
	}
	return c.legacyToken, c.legacySource
}

func (c *trustedRootErrorAwareAuthConfig) ActiveTokenWithError(string) (string, string, error) {
	c.resolverCalls++
	if c.trace != nil {
		*c.trace = append(*c.trace, "resolver")
	}
	return c.token, c.source, c.err
}

type trustedRootLegacyOnlyAuthConfig struct {
	gh.AuthConfig
	hasActiveTokenCalls int
	legacyCalls         int
	trace               *[]string
}

var _ gh.AuthConfig = (*trustedRootLegacyOnlyAuthConfig)(nil)

func (c *trustedRootLegacyOnlyAuthConfig) HasActiveToken(string) bool {
	c.hasActiveTokenCalls++
	if c.trace != nil {
		*c.trace = append(*c.trace, "has-active")
	}
	return true
}

func (c *trustedRootLegacyOnlyAuthConfig) ActiveToken(string) (string, string) {
	c.legacyCalls++
	if c.trace != nil {
		*c.trace = append(*c.trace, "legacy")
	}
	return "synthetic-legacy-trusted-root-token", "oauth_token"
}

type trustedRootRecordingTransport struct {
	calls          int
	authorizations []string
	trace          *[]string
	status         int
}

func (t *trustedRootRecordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.calls++
	t.authorizations = append(t.authorizations, req.Header.Get("Authorization"))
	if t.trace != nil {
		*t.trace = append(*t.trace, "meta")
	}
	status := t.status
	if status == 0 {
		status = http.StatusOK
	}
	body := `{"domains":{"artifact_attestations":{"trust_domain":"synthetic-trust-domain"}}}`
	if status != http.StatusOK {
		body = `{"message":"synthetic provider unauthorized"}`
	}
	return &http.Response{
		StatusCode: status,
		Status:     fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}, nil
}

type trustedRootRunResult struct {
	err           error
	stdout        string
	stderr        string
	trace         []string
	metaCalls     int
	httpCalls     int
	externalCalls int
	runCalls      int
	trustDomain   string
}

func runTrustedRootWithSyntheticAuth(t *testing.T, authCfg gh.AuthConfig, transport, external http.RoundTripper, trace *[]string) trustedRootRunResult {
	t.Helper()
	testIO, _, stdout, stderr := iostreams.Test()
	result := trustedRootRunResult{}
	f := &cmdutil.Factory{
		IOStreams: testIO,
		Config: func() (gh.Config, error) {
			return &ghmock.ConfigMock{
				AuthenticationFunc: func() gh.AuthConfig { return authCfg },
			}, nil
		},
		HttpClient: func() (*http.Client, error) {
			result.httpCalls++
			if trace != nil {
				*trace = append(*trace, "http-factory")
			}
			return &http.Client{Transport: transport}, nil
		},
		ExternalHttpClient: func() (*http.Client, error) {
			result.externalCalls++
			if trace != nil {
				*trace = append(*trace, "external-factory")
			}
			return &http.Client{Transport: external}, nil
		},
	}
	cmd := NewTrustedRootCmd(f, func(opts *Options) error {
		result.runCalls++
		result.trustDomain = opts.TrustDomain
		return nil
	})
	cmd.SetArgs([]string{"--hostname", "foo-bar.ghe.com"})
	cmd.SetIn(&bytes.Buffer{})
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)
	_, result.err = cmd.ExecuteC()
	result.stdout = stdout.String()
	result.stderr = stderr.String()
	if recorder, ok := transport.(*trustedRootRecordingTransport); ok {
		result.metaCalls = recorder.calls
	}
	result.trace = append([]string(nil), (*trace)...)
	return result
}

func requireTrustedRootVaultError(t *testing.T, err error, cause error) {
	t.Helper()
	require.EqualError(t, err, "Automic Vault credential resolution failed")
	require.ErrorIs(t, err, cause)
	var marker interface{ IsAutomicVaultCredentialResolution() bool }
	require.ErrorAs(t, err, &marker)
	require.True(t, marker.IsAutomicVaultCredentialResolution())
	require.NotContains(t, err.Error(), "synthetic-poison")
}

func TestTrustedRootTenancyOperationalVaultFailurePrecedesClientsAndMeta(t *testing.T) {
	trace := []string{}
	authCfg := &trustedRootErrorAwareAuthConfig{
		hasActiveToken: true,
		legacyToken:    "synthetic-poison-legacy-token",
		legacySource:   "synthetic-poison-legacy-source",
		token:          "synthetic-poison-token",
		source:         "synthetic-poison-source",
		err:            &trustedRootOuterVaultError{cause: &trustedRootMarkedVaultError{cause: errSyntheticTrustedRootVaultDenied}},
		trace:          &trace,
	}
	transport := &trustedRootRecordingTransport{trace: &trace}
	result := runTrustedRootWithSyntheticAuth(t, authCfg, transport, transport, &trace)

	require.Equal(t, 0, result.httpCalls, "Vault failure must precede GitHub client construction")
	require.Equal(t, 0, result.externalCalls, "Vault failure must precede external client construction")
	require.Equal(t, 0, result.metaCalls)
	require.Equal(t, 0, transport.calls)
	require.Equal(t, 0, result.runCalls)
	require.Equal(t, []string{"resolver"}, result.trace)
	require.Equal(t, 1, authCfg.resolverCalls)
	require.Equal(t, 0, authCfg.legacyCalls)
	require.Equal(t, 0, authCfg.hasActiveTokenCalls)
	require.Empty(t, result.stdout)
	output := strings.ToLower(result.stderr)
	for _, forbidden := range []string{"not authenticated", "invalid", "logged out", "log in", "re-authenticate", "synthetic"} {
		require.NotContains(t, output, forbidden)
	}
	requireTrustedRootVaultError(t, result.err, errSyntheticTrustedRootVaultDenied)
}

func TestTrustedRootTenancyResolvedCredentialOrderAndHeader(t *testing.T) {
	trace := []string{}
	authCfg := &trustedRootErrorAwareAuthConfig{
		hasActiveToken: true,
		legacyToken:    "synthetic-poison-legacy-token",
		legacySource:   "synthetic-poison-legacy-source",
		token:          "synthetic-resolved-trusted-root-token",
		source:         "keyring",
		trace:          &trace,
	}
	transport := &trustedRootRecordingTransport{trace: &trace}
	result := runTrustedRootWithSyntheticAuth(t, authCfg, transport, transport, &trace)

	require.NoError(t, result.err)
	assert.Equal(t, []string{"resolver", "http-factory", "external-factory", "meta"}, result.trace)
	assert.Equal(t, 1, result.httpCalls)
	assert.Equal(t, 1, result.externalCalls)
	assert.Equal(t, 1, transport.calls)
	assert.Equal(t, []string{"token synthetic-resolved-trusted-root-token"}, transport.authorizations)
	assert.Equal(t, "synthetic-trust-domain", result.trustDomain)
	assert.Equal(t, 1, result.runCalls)
	assert.Equal(t, 1, authCfg.resolverCalls)
	assert.Equal(t, 0, authCfg.legacyCalls)
	assert.Equal(t, 0, authCfg.hasActiveTokenCalls)
}

func TestTrustedRootTenancyIntentionalAbsenceKeepsOrdinaryNotAuthenticated(t *testing.T) {
	trace := []string{}
	authCfg := &trustedRootErrorAwareAuthConfig{
		token:  "",
		source: "default",
		trace:  &trace,
	}
	transport := &trustedRootRecordingTransport{trace: &trace}
	result := runTrustedRootWithSyntheticAuth(t, authCfg, transport, transport, &trace)

	require.Error(t, result.err)
	require.Contains(t, result.err.Error(), "not authenticated")
	require.NotContains(t, strings.ToLower(result.err.Error()), "vault")
	assert.Equal(t, 0, result.httpCalls)
	assert.Equal(t, 0, result.externalCalls)
	assert.Equal(t, 0, transport.calls)
	assert.Equal(t, 0, result.runCalls)
	assert.Equal(t, []string{"resolver"}, result.trace)
	assert.Equal(t, 1, authCfg.resolverCalls)
	assert.Equal(t, 0, authCfg.legacyCalls)
	assert.Equal(t, 0, authCfg.hasActiveTokenCalls)
	require.NotContains(t, strings.ToLower(result.stdout), "synthetic")
	require.NotContains(t, strings.ToLower(result.stderr), "synthetic")
}

func TestTrustedRootTenancyProvider401RemainsOrdinaryHTTPError(t *testing.T) {
	trace := []string{}
	authCfg := &trustedRootErrorAwareAuthConfig{
		hasActiveToken: true,
		token:          "synthetic-valid-trusted-root-token",
		source:         "keyring",
		trace:          &trace,
	}
	transport := &trustedRootRecordingTransport{trace: &trace, status: http.StatusUnauthorized}
	result := runTrustedRootWithSyntheticAuth(t, authCfg, transport, transport, &trace)

	var httpErr ghapi.HTTPError
	require.ErrorAs(t, result.err, &httpErr)
	require.Equal(t, http.StatusUnauthorized, httpErr.StatusCode)
	require.NotContains(t, strings.ToLower(result.err.Error()), "vault")
	assert.Equal(t, []string{"resolver", "http-factory", "external-factory", "meta"}, result.trace)
	assert.Equal(t, 1, result.httpCalls)
	assert.Equal(t, 1, result.externalCalls)
	assert.Equal(t, 1, transport.calls)
	assert.Equal(t, []string{"token synthetic-valid-trusted-root-token"}, transport.authorizations)
	assert.Equal(t, 0, result.runCalls)
	assert.Equal(t, 1, authCfg.resolverCalls)
	assert.Equal(t, 0, authCfg.legacyCalls)
	assert.Equal(t, 0, authCfg.hasActiveTokenCalls)
}

func TestTrustedRootTenancyKeepsLegacyOnlyCompatibility(t *testing.T) {
	trace := []string{}
	authCfg := &trustedRootLegacyOnlyAuthConfig{trace: &trace}
	if _, ok := any(authCfg).(interface {
		ActiveTokenWithError(string) (string, string, error)
	}); ok {
		t.Fatal("legacy-only fixture must not implement the error-aware resolver")
	}
	transport := &trustedRootRecordingTransport{trace: &trace}
	result := runTrustedRootWithSyntheticAuth(t, authCfg, transport, transport, &trace)

	require.NoError(t, result.err)
	require.Equal(t, []string{"legacy", "http-factory", "external-factory", "meta"}, result.trace)
	require.Equal(t, 1, result.httpCalls)
	require.Equal(t, 1, result.externalCalls)
	require.Equal(t, 1, transport.calls)
	require.Equal(t, 1, result.runCalls)
	require.Equal(t, 1, authCfg.legacyCalls)
	require.Equal(t, 0, authCfg.hasActiveTokenCalls, "legacy compatibility must resolve the token rather than a presence-only check")
	require.Len(t, transport.authorizations, 1)
	require.Equal(t, "token synthetic-legacy-trusted-root-token", transport.authorizations[0])
	require.NotContains(t, strings.ToLower(transport.authorizations[0]), "undefined")
}

func TestTrustedRootNonTenancyDoesNotResolveVaultCredentials(t *testing.T) {
	trace := []string{}
	authCfg := &trustedRootErrorAwareAuthConfig{
		token:  "synthetic-poison-token",
		source: "synthetic-poison-source",
		err:    &trustedRootOuterVaultError{cause: &trustedRootMarkedVaultError{cause: errSyntheticTrustedRootVaultDenied}},
		trace:  &trace,
	}
	transport := &trustedRootRecordingTransport{trace: &trace}
	testIO, _, stdout, stderr := iostreams.Test()
	runCalls := 0
	f := &cmdutil.Factory{
		IOStreams: testIO,
		Config: func() (gh.Config, error) {
			return &ghmock.ConfigMock{AuthenticationFunc: func() gh.AuthConfig { return authCfg }}, nil
		},
		HttpClient:         func() (*http.Client, error) { return &http.Client{Transport: transport}, nil },
		ExternalHttpClient: func() (*http.Client, error) { return &http.Client{Transport: transport}, nil },
	}
	cmd := NewTrustedRootCmd(f, func(*Options) error { runCalls++; return nil })
	cmd.SetArgs([]string{"--hostname", "github.com"})
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)
	_, err := cmd.ExecuteC()
	require.NoError(t, err)
	require.Equal(t, 0, authCfg.resolverCalls)
	require.Equal(t, 0, authCfg.legacyCalls)
	require.Equal(t, 0, authCfg.hasActiveTokenCalls)
	require.Equal(t, 1, runCalls)
	require.Empty(t, stdout.String())
	require.Empty(t, stderr.String())
}

func TestTrustedRootUnsupportedHostStopsBeforeVaultAndClients(t *testing.T) {
	trace := []string{}
	authCfg := &trustedRootErrorAwareAuthConfig{trace: &trace}
	transport := &trustedRootRecordingTransport{trace: &trace}
	testIO, _, stdout, stderr := iostreams.Test()
	httpCalls := 0
	externalCalls := 0
	f := &cmdutil.Factory{
		IOStreams: testIO,
		Config: func() (gh.Config, error) {
			return &ghmock.ConfigMock{AuthenticationFunc: func() gh.AuthConfig { return authCfg }}, nil
		},
		HttpClient: func() (*http.Client, error) {
			httpCalls++
			return &http.Client{Transport: transport}, nil
		},
		ExternalHttpClient: func() (*http.Client, error) {
			externalCalls++
			return &http.Client{Transport: transport}, nil
		},
	}
	cmd := NewTrustedRootCmd(f, func(*Options) error {
		t.Fatal("unsupported host must not execute the command")
		return nil
	})
	cmd.SetArgs([]string{"--hostname", "ghe.example.com"})
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)
	_, err := cmd.ExecuteC()
	require.Error(t, err)
	require.Equal(t, 0, authCfg.resolverCalls)
	require.Equal(t, 0, authCfg.legacyCalls)
	require.Equal(t, 0, authCfg.hasActiveTokenCalls)
	require.Equal(t, 0, httpCalls)
	require.Equal(t, 0, externalCalls)
	require.Equal(t, 0, transport.calls)
	require.NotContains(t, strings.ToLower(stdout.String()), "synthetic")
	require.NotContains(t, strings.ToLower(stderr.String()), "synthetic")
}
