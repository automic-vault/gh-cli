package api

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

var errSyntheticVaultDenied = errors.New("synthetic Vault access denied")

// dualTokenConfig models the compatibility seam during the transition from the
// legacy no-error getter to the error-aware getter. The old getter intentionally
// exposes a legacy token so that an implementation which ignores the new error
// will make a visible network request.
type dualTokenConfig struct {
	legacyToken   string
	legacySource  string
	legacyCalls   int
	token         string
	source        string
	resolverCalls int
	err           error
}

func (c *dualTokenConfig) ActiveToken(string) (string, string) {
	c.legacyCalls++
	return c.legacyToken, c.legacySource
}

func (c *dualTokenConfig) ActiveTokenWithError(string) (string, string, error) {
	c.resolverCalls++
	return c.token, c.source, c.err
}

type recoveringTokenConfig struct {
	legacyCalls   int
	resolverCalls int
}

func (c *recoveringTokenConfig) ActiveToken(string) (string, string) {
	c.legacyCalls++
	if c.legacyCalls == 1 {
		return "synthetic-legacy-token", "legacy-host-slot"
	}
	return "synthetic-recovered-token", "keyring"
}

func (c *recoveringTokenConfig) ActiveTokenWithError(string) (string, string, error) {
	c.resolverCalls++
	if c.resolverCalls == 1 {
		return "", "", errSyntheticVaultDenied
	}
	return "synthetic-recovered-token", "keyring", nil
}

type countingRoundTripper struct {
	calls         int
	authorization string
}

func (t *countingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	t.calls++
	t.authorization = req.Header.Get(authorization)
	return &http.Response{
		StatusCode: http.StatusNoContent,
		Header:     make(http.Header),
		Body:       io.NopCloser(http.NoBody),
		Request:    req,
	}, nil
}

func TestAddAuthTokenHeaderVaultCredentialResolution(t *testing.T) {
	t.Run("operational Vault error never falls back or reaches network", func(t *testing.T) {
		transport := &countingRoundTripper{}
		cfg := &dualTokenConfig{
			legacyToken:  "synthetic-legacy-token",
			legacySource: "legacy-host-slot",
			token:        "synthetic-poison-token",
			source:       "synthetic-poison-source",
			err:          errSyntheticVaultDenied,
		}
		req := httptest.NewRequest(http.MethodGet, "https://api.github.com/repos/cli/cli", nil)

		res, err := AddAuthTokenHeader(transport, cfg).RoundTrip(req)

		if !errors.Is(err, errSyntheticVaultDenied) {
			t.Errorf("expected Vault retrieval error, got %v", err)
		}
		if res != nil {
			t.Errorf("expected no HTTP response after local credential failure, got status %d", res.StatusCode)
		}
		if transport.calls != 0 {
			t.Fatalf("expected zero network requests after Vault retrieval failure, got %d", transport.calls)
		}
		if transport.authorization != "" {
			t.Fatalf("expected no authorization header after Vault retrieval failure, got %q", transport.authorization)
		}
		if cfg.legacyCalls != 0 {
			t.Errorf("expected zero legacy resolver calls after Vault retrieval failure, got %d", cfg.legacyCalls)
		}
		if cfg.resolverCalls != 1 {
			t.Errorf("expected one error-aware resolver call after Vault retrieval failure, got %d", cfg.resolverCalls)
		}
	})

	t.Run("account not found permits the intentional legacy fallback", func(t *testing.T) {
		transport := &countingRoundTripper{}
		cfg := &dualTokenConfig{
			legacyToken:  "synthetic-legacy-token",
			legacySource: "legacy-host-slot",
			token:        "synthetic-legacy-token",
			source:       "legacy-host-slot",
		}
		req := httptest.NewRequest(http.MethodGet, "https://api.github.com/repos/cli/cli", nil)

		res, err := AddAuthTokenHeader(transport, cfg).RoundTrip(req)

		if err != nil {
			t.Fatalf("expected legacy fallback request to succeed, got %v", err)
		}
		if res == nil || res.StatusCode != http.StatusNoContent {
			t.Fatalf("expected one fallback request, got %#v", res)
		}
		if transport.calls != 1 {
			t.Fatalf("expected one fallback request, got %d", transport.calls)
		}
		if transport.authorization != "token synthetic-legacy-token" {
			t.Fatalf("expected legacy authorization header, got %q", transport.authorization)
		}
		if cfg.legacyCalls != 0 {
			t.Errorf("expected zero legacy resolver calls for a compatible fallback, got %d", cfg.legacyCalls)
		}
		if cfg.resolverCalls != 1 {
			t.Errorf("expected one error-aware resolver call for a compatible fallback, got %d", cfg.resolverCalls)
		}
	})

	t.Run("both credential slots absent permit an anonymous request", func(t *testing.T) {
		transport := &countingRoundTripper{}
		cfg := &dualTokenConfig{}
		req := httptest.NewRequest(http.MethodGet, "https://api.github.com/meta", nil)

		res, err := AddAuthTokenHeader(transport, cfg).RoundTrip(req)

		if err != nil {
			t.Fatalf("expected anonymous request to succeed, got %v", err)
		}
		if res == nil || res.StatusCode != http.StatusNoContent {
			t.Fatalf("expected one anonymous request, got %#v", res)
		}
		if transport.calls != 1 {
			t.Fatalf("expected one anonymous request, got %d", transport.calls)
		}
		if transport.authorization != "" {
			t.Fatalf("expected no authorization header for anonymous request, got %q", transport.authorization)
		}
		if cfg.legacyCalls != 0 {
			t.Errorf("expected zero legacy resolver calls for an anonymous request, got %d", cfg.legacyCalls)
		}
		if cfg.resolverCalls != 1 {
			t.Errorf("expected one error-aware resolver call for an anonymous request, got %d", cfg.resolverCalls)
		}
	})
}

func TestAddAuthTokenHeaderRecoversAfterTransientVaultFailure(t *testing.T) {
	transport := &countingRoundTripper{}
	cfg := &recoveringTokenConfig{}
	if _, ok := any(cfg).(interface {
		ActiveTokenWithError(string) (string, string, error)
	}); !ok {
		t.Fatal("test config must expose the error-aware token resolver")
	}
	client := AddAuthTokenHeader(transport, cfg)

	firstReq := httptest.NewRequest(http.MethodGet, "https://api.github.com/repos/cli/cli", nil)
	firstRes, firstErr := client.RoundTrip(firstReq)
	if transport.calls != 0 {
		t.Errorf("expected zero network requests after the first Vault failure, got %d", transport.calls)
	}
	if cfg.legacyCalls != 0 {
		t.Errorf("expected zero legacy resolver calls after the first Vault failure, got %d", cfg.legacyCalls)
	}
	if firstRes != nil {
		t.Errorf("expected no response after the first local Vault failure, got status %d", firstRes.StatusCode)
	}
	if !errors.Is(firstErr, errSyntheticVaultDenied) {
		t.Errorf("expected the first Vault error to propagate, got %T", firstErr)
	}

	secondReq := httptest.NewRequest(http.MethodGet, "https://api.github.com/repos/cli/cli", nil)
	secondRes, secondErr := client.RoundTrip(secondReq)
	if secondErr != nil {
		t.Errorf("expected the recovered request to succeed, got %T", secondErr)
	}
	if secondRes == nil || secondRes.StatusCode != http.StatusNoContent {
		t.Errorf("expected one recovered response, got %#v", secondRes)
	}
	if transport.calls != 1 {
		t.Errorf("expected exactly one network request after recovery, got %d", transport.calls)
	}
	if cfg.legacyCalls != 0 {
		t.Errorf("expected zero legacy resolver calls after recovery, got %d", cfg.legacyCalls)
	}
	if transport.authorization != "token synthetic-recovered-token" {
		t.Errorf("expected the recovered request to be authenticated, got %q", transport.authorization)
	}
	if cfg.resolverCalls != 2 {
		t.Errorf("expected two error-aware resolution attempts, got %d", cfg.resolverCalls)
	}
}

type unauthorizedRoundTripper struct {
	calls         int
	authorization string
}

func (t *unauthorizedRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	t.calls++
	t.authorization = req.Header.Get(authorization)
	return &http.Response{
		StatusCode: http.StatusUnauthorized,
		Header:     make(http.Header),
		Body:       io.NopCloser(http.NoBody),
		Request:    req,
	}, nil
}

func TestAddAuthTokenHeaderPreservesProviderHTTP401AfterSuccessfulResolution(t *testing.T) {
	transport := &unauthorizedRoundTripper{}
	cfg := &dualTokenConfig{
		legacyToken:  "synthetic-poison-token",
		legacySource: "synthetic-legacy-source",
		token:        "synthetic-valid-token",
		source:       "synthetic-keyring",
	}
	req := httptest.NewRequest(http.MethodGet, "https://api.github.com/user", nil)

	res, err := AddAuthTokenHeader(transport, cfg).RoundTrip(req)

	if err != nil {
		t.Errorf("expected the provider success to preserve the transport result, got %v", err)
	}
	if res == nil || res.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected the real provider HTTP 401 to remain visible, got %#v", res)
	}
	if transport.calls != 1 {
		t.Errorf("expected one authenticated provider response, got %d requests", transport.calls)
	}
	if transport.authorization != "token synthetic-valid-token" {
		t.Errorf("expected the error-aware token in the Authorization header, got %q", transport.authorization)
	}
	if cfg.legacyCalls != 0 {
		t.Errorf("expected zero legacy resolver calls for a successful provider result, got %d", cfg.legacyCalls)
	}
	if cfg.resolverCalls != 1 {
		t.Errorf("expected one error-aware resolver call for a successful provider result, got %d", cfg.resolverCalls)
	}
}
