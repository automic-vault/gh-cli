package watch

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cli/cli/v2/api"
	"github.com/cli/cli/v2/internal/ghrepo"
	"github.com/cli/cli/v2/pkg/cmd/run/shared"
	"github.com/cli/cli/v2/pkg/httpmock"
	"github.com/cli/cli/v2/pkg/iostreams"
)

var errSyntheticWatcherVaultDenied = errors.New("synthetic Vault retrieval denied while watching")

type watcherTokenConfig struct {
	legacyCalls   int
	resolverCalls int
}

func (c *watcherTokenConfig) ActiveToken(string) (string, string) {
	c.legacyCalls++
	return "synthetic-watcher-token", "legacy-host-slot"
}

func (c *watcherTokenConfig) ActiveTokenWithError(string) (string, string, error) {
	c.resolverCalls++
	if c.resolverCalls == 10 {
		return "synthetic-poison-token", "synthetic-poison-source", errSyntheticWatcherVaultDenied
	}
	return "synthetic-watcher-token", "keyring", nil
}

type recordingRoundTripper struct {
	base     http.RoundTripper
	requests int
}

type retryingWatcherTokenConfig struct {
	legacyCalls   int
	resolverCalls int
}

func (c *retryingWatcherTokenConfig) ActiveToken(string) (string, string) {
	c.legacyCalls++
	return "synthetic-poison-token", "synthetic-poison-source"
}

func (c *retryingWatcherTokenConfig) ActiveTokenWithError(string) (string, string, error) {
	c.resolverCalls++
	if c.resolverCalls == 1 {
		return "synthetic-poison-token", "synthetic-poison-source", errSyntheticWatcherVaultDenied
	}
	return "synthetic-recovered-token", "synthetic-keyring", nil
}

type watcherRecoveryRoundTripper struct {
	calls          int
	runResponses   int
	authorizations []string
	unexpected     []string
}

func (t *watcherRecoveryRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	t.calls++
	t.authorizations = append(t.authorizations, req.Header.Get("Authorization"))
	var body string
	switch {
	case req.URL.Path == "/repos/OWNER/REPO/actions/runs/2":
		t.runResponses++
		run := shared.TestRun(2, shared.Completed, shared.Success)
		if t.runResponses == 1 {
			run = shared.TestRunWithCommit(2, shared.InProgress, "", "synthetic-commit")
		}
		encoded, err := json.Marshal(run)
		if err != nil {
			return nil, err
		}
		body = string(encoded)
	case req.URL.Path == "/graphql":
		body = `{"data":{"repository":{"pullRequests":{"nodes":[]}}}}`
	case strings.HasSuffix(req.URL.Path, "/actions/workflows/123"):
		encoded, err := json.Marshal(shared.TestWorkflow)
		if err != nil {
			return nil, err
		}
		body = string(encoded)
	case strings.HasSuffix(req.URL.Path, "/runs/2/jobs"):
		body = `{"jobs":[]}`
	default:
		t.unexpected = append(t.unexpected, req.URL.Path)
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("")),
			Request:    req,
		}, nil
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}, nil
}

func (t *recordingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	t.requests++
	return t.base.RoundTrip(req)
}

func TestWatchRunStopsBeforeNetworkAfterTransientVaultFailure(t *testing.T) {
	inProgressRun := shared.TestRunWithCommit(2, shared.InProgress, "", "synthetic-commit")
	completedRun := shared.TestRun(2, shared.Completed, shared.Success)
	reg := &httpmock.Registry{}

	// Initial discovery plus two successful polls must complete before the
	// error-aware resolver fails on the next poll's first request.
	for range 3 {
		reg.Register(
			httpmock.REST("GET", "repos/OWNER/REPO/actions/runs/2"),
			httpmock.JSONResponse(inProgressRun))
	}
	reg.Register(
		httpmock.REST("GET", "repos/OWNER/REPO/actions/runs/2"),
		httpmock.JSONResponse(completedRun))
	for range 4 {
		reg.Register(
			httpmock.REST("GET", "repos/OWNER/REPO/actions/workflows/123"),
			httpmock.JSONResponse(shared.TestWorkflow))
	}
	reg.Register(
		httpmock.GraphQL(`PullRequestForRun`),
		httpmock.JSONResponse(map[string]any{
			"data": map[string]any{
				"repository": map[string]any{
					"pullRequests": map[string]any{"nodes": []any{}},
				},
			},
		}))
	for range 3 {
		reg.Register(
			httpmock.REST("GET", "runs/2/jobs"),
			httpmock.JSONResponse(shared.JobsPayload{Jobs: []shared.Job{}}))
	}

	resolver := &watcherTokenConfig{}
	recording := &recordingRoundTripper{base: reg}
	ios, _, _, _ := iostreams.Test()
	err := watchRun(&WatchOptions{
		IO:       ios,
		RunID:    "2",
		Interval: 0,
		HttpClient: func() (*http.Client, error) {
			return &http.Client{Transport: api.AddAuthTokenHeader(recording, resolver)}, nil
		},
		BaseRepo: func() (ghrepo.Interface, error) {
			return ghrepo.FromFullName("OWNER/REPO")
		},
		Now: func() time.Time {
			return shared.TestRunStartTime.Add(time.Hour)
		},
	})

	if !errors.Is(err, errSyntheticWatcherVaultDenied) {
		t.Errorf("expected the watcher to return the Vault error, got %T", err)
	}
	if recording.requests != 9 {
		t.Errorf("expected no request after the failed resolution, got %d total requests", recording.requests)
	}
	if resolver.legacyCalls != 0 {
		t.Errorf("expected zero legacy resolver calls while watching, got %d", resolver.legacyCalls)
	}
	if resolver.resolverCalls != 10 {
		t.Errorf("expected ten error-aware resolution attempts, got %d", resolver.resolverCalls)
	}
}

func TestWatchRunRetriesAfterAFreshInvocationFollowingVaultFailure(t *testing.T) {
	resolver := &retryingWatcherTokenConfig{}
	transport := &watcherRecoveryRoundTripper{}
	ios, _, _, _ := iostreams.Test()
	client := &http.Client{Transport: api.AddAuthTokenHeader(transport, resolver)}
	opts := &WatchOptions{
		IO:       ios,
		RunID:    "2",
		Interval: 0,
		HttpClient: func() (*http.Client, error) {
			return client, nil
		},
		BaseRepo: func() (ghrepo.Interface, error) {
			return ghrepo.FromFullName("OWNER/REPO")
		},
		Now: func() time.Time {
			return shared.TestRunStartTime.Add(time.Hour)
		},
	}

	firstErr := watchRun(opts)
	if !errors.Is(firstErr, errSyntheticWatcherVaultDenied) {
		t.Errorf("expected the first fresh invocation to return the Vault error, got %v", firstErr)
	}
	if transport.calls != 0 {
		t.Errorf("expected zero network requests after the first Vault failure, got %d", transport.calls)
	}

	secondErr := watchRun(opts)
	if secondErr != nil {
		t.Errorf("expected a subsequent invocation to recover, got %v", secondErr)
	}
	if transport.calls != 6 {
		t.Errorf("expected exactly six authenticated requests during recovery, got %d", transport.calls)
	}
	if len(transport.unexpected) != 0 {
		t.Errorf("expected no unexpected watcher endpoints, got %v", transport.unexpected)
	}
	if len(transport.authorizations) != 6 {
		t.Errorf("expected one recovered Authorization header for each of six requests, got %d", len(transport.authorizations))
	}
	for i, authorization := range transport.authorizations {
		if authorization != "token synthetic-recovered-token" {
			t.Errorf("recovered request %d used unexpected Authorization %q", i+1, authorization)
		}
	}
	if resolver.legacyCalls != 0 {
		t.Errorf("expected zero legacy resolver calls across failure and recovery, got %d", resolver.legacyCalls)
	}
	if resolver.resolverCalls != 7 {
		t.Errorf("expected one failed resolution plus six recovery resolutions, got %d", resolver.resolverCalls)
	}
}
