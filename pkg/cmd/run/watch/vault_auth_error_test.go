package watch

import (
	"errors"
	"net/http"
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
		return "", "", errSyntheticWatcherVaultDenied
	}
	return "synthetic-watcher-token", "keyring", nil
}

type recordingRoundTripper struct {
	base     http.RoundTripper
	requests int
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
