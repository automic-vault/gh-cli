package refresh

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"testing"

	"github.com/cli/cli/v2/git"
	"github.com/cli/cli/v2/internal/config"
	"github.com/cli/cli/v2/internal/gh"
	"github.com/cli/cli/v2/internal/prompter"
	"github.com/cli/cli/v2/internal/run"
	"github.com/cli/cli/v2/pkg/iostreams"
	"github.com/stretchr/testify/assert"
)

var errSyntheticRefreshSetupDenied = errors.New("synthetic credential setup denied")
var errSyntheticRefreshUnexpectedPostAuthResolution = errors.New("unexpected post-auth credential resolution")

type refreshSetupAuthConfig struct {
	*config.AuthConfig

	legacyCalls          int
	resolverCalls        int
	preAuthResolverCall  int
	postAuthResolverCall int
	loginCalls           int
	loginToken           string
	authFlowStarted      bool
}

func (c *refreshSetupAuthConfig) Hosts() []string {
	return []string{"github.com"}
}

func (c *refreshSetupAuthConfig) ActiveToken(string) (string, string) {
	c.legacyCalls++
	return "synthetic-poison-token", "synthetic-poison-source"
}

func (c *refreshSetupAuthConfig) ActiveTokenWithError(string) (string, string, error) {
	c.resolverCalls++
	if c.authFlowStarted {
		c.postAuthResolverCall++
		return "", "", errSyntheticRefreshUnexpectedPostAuthResolution
	}
	c.preAuthResolverCall++
	return "synthetic-old-token", "synthetic-keyring", nil
}

func (c *refreshSetupAuthConfig) ActiveUser(string) (string, error) {
	return "synthetic-account", nil
}

func (c *refreshSetupAuthConfig) Login(_, _, token, _ string, _ bool) (bool, error) {
	c.loginCalls++
	c.loginToken = token
	return false, nil
}

type refreshSetupCommandRecorder struct {
	commands       []string
	approvedInputs [][]byte
	failApprove    bool
	setupComplete  bool
}

func (r *refreshSetupCommandRecorder) prepare(cmd *exec.Cmd) run.Runnable {
	return &refreshSetupRunnable{cmd: cmd, recorder: r}
}

type refreshSetupRunnable struct {
	cmd      *exec.Cmd
	recorder *refreshSetupCommandRecorder
}

func (r *refreshSetupRunnable) Output() ([]byte, error) {
	args := strings.Join(r.cmd.Args[1:], " ")
	r.recorder.commands = append(r.recorder.commands, args)

	if strings.HasPrefix(args, "config ") {
		return []byte("osxkeychain\n"), nil
	}
	if strings.HasPrefix(args, "credential approve") {
		input, err := io.ReadAll(r.cmd.Stdin)
		if err != nil {
			return nil, err
		}
		r.recorder.approvedInputs = append(r.recorder.approvedInputs, append([]byte(nil), input...))
		if r.recorder.failApprove {
			return nil, errSyntheticRefreshSetupDenied
		}
		r.recorder.setupComplete = true
	}
	return nil, nil
}

func (r *refreshSetupRunnable) Run() error {
	return nil
}

type refreshSetupOutputWriter struct {
	io.Writer
	recorder             *refreshSetupCommandRecorder
	completedBeforeSetup bool
}

func (w *refreshSetupOutputWriter) Fd() uintptr {
	return 2
}

func (w *refreshSetupOutputWriter) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("Authentication complete.")) && !w.recorder.setupComplete {
		w.completedBeforeSetup = true
	}
	return w.Writer.Write(p)
}

func newRefreshSetupOptions(t *testing.T, authCfg *refreshSetupAuthConfig, recorder *refreshSetupCommandRecorder) (*RefreshOptions, *iostreams.IOStreams, *bytes.Buffer, *bytes.Buffer, *refreshSetupOutputWriter) {
	t.Helper()

	originalPrepareCmd := run.PrepareCmd
	run.PrepareCmd = recorder.prepare
	t.Cleanup(func() {
		run.PrepareCmd = originalPrepareCmd
	})

	ios, _, stdout, stderr := iostreams.Test()
	output := &refreshSetupOutputWriter{Writer: ios.ErrOut, recorder: recorder}
	ios.ErrOut = output

	mockConfig := config.NewMockConfig()
	mockConfig.AuthenticationFunc = func() gh.AuthConfig {
		return authCfg
	}

	return &RefreshOptions{
		IO:              ios,
		Config:          func() (gh.Config, error) { return mockConfig, nil },
		PlainHttpClient: func() (*http.Client, error) { return &http.Client{Transport: &refreshRejectingTransport{}}, nil },
		GitClient:       &git.Client{GitPath: "synthetic-git"},
		Prompter: &prompter.PrompterMock{
			ConfirmFunc: func(string, bool) (bool, error) { return true, nil },
		},
		MainExecutable: "/synthetic/gh",
		Hostname:       "github.com",
		Interactive:    true,
		ResetScopes:    true,
	}, ios, stdout, stderr, output
}

func requireRefreshSetupOutputSecretFree(t *testing.T, output string) {
	t.Helper()
	for _, forbidden := range []string{
		"synthetic-old-token",
		"synthetic-flow-token",
		"synthetic-poison-token",
		"synthetic-poison-source",
		"synthetic-account",
		"undefined",
	} {
		assert.False(t, strings.Contains(strings.ToLower(output), forbidden), "refresh output contains forbidden credential material")
	}
}

func TestRefreshRunInteractiveHTTPSUsesFreshAuthFlowCredentialForSetup(t *testing.T) {
	authCfg := &refreshSetupAuthConfig{AuthConfig: &config.AuthConfig{}}
	recorder := &refreshSetupCommandRecorder{}
	opts, _, stdout, stderr, output := newRefreshSetupOptions(t, authCfg, recorder)

	opts.AuthFlow = func(_ *http.Client, _ *iostreams.IOStreams, hostname string, _ []string, interactive, clipboard bool) (token, username, error) {
		authCfg.authFlowStarted = true
		if hostname != "github.com" || !interactive || clipboard {
			t.Errorf("unexpected auth-flow context")
		}
		return token("synthetic-flow-token"), username("synthetic-account"), nil
	}

	err := refreshRun(opts)

	assert.False(t, errors.Is(err, errSyntheticRefreshUnexpectedPostAuthResolution), "post-auth credential resolution was attempted")
	assert.NoError(t, err)
	assert.False(t, output.completedBeforeSetup, "authentication success was reported before credential setup completed")
	assert.Contains(t, stderr.String(), "Authentication complete.")
	assert.Empty(t, stdout.String())
	assert.Equal(t, 1, authCfg.preAuthResolverCall)
	assert.Equal(t, 0, authCfg.postAuthResolverCall)
	assert.Equal(t, 1, authCfg.resolverCalls)
	assert.Equal(t, 0, authCfg.legacyCalls)
	assert.Equal(t, 1, authCfg.loginCalls)
	assert.Equal(t, "synthetic-flow-token", authCfg.loginToken)
	assert.Equal(t, []string{"config credential.https://github.com.helper", "credential reject", "credential approve"}, recorder.commands)
	if assert.Len(t, recorder.approvedInputs, 1) {
		assert.True(t, bytes.Equal(recorder.approvedInputs[0], []byte("protocol=https\nhost=github.com\nusername=synthetic-account\npassword=synthetic-flow-token\n")), "credential setup did not receive the fresh auth-flow credential")
	}
	requireRefreshSetupOutputSecretFree(t, strings.ToLower(stderr.String()+stdout.String()))
}

func TestRefreshRunInteractiveHTTPSSetupFailureHasNoSuccessOutput(t *testing.T) {
	authCfg := &refreshSetupAuthConfig{AuthConfig: &config.AuthConfig{}}
	recorder := &refreshSetupCommandRecorder{failApprove: true}
	opts, _, stdout, stderr, output := newRefreshSetupOptions(t, authCfg, recorder)

	opts.AuthFlow = func(_ *http.Client, _ *iostreams.IOStreams, _ string, _ []string, _ bool, _ bool) (token, username, error) {
		authCfg.authFlowStarted = true
		return token("synthetic-flow-token"), username("synthetic-account"), nil
	}

	err := refreshRun(opts)
	errText := ""
	if err != nil {
		errText = err.Error()
	}
	combined := errText + stdout.String() + stderr.String()

	assert.False(t, errors.Is(err, errSyntheticRefreshUnexpectedPostAuthResolution), "post-auth credential resolution was attempted")
	assert.Empty(t, stdout.String())
	assert.False(t, strings.Contains(stderr.String(), "Authentication complete."), "authentication success was reported after credential setup failed")
	assert.False(t, output.completedBeforeSetup, "authentication success was reported before credential setup completed")
	assert.Equal(t, 1, authCfg.preAuthResolverCall)
	assert.Equal(t, 0, authCfg.postAuthResolverCall)
	assert.Equal(t, 1, authCfg.resolverCalls)
	assert.Equal(t, 0, authCfg.legacyCalls)
	assert.Equal(t, 1, authCfg.loginCalls)
	assert.Len(t, recorder.approvedInputs, 1)
	requireRefreshSetupOutputSecretFree(t, strings.ToLower(combined))
	assert.ErrorIs(t, err, errSyntheticRefreshSetupDenied)
}
