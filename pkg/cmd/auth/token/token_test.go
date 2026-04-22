package token

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/cli/cli/v2/internal/config"
	"github.com/cli/cli/v2/internal/gh"
	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/cli/cli/v2/pkg/iostreams"
	"github.com/google/shlex"
	"github.com/stretchr/testify/require"
)

func TestNewCmdToken(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		output     TokenOptions
		wantErr    bool
		wantErrMsg string
	}{
		{
			name:   "no flags",
			input:  "",
			output: TokenOptions{},
		},
		{
			name:   "with hostname",
			input:  "--hostname github.mycompany.com",
			output: TokenOptions{Hostname: "github.mycompany.com"},
		},
		{
			name:   "with user",
			input:  "--user test-user",
			output: TokenOptions{Username: "test-user"},
		},
		{
			name:   "with shorthand user",
			input:  "-u test-user",
			output: TokenOptions{Username: "test-user"},
		},
		{
			name:   "with shorthand hostname",
			input:  "-h github.mycompany.com",
			output: TokenOptions{Hostname: "github.mycompany.com"},
		},
		{
			name:   "with secure-storage",
			input:  "--secure-storage",
			output: TokenOptions{SecureStorage: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ios, _, _, _ := iostreams.Test()
			f := &cmdutil.Factory{
				IOStreams: ios,
				Config: func() (gh.Config, error) {
					cfg := config.NewBlankConfig()
					return cfg, nil
				},
			}
			argv, err := shlex.Split(tt.input)
			require.NoError(t, err)

			var cmdOpts *TokenOptions
			cmd := NewCmdToken(f, func(opts *TokenOptions) error {
				cmdOpts = opts
				return nil
			})
			// TODO cobra hack-around
			cmd.Flags().BoolP("help", "x", false, "")

			cmd.SetArgs(argv)
			cmd.SetIn(&bytes.Buffer{})
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetErr(&bytes.Buffer{})

			_, err = cmd.ExecuteC()
			if tt.wantErr {
				require.Error(t, err)
				require.EqualError(t, err, tt.wantErrMsg)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.output.Hostname, cmdOpts.Hostname)
			require.Equal(t, tt.output.SecureStorage, cmdOpts.SecureStorage)
		})
	}
}

func TestTokenRun(t *testing.T) {
	tests := []struct {
		name       string
		opts       TokenOptions
		env        map[string]string
		cfgStubs   func(*testing.T, gh.Config)
		wantStdout string
		wantErr    bool
		wantErrMsg string
	}{
		{
			name: "token",
			opts: TokenOptions{},
			cfgStubs: func(t *testing.T, cfg gh.Config) {
				login(t, cfg, "github.com", "test-user", "gho_ABCDEFG", "https", false)
			},
			wantStdout: "gho_ABCDEFG\n",
		},
		{
			name: "token by hostname",
			opts: TokenOptions{
				Hostname: "github.mycompany.com",
			},
			cfgStubs: func(t *testing.T, cfg gh.Config) {
				login(t, cfg, "github.com", "test-user", "gho_ABCDEFG", "https", false)
				login(t, cfg, "github.mycompany.com", "test-user", "gho_1234567", "https", false)
			},
			wantStdout: "gho_1234567\n",
		},
		{
			name:       "no token",
			opts:       TokenOptions{},
			wantErr:    true,
			wantErrMsg: "no oauth token found for github.com",
		},
		{
			name: "no token for hostname user",
			opts: TokenOptions{
				Hostname: "ghe.io",
				Username: "test-user",
			},
			wantErr:    true,
			wantErrMsg: "no oauth token found for ghe.io account test-user",
		},
		{
			name: "uses default host when one is not provided",
			opts: TokenOptions{},
			cfgStubs: func(t *testing.T, cfg gh.Config) {
				login(t, cfg, "github.com", "test-user", "gho_ABCDEFG", "https", false)
				login(t, cfg, "github.mycompany.com", "test-user", "gho_1234567", "https", false)
			},
			env:        map[string]string{"GH_HOST": "github.mycompany.com"},
			wantStdout: "gho_1234567\n",
		},
		{
			name: "token for user",
			opts: TokenOptions{
				Hostname: "github.com",
				Username: "test-user",
			},
			cfgStubs: func(t *testing.T, cfg gh.Config) {
				login(t, cfg, "github.com", "test-user", "gho_ABCDEFG", "https", false)
				login(t, cfg, "github.com", "test-user-2", "gho_1234567", "https", false)
			},
			wantStdout: "gho_ABCDEFG\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ios, _, stdout, _ := iostreams.Test()
			tt.opts.IO = ios
			tt.opts.ApprovalFunc = approveAutomicVaultRequest

			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			cfg, _ := config.NewIsolatedTestConfig(t)
			if tt.cfgStubs != nil {
				tt.cfgStubs(t, cfg)
			}

			tt.opts.Config = func() (gh.Config, error) {
				return cfg, nil
			}

			err := tokenRun(&tt.opts)
			if tt.wantErr {
				require.Error(t, err)
				require.EqualError(t, err, tt.wantErrMsg)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantStdout, stdout.String())
		})
	}
}

func TestTokenRunSecureStorage(t *testing.T) {
	tests := []struct {
		name       string
		opts       TokenOptions
		cfgStubs   func(*testing.T, gh.Config)
		wantStdout string
		wantErr    bool
		wantErrMsg string
	}{
		{
			name: "token",
			opts: TokenOptions{},
			cfgStubs: func(t *testing.T, cfg gh.Config) {
				login(t, cfg, "github.com", "test-user", "gho_ABCDEFG", "https", true)
			},
			wantStdout: "gho_ABCDEFG\n",
		},
		{
			name: "token by hostname",
			opts: TokenOptions{
				Hostname: "mycompany.com",
			},
			cfgStubs: func(t *testing.T, cfg gh.Config) {
				login(t, cfg, "mycompany.com", "test-user", "gho_1234567", "https", true)
			},
			wantStdout: "gho_1234567\n",
		},
		{
			name:       "no token",
			opts:       TokenOptions{},
			wantErr:    true,
			wantErrMsg: "no oauth token found for github.com",
		},
		{
			name: "no token for hostname user",
			opts: TokenOptions{
				Hostname: "ghe.io",
				Username: "test-user",
			},
			wantErr:    true,
			wantErrMsg: "no oauth token found for ghe.io account test-user",
		},
		{
			name: "token for user",
			opts: TokenOptions{
				Hostname: "github.com",
				Username: "test-user",
			},
			cfgStubs: func(t *testing.T, cfg gh.Config) {
				login(t, cfg, "github.com", "test-user", "gho_ABCDEFG", "https", true)
				login(t, cfg, "github.com", "test-user-2", "gho_1234567", "https", true)
			},
			wantStdout: "gho_ABCDEFG\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ios, _, stdout, _ := iostreams.Test()
			tt.opts.IO = ios
			tt.opts.SecureStorage = true
			tt.opts.ApprovalFunc = approveAutomicVaultRequest

			cfg, _ := config.NewIsolatedTestConfig(t)
			if tt.cfgStubs != nil {
				tt.cfgStubs(t, cfg)
			}

			tt.opts.Config = func() (gh.Config, error) {
				return cfg, nil
			}

			err := tokenRun(&tt.opts)
			if tt.wantErr {
				require.Error(t, err)
				require.EqualError(t, err, tt.wantErrMsg)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantStdout, stdout.String())
		})
	}
}

func TestTokenRunRequiresAutomicVaultApproval(t *testing.T) {
	ios, _, _, _ := iostreams.Test()
	cfg, _ := config.NewIsolatedTestConfig(t)
	login(t, cfg, "github.com", "test-user", "gho_ABCDEFG", "https", false)

	opts := &TokenOptions{
		IO: ios,
		Config: func() (gh.Config, error) {
			return cfg, nil
		},
		ApprovalFunc: func(hostname, username string) error {
			require.Equal(t, "github.com", hostname)
			require.Empty(t, username)
			return os.ErrPermission
		},
	}

	err := tokenRun(opts)

	require.ErrorIs(t, err, os.ErrPermission)
}

func TestRequestAutomicVaultApprovalApproves(t *testing.T) {
	request := newAutomicVaultApprovalRequest("github.com", "")
	socketPath := startAutomicVaultApprovalServer(t, func(t *testing.T, requestLine string) []string {
		var decoded automicVaultApprovalRequest
		require.NoError(t, json.Unmarshal([]byte(requestLine), &decoded))
		require.Equal(t, "approval_request", decoded.Type)
		require.Equal(t, "gh auth token", decoded.Intent.Tool)
		require.Equal(t, []string{"--hostname", "github.com"}, decoded.Intent.Args)

		return []string{
			`{"type":"approval_response","id":"` + decoded.ID + `","approved":true}`,
			`{"type":"error","id":"` + decoded.ID + `","code":404,"message":"unable to resolve gh auth token"}`,
		}
	})
	t.Setenv("VAULT_SOCKET_PATH", socketPath)

	require.NoError(t, requestAutomicVaultApproval(request))
}

func TestRequestAutomicVaultApprovalDenies(t *testing.T) {
	request := newAutomicVaultApprovalRequest("github.com", "")
	socketPath := startAutomicVaultApprovalServer(t, func(t *testing.T, requestLine string) []string {
		var decoded automicVaultApprovalRequest
		require.NoError(t, json.Unmarshal([]byte(requestLine), &decoded))
		return []string{
			`{"type":"approval_response","id":"` + decoded.ID + `","approved":false,"reason":"Denied by operator"}`,
		}
	})
	t.Setenv("VAULT_SOCKET_PATH", socketPath)

	err := requestAutomicVaultApproval(request)

	require.EqualError(t, err, "Denied by operator")
}

func TestRequestAutomicVaultApprovalFailsClosedWhenUnavailable(t *testing.T) {
	t.Setenv("VAULT_SOCKET_PATH", filepath.Join(t.TempDir(), "missing.sock"))

	err := requestAutomicVaultApproval(newAutomicVaultApprovalRequest("github.com", ""))

	require.ErrorContains(t, err, "automic vault approval unavailable")
}

func login(t *testing.T, c gh.Config, hostname, username, token, gitProtocol string, secureStorage bool) {
	t.Helper()
	_, err := c.Authentication().Login(hostname, username, token, gitProtocol, secureStorage)
	require.NoError(t, err)
}

func approveAutomicVaultRequest(_, _ string) error {
	return nil
}

func startAutomicVaultApprovalServer(
	t *testing.T,
	handler func(*testing.T, string) []string,
) string {
	t.Helper()

	socketPath := filepath.Join(os.TempDir(), "gh-token-vault-"+randomString(t)+".sock")
	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = listener.Close()
		_ = os.Remove(socketPath)
	})

	done := make(chan struct{})
	t.Cleanup(func() {
		<-done
	})

	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		requestLine := string(bytes.TrimSpace(buf[:n]))
		for _, response := range handler(t, requestLine) {
			_, _ = conn.Write([]byte(response + "\n"))
		}
	}()

	return socketPath
}

func randomString(t *testing.T) string {
	t.Helper()
	file, err := os.CreateTemp("", "gh-token-vault-")
	require.NoError(t, err)
	path := file.Name()
	require.NoError(t, file.Close())
	require.NoError(t, os.Remove(path))
	return filepath.Base(path)
}
