package token

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/MakeNowJust/heredoc"
	"github.com/cli/cli/v2/internal/gh"
	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/cli/cli/v2/pkg/iostreams"
	"github.com/spf13/cobra"
)

type TokenOptions struct {
	IO     *iostreams.IOStreams
	Config func() (gh.Config, error)

	Hostname      string
	Username      string
	SecureStorage bool
	ApprovalFunc  func(hostname, username string) error
}

func NewCmdToken(f *cmdutil.Factory, runF func(*TokenOptions) error) *cobra.Command {
	opts := &TokenOptions{
		IO:     f.IOStreams,
		Config: f.Config,
	}

	cmd := &cobra.Command{
		Use:   "token",
		Short: "Print the authentication token gh uses for a hostname and account",
		Long: heredoc.Docf(`
			This command outputs the authentication token for an account on a given GitHub host.

			Without the %[1]s--hostname%[1]s flag, the default host is chosen.

			Without the %[1]s--user%[1]s flag, the active account for the host is chosen.
		`, "`"),
		Args: cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			if runF != nil {
				return runF(opts)
			}

			return tokenRun(opts)
		},
	}

	cmd.Flags().StringVarP(&opts.Hostname, "hostname", "h", "", "The hostname of the GitHub instance authenticated with")
	cmd.Flags().StringVarP(&opts.Username, "user", "u", "", "The account to output the token for")
	cmd.Flags().BoolVarP(&opts.SecureStorage, "secure-storage", "", false, "Search only secure credential store for authentication token")
	_ = cmd.Flags().MarkHidden("secure-storage")

	return cmd
}

func tokenRun(opts *TokenOptions) error {
	cfg, err := opts.Config()
	if err != nil {
		return err
	}
	authCfg := cfg.Authentication()

	hostname := opts.Hostname
	if hostname == "" {
		hostname, _ = authCfg.DefaultHost()
	}

	approval := opts.ApprovalFunc
	if approval == nil {
		approval = requestAutomicVaultApprovalForToken
	}
	if err := approval(hostname, opts.Username); err != nil {
		return err
	}

	var val string
	// If this conditional logic ends up being duplicated anywhere,
	// we should consider making a factory function that returns the correct
	// behavior. For now, keeping it all inline is simplest.
	if opts.SecureStorage {
		if opts.Username == "" {
			val, _ = authCfg.TokenFromKeyring(hostname)
		} else {
			val, _ = authCfg.TokenFromKeyringForUser(hostname, opts.Username)
		}
	} else {
		if opts.Username == "" {
			val, _ = authCfg.ActiveToken(hostname)
		} else {
			val, _, _ = authCfg.TokenForUser(hostname, opts.Username)
		}
	}

	if val == "" {
		errMsg := fmt.Sprintf("no oauth token found for %s", hostname)
		if opts.Username != "" {
			errMsg += fmt.Sprintf(" account %s", opts.Username)
		}
		return errors.New(errMsg)
	}

	if val != "" {
		fmt.Fprintf(opts.IO.Out, "%s\n", val)
	}

	return nil
}

func requestAutomicVaultApprovalForToken(hostname, username string) error {
	return requestAutomicVaultApproval(newAutomicVaultApprovalRequest(hostname, username))
}

type automicVaultApprovalRequest struct {
	Type   string                      `json:"type"`
	ID     string                      `json:"id"`
	Intent automicVaultExecutionIntent `json:"intent"`
}

type automicVaultExecutionIntent struct {
	Tool    string            `json:"tool"`
	Args    []string          `json:"args"`
	Cwd     string            `json:"cwd"`
	Env     map[string]string `json:"env"`
	AgentID string            `json:"agent_id,omitempty"`
}

type automicVaultDaemonEvent struct {
	Type     string `json:"type"`
	ID       string `json:"id"`
	Approved bool   `json:"approved"`
	Reason   string `json:"reason"`
	Code     int    `json:"code"`
	Message  string `json:"message"`
}

func newAutomicVaultApprovalRequest(hostname, username string) automicVaultApprovalRequest {
	args := []string{"--hostname", hostname}
	if username != "" {
		args = append(args, "--user", username)
	}

	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}

	return automicVaultApprovalRequest{
		Type: "approval_request",
		ID: fmt.Sprintf(
			"gh-auth-token-%d-%d",
			os.Getpid(),
			time.Now().UnixMilli(),
		),
		Intent: automicVaultExecutionIntent{
			Tool:    "gh auth token",
			Args:    args,
			Cwd:     cwd,
			Env:     filteredAutomicVaultEnv(),
			AgentID: os.Getenv("VAULT_AGENT_ID"),
		},
	}
}

func requestAutomicVaultApproval(request automicVaultApprovalRequest) error {
	socketPath, err := automicVaultSocketPath()
	if err != nil {
		return err
	}

	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		return fmt.Errorf("automic vault approval unavailable: %w", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(15 * time.Minute)); err != nil {
		return fmt.Errorf("failed to configure automic vault approval timeout: %w", err)
	}

	encoded, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("failed to encode automic vault approval request: %w", err)
	}
	if _, err := conn.Write(append(encoded, '\n')); err != nil {
		return fmt.Errorf("failed to send automic vault approval request: %w", err)
	}

	scanner := bufio.NewScanner(conn)
	approved := false
	for scanner.Scan() {
		var event automicVaultDaemonEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return fmt.Errorf("failed to decode automic vault approval response: %w", err)
		}
		if event.ID != "" && event.ID != request.ID {
			return errors.New("automic vault returned a mismatched approval response")
		}

		switch event.Type {
		case "approval_response":
			if !event.Approved {
				reason := event.Reason
				if reason == "" {
					reason = "denied by automic vault"
				}
				return errors.New(reason)
			}
			approved = true
		case "error":
			if approved {
				return nil
			}
			if event.Message == "" {
				event.Message = "automic vault approval failed"
			}
			if event.Code != 0 {
				return fmt.Errorf("automic vault error %d: %s", event.Code, event.Message)
			}
			return errors.New(event.Message)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("failed to read automic vault approval response: %w", err)
	}
	if approved {
		return nil
	}
	return errors.New("automic vault closed the approval request before approval")
}

func automicVaultSocketPath() (string, error) {
	if socketPath := os.Getenv("VAULT_SOCKET_PATH"); socketPath != "" {
		return socketPath, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to locate home directory for automic vault socket: %w", err)
	}
	return filepath.Join(home, "Library", "Application Support", "Automic Vault", "vault.sock"), nil
}

func filteredAutomicVaultEnv() map[string]string {
	env := map[string]string{}
	for _, key := range []string{
		"HOME",
		"LANG",
		"LC_ALL",
		"LOGNAME",
		"PATH",
		"PWD",
		"SHELL",
		"TERM",
		"TMPDIR",
		"USER",
		"VAULT_AGENT_ID",
		"VAULT_SOCKET_PATH",
		"VAULT_TOOLCHAIN_ROOT",
	} {
		if value, ok := os.LookupEnv(key); ok {
			env[key] = value
		}
	}
	return env
}
