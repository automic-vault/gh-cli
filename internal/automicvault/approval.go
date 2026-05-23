package automicvault

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
)

type approvalRequest struct {
	Type   string          `json:"type"`
	ID     string          `json:"id"`
	Intent executionIntent `json:"intent"`
}

type executionIntent struct {
	Tool    string            `json:"tool"`
	Args    []string          `json:"args"`
	Cwd     string            `json:"cwd"`
	Env     map[string]string `json:"env"`
	AgentID string            `json:"agent_id,omitempty"`
}

type daemonEvent struct {
	Type     string `json:"type"`
	ID       string `json:"id"`
	Approved bool   `json:"approved"`
	Reason   string `json:"reason"`
	Code     int    `json:"code"`
	Message  string `json:"message"`
}

// RequestApproval asks the Automic Vault daemon to approve a token-exposing command.
func RequestApproval(tool string, args []string) error {
	return requestApproval(newApprovalRequest(tool, args))
}

func newApprovalRequest(tool string, args []string) approvalRequest {
	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}

	return approvalRequest{
		Type: "approval_request",
		ID: fmt.Sprintf(
			"gh-token-exposure-%d-%d",
			os.Getpid(),
			time.Now().UnixMilli(),
		),
		Intent: executionIntent{
			Tool:    tool,
			Args:    args,
			Cwd:     cwd,
			Env:     filteredEnv(),
			AgentID: os.Getenv("VAULT_AGENT_ID"),
		},
	}
}

func requestApproval(request approvalRequest) error {
	socketPath, err := socketPath()
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
		var event daemonEvent
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

func socketPath() (string, error) {
	if socketPath := os.Getenv("VAULT_SOCKET_PATH"); socketPath != "" {
		return socketPath, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to locate home directory for automic vault socket: %w", err)
	}
	return filepath.Join(home, "Library", "Application Support", "Automic Vault", "vault.sock"), nil
}

func filteredEnv() map[string]string {
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
