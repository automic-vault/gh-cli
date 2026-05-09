package automicvault

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRequestApprovalApproves(t *testing.T) {
	request := newApprovalRequest("gh auth token", []string{"--hostname", "github.com"})
	socketPath := startApprovalServer(t, func(t *testing.T, requestLine string) []string {
		var decoded approvalRequest
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

	require.NoError(t, requestApproval(request))
}

func TestRequestApprovalDenies(t *testing.T) {
	request := newApprovalRequest("gh auth token", []string{"--hostname", "github.com"})
	socketPath := startApprovalServer(t, func(t *testing.T, requestLine string) []string {
		var decoded approvalRequest
		require.NoError(t, json.Unmarshal([]byte(requestLine), &decoded))
		return []string{
			`{"type":"approval_response","id":"` + decoded.ID + `","approved":false,"reason":"Denied by operator"}`,
		}
	})
	t.Setenv("VAULT_SOCKET_PATH", socketPath)

	err := requestApproval(request)

	require.EqualError(t, err, "Denied by operator")
}

func TestRequestApprovalFailsClosedWhenUnavailable(t *testing.T) {
	t.Setenv("VAULT_SOCKET_PATH", filepath.Join(t.TempDir(), "missing.sock"))

	err := RequestApproval("gh auth token", []string{"--hostname", "github.com"})

	require.ErrorContains(t, err, "automic vault approval unavailable")
}

func startApprovalServer(
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
