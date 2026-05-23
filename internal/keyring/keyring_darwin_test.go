//go:build darwin

package keyring

import (
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecodePlainSecret(t *testing.T) {
	secret, err := decode("test-token")

	require.NoError(t, err)
	require.Equal(t, "test-token", secret)
}

func TestDecodeGoKeyringBase64Secret(t *testing.T) {
	encoded := base64EncodingPrefix + base64.StdEncoding.EncodeToString([]byte("test-token"))

	secret, err := decode(encoded)

	require.NoError(t, err)
	require.Equal(t, "test-token", secret)
}

func TestDecodeGoKeyringHexSecret(t *testing.T) {
	encoded := encodingPrefix + hex.EncodeToString([]byte("test-token"))

	secret, err := decode(encoded)

	require.NoError(t, err)
	require.Equal(t, "test-token", secret)
}
