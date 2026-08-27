package keyring

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDeleteNormalizesBackendNotFound(t *testing.T) {
	MockInit()
	t.Cleanup(MockInit)

	err := Delete("synthetic-service", "synthetic-account")

	require.Error(t, err)
	require.ErrorIs(t, err, ErrNotFound)
}
