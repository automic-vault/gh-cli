//go:build darwin

package keyring

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVaultKey(t *testing.T) {
	require.Equal(t, "GH_TOKEN_GITHUB_COM", vaultKey("gh:github.com", ""))
	require.Equal(t, "GH_TOKEN_GITHUB_COM_MONA_LISA", vaultKey("gh:github.com", "mona-lisa"))
	require.Equal(t, "GH_TOKEN_GHE_EXAMPLE_COM_OCTO_CAT", vaultKey("gh:ghe.example.com", "octo_cat"))
}

func TestTokenRequestDetail(t *testing.T) {
	require.Equal(t, "gh needs the active GitHub token for github.com", tokenRequestDetail("gh:github.com", ""))
	require.Equal(t, "gh needs the GitHub token for github.com account monalisa", tokenRequestDetail("gh:github.com", "monalisa"))
}

func TestApprovalServiceSigningRequirementPinsTeamAndIdentifier(t *testing.T) {
	require.Contains(t, approvalServiceSigningRequirement, `certificate leaf[subject.OU] = ZU76A67LGU`)
	require.Contains(t, approvalServiceSigningRequirement, `identifier "com.automicvault"`)
	require.NotContains(t, approvalServiceSigningRequirement, "menu-helper")
}

func TestApprovalEventNotice(t *testing.T) {
	require.Equal(t, "automic vault: human approval required\n", approvalEventNotice("human-approval-required"))
	require.Empty(t, approvalEventNotice("other-event"))
}
