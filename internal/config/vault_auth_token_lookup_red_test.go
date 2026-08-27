package config

import (
	"errors"
	"testing"

	"github.com/cli/cli/v2/internal/keyring"
	"github.com/stretchr/testify/require"
)

var errSyntheticTokenLookupVaultDenied = errors.New("synthetic Vault token lookup denied")

type tokenLookupCall struct {
	service string
	user    string
}

func TestTokenFromKeyringUsesTheConfiguredProviderContract(t *testing.T) {
	const (
		hostname    = "github.com"
		validToken  = "synthetic-token-from-vault"
		poisonToken = "synthetic-poison-token"
	)

	tests := []struct {
		name       string
		result     string
		err        error
		wantToken  string
		wantAbsent bool
	}{
		{
			name:      "valid credential",
			result:    validToken,
			wantToken: validToken,
		},
		{
			name:       "intentional absence",
			err:        keyring.ErrNotFound,
			wantAbsent: true,
		},
		{
			name:   "operational Vault failure",
			result: poisonToken,
			err:    errSyntheticTokenLookupVaultDenied,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authCfg := newTestAuthConfig(t)
			var calls []tokenLookupCall
			authCfg.keyringGet = func(service, user string) (string, error) {
				calls = append(calls, tokenLookupCall{service: service, user: user})
				return tt.result, tt.err
			}

			token, err := authCfg.TokenFromKeyring(hostname)

			require.Len(t, calls, 1)
			require.Equal(t, tokenLookupCall{service: keyringServiceName(hostname), user: ""}, calls[0])
			if tt.err == nil {
				require.NoError(t, err)
				require.Equal(t, tt.wantToken, token)
				return
			}

			require.Empty(t, token)
			if tt.wantAbsent {
				require.ErrorIs(t, err, keyring.ErrNotFound)
				return
			}

			require.EqualError(t, err, "Automic Vault credential resolution failed")
			var resolutionErr *AutomicVaultCredentialResolutionError
			require.ErrorAs(t, err, &resolutionErr)
			require.ErrorIs(t, err, errSyntheticTokenLookupVaultDenied)
			require.NotContains(t, err.Error(), poisonToken)
		})
	}
}

func TestTokenFromKeyringForUserUsesTheConfiguredProviderContract(t *testing.T) {
	const (
		hostname    = "github.com"
		username    = "synthetic-account"
		validToken  = "synthetic-user-token-from-vault"
		poisonToken = "synthetic-user-poison-token"
	)

	tests := []struct {
		name       string
		result     string
		err        error
		wantToken  string
		wantAbsent bool
	}{
		{
			name:      "valid credential",
			result:    validToken,
			wantToken: validToken,
		},
		{
			name:       "intentional absence",
			err:        keyring.ErrNotFound,
			wantAbsent: true,
		},
		{
			name:   "operational Vault failure",
			result: poisonToken,
			err:    errSyntheticTokenLookupVaultDenied,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authCfg := newTestAuthConfig(t)
			var calls []tokenLookupCall
			authCfg.keyringGet = func(service, user string) (string, error) {
				calls = append(calls, tokenLookupCall{service: service, user: user})
				return tt.result, tt.err
			}

			token, err := authCfg.TokenFromKeyringForUser(hostname, username)

			require.Len(t, calls, 1)
			require.Equal(t, tokenLookupCall{service: keyringServiceName(hostname), user: username}, calls[0])
			if tt.err == nil {
				require.NoError(t, err)
				require.Equal(t, tt.wantToken, token)
				return
			}

			require.Empty(t, token)
			if tt.wantAbsent {
				require.ErrorIs(t, err, keyring.ErrNotFound)
				return
			}

			require.EqualError(t, err, "Automic Vault credential resolution failed")
			var resolutionErr *AutomicVaultCredentialResolutionError
			require.ErrorAs(t, err, &resolutionErr)
			require.ErrorIs(t, err, errSyntheticTokenLookupVaultDenied)
			require.NotContains(t, err.Error(), poisonToken)
		})
	}
}

func TestTokenFromKeyringForUserRejectsBlankBeforeProviderLookup(t *testing.T) {
	authCfg := newTestAuthConfig(t)
	providerCalls := 0
	authCfg.keyringGet = func(string, string) (string, error) {
		providerCalls++
		return "synthetic-unexpected-token", nil
	}

	token, err := authCfg.TokenFromKeyringForUser("github.com", "")

	require.Empty(t, token)
	require.EqualError(t, err, "username cannot be blank")
	require.Zero(t, providerCalls)
}
