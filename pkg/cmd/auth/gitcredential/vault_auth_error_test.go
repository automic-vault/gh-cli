package login

import (
	"errors"
	"fmt"
	"testing"

	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/cli/cli/v2/pkg/iostreams"
)

var errSyntheticGitCredentialVaultDenied = errors.New("synthetic Vault retrieval denied for git credential helper")

// dualVaultCredentialConfig keeps the old getter available so that a helper
// which silently ignores the error-aware getter emits a visible legacy
// credential instead of satisfying this test accidentally.
type dualVaultCredentialConfig struct {
	legacyToken   string
	legacySource  string
	legacyCalls   int
	token         string
	source        string
	resolverCalls int
	err           error
	user          string
}

func (c *dualVaultCredentialConfig) ActiveToken(string) (string, string) {
	c.legacyCalls++
	return c.legacyToken, c.legacySource
}

func (c *dualVaultCredentialConfig) ActiveTokenWithError(string) (string, string, error) {
	c.resolverCalls++
	return c.token, c.source, c.err
}

func (c *dualVaultCredentialConfig) ActiveUser(string) (string, error) {
	return c.user, nil
}

func requireErrorAwareGitCredentialConfig(t *testing.T, cfg config) {
	t.Helper()
	if _, ok := any(cfg).(interface {
		ActiveTokenWithError(string) (string, string, error)
	}); !ok {
		t.Fatal("test config must expose the error-aware token resolver")
	}
}

func TestHelperRunOperationalVaultErrorDoesNotUseLegacyCredential(t *testing.T) {
	cfg := &dualVaultCredentialConfig{
		legacyToken:  "synthetic-legacy-token",
		legacySource: "legacy-host-slot",
		err:          errSyntheticGitCredentialVaultDenied,
		user:         "synthetic-account",
	}
	requireErrorAwareGitCredentialConfig(t, cfg)

	ios, stdin, stdout, _ := iostreams.Test()
	fmt.Fprint(stdin, "protocol=https\nhost=github.com\n\n")

	err := helperRun(&CredentialOptions{
		IO:        ios,
		Operation: "get",
		Config: func() (config, error) {
			return cfg, nil
		},
	})

	if stdout.Len() != 0 {
		t.Errorf("expected completely empty protocol stdout after Vault failure, got %d bytes", stdout.Len())
	}
	if cfg.legacyCalls != 0 {
		t.Errorf("expected no legacy credential lookup after Vault failure, got %d", cfg.legacyCalls)
	}
	if cfg.resolverCalls != 1 {
		t.Errorf("expected one error-aware credential lookup after Vault failure, got %d", cfg.resolverCalls)
	}
	if !errors.Is(err, errSyntheticGitCredentialVaultDenied) {
		t.Errorf("expected the operational Vault error to propagate, got %T", err)
	}
}

func TestHelperRunResolvedVaultTokenRemainsCompatible(t *testing.T) {
	cfg := &dualVaultCredentialConfig{
		legacyToken:  "synthetic-resolved-token",
		legacySource: "keyring",
		token:        "synthetic-resolved-token",
		source:       "keyring",
		user:         "synthetic-account",
	}
	requireErrorAwareGitCredentialConfig(t, cfg)

	ios, stdin, stdout, _ := iostreams.Test()
	fmt.Fprint(stdin, "protocol=https\nhost=github.com\n\n")

	err := helperRun(&CredentialOptions{
		IO:        ios,
		Operation: "get",
		Config: func() (config, error) {
			return cfg, nil
		},
	})

	if err != nil {
		t.Errorf("expected a resolved Vault credential to remain compatible, got %T", err)
	}
	if cfg.legacyCalls != 0 {
		t.Errorf("expected no legacy credential lookup for a resolved Vault credential, got %d", cfg.legacyCalls)
	}
	if cfg.resolverCalls != 1 {
		t.Errorf("expected one error-aware credential lookup for a resolved Vault credential, got %d", cfg.resolverCalls)
	}
	if got, want := stdout.String(), "protocol=https\nhost=github.com\nusername=synthetic-account\npassword=synthetic-resolved-token\n"; got != want {
		t.Errorf("expected exact resolved credential protocol response, got %q, want %q", got, want)
	}
}

func TestHelperRunTrulyAbsentCredentialRemainsAnonymous(t *testing.T) {
	cfg := &dualVaultCredentialConfig{}
	requireErrorAwareGitCredentialConfig(t, cfg)

	ios, stdin, stdout, _ := iostreams.Test()
	fmt.Fprint(stdin, "protocol=https\nhost=github.com\n\n")

	err := helperRun(&CredentialOptions{
		IO:        ios,
		Operation: "get",
		Config: func() (config, error) {
			return cfg, nil
		},
	})

	if !errors.Is(err, cmdutil.SilentError) {
		t.Errorf("expected truly absent credentials to remain silent, got %T", err)
	}
	if stdout.Len() != 0 {
		t.Errorf("expected empty protocol stdout for absent credentials, got %d bytes", stdout.Len())
	}
	if cfg.legacyCalls != 0 {
		t.Errorf("expected no legacy credential lookup for absent credentials, got %d", cfg.legacyCalls)
	}
	if cfg.resolverCalls != 1 {
		t.Errorf("expected one error-aware credential lookup for absent credentials, got %d", cfg.resolverCalls)
	}
}
