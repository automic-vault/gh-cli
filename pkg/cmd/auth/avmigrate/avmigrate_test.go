package avmigrate

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cli/cli/v2/internal/config"
	"github.com/cli/cli/v2/internal/gh"
	"github.com/cli/cli/v2/internal/keyring"
	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/cli/cli/v2/pkg/iostreams"
	"github.com/google/shlex"
	"github.com/stretchr/testify/require"
)

func TestNewCmdAVMigrate(t *testing.T) {
	ios, _, _, _ := iostreams.Test()
	f := &cmdutil.Factory{
		IOStreams: ios,
		Config: func() (gh.Config, error) {
			cfg := config.NewBlankConfig()
			return cfg, nil
		},
	}

	var cmdOpts *MigrateOptions
	cmd := NewCmdAVMigrate(f, func(opts *MigrateOptions) error {
		cmdOpts = opts
		return nil
	})
	cmd.Flags().BoolP("help", "x", false, "")

	argv, err := shlex.Split("--hostname github.example.com --user monalisa")
	require.NoError(t, err)

	cmd.SetArgs(argv)
	cmd.SetIn(&bytes.Buffer{})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})

	_, err = cmd.ExecuteC()
	require.NoError(t, err)
	require.True(t, cmd.Hidden)
	require.Equal(t, "github.example.com", cmdOpts.Hostname)
	require.Equal(t, "monalisa", cmdOpts.Username)
}

func TestMigrateRunMigratesActiveTokenToUserEntry(t *testing.T) {
	ios, _, _, stderr := iostreams.Test()
	cfg, _ := config.NewIsolatedTestConfig(t)
	authCfg := cfg.Authentication()

	_, err := authCfg.Login("github.com", "monalisa", "old-token", "https", false)
	require.NoError(t, err)

	err = migrateRun(&MigrateOptions{
		IO: ios,
		Config: func() (gh.Config, error) {
			return cfg, nil
		},
		LegacyTokenFunc: func(hostname, username string) (string, error) {
			require.Equal(t, "github.com", hostname)
			require.Equal(t, "monalisa", username)
			return "old-token", nil
		},
		LegacyDeleteFunc: func(hostname, username string) error {
			require.Equal(t, "github.com", hostname)
			require.Equal(t, "monalisa", username)
			return nil
		},
	})
	require.NoError(t, err)

	token, err := authCfg.TokenFromKeyringForUser("github.com", "monalisa")
	require.NoError(t, err)
	require.Equal(t, "old-token", token)

	activeToken, source := authCfg.ActiveToken("github.com")
	require.Equal(t, "old-token", activeToken)
	require.Equal(t, "keyring", source)
	require.Contains(t, stderr.String(), "migrated credentials for github.com account monalisa")
}

func TestMigrateRunUsesExplicitUser(t *testing.T) {
	ios, _, _, _ := iostreams.Test()
	cfg, _ := config.NewIsolatedTestConfig(t)
	authCfg := cfg.Authentication()

	_, err := authCfg.Login("github.com", "monalisa", "token-1", "https", false)
	require.NoError(t, err)
	_, err = authCfg.Login("github.com", "hubot", "token-2", "https", false)
	require.NoError(t, err)

	err = migrateRun(&MigrateOptions{
		IO:       ios,
		Hostname: "github.com",
		Username: "hubot",
		Config: func() (gh.Config, error) {
			return cfg, nil
		},
		LegacyTokenFunc: func(hostname, username string) (string, error) {
			require.Equal(t, "github.com", hostname)
			require.Equal(t, "hubot", username)
			return "token-2", nil
		},
		LegacyDeleteFunc: func(hostname, username string) error {
			require.Equal(t, "github.com", hostname)
			require.Equal(t, "hubot", username)
			return nil
		},
	})
	require.NoError(t, err)

	token, err := authCfg.TokenFromKeyringForUser("github.com", "hubot")
	require.NoError(t, err)
	require.Equal(t, "token-2", token)
}

func TestMigrateRunErrorsWithoutKeychainToken(t *testing.T) {
	ios, _, _, _ := iostreams.Test()
	cfg, _ := config.NewIsolatedTestConfig(t)

	err := migrateRun(&MigrateOptions{
		IO:       ios,
		Hostname: "github.com",
		Username: "monalisa",
		Config: func() (gh.Config, error) {
			return cfg, nil
		},
		LegacyTokenFunc: func(hostname, username string) (string, error) {
			require.Equal(t, "github.com", hostname)
			require.Equal(t, "monalisa", username)
			return "", errors.New("not found")
		},
	})

	require.EqualError(t, err, "failed to read legacy keychain token for github.com account monalisa: not found")
}

func TestMigrateRunFailsClosedWhenKeyringWriteFails(t *testing.T) {
	ios, _, _, _ := iostreams.Test()
	cfg, _ := config.NewIsolatedTestConfig(t)
	keyring.MockInitWithError(errors.New("test-explosion"))

	err := migrateRun(&MigrateOptions{
		IO:       ios,
		Hostname: "github.com",
		Username: "monalisa",
		Config: func() (gh.Config, error) {
			return cfg, nil
		},
		LegacyTokenFunc: func(hostname, username string) (string, error) {
			require.Equal(t, "github.com", hostname)
			require.Equal(t, "monalisa", username)
			return "old-token", nil
		},
		LegacyDeleteFunc: func(hostname, username string) error {
			require.Equal(t, "github.com", hostname)
			require.Equal(t, "monalisa", username)
			return nil
		},
	})
	require.EqualError(t, err, "failed to store user token in keychain: test-explosion")

	authCfg := cfg.Authentication()
	token, _ := authCfg.ActiveToken("github.com")
	require.Empty(t, token)
}

func TestMigrateRunDeletesBeforeSecureLogin(t *testing.T) {
	ios, _, _, _ := iostreams.Test()
	cfg, _ := config.NewIsolatedTestConfig(t)
	deleted := false

	err := migrateRun(&MigrateOptions{
		IO:       ios,
		Hostname: "github.com",
		Username: "monalisa",
		Config: func() (gh.Config, error) {
			return cfg, nil
		},
		LegacyTokenFunc: func(hostname, username string) (string, error) {
			require.Equal(t, "github.com", hostname)
			require.Equal(t, "monalisa", username)
			return "old-token", nil
		},
		LegacyDeleteFunc: func(hostname, username string) error {
			require.Equal(t, "github.com", hostname)
			require.Equal(t, "monalisa", username)
			deleted = true
			return nil
		},
		SecureLoginFunc: func(authCfg *config.AuthConfig, hostname, username, token string) error {
			require.True(t, deleted)
			require.Equal(t, "github.com", hostname)
			require.Equal(t, "monalisa", username)
			require.Equal(t, "old-token", token)
			return nil
		},
	})

	require.NoError(t, err)
}

func TestMigrateRunRestoresLegacyItemsWhenSecureLoginFails(t *testing.T) {
	ios, _, _, _ := iostreams.Test()
	cfg, _ := config.NewIsolatedTestConfig(t)
	deleted := false
	restored := false

	err := migrateRun(&MigrateOptions{
		IO:       ios,
		Hostname: "github.com",
		Username: "monalisa",
		Config: func() (gh.Config, error) {
			return cfg, nil
		},
		LegacyTokenFunc: func(hostname, username string) (string, error) {
			require.Equal(t, "github.com", hostname)
			require.Equal(t, "monalisa", username)
			return "old-token", nil
		},
		LegacyDeleteFunc: func(hostname, username string) error {
			deleted = true
			return nil
		},
		SecureLoginFunc: func(authCfg *config.AuthConfig, hostname, username, token string) error {
			require.True(t, deleted)
			return errors.New("boom")
		},
		LegacyRestoreFunc: func(hostname, username, token string) error {
			require.True(t, deleted)
			require.Equal(t, "github.com", hostname)
			require.Equal(t, "monalisa", username)
			require.Equal(t, "old-token", token)
			restored = true
			return nil
		},
	})

	require.EqualError(t, err, "boom")
	require.True(t, restored)
}

func TestLegacySecurityArgsUseLoginKeychainWhenAvailable(t *testing.T) {
	home := t.TempDir()
	keychain := filepath.Join(home, "Library", "Keychains", "login.keychain-db")
	require.NoError(t, os.MkdirAll(filepath.Dir(keychain), 0755))
	require.NoError(t, os.WriteFile(keychain, []byte{}, 0644))
	t.Setenv("HOME", home)

	args := legacySecurityArgs("find-generic-password", "-s", "gh:github.com", "-w")

	require.Equal(t, []string{
		"find-generic-password",
		"-s",
		"gh:github.com",
		"-w",
		keychain,
	}, args)
}

func TestLegacySecurityArgsFallBackToAmbientSearchList(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	args := legacySecurityArgs("find-generic-password", "-s", "gh:github.com", "-w")

	require.Equal(t, []string{
		"find-generic-password",
		"-s",
		"gh:github.com",
		"-w",
	}, args)
}
