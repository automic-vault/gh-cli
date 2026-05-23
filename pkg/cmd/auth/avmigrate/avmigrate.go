package avmigrate

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/MakeNowJust/heredoc"
	"github.com/cli/cli/v2/internal/config"
	"github.com/cli/cli/v2/internal/gh"
	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/cli/cli/v2/pkg/iostreams"
	"github.com/spf13/cobra"
)

type MigrateOptions struct {
	IO     *iostreams.IOStreams
	Config func() (gh.Config, error)

	Hostname          string
	Username          string
	LegacyTokenFunc   func(hostname, username string) (string, error)
	LegacyDeleteFunc  func(hostname, username string) error
	LegacyRestoreFunc func(hostname, username, token string) error
	SecureLoginFunc   func(authCfg *config.AuthConfig, hostname, username, token string) error
}

func NewCmdAVMigrate(f *cmdutil.Factory, runF func(*MigrateOptions) error) *cobra.Command {
	opts := &MigrateOptions{
		IO:     f.IOStreams,
		Config: f.Config,
	}

	cmd := &cobra.Command{
		Use:   "av-migrate",
		Short: "Migrate stored credentials into Automic Vault-compatible storage",
		Long: heredoc.Doc(`
			Migrate stored credentials for a host into the Automic Vault-compatible
			keychain storage path without opening a browser or printing the token.
		`),
		Args:   cobra.ExactArgs(0),
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if runF != nil {
				return runF(opts)
			}
			return migrateRun(opts)
		},
	}

	cmd.Flags().StringVarP(&opts.Hostname, "hostname", "h", "", "The hostname of the GitHub instance to migrate")
	cmd.Flags().StringVarP(&opts.Username, "user", "u", "", "The account to migrate")

	return cmd
}

func migrateRun(opts *MigrateOptions) error {
	cfg, err := opts.Config()
	if err != nil {
		return err
	}
	authCfg := cfg.Authentication()

	hostname := opts.Hostname
	if hostname == "" {
		hostname, _ = authCfg.DefaultHost()
	}

	username := opts.Username
	if username == "" {
		username, err = authCfg.ActiveUser(hostname)
		if err != nil {
			return fmt.Errorf("could not determine active account for %s", hostname)
		}
	}

	legacyToken := opts.LegacyTokenFunc
	if legacyToken == nil {
		legacyToken = readLegacyToken
	}

	token, err := legacyToken(hostname, username)
	if err != nil {
		return fmt.Errorf("failed to read legacy keychain token for %s account %s: %w", hostname, username, err)
	}
	if token == "" {
		return errors.New("refusing to migrate an empty token")
	}

	deleteLegacy := opts.LegacyDeleteFunc
	if deleteLegacy == nil {
		deleteLegacy = deleteLegacyTokens
	}
	if err := deleteLegacy(hostname, username); err != nil {
		return fmt.Errorf("failed to delete legacy keychain items for %s account %s: %w", hostname, username, err)
	}

	concreteAuthCfg, ok := authCfg.(*config.AuthConfig)
	if !ok {
		return errors.New("unsupported auth config implementation")
	}

	secureLogin := opts.SecureLoginFunc
	if secureLogin == nil {
		secureLogin = func(authCfg *config.AuthConfig, hostname, username, token string) error {
			return authCfg.SecureLogin(hostname, username, token, "")
		}
	}
	if err := secureLogin(concreteAuthCfg, hostname, username, token); err != nil {
		restoreLegacy := opts.LegacyRestoreFunc
		if restoreLegacy == nil {
			restoreLegacy = restoreLegacyTokens
		}
		if restoreErr := restoreLegacy(hostname, username, token); restoreErr != nil {
			return fmt.Errorf("%w (also failed to restore legacy keychain items: %v)", err, restoreErr)
		}
		return err
	}

	fmt.Fprintf(opts.IO.ErrOut, "migrated credentials for %s account %s\n", hostname, username)
	return nil
}

func readLegacyToken(hostname, username string) (string, error) {
	if runtime.GOOS != "darwin" {
		return "", errors.New("legacy keychain migration is only supported on macOS")
	}

	service := "gh:" + hostname
	if username != "" {
		if token, err := securityFindGenericPassword(service, username); err == nil {
			return token, nil
		}
	}

	if token, err := securityFindGenericPassword(service, ""); err == nil {
		return token, nil
	}

	return securityFindGenericPasswordWithoutAccount(service)
}

func deleteLegacyTokens(hostname, username string) error {
	service := "gh:" + hostname
	if username != "" {
		if err := securityDeleteGenericPassword(service, username); err != nil {
			return err
		}
	}
	return securityDeleteGenericPassword(service, "")
}

func restoreLegacyTokens(hostname, username, token string) error {
	service := "gh:" + hostname
	if username != "" {
		if err := securityAddGenericPassword(service, username, token); err != nil {
			return err
		}
	}
	return securityAddGenericPassword(service, "", token)
}

func securityFindGenericPassword(service, account string) (string, error) {
	args := legacySecurityArgs("find-generic-password", "-s", service, "-a", account, "-w")
	out, err := exec.Command("/usr/bin/security", args...).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			return "", err
		}
		return "", fmt.Errorf("%w: %s", err, msg)
	}
	return strings.TrimSpace(string(out)), nil
}

func securityDeleteGenericPassword(service, account string) error {
	args := legacySecurityArgs("delete-generic-password", "-s", service, "-a", account)
	out, err := exec.Command("/usr/bin/security", args...).CombinedOutput()
	if err == nil {
		return nil
	}

	msg := strings.TrimSpace(string(out))
	if strings.Contains(msg, "could not be found") || strings.Contains(msg, "The specified item could not be found") {
		return nil
	}
	if msg == "" {
		return err
	}
	return fmt.Errorf("%w: %s", err, msg)
}

func securityAddGenericPassword(service, account, token string) error {
	args := legacySecurityArgs("add-generic-password", "-U", "-s", service, "-a", account, "-w", token)
	out, err := exec.Command("/usr/bin/security", args...).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			return err
		}
		return fmt.Errorf("%w: %s", err, msg)
	}
	return nil
}

func securityFindGenericPasswordWithoutAccount(service string) (string, error) {
	args := legacySecurityArgs("find-generic-password", "-s", service, "-w")
	out, err := exec.Command("/usr/bin/security", args...).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			return "", err
		}
		return "", fmt.Errorf("%w: %s", err, msg)
	}
	return strings.TrimSpace(string(out)), nil
}

func legacySecurityArgs(args ...string) []string {
	if keychain := legacyLoginKeychainPath(); keychain != "" {
		return append(args, keychain)
	}
	return args
}

func legacyLoginKeychainPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	for _, name := range []string{"login.keychain-db", "login.keychain"} {
		path := filepath.Join(home, "Library", "Keychains", name)
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}
