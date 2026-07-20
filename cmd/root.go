package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/charmbracelet/fang"
	"github.com/jaxxstorm/vers"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile  string
	settings = viper.New()
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "proxyt",
	Short: "A Tailscale login server proxy",
	Long: `proxyt is a proxy server that intercepts Tailscale login requests
and provides SSL termination with automatic Let's Encrypt certificates.

This allows you to use a custom domain as a Tailscale login server
by proxying requests to the actual Tailscale control plane.`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := fang.Execute(rootCmd.Context(), rootCmd, fang.WithVersion(GetVersion()))
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.proxyt.yaml)")
	rootCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		if err := loadConfiguration(settings, cfgFile, os.UserHomeDir); err != nil {
			return err
		}
		if cmd.Name() == "serve" {
			return validateServeConfiguration(settings)
		}
		return nil
	}
}

func loadConfiguration(settings *viper.Viper, configFile string, homeDir func() (string, error)) error {
	explicit := configFile != ""
	if !explicit {
		home, err := homeDir()
		if err != nil {
			return fmt.Errorf("determine home directory: %w", err)
		}
		configFile = filepath.Join(home, ".proxyt.yaml")
	}

	settings.SetConfigFile(configFile)
	if err := settings.ReadInConfig(); err != nil {
		var notFound viper.ConfigFileNotFoundError
		if !explicit && (os.IsNotExist(err) || errors.As(err, &notFound)) {
			return nil
		}
		return fmt.Errorf("read configuration %q: %w", configFile, err)
	}

	return nil
}

// Version is the version of this tool.
var Version string

// GetVersion returns the version using the same logic as the version command
func GetVersion() string {
	v := Version
	// If we haven't set a version with linker flags, calculate from git
	if v == "" {
		repo, err := vers.OpenRepository(".")
		if err != nil {
			return "unknown"
		}

		opts := vers.Options{
			Repository: repo,
			Commitish:  "HEAD",
		}

		versions, err := vers.Calculate(opts)
		if err != nil {
			return "unknown"
		}
		v = versions.SemVer
	}
	return v
}
