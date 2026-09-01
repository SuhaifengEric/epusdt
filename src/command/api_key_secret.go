package command

import (
	"encoding/json"
	"fmt"

	"github.com/GMWalletApp/epusdt/bootstrap"
	"github.com/GMWalletApp/epusdt/model/data"
	"github.com/spf13/cobra"
)

var apiKeySecretCmd = &cobra.Command{
	Use:   "api-key-secret",
	Short: "Scan, migrate, or reencrypt API key secrets",
}

var apiKeySecretScanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Count API key secret storage formats without printing values",
	RunE: func(cmd *cobra.Command, args []string) error {
		bootstrap.InitConfigAndStore()
		report, err := data.ScanApiKeySecrets()
		if err != nil {
			return err
		}
		return printSecretScanReport(cmd, report)
	},
}

var apiKeySecretMigrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Encrypt leftover plaintext API key secrets with the active master key",
	RunE: func(cmd *cobra.Command, args []string) error {
		bootstrap.InitConfigAndStore()
		report, err := data.MigratePlaintextApiKeySecrets()
		if printErr := printSecretScanReport(cmd, report); printErr != nil {
			return printErr
		}
		return err
	},
}

var apiKeySecretReencryptCmd = &cobra.Command{
	Use:   "reencrypt",
	Short: "Rewrite envelopes with the active master key for overlapping rotation",
	RunE: func(cmd *cobra.Command, args []string) error {
		bootstrap.InitConfigAndStore()
		report, err := data.ReencryptApiKeySecrets()
		if printErr := printSecretScanReport(cmd, report); printErr != nil {
			return printErr
		}
		return err
	},
}

func printSecretScanReport(cmd *cobra.Command, report data.SecretScanReport) error {
	out, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(cmd.OutOrStdout(), string(out))
	return err
}

func init() {
	apiKeySecretCmd.AddCommand(apiKeySecretScanCmd, apiKeySecretMigrateCmd, apiKeySecretReencryptCmd)
	rootCmd.AddCommand(apiKeySecretCmd)
}
