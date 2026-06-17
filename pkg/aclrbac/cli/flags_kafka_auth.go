// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package cli

import "github.com/spf13/cobra"

// KafkaAuthFlags holds <kafka-auth> values.
type KafkaAuthFlags struct {
	BootstrapServer string
	CommandConfig   string
	bootstrapAlias  string
}

// AddKafkaAuthFlags wires <kafka-auth> onto cmd.
func (f *KafkaAuthFlags) AddKafkaAuthFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.BootstrapServer, "bootstrap-server", envOr("MONEDULA_ACL_RBAC_BOOTSTRAP_SERVER", ""), "Kafka bootstrap server(s) (comma-separated)")
	cmd.Flags().StringVar(&f.bootstrapAlias, "bootstrap", "", "Alias for --bootstrap-server")
	cmd.Flags().StringVar(&f.CommandConfig, "command-config", envOr("MONEDULA_ACL_RBAC_COMMAND_CONFIG", ""), "Path to a Kafka client properties file")

	// Resolve the --bootstrap alias. Precedence: an explicit --bootstrap-server
	// wins; otherwise an explicit --bootstrap alias wins over the
	// MONEDULA_ACL_RBAC_BOOTSTRAP_SERVER env default. Gating on
	// Changed("bootstrap-server") (rather than emptiness) is what lets the
	// alias override the env default — the previous emptiness check silently
	// discarded an explicit --bootstrap whenever the env var was set.
	prev := cmd.PreRunE
	cmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		if f.bootstrapAlias != "" && !cmd.Flags().Changed("bootstrap-server") {
			f.BootstrapServer = f.bootstrapAlias
		}
		if prev != nil {
			return prev(cmd, args)
		}
		return nil
	}
}
