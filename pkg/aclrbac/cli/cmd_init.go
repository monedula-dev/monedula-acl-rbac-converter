// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

const initScopesYAML = `# scopes.yaml — Confluent cluster IDs the planner maps bindings into.
#
# Only the cluster IDs needed for your actual bindings are required.
# Most Kafka-only migrations only need kafka_cluster. Run
# 'monedula-acl-rbac discover --mds-url ...' to bootstrap from MDS.

# Required for any binding that targets a Kafka resource (Topic, Group,
# TransactionalId, Cluster). The cluster ID is whatever Confluent assigns
# (e.g., lkc-abc123 on Confluent Cloud).
kafka_cluster: ""

# Optional. Set only if your bindings target Schema Registry subjects.
# schema_registry_cluster: ""

# Optional. Set only if your bindings target ksqlDB.
# ksql_cluster: ""

# Optional. Set only if your bindings target Kafka Connect.
# connect_cluster: ""

# Optional. Confluent organization + environment IDs for multi-tenant
# clusters. Most migrations leave these empty.
# organization: ""
# environment: ""
`

const initRulesYAML = `# rules.yaml — optional mapping rule overrides.
#
# This file is OPTIONAL. The tool ships with a default rule set that
# covers the common Kafka ACL -> Confluent RBAC mappings (Read+Describe
# on Topic -> DeveloperRead, etc.). Run 'monedula-acl-rbac rules show'
# to see the full default rule set.
#
# Add entries here only when you need to override a default or add a
# mapping the defaults don't cover.

rules:
  # Example: map an ALL-on-Cluster Allow to ClusterAdmin instead of
  # the default SystemAdmin role. Uncomment and adapt as needed.
  #
  # - when:
  #     operations: [All]
  #     operations_mode: any
  #     resource_type: Cluster
  #     permission_type: Allow
  #   then:
  #     role: ClusterAdmin
  #     scope_template: kafka-cluster
`

func newInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init [DIR]",
		Short: "Scaffold scopes.yaml + rules.yaml in DIR (default: current dir)",
		Long: `Creates a starter scopes.yaml and rules.yaml in the given directory.
The placeholders are documented inline. After running this, edit scopes.yaml
to set your cluster IDs, then run 'extract' + 'plan' against your ACL source.

Refuses to overwrite an existing scopes.yaml or rules.yaml.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := "."
			if len(args) == 1 {
				dir = args[0]
			}
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return fmt.Errorf("init: create dir: %w", err)
			}

			files := map[string]string{
				"scopes.yaml": initScopesYAML,
				"rules.yaml":  initRulesYAML,
			}
			for name := range files {
				path := filepath.Join(dir, name)
				if _, err := os.Stat(path); err == nil {
					return NewGuardrailError(fmt.Sprintf("init: %s already exists; refusing to overwrite", path))
				}
			}
			for name, body := range files {
				path := filepath.Join(dir, name)
				if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
					return fmt.Errorf("init: write %s: %w", path, err)
				}
				fmt.Fprintln(os.Stderr, "created", path)
			}
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintln(os.Stderr, "Next: edit scopes.yaml (set kafka_cluster), then run:")
			fmt.Fprintln(os.Stderr, "  monedula-acl-rbac extract --from text --input acls.txt --out", filepath.Join(dir, "acls.json"))
			return nil
		},
	}
}
