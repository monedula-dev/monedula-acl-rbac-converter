// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package cli

import (
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/extract"
	extractcfk "github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/extract/cfk"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/extract/csv"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/extract/jsonyaml"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/extract/k8s"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/extract/live"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/extract/script"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/extract/strimzi"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/extract/text"
)

func newExtractCmd() *cobra.Command {
	var (
		from            string
		input           string
		varsFile        string
		ignoreNonAdd    bool
		principalFilter []string
		topicFilter     []string
		k8sContext      string
		k8sNamespace    string
		k8sAllNS        bool
		k8sLabelSel     string
		k8sKubeconfig   string
	)
	var rdf RunDirFlags
	var kaf KafkaAuthFlags

	cmd := &cobra.Command{
		Use:   "extract",
		Short: "Read ACLs from a source and emit canonical acls.json",
		Long: `Read Kafka ACLs from one of nine sources and serialise them into the
canonical acls.json that every downstream command consumes.

Sources (pass via --from):
  live      Apache Kafka cluster (requires --bootstrap-server, optional --command-config)
  text      a 'kafka-acls.sh --list' text dump (--input)
  json|yaml an acls.json/yaml matching schemas/acls.v1.json (--input)
  csv       flat tabular form, RFC 4180 (--input)
  script    a shell script of 'kafka-acls --add' invocations (--input, optional --vars)
  strimzi   Strimzi KafkaUser CRs on disk (--input)
  cfk       CFK Kafka + ConfluentRolebinding manifests on disk (--input)
  k8s       a running Kubernetes cluster (--context / --namespace / --all-namespaces)

Example:
  monedula-acl-rbac extract --from live \
    --bootstrap-server kafka.example.com:9093 \
    --command-config admin.properties \
    --out runs/2026-05-21T10-00-00Z/acls.json

acls.json is the only mutating output. extract.log and extract-source.json
sidecars are also written for audit.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if from == "" {
				return NewUsageError("--from is required")
			}
			outPath := rdf.Out
			if outPath == "" {
				dir, err := rdf.Resolve("")
				if err != nil {
					return err
				}
				outPath = filepath.Join(dir, "acls.json")
			}

			var (
				adapter extract.Adapter
				err     error
			)
			switch from {
			case "live":
				adapter, err = live.New([]string{kaf.BootstrapServer}, kaf.CommandConfig, principalFilter, topicFilter)
			case "text":
				adapter, err = text.New(input)
			case "json", "yaml":
				adapter, err = jsonyaml.New(input)
			case "csv":
				adapter, err = csv.New(input)
			case "strimzi":
				adapter, err = strimzi.New(input)
			case "cfk":
				adapter, err = extractcfk.New(input)
			case "k8s":
				adapter, err = k8s.New(k8s.Options{
					Kubeconfig:    k8sKubeconfig,
					Context:       k8sContext,
					Namespace:     k8sNamespace,
					AllNamespaces: k8sAllNS,
					LabelSelector: k8sLabelSel,
				})
			case "script":
				vars, ve := script.LoadVars(varsFile)
				if ve != nil {
					return NewInputError(ve.Error())
				}
				adapter, err = script.New(input, vars, ignoreNonAdd)
			default:
				return NewUsageError("--from " + from + " is not a recognized source")
			}
			if err != nil {
				return err
			}

			set, bindings, src, log, err := adapter.Extract()
			if err != nil {
				return err
			}
			if err := extract.WriteExtractedSet(outPath, set, bindings, src, log); err != nil {
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&from, "from", "", "live|text|json|yaml|csv|strimzi|cfk|k8s|script")
	cmd.Flags().StringVar(&input, "input", "", "Input file path (file sources only)")
	cmd.Flags().StringVar(&varsFile, "vars", "", "vars.yaml for the script source")
	cmd.Flags().BoolVar(&ignoreNonAdd, "ignore-non-add", false, "Script source: skip --remove/--list invocations")
	cmd.Flags().StringSliceVar(&principalFilter, "principal-filter", nil, "Live source: restrict by principal (repeatable)")
	cmd.Flags().StringSliceVar(&topicFilter, "topic-filter", nil, "Live source: restrict by topic prefix (repeatable)")
	cmd.Flags().StringVar(&k8sContext, "context", "", "K8s source: kubeconfig context")
	cmd.Flags().StringVar(&k8sNamespace, "namespace", "", "K8s source: namespace")
	cmd.Flags().BoolVar(&k8sAllNS, "all-namespaces", false, "K8s source: walk all visible namespaces")
	cmd.Flags().StringVar(&k8sLabelSel, "label-selector", "", "K8s source: label selector")
	cmd.Flags().StringVar(&k8sKubeconfig, "kubeconfig", "", "K8s source: kubeconfig path override")
	rdf.AddRunDirFlags(cmd)
	kaf.AddKafkaAuthFlags(cmd)
	return cmd
}
