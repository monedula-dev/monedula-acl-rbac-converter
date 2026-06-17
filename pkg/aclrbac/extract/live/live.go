// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

// Package live extracts ACLs from a running Kafka cluster via the Kafka
// AdminClient API (franz-go's kadm). Returns the canonical ACLSet with
// each described ACL assigned a 1-indexed ID in deterministic order.
//
// SASL/SSL configuration is sourced from a Java client.properties file
// passed via --command-config; see live_opts.go for the recognized key
// set. v1 honors PEM-encoded truststore/keystore files only — JKS and
// PKCS12 stores must be re-exported to PEM before use.
package live

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kerr"
	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/extract"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// errACLsNotEnabled is returned when the source broker reports
// SECURITY_DISABLED — it has no authorizer configured, so there are no ACLs
// to extract. We surface an operator-actionable message rather than leaking
// the raw Kafka error code.
var errACLsNotEnabled = errors.New(
	"live: the source Kafka cluster does not have ACLs enabled — the broker reported " +
		"SECURITY_DISABLED, meaning no authorizer is configured. Configure an authorizer " +
		"(authorizer.class.name, e.g. org.apache.kafka.metadata.authorizer.StandardAuthorizer " +
		"for KRaft or kafka.security.authorizer.AclAuthorizer for ZooKeeper) on the brokers and " +
		"retry. If the cluster intentionally runs without ACLs, there is nothing to migrate")

// describeTimeout caps how long a single DescribeACLs call can take.
// 30 seconds matches the MDS client default and is plenty for a healthy
// cluster; if any single describe takes longer, something is wrong.
const describeTimeout = 30 * time.Second

// Adapter is the live-Kafka adapter.
type Adapter struct {
	bootstrap         []string
	commandConfigPath string
	principalFilter   []string
	topicFilter       []string
}

// New constructs an Adapter. Properties-file parsing happens later in
// Extract, where it can populate the extract.Logger; this constructor
// only retains the path.
func New(bootstrap []string, commandConfigPath string, principalFilter, topicFilter []string) (*Adapter, error) {
	return &Adapter{
		bootstrap:         bootstrap,
		commandConfigPath: commandConfigPath,
		principalFilter:   principalFilter,
		topicFilter:       topicFilter,
	}, nil
}

func (a *Adapter) Name() string { return "live" }

func (a *Adapter) Extract() (types.ACLSet, []types.Binding, extract.ExtractSource, *extract.Logger, error) {
	log := extract.NewLogger()

	opts, err := buildKgoOpts(a.bootstrap, a.commandConfigPath, log)
	if err != nil {
		return types.ACLSet{}, nil, extract.ExtractSource{}, log, fmt.Errorf("live: command-config: %w", err)
	}
	cl, err := kgo.NewClient(opts...)
	if err != nil {
		return types.ACLSet{}, nil, extract.ExtractSource{}, log, fmt.Errorf("live: build Kafka client: %w", err)
	}
	defer cl.Close()
	adm := kadm.NewClient(cl)

	rows, err := a.describeAll(adm, log)
	if err != nil {
		return types.ACLSet{}, nil, extract.ExtractSource{}, log, err
	}

	set := types.ACLSet{
		SchemaVersion: "1",
		Source:        types.ACLSetSource{Type: "live", GeneratedAt: time.Now().UTC().Format(time.RFC3339)},
		ACLs:          rows,
	}
	src := extract.ExtractSource{
		Kind:                 "live",
		LiveBootstrapServers: strings.Join(a.bootstrap, ","),
		Timestamp:            time.Now().UTC(),
	}
	log.Logf("DESCRIBED %d ACLs from %s", len(rows), src.LiveBootstrapServers)
	return set, nil, src, log, nil
}

// describeAll fans out one DescribeACLs call per filter cell, deduplicates
// the union of returned rows, and assigns 1-indexed IDs in stable order.
func (a *Adapter) describeAll(adm *kadm.Client, log *extract.Logger) ([]types.ACLRow, error) {
	builders := buildFilters(a.principalFilter, a.topicFilter)

	// Deduplicate by (principal, host, op, resource_type, resource_name,
	// pattern_type, permission). The same ACL can match multiple filter
	// cells when --principal-filter and --topic-filter cross; without
	// dedup we'd emit duplicate rows.
	type key struct {
		principal      string
		host           string
		op             types.Operation
		resourceType   types.ResourceType
		resourceName   string
		patternType    types.PatternType
		permissionType types.PermissionType
	}
	seen := map[key]bool{}
	rows := make([]types.ACLRow, 0)

	for _, b := range builders {
		ctx, cancel := context.WithTimeout(context.Background(), describeTimeout)
		results, err := adm.DescribeACLs(ctx, b)
		cancel()
		if err != nil {
			if errors.Is(err, kerr.SecurityDisabled) {
				return nil, errACLsNotEnabled
			}
			return nil, fmt.Errorf("live: DescribeACLs: %w", err)
		}
		for _, res := range results {
			if res.Err != nil {
				if errors.Is(res.Err, kerr.SecurityDisabled) {
					return nil, errACLsNotEnabled
				}
				return nil, fmt.Errorf("live: filter error: %w", res.Err)
			}
			for _, d := range res.Described {
				op, ok := mapOperation(d.Operation)
				if !ok {
					log.Logf("SKIPPED ACL with unmappable operation %v on %v:%s", d.Operation, d.Type, d.Name)
					continue
				}
				rt, ok := mapResourceType(d.Type)
				if !ok {
					log.Logf("SKIPPED ACL with unmappable resource type %v on %s", d.Type, d.Name)
					continue
				}
				pt, ok := mapPattern(d.Pattern)
				if !ok {
					log.Logf("SKIPPED ACL with unmappable pattern type %v on %v:%s", d.Pattern, d.Type, d.Name)
					continue
				}
				perm, ok := mapPermission(d.Permission)
				if !ok {
					log.Logf("SKIPPED ACL with unmappable permission %v on %v:%s for %s", d.Permission, d.Type, d.Name, d.Principal)
					continue
				}
				k := key{
					principal: d.Principal, host: d.Host, op: op,
					resourceType: rt, resourceName: d.Name,
					patternType: pt, permissionType: perm,
				}
				if seen[k] {
					continue
				}
				seen[k] = true
				rows = append(rows, types.ACLRow{
					Principal:      d.Principal,
					Host:           d.Host,
					Operation:      op,
					ResourceType:   rt,
					ResourceName:   d.Name,
					PatternType:    pt,
					PermissionType: perm,
				})
			}
		}
	}

	// Stable order: principal, then resource_name, then operation. Matches
	// the ordering established by pkg/aclrbac/normalize.GroupRows so a live
	// extract feeds the planner with the same row order a text/script
	// source would.
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Principal != rows[j].Principal {
			return rows[i].Principal < rows[j].Principal
		}
		if rows[i].ResourceName != rows[j].ResourceName {
			return rows[i].ResourceName < rows[j].ResourceName
		}
		return rows[i].Operation < rows[j].Operation
	})

	// Assign IDs in the post-sort order so they're deterministic across
	// runs against the same cluster state.
	for i := range rows {
		rows[i].ID = i + 1
	}
	return rows, nil
}
