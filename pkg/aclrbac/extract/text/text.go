// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

// Package text parses `kafka-acls.sh --list` human-readable output. It uses
// regex over the key=value blocks rather than fixed columns, so minor
// formatting changes across Apache Kafka versions don't break it.
package text

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/extract"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

type Adapter struct {
	path string
}

func New(path string) (*Adapter, error) {
	return &Adapter{path: path}, nil
}

func (a *Adapter) Name() string { return "text" }

var (
	resourceHeader = regexp.MustCompile(`resourceType=(\w+),\s*name=(\S+?),\s*patternType=(\w+)`)
	// The principal capture is non-greedy up to the `, host=` separator so it
	// spans the internal commas of SSL/DN principals such as
	// `User:CN=alice,OU=eng,O=Acme` (a plain `[^,]+` stopped at the first
	// comma and the whole line fell through to UNPARSED).
	aclLine = regexp.MustCompile(`principal=(.+?),\s*host=([^,]+),\s*operation=(\w+),\s*permissionType=(\w+)`)
)

func (a *Adapter) Extract() (types.ACLSet, []types.Binding, extract.ExtractSource, *extract.Logger, error) {
	log := extract.NewLogger()
	data, err := os.ReadFile(a.path)
	if err != nil {
		return types.ACLSet{}, nil, extract.ExtractSource{}, log, fmt.Errorf("read %s: %w", a.path, err)
	}

	rows, err := parseText(string(data), log)
	if err != nil {
		return types.ACLSet{}, nil, extract.ExtractSource{}, log, err
	}

	sum := sha256.Sum256(data)
	set := types.ACLSet{
		SchemaVersion: "1",
		Source:        types.ACLSetSource{Type: "text", GeneratedAt: time.Now().UTC().Format(time.RFC3339)},
		ACLs:          rows,
	}
	src := extract.ExtractSource{
		Kind:        "text",
		InputPath:   a.path,
		InputSHA256: hex.EncodeToString(sum[:]),
		Timestamp:   time.Now().UTC(),
	}
	return set, nil, src, log, nil
}

func parseText(text string, log *extract.Logger) ([]types.ACLRow, error) {
	var (
		rows           []types.ACLRow
		currentRes     string
		currentResType types.ResourceType
		currentPattern types.PatternType
		nextID         = 1
	)
	for lineNo, line := range strings.Split(text, "\n") {
		lineNo++

		if m := resourceHeader.FindStringSubmatch(line); m != nil {
			currentResType = normalizeResourceType(m[1])
			currentRes = strings.TrimRight(m[2], "`,")
			currentPattern = types.PatternType(strings.ToUpper(m[3]))
			log.Logf("PARSED line %d: resource %s:%s (%s)", lineNo, currentResType, currentRes, currentPattern)
			continue
		}
		if m := aclLine.FindStringSubmatch(line); m != nil {
			if currentRes == "" {
				log.Logf("UNPARSED line %d: ACL outside resource block", lineNo)
				continue
			}
			rows = append(rows, types.ACLRow{
				ID:             nextID,
				Principal:      strings.TrimSpace(m[1]),
				Host:           strings.TrimSpace(m[2]),
				Operation:      normalizeOperation(m[3]),
				ResourceType:   currentResType,
				ResourceName:   currentRes,
				PatternType:    currentPattern,
				PermissionType: normalizePermission(m[4]),
			})
			nextID++
			continue
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		// A line that looks like a resource header but failed the
		// resourceHeader regex (e.g. format drift across Kafka versions) must
		// reset the current resource, otherwise the following ACL lines would
		// be silently misattributed to the previous resource block.
		if strings.Contains(line, "resourceType=") || strings.Contains(line, "Current ACLs for resource") {
			currentRes = ""
			currentResType = ""
			currentPattern = ""
			log.Logf("UNPARSED line %d: unrecognized resource header %q", lineNo, line)
			continue
		}
		log.Logf("UNPARSED line %d: %q", lineNo, line)
	}
	return rows, nil
}

func normalizeResourceType(s string) types.ResourceType {
	switch strings.ToUpper(s) {
	case "TOPIC":
		return types.ResourceTopic
	case "GROUP":
		return types.ResourceGroup
	case "CLUSTER":
		return types.ResourceCluster
	case "TRANSACTIONAL_ID", "TRANSACTIONALID":
		return types.ResourceTransactionalID
	case "DELEGATION_TOKEN", "DELEGATIONTOKEN":
		return types.ResourceDelegationToken
	case "SUBJECT":
		return types.ResourceSubject
	default:
		return types.ResourceType(s)
	}
}

func normalizeOperation(s string) types.Operation {
	switch strings.ToUpper(s) {
	case "READ":
		return types.OpRead
	case "WRITE":
		return types.OpWrite
	case "CREATE":
		return types.OpCreate
	case "DELETE":
		return types.OpDelete
	case "ALTER":
		return types.OpAlter
	case "DESCRIBE":
		return types.OpDescribe
	case "CLUSTER_ACTION":
		return types.OpClusterAction
	case "DESCRIBE_CONFIGS":
		return types.OpDescribeConfigs
	case "ALTER_CONFIGS":
		return types.OpAlterConfigs
	case "IDEMPOTENT_WRITE":
		return types.OpIdempotentWrite
	case "ALL":
		return types.OpAll
	}
	return types.Operation(s)
}

func normalizePermission(s string) types.PermissionType {
	switch strings.ToUpper(s) {
	case "ALLOW":
		return types.PermissionAllow
	case "DENY":
		return types.PermissionDeny
	}
	return types.PermissionType(s)
}
