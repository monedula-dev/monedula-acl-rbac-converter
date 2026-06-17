// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package script

import (
	"fmt"
	"strings"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/extract"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

// parsedInvocation is the result of decoding one argv into the per-row
// fields needed to assemble ACLRow values.
type parsedInvocation struct {
	subAction        string // --add | --remove | --list | ""
	allowPrincipals  []string
	denyPrincipals   []string
	allowHosts       []string
	denyHosts        []string
	operations       []types.Operation
	resources        []resourceRef
	patternType      types.PatternType
	producerShortcut bool
	consumerShortcut bool
	idempotent       bool
	transactionalID  string
	groupName        string
}

type resourceRef struct {
	rt   types.ResourceType
	name string
}

// parseInvocation walks `argv` of a single kafka-acls command. The first
// element should already be the program name (e.g., "kafka-acls"). Returns
// a structural decomposition; row expansion is done in `expand`.
func parseInvocation(argv []string) (parsedInvocation, error) {
	out := parsedInvocation{patternType: types.PatternLiteral}
	i := 1
	for i < len(argv) {
		tok := argv[i]
		next := func() (string, error) {
			i++
			if i >= len(argv) {
				return "", fmt.Errorf("flag %s missing value", tok)
			}
			return argv[i], nil
		}
		switch tok {
		case "--add", "--remove", "--list":
			out.subAction = tok
		case "--allow-principal":
			v, err := next()
			if err != nil {
				return out, err
			}
			out.allowPrincipals = append(out.allowPrincipals, v)
		case "--deny-principal":
			v, err := next()
			if err != nil {
				return out, err
			}
			out.denyPrincipals = append(out.denyPrincipals, v)
		case "--allow-host":
			v, err := next()
			if err != nil {
				return out, err
			}
			out.allowHosts = append(out.allowHosts, v)
		case "--deny-host":
			v, err := next()
			if err != nil {
				return out, err
			}
			out.denyHosts = append(out.denyHosts, v)
		case "--operation":
			v, err := next()
			if err != nil {
				return out, err
			}
			out.operations = append(out.operations, normalizeOp(v))
		case "--topic":
			v, err := next()
			if err != nil {
				return out, err
			}
			out.resources = append(out.resources, resourceRef{types.ResourceTopic, v})
		case "--group":
			v, err := next()
			if err != nil {
				return out, err
			}
			out.resources = append(out.resources, resourceRef{types.ResourceGroup, v})
			out.groupName = v
		case "--cluster":
			out.resources = append(out.resources, resourceRef{types.ResourceCluster, "kafka-cluster"})
		case "--transactional-id":
			v, err := next()
			if err != nil {
				return out, err
			}
			out.resources = append(out.resources, resourceRef{types.ResourceTransactionalID, v})
			out.transactionalID = v
		case "--delegation-token":
			v, err := next()
			if err != nil {
				return out, err
			}
			out.resources = append(out.resources, resourceRef{types.ResourceDelegationToken, v})
		case "--resource-pattern-type":
			v, err := next()
			if err != nil {
				return out, err
			}
			out.patternType = types.PatternType(strings.ToUpper(v))
		case "--producer":
			out.producerShortcut = true
		case "--consumer":
			out.consumerShortcut = true
		case "--idempotent":
			out.idempotent = true
		default:
			// Unknown flags are skipped — they're benign noise from wrapper
			// scripts. Bootstrap URLs, command-config paths, etc. fall here.
			// Skip past a value if the flag uses --flag value form.
			if strings.HasPrefix(tok, "--") {
				// Heuristic: if the next token doesn't start with -- and we
				// recognise specific value-taking flags, consume it. For now
				// be conservative: skip just the flag itself.
				switch tok {
				case "--bootstrap-server", "--bootstrap", "--command-config":
					_, _ = next()
				}
			}
		}
		i++
	}
	return out, nil
}

// expand returns the rows produced by one invocation, with running ID
// starting at `firstID`. Each row gets a unique ID assigned by the caller.
// Convenience shortcuts (--producer / --consumer) are expanded here; the
// logger records the expansion for the report.
func expand(p parsedInvocation, firstID int, log *extract.Logger) ([]types.ACLRow, int) {
	if p.subAction != "--add" {
		return nil, firstID
	}

	// Hosts default to the kafka-acls default of "*" when no --allow-host /
	// --deny-host is given. Otherwise each principal's grant is emitted once
	// per host so a host-restricted ACL is not silently broadened.
	allowHosts := p.allowHosts
	if len(allowHosts) == 0 {
		allowHosts = []string{"*"}
	}
	denyHosts := p.denyHosts
	if len(denyHosts) == 0 {
		denyHosts = []string{"*"}
	}

	type permPrincipal struct {
		permission types.PermissionType
		principal  string
		hosts      []string
	}
	var pps []permPrincipal
	for _, pr := range p.allowPrincipals {
		pps = append(pps, permPrincipal{types.PermissionAllow, pr, allowHosts})
	}
	for _, pr := range p.denyPrincipals {
		pps = append(pps, permPrincipal{types.PermissionDeny, pr, denyHosts})
	}

	type opRes struct {
		op types.Operation
		rt types.ResourceType
		rn string
	}
	var matrix []opRes

	if p.producerShortcut {
		// kafka-acls getProducerAcls: WRITE, DESCRIBE, CREATE on each topic;
		// WRITE, DESCRIBE on the transactional id; and IDEMPOTENT_WRITE on the
		// cluster ONLY when --idempotent is given.
		log.Logf("EXPANDED --producer into Write+Describe+Create on Topic[+Write+Describe on TransactionalId][+IdempotentWrite on Cluster if --idempotent]")
		for _, r := range p.resources {
			if r.rt == types.ResourceTopic {
				matrix = append(matrix,
					opRes{types.OpWrite, r.rt, r.name},
					opRes{types.OpDescribe, r.rt, r.name},
					opRes{types.OpCreate, r.rt, r.name})
			}
		}
		if p.transactionalID != "" {
			matrix = append(matrix,
				opRes{types.OpWrite, types.ResourceTransactionalID, p.transactionalID},
				opRes{types.OpDescribe, types.ResourceTransactionalID, p.transactionalID})
		}
		if p.idempotent {
			matrix = append(matrix, opRes{types.OpIdempotentWrite, types.ResourceCluster, "kafka-cluster"})
		}
	}
	if p.consumerShortcut {
		// kafka-acls getConsumerAcls: READ, DESCRIBE on each topic; READ only
		// on the group.
		log.Logf("EXPANDED --consumer into Read+Describe on Topic + Read on Group")
		for _, r := range p.resources {
			if r.rt == types.ResourceTopic {
				matrix = append(matrix, opRes{types.OpRead, r.rt, r.name}, opRes{types.OpDescribe, r.rt, r.name})
			}
			if r.rt == types.ResourceGroup {
				matrix = append(matrix, opRes{types.OpRead, r.rt, r.name})
			}
		}
	}
	if !p.producerShortcut && !p.consumerShortcut {
		for _, op := range p.operations {
			for _, r := range p.resources {
				matrix = append(matrix, opRes{op, r.rt, r.name})
			}
		}
	}

	var rows []types.ACLRow
	id := firstID
	for _, pp := range pps {
		for _, host := range pp.hosts {
			for _, m := range matrix {
				rows = append(rows, types.ACLRow{
					ID:             id,
					Principal:      pp.principal,
					Host:           host,
					Operation:      m.op,
					ResourceType:   m.rt,
					ResourceName:   m.rn,
					PatternType:    p.patternType,
					PermissionType: pp.permission,
				})
				id++
			}
		}
	}
	return rows, id
}

func normalizeOp(s string) types.Operation {
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
	case "DESCRIBECONFIGS", "DESCRIBE_CONFIGS":
		return types.OpDescribeConfigs
	case "ALTERCONFIGS", "ALTER_CONFIGS":
		return types.OpAlterConfigs
	case "IDEMPOTENTWRITE", "IDEMPOTENT_WRITE":
		return types.OpIdempotentWrite
	case "ALL":
		return types.OpAll
	}
	return types.Operation(s)
}
