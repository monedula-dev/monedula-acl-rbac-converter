// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

// Package script parses shell scripts containing `kafka-acls --add ...`
// commands and converts each invocation to canonical ACL rows. It uses a
// real shell parser (mvdan/sh) so quoting, line continuations, and wrapper
// prefixes (docker exec, kubectl exec) are handled correctly.
package script

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"mvdan.cc/sh/v3/syntax"

	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/extract"
	"github.com/monedula-dev/monedula-acl-rbac-converter/pkg/aclrbac/types"
)

type Adapter struct {
	path         string
	vars         map[string]string
	ignoreNonAdd bool
}

func New(path string, vars map[string]string, ignoreNonAdd bool) (*Adapter, error) {
	return &Adapter{path: path, vars: vars, ignoreNonAdd: ignoreNonAdd}, nil
}

func (a *Adapter) Name() string { return "script" }

func (a *Adapter) Extract() (types.ACLSet, []types.Binding, extract.ExtractSource, *extract.Logger, error) {
	log := extract.NewLogger()
	data, err := os.ReadFile(a.path)
	if err != nil {
		return types.ACLSet{}, nil, extract.ExtractSource{}, log, fmt.Errorf("read %s: %w", a.path, err)
	}

	rows, err := parseScript(data, a.vars, a.ignoreNonAdd, log)
	if err != nil {
		return types.ACLSet{}, nil, extract.ExtractSource{}, log, err
	}

	sum := sha256.Sum256(data)
	set := types.ACLSet{
		SchemaVersion: "1",
		Source:        types.ACLSetSource{Type: "script", GeneratedAt: time.Now().UTC().Format(time.RFC3339)},
		ACLs:          rows,
	}
	src := extract.ExtractSource{
		Kind:        "script",
		InputPath:   a.path,
		InputSHA256: hex.EncodeToString(sum[:]),
		Timestamp:   time.Now().UTC(),
	}
	return set, nil, src, log, nil
}

func parseScript(data []byte, vars map[string]string, ignoreNonAdd bool, log *extract.Logger) ([]types.ACLRow, error) {
	parser := syntax.NewParser()
	file, err := parser.Parse(bytes.NewReader(data), "")
	if err != nil {
		return nil, fmt.Errorf("parse shell: %w", err)
	}

	var rows []types.ACLRow
	nextID := 1
	var firstErr error

	syntax.Walk(file, func(node syntax.Node) bool {
		if firstErr != nil {
			return false
		}
		switch n := node.(type) {
		case *syntax.ForClause, *syntax.WhileClause, *syntax.IfClause, *syntax.CaseClause, *syntax.FuncDecl:
			firstErr = fmt.Errorf("script: rejected control flow at line %d (%T) — pre-expand or use --vars", n.Pos().Line(), n)
			return false
		case *syntax.CmdSubst:
			firstErr = fmt.Errorf("script: rejected command substitution at line %d", n.Pos().Line())
			return false
		case *syntax.CallExpr:
			invoked, ok := tryDecode(n, vars)
			if !ok {
				return true
			}
			if invoked.parseErr != nil {
				firstErr = fmt.Errorf("script: line %d: malformed kafka-acls command: %w", n.Pos().Line(), invoked.parseErr)
				return false
			}
			if invoked.unsupported {
				firstErr = fmt.Errorf("script: line %d: %s — rewrite the line to avoid the construct, or pre-expand the script", n.Pos().Line(), invoked.unsupportedDesc)
				return false
			}
			if invoked.unresolved {
				firstErr = fmt.Errorf("script: line %d: unresolved variable %q — pass --vars or pre-expand", n.Pos().Line(), invoked.unresolvedVar)
				return false
			}
			if invoked.parsed.subAction != "--add" {
				if invoked.parsed.subAction == "" {
					log.Logf("SKIPPED line %d: kafka-acls call without --add/--remove/--list", n.Pos().Line())
					return true
				}
				if ignoreNonAdd {
					log.Logf("SKIPPED line %d: %s (ignore-non-add)", n.Pos().Line(), invoked.parsed.subAction)
					return true
				}
				firstErr = fmt.Errorf("script: line %d: %s not supported (rerun with --ignore-non-add to skip)", n.Pos().Line(), invoked.parsed.subAction)
				return false
			}
			out, newID := expand(invoked.parsed, nextID, log)
			rows = append(rows, out...)
			nextID = newID
			log.Logf("PARSED line %d: %d ACL row(s)", n.Pos().Line(), len(out))
		}
		return true
	})
	if firstErr != nil {
		return nil, firstErr
	}
	return rows, nil
}

type decodedCall struct {
	parsed parsedInvocation
	// unresolved: flattenArgs hit a `$VAR` not in `--vars`. Operator can
	// fix this by re-running with `--vars VAR=value` or by pre-expanding.
	unresolved    bool
	unresolvedVar string
	// unsupported: flattenArgs hit a shell AST node we don't decode (command
	// substitution, arithmetic, glob, etc.). `--vars` cannot help — the
	// operator must rewrite the script to avoid the construct.
	unsupported     bool
	unsupportedDesc string
	// parseErr: the call was recognized as kafka-acls but its argv failed to
	// parse (e.g. a flag missing its value). Must surface as a hard error, not
	// be silently skipped as "not a kafka-acls call".
	parseErr error
}

// tryDecode returns a decodedCall if `call` invokes kafka-acls (possibly via
// a wrapper like `docker exec`, `kubectl exec --`, `ssh`, `sudo`).
func tryDecode(call *syntax.CallExpr, vars map[string]string) (decodedCall, bool) {
	argv, unresolved, unsupported := flattenArgs(call.Args, vars)
	if unsupported != "" {
		return decodedCall{unsupported: true, unsupportedDesc: unsupported}, true
	}
	if unresolved != "" {
		return decodedCall{unresolved: true, unresolvedVar: unresolved}, true
	}
	// Walk past wrapper prefixes until we find kafka-acls.
	i := 0
	for i < len(argv) {
		switch base(argv[i]) {
		case "kafka-acls", "kafka-acls.sh":
			parsed, err := parseInvocation(argv[i:])
			if err != nil {
				return decodedCall{parseErr: err}, true
			}
			return decodedCall{parsed: parsed}, true
		case "docker", "kubectl", "ssh", "sudo":
			i++
			for i < len(argv) && strings.HasPrefix(argv[i], "-") {
				if argv[i] == "exec" || argv[i] == "--" {
					i++
					break
				}
				i++
			}
		default:
			i++
		}
	}
	return decodedCall{}, false
}

func base(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

// flattenArgs walks a list of shell `Word`s and returns the literal argv they
// would expand to. Three outcomes:
//   - argv set, unresolvedVar = "", unsupportedDesc = "" — success.
//   - argv nil, unresolvedVar = "$VAR" — a parameter expansion has no entry
//     in vars; the caller can ask for `--vars` to fix this.
//   - argv nil, unsupportedDesc != "" — the shell AST has a node we don't
//     decode (command substitution, arithmetic, glob, etc.). `--vars` does
//     not help here; the caller surfaces a different error.
//
// Previously this function squashed "unsupported AST" into unresolvedVar by
// returning a synthetic `(unsupported part: T)` string, so the caller's
// error read "unresolved variable \"(unsupported part: ...)\" — pass --vars"
// which misdirected operators. Distinguishing the two outcomes lets the
// caller give honest advice.
func flattenArgs(words []*syntax.Word, vars map[string]string) (argv []string, unresolvedVar string, unsupportedDesc string) {
	for _, w := range words {
		var b strings.Builder
		for _, part := range w.Parts {
			switch p := part.(type) {
			case *syntax.Lit:
				b.WriteString(p.Value)
			case *syntax.SglQuoted:
				b.WriteString(p.Value)
			case *syntax.DblQuoted:
				for _, dp := range p.Parts {
					switch d := dp.(type) {
					case *syntax.Lit:
						b.WriteString(d.Value)
					case *syntax.ParamExp:
						v := d.Param.Value
						val, ok := vars[v]
						if !ok {
							return nil, v, ""
						}
						b.WriteString(val)
					default:
						return nil, "", fmt.Sprintf("unsupported shell syntax inside double quotes: %T", dp)
					}
				}
			case *syntax.ParamExp:
				v := p.Param.Value
				val, ok := vars[v]
				if !ok {
					return nil, v, ""
				}
				b.WriteString(val)
			default:
				return nil, "", fmt.Sprintf("unsupported shell syntax: %T", part)
			}
		}
		argv = append(argv, b.String())
	}
	return argv, "", ""
}
