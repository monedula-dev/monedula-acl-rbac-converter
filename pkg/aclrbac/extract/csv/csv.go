// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

// Package csv parses RFC 4180 CSV files into a canonical ACLSet. The first
// non-blank, non-comment line is the header; column order is free; the
// column names must match the canonical IR JSON keys exactly.
package csv

import (
	"crypto/sha256"
	encodingcsv "encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strconv"
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

func (a *Adapter) Name() string { return "csv" }

func (a *Adapter) Extract() (types.ACLSet, []types.Binding, extract.ExtractSource, *extract.Logger, error) {
	log := extract.NewLogger()
	data, err := os.ReadFile(a.path)
	if err != nil {
		return types.ACLSet{}, nil, extract.ExtractSource{}, log, fmt.Errorf("read %s: %w", a.path, err)
	}

	rows, err := parseCSV(data, log)
	if err != nil {
		return types.ACLSet{}, nil, extract.ExtractSource{}, log, err
	}

	sum := sha256.Sum256(data)
	set := types.ACLSet{
		SchemaVersion: "1",
		Source:        types.ACLSetSource{Type: "csv", GeneratedAt: time.Now().UTC().Format(time.RFC3339)},
		ACLs:          rows,
	}
	src := extract.ExtractSource{
		Kind:        "csv",
		InputPath:   a.path,
		InputSHA256: hex.EncodeToString(sum[:]),
		Timestamp:   time.Now().UTC(),
	}
	return set, nil, src, log, nil
}

func parseCSV(data []byte, log *extract.Logger) ([]types.ACLRow, error) {
	r := encodingcsv.NewReader(stripComments(data))
	r.TrimLeadingSpace = true
	r.FieldsPerRecord = -1

	headers, err := r.Read()
	if err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}
	required := []string{"id", "principal", "host", "operation", "resource_type", "resource_name", "pattern_type", "permission_type"}
	idx := map[string]int{}
	for i, h := range headers {
		idx[strings.TrimSpace(h)] = i
	}
	for _, req := range required {
		if _, ok := idx[req]; !ok {
			return nil, fmt.Errorf("missing required column %q", req)
		}
	}

	var rows []types.ACLRow
	lineNo := 1
	for {
		rec, err := r.Read()
		lineNo++
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}
		row, err := buildRow(rec, idx, lineNo)
		if err != nil {
			return nil, err
		}
		log.Logf("PARSED line %d: id=%d principal=%s", lineNo, row.ID, row.Principal)
		rows = append(rows, row)
	}
	return rows, nil
}

func buildRow(rec []string, idx map[string]int, lineNo int) (types.ACLRow, error) {
	// Guard against rows shorter than the header. FieldsPerRecord = -1
	// lets the CSV reader accept ragged input, so we have to enforce
	// length here. Compute the highest column index we need to read.
	maxIdx := 0
	for _, i := range idx {
		if i > maxIdx {
			maxIdx = i
		}
	}
	if len(rec) <= maxIdx {
		return types.ACLRow{}, fmt.Errorf("line %d: row has %d fields, want at least %d", lineNo, len(rec), maxIdx+1)
	}

	id, err := strconv.Atoi(strings.TrimSpace(rec[idx["id"]]))
	if err != nil {
		return types.ACLRow{}, fmt.Errorf("line %d: id: %w", lineNo, err)
	}
	return types.ACLRow{
		ID:             id,
		Principal:      strings.TrimSpace(rec[idx["principal"]]),
		Host:           strings.TrimSpace(rec[idx["host"]]),
		Operation:      types.Operation(strings.TrimSpace(rec[idx["operation"]])),
		ResourceType:   types.ResourceType(strings.TrimSpace(rec[idx["resource_type"]])),
		ResourceName:   strings.TrimSpace(rec[idx["resource_name"]]),
		PatternType:    types.PatternType(strings.TrimSpace(rec[idx["pattern_type"]])),
		PermissionType: types.PermissionType(strings.TrimSpace(rec[idx["permission_type"]])),
	}, nil
}

// stripComments removes full-line comments (a line whose first non-whitespace
// character is `#`) before handing bytes to the CSV reader. RFC 4180 has no
// comment support; the tool adds them for human-friendliness. The pass is
// quote-aware: a `#`-leading line INSIDE a quoted multiline field is left
// intact — the old naive split-on-newline corrupted such records.
func stripComments(data []byte) io.Reader {
	var b strings.Builder
	inQuotes := false
	for _, line := range strings.Split(string(data), "\n") {
		if !inQuotes {
			if trim := strings.TrimLeft(line, " \t"); strings.HasPrefix(trim, "#") {
				continue // full-line comment outside any quoted field
			}
		}
		b.WriteString(line)
		b.WriteString("\n")
		// Toggle quote state by the parity of unescaped double quotes on this
		// physical line. RFC 4180 escapes a literal quote as "", which is two
		// quotes and so does not change the parity — exactly the behaviour we
		// want for tracking whether the next line continues a quoted field.
		if strings.Count(line, "\"")%2 == 1 {
			inQuotes = !inQuotes
		}
	}
	return strings.NewReader(b.String())
}
