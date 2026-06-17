// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Monedula contributors

package schema

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

const (
	aclsSchemaURL          = "https://github.com/monedula-dev/monedula-acl-rbac-converter/schemas/acls.v1.json"
	planSchemaURL          = "https://github.com/monedula-dev/monedula-acl-rbac-converter/schemas/plan.v1.json"
	applySummarySchemaURL  = "https://github.com/monedula-dev/monedula-acl-rbac-converter/schemas/apply-summary.v1.json"
	verifySummarySchemaURL = "https://github.com/monedula-dev/monedula-acl-rbac-converter/schemas/verify-summary.v1.json"
	statusReportSchemaURL  = "https://github.com/monedula-dev/monedula-acl-rbac-converter/schemas/status.v1.json"
	reportOutputSchemaURL  = "https://github.com/monedula-dev/monedula-acl-rbac-converter/schemas/report.v1.json"
)

var (
	aclsSchema          *jsonschema.Schema
	planSchema          *jsonschema.Schema
	applySummarySchema  *jsonschema.Schema
	verifySummarySchema *jsonschema.Schema
	statusReportSchema  *jsonschema.Schema
	reportOutputSchema  *jsonschema.Schema
)

func init() {
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020

	mustAddResource(compiler, aclsSchemaURL, "acls.v1.json")
	mustAddResource(compiler, planSchemaURL, "plan.v1.json")
	mustAddResource(compiler, applySummarySchemaURL, "apply-summary.v1.json")
	mustAddResource(compiler, verifySummarySchemaURL, "verify-summary.v1.json")
	mustAddResource(compiler, statusReportSchemaURL, "status.v1.json")
	mustAddResource(compiler, reportOutputSchemaURL, "report.v1.json")

	aclsSchema = mustCompile(compiler, aclsSchemaURL)
	planSchema = mustCompile(compiler, planSchemaURL)
	applySummarySchema = mustCompile(compiler, applySummarySchemaURL)
	verifySummarySchema = mustCompile(compiler, verifySummarySchemaURL)
	statusReportSchema = mustCompile(compiler, statusReportSchemaURL)
	reportOutputSchema = mustCompile(compiler, reportOutputSchemaURL)
}

func mustAddResource(c *jsonschema.Compiler, url, file string) {
	data, err := embeddedSchemas.ReadFile(file)
	if err != nil {
		panic(fmt.Sprintf("read embedded %s: %v", file, err))
	}
	if err := c.AddResource(url, bytes.NewReader(data)); err != nil {
		panic(fmt.Sprintf("compile %s: %v", file, err))
	}
}

func mustCompile(c *jsonschema.Compiler, url string) *jsonschema.Schema {
	s, err := c.Compile(url)
	if err != nil {
		panic(fmt.Sprintf("compile %s: %v", url, err))
	}
	return s
}

// ValidateACLs validates an acls.json document.
func ValidateACLs(doc []byte) error {
	return validate(aclsSchema, doc)
}

// ValidatePlan validates a plan.json document.
func ValidatePlan(doc []byte) error {
	return validate(planSchema, doc)
}

// ValidateApplySummary validates an apply summary JSON envelope
// (the shape emitted by `apply --format json`).
func ValidateApplySummary(doc []byte) error {
	return validate(applySummarySchema, doc)
}

// ValidateVerifySummary validates a verify summary JSON envelope
// (the shape emitted by `verify --format json` on stdout and written
// to `verify.json` on disk).
func ValidateVerifySummary(doc []byte) error {
	return validate(verifySummarySchema, doc)
}

// ValidateStatusReport validates a status report JSON envelope
// (the shape emitted by `status --format json`).
func ValidateStatusReport(doc []byte) error {
	return validate(statusReportSchema, doc)
}

// ValidateReportOutput validates a report JSON envelope
// (the shape emitted by `report --format json`: `{schema_version, plan}`).
// The inner `plan` field is intentionally not cross-validated against
// plan.v1.json — callers wanting strict plan-body validation should call
// ValidatePlan on the unwrapped plan.
func ValidateReportOutput(doc []byte) error {
	return validate(reportOutputSchema, doc)
}

func validate(s *jsonschema.Schema, doc []byte) error {
	var v interface{}
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	if err := s.Validate(v); err != nil {
		return prettyValidationError(err)
	}
	return nil
}

func prettyValidationError(err error) error {
	if ve, ok := err.(*jsonschema.ValidationError); ok {
		var b strings.Builder
		b.WriteString("schema validation failed:")
		flatten(&b, ve, 0)
		return fmt.Errorf("%s", b.String())
	}
	return err
}

func flatten(b *strings.Builder, ve *jsonschema.ValidationError, depth int) {
	if depth > 0 {
		b.WriteString("\n")
		b.WriteString(strings.Repeat("  ", depth))
		b.WriteString("- ")
		fmt.Fprintf(b, "%s: %s", ve.InstanceLocation, ve.Message)
	}
	for _, cause := range ve.Causes {
		flatten(b, cause, depth+1)
	}
}
