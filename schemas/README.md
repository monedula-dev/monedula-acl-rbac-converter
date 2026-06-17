# JSON Schemas

These schemas describe canonical artefacts produced by
`monedula-acl-rbac`. All are JSON Schema draft 2020-12.

| Schema | Used by |
|---|---|
| [`acls.v1.json`](acls.v1.json) | `extract` output (run-dir `acls.json`); validated on read |
| [`plan.v1.json`](plan.v1.json) | `plan` output (run-dir `plan.json`); validated on read |
| [`apply-summary.v1.json`](apply-summary.v1.json) | `apply --format json` stdout envelope |
| [`verify-summary.v1.json`](verify-summary.v1.json) | `verify --format json` stdout AND run-dir `verify.json` |
| [`status.v1.json`](status.v1.json) | `status --format json` envelope |
| [`report.v1.json`](report.v1.json) | `report --format json` envelope (wraps a plan) |

All six schemas use a **string** `schema_version: "1"` field at the
envelope root — uniform across both on-disk artefacts (`acls.json`,
`plan.json`) and stdout envelopes (`apply`, `verify`, `status`,
`report`). A single "fail if `schema_version` changes" check works
uniformly across every JSON the tool produces.

## Usage

```sh
# Validate apply output with ajv-cli
monedula-acl-rbac apply --plan plan.json --format json \
  | ajv validate -s schemas/apply-summary.v1.json -d -

# Validate plan.json
ajv validate -s schemas/plan.v1.json -d runs/.../plan.json
```

The Go embedded copies (in `pkg/aclrbac/schema/`) are kept in sync
via `make sync-schemas`. The canonical source of truth is this
directory.

## Versioning

When a schema's shape changes incompatibly:
- The file is copied to `<name>.v2.json` (v1 stays for back-compat readers)
- The bumped envelope's `schema_version` field bumps to `"2"`
- CHANGELOG notes the migration path
