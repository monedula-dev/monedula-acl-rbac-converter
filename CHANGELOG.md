# Changelog

All notable changes to monedula-acl-rbac are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

_Nothing yet._

## [0.9.0] - 2026-06-17

First tagged release — a feature-complete preview ahead of `1.0.0`.

### Added

- **Extract** Apache Kafka ACLs from nine sources: live cluster (`--from live`),
  `kafka-acls.sh --list` text dumps, structured `acls.json`/`acls.yaml`,
  CSV, shell scripts of `kafka-acls --add`, Strimzi `KafkaUser` CRs,
  CFK (Confluent for Kubernetes) manifests, a running Kubernetes cluster,
  and a stateless one-shot `convert` pipeline.
- **Plan** transforms `acls.json` into a `plan.json` + `report.txt` against
  user-supplied scopes and rules. Co-emits the report; refuses unhealthy
  plans unless `--allow-unmapped` / `--allow-rejected` are explicit.
- **Implicitly-derived operations** are expanded during planning: an Allow
  ACL granting only `Read`/`Write`/`Delete`/`Alter` is treated as also
  granting `Describe` (and `AlterConfigs` as granting `DescribeConfigs`),
  mirroring Kafka's authorizer. A lone `Write` ACL now maps cleanly to
  `DeveloperWrite` instead of landing in `UNMAPPED`. DENY ACLs are left
  untouched (denial is not transitive through implication).
- **Greedy multi-role coverage.** A principal that holds both consume and
  produce access on a resource (e.g. `Read`+`Write` on a Topic) now yields
  **both** `DeveloperRead` and `DeveloperWrite` bindings rather than a single
  `DeveloperRead` with the `Write` grant dropped to a warning. Rules are
  applied greedily in priority order until every operation is covered; an
  `ALL` group still collapses to one `ResourceOwner`/`SystemAdmin` binding.
  `PARTIAL_RULE_COVERAGE` now warns only when an operation is covered by no
  rule at all.
- **Apply** creates RBAC bindings in MDS, idempotent against the existing
  state, with per-binding parallelism. Emits a structured text/JSON
  summary on stdout (`--format text|json`) and a per-call audit trail
  in `apply.log`.
- **Verify** checks effective access of each binding in MDS (`--mode
  effective` default, `--mode bindings-exist` alternate). Emits an
  envelope `{schema_version, results, counts}` to both disk and stdout.
- **MDS retry middleware**: 5xx, 429, `io.EOF`, and connection resets
  retry with exponential backoff + jitter. Default 3 retries;
  `--mds-max-retries 0` disables; honours `Retry-After` (capped 60s).
- **JKS / PKCS12 / PEM** truststore + keystore support in the live
  Kafka extractor, detected by file extension.
- **JSON Schemas** for four stdout envelopes (`apply`, `verify`, `status`,
  `report`) and the two on-disk artefacts (`acls.json`, `plan.json`); all
  use string `schema_version: "1"`. (`diff` and `mds list-bindings` emit
  envelopes too — see their `--format json` output — but ship without a
  formal schema in v1.)
- **Cosign** keyless signing + **Syft** SBOMs in the release pipeline.

### Safety

- **Script-only deletion.** `delete-acls` and `delete-deny-acls` emit
  inspectable `kafka-acls --remove` scripts plus symmetric rollbacks rather
  than executing destructive changes themselves; there is no in-process
  deletion path.
- **Generated scripts re-verify integrity at run time.** They re-hash
  `plan.json` and refuse to run (exit 5) on a mismatch or when it cannot be
  hashed at all (fail-closed; override with `MONEDULA_SKIP_PLAN_HASH_CHECK=1`
  when the run directory is intentionally absent, e.g. inside a broker
  container).
- **Wildcard-principal DENYs are never removable.** `User:*`, the bare `*`,
  and any `<Type>:*` are classified `UNKNOWN` (their blast radius is
  unbounded) and are refused by both the generator and the `delete-deny-one`
  helper — there is no confirmation-token override.
- **DENY-removal safety** uses set-intersection overlap analysis with a live
  MDS re-check per ACL at script-execution time, not generation time.
- **MDS error bodies are length-capped** before they enter `verify.json`,
  stderr, or `apply.log` — the auth-token exchange caps at 256 B and every
  other HTTP call at 4 KiB. Defence-in-depth against a misbehaving server
  echoing the `Authorization` header or session state into an error body,
  and against an unbounded multi-MB body inflating memory or log files.
- **Malformed `client.properties` errors name the line number only** — the
  raw line content (which may be a misformatted `sasl.jaas.config` carrying
  `password="..."`) is never echoed into the error message.
- **Plan binding fields reject control characters** symmetrically with the
  ACL field gate. Tabs, NULs, and other C0/C1 controls are refused at plan
  load to keep them out of generated `kafka-acls --remove` scripts and the
  rolebinding payloads sent to MDS.
- **`diff` catches Scope and ResourcePattern drift.** A plan whose binding
  switched cluster scope or resource patterns (but kept Action/Role) is
  now reported as `changed` instead of silently matching.
- **`apply --apply-parallelism` is hard-capped at 64** (was previously
  unbounded). Above 64 the goroutine pool yields negligible additional
  throughput against MDS while exhausting file descriptors and risking
  rate-limit cascade. Pass `--apply-parallelism 64` to opt back in
  explicitly.
- **AGPL-3.0-or-later**; SPDX headers on every source file.

See [README.md](README.md) for the operator workflow.
