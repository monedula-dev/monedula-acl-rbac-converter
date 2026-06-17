# monedula-acl-rbac

[![CI](https://github.com/monedula-dev/monedula-acl-rbac-converter/actions/workflows/ci.yml/badge.svg)](https://github.com/monedula-dev/monedula-acl-rbac-converter/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/monedula-dev/monedula-acl-rbac-converter.svg)](https://pkg.go.dev/github.com/monedula-dev/monedula-acl-rbac-converter)
[![Go Report Card](https://goreportcard.com/badge/github.com/monedula-dev/monedula-acl-rbac-converter)](https://goreportcard.com/report/github.com/monedula-dev/monedula-acl-rbac-converter)
[![License: AGPL v3](https://img.shields.io/badge/license-AGPL%20v3-blue.svg)](LICENSE)

A safe, auditable command-line tool for converting Apache Kafka ACLs into Confluent RBAC role bindings.

Repository: <https://github.com/monedula-dev/monedula-acl-rbac-converter>

## Contents

- [What it does](#what-it-does)
- [Two paths: with or without MDS access](#two-paths-with-or-without-mds-access)
- [Examples](#examples)
- [Install](#install)
  - [Verifying a release](#verifying-a-release)
- [Migration checklist](#migration-checklist)
- [Quick path: one-shot conversion](#quick-path-one-shot-conversion)
- [The migration workflow](#the-migration-workflow)
- [Checking on a previous run](#checking-on-a-previous-run)
- [Working with existing MDS state](#working-with-existing-mds-state)
- [Advanced / special cases](#advanced--special-cases)
- [Config files](#config-files)
- [Safety guarantees](#safety-guarantees)
- [Logging](#logging)
- [Recovery](#recovery)
- [Exit codes](#exit-codes)
- [Limitations](#limitations)
- [API stability](#api-stability)
- [Command reference](#command-reference)
- [Reporting issues](#reporting-issues)

For runnable end-to-end flows see [Examples](#examples).

## Command reference

Quick alphabetical index — see the per-step sections below or
`monedula-acl-rbac <cmd> --help` for full flag lists.

| Command | Purpose | Mutating? |
|---|---|---|
| `apply` | Create RBAC bindings in MDS from a plan. | yes |
| `auth login` | Interactive MDS login; caches the token. | no (writes local cache file) |
| `completion` | Emit bash/zsh/fish/PowerShell completion scripts. | no |
| `convert` | One-shot extract → plan → emit (stateless, file-to-file). | no |
| `delete-acls` | Generate the source-ACL deletion script (you run it). | emits script only |
| `delete-deny-acls` | Generate the DENY-ACL deletion script (you run it). | emits script only |
| `diff` | Compare two `acls.json` or two `plan.json` files. | no |
| `discover` | Query MDS for cluster IDs; emit a `scopes.yaml` stub. | no |
| `emit` | Render a plan as a script, CFK manifest, or curl commands. | no |
| `extract` | Read ACLs from one of nine sources into canonical `acls.json`. | no |
| `init` | Scaffold a fresh run directory with `scopes.yaml` + `rules.yaml`. | no |
| `mds list-bindings` | Read-only inventory of MDS role bindings. | no |
| `plan` | Transform `acls.json` into `plan.json` + `report.txt`. | no |
| `report` | Re-print `plan.json`'s report in alternate formats. | no |
| `rules show` | Print the embedded default mapping rules. | no |
| `status` | Summarise the state of a run directory. | no |
| `verify` | Check effective access of each binding in MDS. | no |

Persistent flags on every subcommand: `--log-format text|json`, `--log-level debug|info|warn|error`.

## What it does

- Reads Kafka ACLs from many sources: a live cluster, exported `kafka-acls.sh --list` output, structured dumps (JSON/YAML/CSV against a versioned schema), Strimzi `KafkaUser` CRs, CFK (Confluent for Kubernetes) manifests on disk, a running Kubernetes cluster, or a shell script containing `kafka-acls --add ...` commands.
- Converts them into a `RoleBindingPlan` using built-in default rules you can override.
- Emits the plan as a shell script, a CFK manifest (`ConfluentRolebinding` CRs), or applies it directly to Confluent's Metadata Service (MDS).
- Verifies that bindings grant the **effective access** the original ACLs granted, not just that they exist.
- Optionally generates an ACL-deletion script you inspect and run yourself, after verification and an operator-determined cooldown.

The tool never mutates external state unless you pass `--confirm` or type `yes` at an interactive prompt. Destructive operations still default to producing an inspectable script rather than executing deletions directly.

For exploration, a one-shot `convert` subcommand runs extract → plan → emit in a single call (no run directory). For production migrations, use the explicit step-by-step pipeline.

## Two paths: with or without MDS access

The first thing to decide is whether **this tool** talks to Confluent's Metadata Service (MDS) directly, or whether it only produces artifacts that *someone else* applies. The extract and plan steps are identical either way — the difference is what happens after `plan.json` exists.

**Path A — direct to MDS (you give the tool MDS access).** The tool creates the RBAC bindings itself and confirms they work:

```
extract → plan → apply → verify → delete-acls
```

`apply` writes bindings to MDS, and `verify` asks MDS — per source ACL — whether the original `(principal, operation, resource)` is now actually allowed (effective-access check, not just "the binding row exists"). This is the fullest, safest workflow: the same tool that planned the change also proves it landed before you delete any ACLs. It needs MDS credentials (token, or username/password) on the host that runs `apply`/`verify`. The commands that reach MDS are `apply`, `verify`, `discover`, `mds list-bindings`, and `auth login`.

**Path B — no MDS access (you don't want to, or can't, give the tool MDS credentials).** The tool never contacts MDS; instead it emits an artifact your platform team, GitOps repo, or change-control pipeline applies:

```
extract → plan → emit  (→ your CD pipeline applies it)
```

`emit` renders the plan as one of three shapes (`--format`):

- `script` — a shell script of `confluent iam rbac role-binding create …` commands.
- `cfk` — `ConfluentRolebinding` CRs for Confluent for Kubernetes (`kubectl apply`).
- `mds-curl` — `curl` commands hitting the MDS REST API.

Hand the artifact to whoever *does* hold MDS access. The trade-off: `verify` also needs MDS, so on this path you cannot use the tool's automated effective-access check — confirm access out of band (or run `verify` later from a host that does have credentials). See [Advanced / special cases → Emit artifacts](#emit-artifacts-for-external-cd-pipelines) for rollback guidance, and `discover` (which also needs MDS) for bootstrapping `scopes.yaml` — on Path B, fill `scopes.yaml` in by hand or have someone with access run `discover` once.

For a quick file-to-file render with no run directory, `convert` is the one-shot form of Path B (see [Quick path](#quick-path-one-shot-conversion)).

### Getting the `scopes.yaml` cluster ID without MDS access

`plan` needs `kafka_cluster` in [`scopes.yaml`](#scopesyaml-conditionally-required) — the Kafka cluster ID that MDS uses as the scope of every role binding. On Path A you get it from `discover` (which queries MDS). On Path B you don't have MDS, so fill it in by hand. **It is not a value you set in `server.properties`** — it's the cluster's own identity, generated when the cluster is first formatted, that you read back:

- **Self-managed Confluent Platform** — a base64 cluster UUID (e.g. `MkU3OEVBNTcwNTJENDM2Qk`):
  - read it from any broker's log dir: `grep cluster.id <log.dir>/meta.properties`;
  - or ask the broker: `kafka-cluster cluster-id --bootstrap-server …`, `kafka-metadata-quorum … describe`, or `kcat -L` (it prints the cluster id);
  - or via the AdminClient `describeCluster().clusterId()`.
- **Confluent Cloud** — the logical `lkc-…` cluster ID from the Cloud Console or `confluent kafka cluster list`.

**The value must match exactly what MDS knows the cluster as.** In a self-managed deployment MDS learns it from the broker's own `cluster.id`, so the broker-reported ID above is authoritative. If you can borrow MDS access even once, `monedula-acl-rbac discover --mds-url …` (or `GET /security/1.0/registry/clusters`) is the surest source. A mismatched `kafka_cluster` produces bindings that apply cleanly yet grant no effective access — exactly the `EFFECTIVE_MISSING` that `verify` is designed to catch. The same applies to `schema_registry_cluster` / `ksql_cluster` / `connect_cluster` when your ACLs reference those resources.

## Install

Download the latest release binary for your platform from the [releases page](https://github.com/monedula-dev/monedula-acl-rbac-converter/releases), or build from source:

```sh
go install github.com/monedula-dev/monedula-acl-rbac-converter/cmd/monedula-acl-rbac@latest
```

### Shell completion

cobra-generated completion scripts for bash, zsh, fish, and PowerShell are auto-registered. To enable for the current shell, pick the matching subcommand:

```sh
# bash (per-user)
monedula-acl-rbac completion bash > ~/.local/share/bash-completion/completions/monedula-acl-rbac

# zsh — add to a directory on $fpath
monedula-acl-rbac completion zsh > "${fpath[1]}/_monedula-acl-rbac"

# fish
monedula-acl-rbac completion fish > ~/.config/fish/completions/monedula-acl-rbac.fish

# PowerShell
monedula-acl-rbac completion powershell | Out-String | Invoke-Expression
```

Run `monedula-acl-rbac completion --help` for distro-specific install paths.

### Verifying a release

Each release's `checksums.txt` is signed with [cosign](https://github.com/sigstore/cosign) using keyless signing through GitHub OIDC — no public key to manage. Verifying that signature lets you trust the checksums; you then verify any downloaded archive against them (the archives are not individually signed). Each release also includes a per-archive Syft SBOM. To verify the signed checksums file before extracting:

```sh
# Fetch the checksums + signature + certificate from the release page
VERSION=v1.0.0   # check https://github.com/monedula-dev/monedula-acl-rbac-converter/releases/latest
curl -LO https://github.com/monedula-dev/monedula-acl-rbac-converter/releases/download/$VERSION/checksums.txt
curl -LO https://github.com/monedula-dev/monedula-acl-rbac-converter/releases/download/$VERSION/checksums.txt.sig
curl -LO https://github.com/monedula-dev/monedula-acl-rbac-converter/releases/download/$VERSION/checksums.txt.pem

cosign verify-blob \
  --certificate-identity-regexp '^https://github.com/monedula-dev/monedula-acl-rbac-converter/.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  --signature checksums.txt.sig \
  --certificate checksums.txt.pem \
  checksums.txt
```

A successful verification prints `Verified OK`. Then validate the archive you downloaded against `checksums.txt`. It lists **every** release artifact, so checking the whole manifest fails on the ones you didn't fetch — verify just your file's line instead:

```sh
# Set ARCHIVE to the file you downloaded (substitute version/os/arch).
ARCHIVE=monedula-acl-rbac_1.0.0_linux_amd64.tar.gz
grep "$ARCHIVE" checksums.txt | sha256sum -c -
# GNU coreutils alternative that skips the artifacts you didn't download:
# sha256sum --ignore-missing -c checksums.txt
```

The release also ships a Syft SBOM (`*.sbom.json`) next to each archive — plain SBOM files, not signed attestations. Scan one for vulnerabilities with `grype sbom:<archive>.sbom.json`, or inspect it directly.

## Examples

The [`examples/`](examples/) directory holds self-contained, runnable end-to-end flows — one per input source. Each has its own `README.md`, the source input file(s), a `scopes.yaml`, a `run.sh`, and committed `expected/` outputs so you can see exactly **what ACLs convert to what RBAC bindings** and diff against a known-good result.

| Example | Input source | Path |
|---|---|---|
| [`live-mds-migration/`](examples/live-mds-migration/) | live broker + real MDS | **Path A**: `extract → plan → apply → verify → delete-acls` (Docker) |
| [`k8s-live-cluster/`](examples/k8s-live-cluster/) | running Kubernetes | Path B: `extract → plan → emit` from a kind cluster |
| [`text-dump/`](examples/text-dump/) | `kafka-acls.sh --list` text | Path B: `extract → plan → emit` |
| [`structured-dump/`](examples/structured-dump/) | `acls.json` / `acls.yaml` | Path B: `extract → plan → emit` |
| [`csv-spreadsheet/`](examples/csv-spreadsheet/) | CSV export | Path B: `extract → plan → emit` |
| [`setup-script/`](examples/setup-script/) | `kafka-acls --add` script | Path B: `extract → plan → emit` |
| [`strimzi-kafkauser/`](examples/strimzi-kafkauser/) | Strimzi `KafkaUser` CRs | Path B: `extract → plan → emit` |
| [`cfk-manifests/`](examples/cfk-manifests/) | CFK manifests on disk | Path B: `extract → plan → emit cfk` |

Start with [`live-mds-migration/`](examples/live-mds-migration/) for the full Path A picture (it stands up a real Confluent stack with docker-compose). The file-based examples need only a built binary — each also ships a `docker-compose.yml` so you can run with Docker alone:

```sh
cd examples/text-dump
./run.sh --check     # regenerates out/ and diffs against committed expected/
```

See [`examples/README.md`](examples/README.md) for the full index and how to add a new one.

## Migration checklist

For a production migration, this is the full operator workflow at a glance. Each item maps to one of the sections below.

```
[ ] discover scopes.yaml             (one-time per cluster)
[ ] extract                          ACLs → acls.json
[ ] inspect acls.json                sanity-check the input
[ ] plan                             writes plan.json + report.txt
[ ] read report.txt                  understand UNMAPPED / REJECTED / WARN
[ ] apply --dry-run                  preview MDS calls
[ ] apply --confirm                  create RBAC bindings
[ ] verify                           confirm users actually have access
[ ] wait at least 24h                let users exercise the new path
[ ] delete-acls --principal …        generate a per-principal deletion script
[ ] read + run delete-acls.sh        the human checkpoint
[ ] keep rollback.sh on hand         until the migration is stable
[ ] (only if needed) delete-deny-acls   special-case DENY removal
```

## Quick path: one-shot conversion

For exploration or small batches where you just want to see what RBAC bindings a set of ACLs would produce, skip the pipeline:

```sh
monedula-acl-rbac convert \
  --from yaml \
  --input acls.yaml \
  --scopes scopes.yaml \
  --rules rules.yaml \
  --principals principals.yaml \
  > bindings.sh
```

`--rules` and `--principals` are optional. `--from` can be omitted for file inputs whose extension makes it unambiguous (`.yaml`/`.yml`/`.json`/`.csv`/`.sh`/`.txt`); it is required for the directory form of `cfk`. `convert` only supports file-based sources — `live` and `k8s` require the explicit `extract` → `plan` → `emit` pipeline so the audit artefacts (run directory, `acls.json`, `existing-bindings.json`) are persisted.

This runs extract → plan → emit-script in one call and writes the result to stdout (or `--out FILE`). It does **not** create a run directory and **does not apply anything**; you still need the pipeline below if you want to apply, verify, or delete.

## The migration workflow

The tool is structured as a pipeline. Each step writes into a **run directory**. By default this is a fresh `runs/<UTC-timestamp>/`, but you can choose one explicitly with `--run-dir runs/billing-batch-1` (let each command write its standard filenames there) or by passing per-file `--out` paths as shown in the examples below. Commands that consume a run artifact infer the run directory from that artifact when `--run-dir`/`--out` is not supplied, so `apply --plan runs/<ts>/plan.json` writes logs back into `runs/<ts>/`. Only `apply`, `delete-acls`, and `delete-deny-acls` change anything outside that directory.

The happy path is five steps:

```
  1. extract       → acls.json
  2. plan          → plan.json + report.txt
  3. apply         → creates RBAC bindings in MDS (use --dry-run first)
  4. verify        → verify.json (effective-access check)
  5. delete-acls   → emits a deletion script you inspect and run
```

`plan` always writes `report.txt` alongside `plan.json` and prints a summary to stderr, so there's no separate "report" step.

Advanced and special-case commands (`emit`, `delete-deny-acls`, `discover`, `status`, `diff`, `mds list-bindings`) are covered later under [Advanced / special cases](#advanced--special-cases).

The recommended cadence: run steps 1–2 first and **read `report.txt` carefully**, then dry-run + real-apply (step 3), then verify (step 4), **wait at least 24 hours**, then generate and run the deletion script (step 5).

### Step 0 — Bootstrap `scopes.yaml` (one-time, optional)

If you don't already have a `scopes.yaml` with your Confluent cluster IDs, ask MDS:

```sh
monedula-acl-rbac discover --mds-url https://mds.example.com > scopes.yaml
```

This emits a stub with comments indicating which fields you need to fill. For a Kafka-only migration, only `kafka_cluster` is required; Schema Registry / ksqlDB / Connect fields are needed only if your input ACLs reference those resources.

### Step 1 — Extract

Pick a source:

```sh
# From a live cluster
monedula-acl-rbac extract --from live \
  --bootstrap-server kafka.example.com:9093 \
  --command-config admin.properties \
  --out runs/2026-05-21T10-00-00Z/acls.json

# From an exported `kafka-acls.sh --list` text dump
monedula-acl-rbac extract --from text --input acls.txt \
  --out runs/2026-05-21T10-00-00Z/acls.json

# From a JSON or YAML file matching the canonical schema (schemas/acls.v1.json)
monedula-acl-rbac extract --from yaml --input acls.yaml \
  --out runs/2026-05-21T10-00-00Z/acls.json

# From a CSV with columns: id,principal,host,operation,resource_type,
# resource_name,pattern_type,permission_type
monedula-acl-rbac extract --from csv --input acls.csv \
  --out runs/2026-05-21T10-00-00Z/acls.json

# From a shell script of `kafka-acls --add ...` commands
monedula-acl-rbac extract --from script --input setup-acls.sh \
  --vars vars.yaml \
  --out runs/2026-05-21T10-00-00Z/acls.json

# From a Strimzi KafkaUser manifest
monedula-acl-rbac extract --from strimzi --input kafka-users.yaml \
  --out runs/2026-05-21T10-00-00Z/acls.json

# From CFK (Confluent for Kubernetes) manifests on disk
# Parses Kafka CR superusers as cluster-wide ALL ACLs and reads any
# existing ConfluentRolebinding CRs into a sidecar inventory so the
# planner can skip bindings that already exist.
monedula-acl-rbac extract --from cfk --input cfk-manifests/ \
  --out runs/2026-05-21T10-00-00Z/acls.json

# From a running Kubernetes cluster (reads Strimzi KafkaUser and CFK Kafka /
# ConfluentRolebinding CRs directly via the K8s API). Uses your kubeconfig.
monedula-acl-rbac extract --from k8s \
  --context prod-cluster \
  --namespace kafka \
  --out runs/2026-05-21T10-00-00Z/acls.json

# k8s source — broader scope across all visible namespaces, with a label filter
monedula-acl-rbac extract --from k8s \
  --context prod-cluster \
  --all-namespaces \
  --label-selector team=payments \
  --out runs/2026-05-21T10-00-00Z/acls.json
```

The `k8s` source needs only `get`/`list` on `kafkausers`, `kafkas`, `confluentrolebindings`, and `kafkatopics`. See the spec for the recommended ClusterRole.

The output is a canonical `acls.json`. Inspect it before going further.

> **Flag aliases:** `--bootstrap-server` is the canonical name (matching upstream Kafka tooling); `--bootstrap` is accepted as a short alias.

> **Client properties:** accepts truststore/keystore files in
> PEM (`.pem`/`.crt`/`.cer`), PKCS12 (`.p12`/`.pfx`), and JKS
> (`.jks`/`.keystore`) formats. Passwords come from
> `ssl.truststore.password` and `ssl.keystore.password` in the
> properties file. Encrypted PEM private keys (`ssl.key.password`
> set on a PEM keystore) are still rejected — decrypt to PEM first
> with `openssl rsa -in encrypted.pem -out decrypted.pem`, or convert
> the keystore to PKCS12 with `openssl pkcs12 -export -inkey key.pem -in cert.pem -out keystore.p12`.

### Step 2 — Plan (writes plan.json AND report.txt)

Convert ACLs into RBAC bindings. You must provide a `scopes.yaml` identifying the Confluent clusters you're binding to.

```sh
monedula-acl-rbac plan \
  --acls runs/2026-05-21T10-00-00Z/acls.json \
  --rules rules.yaml \
  --principals principals.yaml \
  --scopes scopes.yaml \
  --out runs/2026-05-21T10-00-00Z/plan.json
```

`plan` co-emits `report.txt` next to `plan.json` and prints a summary to stderr. **Read the report before continuing** — it shows each source ACL and the binding it produced (or `UNMAPPED` / `REJECTED`), DENY analysis, principal warnings, and convenience-flag expansions.

`plan` exits non-zero if any ACL was unmapped or rejected (e.g., DENY ACLs). That's intentional — investigate before proceeding. To proceed anyway:

```sh
monedula-acl-rbac plan ... --allow-unmapped --allow-rejected
```

Note: those flags don't *convert* the unmapped/rejected ACLs; they just allow the plan to succeed with them recorded as unconverted. (The older flag name `--allow-deny-drop` is still accepted but prints a deprecation warning.)

To re-view a report later (e.g., from an old run dir) in a different format, use the standalone `report` subcommand:

```sh
monedula-acl-rbac report --plan runs/2026-05-21T10-00-00Z/plan.json --format markdown
```

#### Editing the plan before applying

You can edit `plan.json` by hand — for example, to drop a binding you're not yet ready to apply, or to fix a principal. To make the edited plan accepted by downstream commands, re-checksum it:

```sh
monedula-acl-rbac plan --revalidate runs/2026-05-21T10-00-00Z/plan.json
```

This **structurally** re-validates the edited file (schema version + per-binding fields) and rewrites `plan.sha256`. Without this step, `apply` will refuse the edited plan with exit code 5 (stale checksum).

> **Trust boundary.** `--revalidate` re-checks only *structural* validity (schema + per-binding fields). It does **not** re-derive the plan from `acls.json` + `rules.yaml`, nor re-run the DENY / UNMAPPED analysis. If you hand-edit `plan.json` to add a binding the rules would never have produced, `--revalidate` gives you exactly that binding back — validated, with a fresh `plan.sha256` that downstream `apply`/`verify`/`delete-*` will trust. This is intentional (operator overrides are supported), but it means the refreshed fingerprint vouches for "this is the plan that was reviewed", not "this is the plan the rules produced". Review the diff, not just the checksum.

### Step 3 — Apply

Create the RBAC bindings in MDS. **Always dry-run first** to see exactly which API calls would be made:

```sh
monedula-acl-rbac apply \
  --plan runs/2026-05-21T10-00-00Z/plan.json \
  --mds-url https://mds.example.com \
  --mds-token-file ~/.confluent/token \
  --dry-run
```

Dry-run reads MDS for the idempotency check (skipping bindings that already exist) but makes no writes, and records every would-be call to `runs/<ts>/would-apply.log`. Inspect that log, then re-run with `--confirm` instead of `--dry-run` to actually apply.

Use `--apply-parallelism N` (default 4) to tune concurrency. By default the command shows per-binding progress on stderr when run in a terminal.

#### Apply flags worth knowing

- **`--format text|json`** — emit a structured summary on stdout
  at the end of the apply run. JSON output includes a per-binding result
  list (`binding_id`, `principal`, `role`, `status`, optional `error`)
  and aggregate counts (`total`, `created`, `skip_exists`, `failed`),
  suitable for downstream CI/CD parsing (`jq`, etc.). Default: `text`.
- **`verify --format text|json`** — same shape as apply's `--format`,
  but with `effective_ok`/`effective_missing`/`effective_unknown`
  counts and per-source-ACL results. `verify.json` on disk uses
  the same envelope, so `jq '.results'` works on both stdout and
  the run-directory artefact.

Both JSON envelopes carry a `schema_version` field (currently the
string `"1"`) and are formally described by the JSON Schemas shipped in
`schemas/apply-summary.v1.json` and `schemas/verify-summary.v1.json`.
`status --format json` and `report --format json` also carry
`schema_version: "1"` for parity, described by
`schemas/status.v1.json` and `schemas/report.v1.json`. The same
convention is followed by `diff --format json` and
`mds list-bindings --format json|yaml`. The on-disk artefacts
(`acls.json`, `plan.json`) use the same string `"1"` form so a
single "fail if schema_version changes" check works uniformly across
every JSON the tool produces. Downstream CI consumers can validate
output against the schemas; future versions will bump `schema_version`
if any envelope shape changes incompatibly.
- **`--mds-max-retries N`** — retry transient MDS failures (HTTP 5xx,
  429, `io.EOF`, connection reset) up to N additional times after the
  initial call. Exponential backoff with jitter, capped at 5s per
  attempt. HTTP 429 honours `Retry-After` (capped at 60s). Default: 3.
  Pass `0` to disable retries (restores the original fail-fast behaviour).
  Also configurable via `MONEDULA_ACL_RBAC_MDS_MAX_RETRIES`.

#### Authentication

You can authenticate to MDS in any of three ways:

**a) Username + password (the tool exchanges them for a token):**

```sh
monedula-acl-rbac apply \
  --plan runs/2026-05-21T10-00-00Z/plan.json \
  --mds-url https://mds.example.com \
  --mds-user admin \
  --mds-password-file ~/.confluent/mds-password \
  --confirm
```

The token is kept in memory only. Add `--cache-token` to persist it under your user config directory (`~/.config/monedula-acl-rbac/tokens/` on Linux, `~/Library/Application Support/monedula-acl-rbac/tokens/` on macOS, `%LOCALAPPDATA%\monedula-acl-rbac\tokens\` on Windows; mode 0600 on POSIX). The cache file name incorporates both the MDS URL and the username, so multiple users on a shared host don't collide.

**b) Interactive login (one-time, then token-cached):**

```sh
monedula-acl-rbac auth login --mds-url https://mds.example.com
# Prompts for username + password, exchanges for a token, writes the cache file.

monedula-acl-rbac apply --plan ... --mds-url https://mds.example.com --confirm
# Subsequent calls pick up the cached token automatically.
```

**c) Pre-fetched token (recommended for CI/CD):**

```sh
monedula-acl-rbac apply \
  --plan runs/2026-05-21T10-00-00Z/plan.json \
  --mds-url https://mds.example.com \
  --mds-token-file ~/.confluent/token \
  --confirm
```

`apply` is idempotent: re-running skips bindings that already exist. If it fails midway, `apply.log` records exactly which bindings succeeded; re-running picks up where it left off.

#### Where do I get an MDS token manually?

If you'd rather provision the token yourself (e.g., your team manages MDS credentials in Vault), exchange username/password for a token directly:

```sh
curl -u USER:PASS https://mds.example.com/security/1.0/authenticate \
  | jq -r .auth_token > ~/.confluent/token
chmod 0600 ~/.confluent/token
```

The Confluent CLI also produces compatible tokens via `confluent iam mds login`.

#### TLS to MDS

Almost every production MDS is behind HTTPS, often with a private CA. The same flags apply to `apply`, `verify`, `discover`, `mds list-bindings`, and `auth login`:

```sh
monedula-acl-rbac apply \
  --plan ... \
  --mds-url https://mds.example.com \
  --mds-ca-cert /etc/ssl/corp-ca.pem \
  --mds-client-cert /etc/ssl/client.pem \
  --mds-client-key /etc/ssl/client-key.pem \
  --mds-token-file ~/.confluent/token \
  --confirm
```

If you must skip certificate verification (development clusters, never production), `--mds-insecure-skip-verify` is available — every invocation prints a prominent warning on stderr.

For Kafka connections (used by `extract --from live` and `delete-acls`), TLS goes through the standard `--command-config` Kafka client properties file (`security.protocol=SSL`, `ssl.truststore.location=...`, etc.) — same as `kafka-acls.sh` and friends.

### Step 4 — Verify

Confirm that each created binding actually grants the **effective access** the original ACL granted. This is stronger than just checking that the binding exists in MDS — it asks MDS, per source ACL, whether the original `(principal, operation, resource)` tuple is now allowed.

```sh
monedula-acl-rbac verify \
  --plan runs/2026-05-21T10-00-00Z/plan.json \
  --mds-url https://mds.example.com \
  --mds-token-file ~/.confluent/token
```

`verify.json` is written into the run directory inferred from `--plan`.

(Uses any of the three auth methods from Step 3.)

`verify` runs in `--mode effective` by default. Each source ACL is classified:

- `EFFECTIVE_OK` — the binding works as intended.
- `EFFECTIVE_MISSING` — the binding exists in MDS but the principal still cannot perform the operation (often: LDAP didn't resolve the principal, group membership isn't propagated yet, scope mismatch). These block `delete-acls`.
- `EFFECTIVE_UNKNOWN` — MDS didn't answer clearly. Treated as unsafe; blocks `delete-acls` unless `--accept-unknown-verify` is passed.

For a fast smoke check (no LDAP / group expansion latency), use `--mode bindings-exist`. That mode only confirms the binding rows exist in MDS — it does **not** prove users can actually use them.

`verify` has no `--dry-run` flag because verify is read-only — it never mutates external state. The canonical "what would verify say?" rehearsal is `verify --format json | jq` against a previous run's `verify.json` (or the live run, since re-running is safe).

`verify` exits **5** (Guardrail) if any result is `EFFECTIVE_MISSING` / `BindingMissing` / `EFFECTIVE_UNKNOWN` — so it can be used as a CI gate without parsing `verify.json`. Exit 0 means every result is OK (and `delete-acls` would be willing to delete). Pass `--accept-unknown-verify` to downgrade `EFFECTIVE_UNKNOWN` → `EFFECTIVE_OK` in environments where MDS lacks the lookup endpoint. `verify.json` is still written before the exit-code check, so on a non-zero exit you can `jq '.results[] | select(.status != "EFFECTIVE_OK")' verify.json` for details.

**Stop here for now.** Let users exercise their access against the new RBAC bindings for at least 24 hours before going to step 5. ACLs and RBAC permissions are additive in Confluent — both layers grant access during this window, so deleting ACLs is purely a cleanup operation, not a cutover.

### Step 5 — Delete converted Allow ACLs

Only after step 4 (verify) succeeded **and** after you decide enough time has passed (typically 24h, operator-judgement).

**The tool does not delete ACLs directly by default.** It generates a `delete-acls.sh` shell script that you inspect, then run yourself. This is a deliberate extra human checkpoint between "decide what to delete" and "actually delete." The script is plain `kafka-acls --remove ...` invocations, so it works on any host with the standard Kafka CLI.

```sh
monedula-acl-rbac delete-acls \
  --plan runs/2026-05-21T10-00-00Z/plan.json \
  --verify runs/2026-05-21T10-00-00Z/verify.json \
  --bootstrap-server kafka.example.com:9093 \
  --command-config admin.properties \
  --principal User:alice \
  --principal User:bob \
  --confirm --i-understand-this-is-destructive
```

This produces, in the run directory:

- `delete-acls.sh` — the deletion script. **Open it, read it, then run it.**
- `deleted-acls.json` — the exact ACLs the script will remove.
- `rollback.sh` — a runnable `kafka-acls.sh --add ...` script that recreates them if anything goes wrong.

Then execute the deletion yourself:

```sh
bash runs/2026-05-21T10-00-00Z/delete-acls.sh
```

If something looks off in the script (an unexpected ACL, the wrong cluster, a typo in `--bootstrap-server`), edit it or just abandon the run.

Recommended: delete one principal at a time (`--principal` is repeatable, or use `--principal-file`). Then re-run `delete-acls` for the next principal. This makes mistakes recoverable.

> **No in-process deletion mode.** `delete-acls` only emits the script; the tool itself never runs `kafka-acls --remove`. This is a deliberate safety property — every destructive ACL change goes through a script artifact you (or your CI/CD pipeline) execute explicitly. If you need automation, have your pipeline shell out to `bash runs/<ts>/delete-acls.sh` after the artifact is generated.

## Checking on a previous run

When you come back to a run dir from yesterday (or want to know what state it's in for CI):

```sh
monedula-acl-rbac status runs/2026-05-21T10-00-00Z
```

Sample output:

```
Run directory: runs/2026-05-21T10-00-00Z

extract:           acl_count=500, source=json
plan:              bindings=487, checksum_ok=true, rejected=0, unmapped=13
apply:             
verify:            487 EFFECTIVE_OK, 0 missing, 0 unknown (487 total)
delete-acls:       NOT RUN
delete-deny-acls:  NOT RUN
lock:              none
```

Add `--format json` for CI/CD consumption. `status` makes no external calls; it inspects only files in the run directory.

## Working with existing MDS state

To see what role bindings already exist in MDS (e.g., before planning a new batch):

```sh
monedula-acl-rbac mds list-bindings \
  --mds-url https://mds.example.com \
  --principal-filter User:alice
```

This is a read-only query, useful for "what does MDS think User:alice has access to?" before designing a migration. Pair with `--scope-filter` (e.g., `--scope-filter kafka-cluster`) to narrow further.

## Advanced / special cases

### Emit artifacts for external CD pipelines

When your environment requires apply to go through a separate CD pipeline (GitOps, change-control), generate the artifact rather than calling MDS directly:

```sh
# Shell script of `confluent iam rbac role-binding create ...` commands
monedula-acl-rbac emit --plan runs/.../plan.json --format script --out-dir emit/

# CFK manifest (ConfluentRolebinding CRs for Confluent for Kubernetes)
monedula-acl-rbac emit --plan runs/.../plan.json --format cfk --out-dir emit/

# Curl commands hitting MDS REST
monedula-acl-rbac emit --plan runs/.../plan.json --format mds-curl --out-dir emit/
```

**Rolling back externally-applied bindings.** This tool does not delete RBAC bindings (out of scope for v1), so if your CD pipeline applied generated artifacts and you need to roll them back:

- For `--format script` artifacts: for each generated `confluent iam rbac role-binding create` invocation, run the corresponding `confluent iam rbac role-binding delete` preserving the same principal, role, and scope arguments. (Exact required flags differ slightly between `create` and `delete` in some Confluent CLI versions — check `confluent iam rbac role-binding delete --help`.)
- For `--format cfk` artifacts: `kubectl delete -f emit/cfk.yaml` removes the `ConfluentRolebinding` CRs the operator created.
- For `--format mds-curl` artifacts: replace each `POST` to `/security/1.0/principals/.../roleBindings/...` with a `DELETE` to the same path.

Save the emitted artifacts in your CD repo until the migration is stable so rollback stays trivial.

### Diffing two runs

For incremental migrations, compare the ACLs or plans between two run directories:

```sh
# What ACLs are new this batch?
monedula-acl-rbac diff --acls runs/A/acls.json runs/B/acls.json

# What does the new plan add or change vs. the previously-approved one?
monedula-acl-rbac diff --plan runs/A/plan.json runs/B/plan.json
```

Output sections: `ADDED`, `REMOVED`, `CHANGED`. Local-only; no external calls.

### Removing DENY ACLs

DENY ACLs are **never** converted (Confluent RBAC has no deny semantics) and are **never** touched by `delete-acls`. To remove them, use the separate `delete-deny-acls` command.

Like `delete-acls`, this command **generates a script** by default rather than running deletions itself:

```sh
monedula-acl-rbac delete-deny-acls \
  --plan runs/2026-05-21T10-00-00Z/plan.json \
  --verify runs/2026-05-21T10-00-00Z/verify.json \
  --mds-url https://mds.example.com \
  --mds-token-file ~/.confluent/token \
  --bootstrap-server kafka.example.com:9093 \
  --command-config admin.properties \
  --principal User:alice \
  --confirm \
  --i-understand-this-may-grant-access
```

Both MDS and Kafka credentials are required: the live re-check at script-execution time queries MDS for effective permissions and removes the ACL via Kafka. The resolved connection settings and credential references are written to `runtime.env` with mode `0600`; secrets are never embedded in the generated script or in command-line arguments.

Unlike `apply`/`verify`, `delete-deny-acls` does **not** accept cache-only authentication — you must pass `--mds-token-file`, or `--mds-user` + `--mds-password-file`. The credentials are baked into `runtime.env` so the generated script's `delete-deny-one` calls can authenticate **non-interactively at execution time**, which may be hours later; a cached token discovered at generation time may have expired by then, with no operator present to re-prompt. The `--mds-insecure-skip-verify` and `--mds-max-retries` settings you pass are likewise carried through `runtime.env`, so the per-ACL re-check uses the same TLS posture and retry tuning as generation time.

(Earlier revisions of this tool also required `--i-understand-this-is-destructive` on this command. That's now redundant — "may grant access" already implies destructiveness — and is no longer accepted on `delete-deny-acls`. It's still required on `delete-acls`.)

The generated `delete-deny-acls.sh` does **not** contain bare `kafka-acls --remove` commands. Each DENY removal is routed through an internal per-ACL helper (`delete-deny-one`, invoked by the script — not a command you run yourself) that performs a **live effective-permission re-check at script-execution time**. This means:

- The static script is safe to inspect, reorder, or partially run by hand.
- The safety property (don't remove a DENY if removing it would grant access right now) is preserved even if the cluster state changes between generating the script and running it.
- Credentials are **not** embedded in the script. The script `source`s `<absolute-rundir>/runtime.env` (mode 0600), which contains the resolved Kafka/MDS endpoints and a per-run auth token. The runtime file is removed when the script exits.

To execute:

```sh
bash runs/2026-05-21T10-00-00Z/delete-deny-acls.sh
```

Each DENY is deleted only if its live re-check returns `SAFE_TO_REMOVE`. If something else now grants the access (a binding added since you ran `plan`, for example), the script skips that DENY and logs it as `WOULD_GRANT_ACCESS` in `delete-deny.log`.

Wildcard-principal DENYs (`Deny User:* ...`, the bare `*` form, or any `<Type>:*`) are **never removable by this tool**. Their blast radius is unbounded — they cover principals the analysis cannot enumerate — so the planner classifies them `UNKNOWN`, and `delete-deny-acls` refuses them outright (there is no confirmation-token override). If you are certain a wildcard DENY must go, remove it manually with `kafka-acls`.

> **Script-only by design.** Like `delete-acls`, this command never runs the deletion in-process. Each line in the generated script invokes `monedula-acl-rbac delete-deny-one`, which re-checks effective access right before deleting the ACL. CI pipelines can `bash runs/<ts>/delete-deny-acls.sh` after the artifact is generated and reviewed.

## Config files

### `scopes.yaml` (conditionally required)

Identifies which Confluent clusters bindings target. For a Kafka-only migration (the common case), only `kafka_cluster` is required; Schema Registry / ksqlDB / Connect IDs are required only if your input ACLs reference resources on those clusters. To bootstrap from a live MDS, run `monedula-acl-rbac discover --mds-url ...`.

```yaml
organization: 123e4567-e89b-12d3-a456-426614174000   # required if any binding targets org scope
environment:  env-abc123                              # required if any binding targets environment scope
kafka_cluster:           lkc-kafka01                  # required for the common case
schema_registry_cluster: lsrc-sr01                    # only if input ACLs reference Subject resources
ksql_cluster:            lksqlc-ksql01                # only if input ACLs reference ksqlDB resources
connect_cluster:         lcc-connect01                # only if input ACLs reference Connect resources
```

### `rules.yaml` (optional)

Overrides or extends the built-in mapping rules. Merge is key-by-key, so you can override one rule without restating the rest. To see the defaults:

```sh
monedula-acl-rbac rules show > rules.default.yaml
```

Example custom rule:

```yaml
rules:
  - when:
      operations: [Read, Describe]
      operations_mode: all   # default; alternatives: any
      resource_type: Topic
      permission_type: Allow
    then:
      role: DeveloperRead
      scope_template: kafka-cluster
```

### `principals.yaml` (optional)

Maps source ACL principals (e.g., mTLS DNs, SASL usernames) to the principal forms MDS expects.

```yaml
principals:
  "User:CN=alice,O=acme,C=US": "User:alice@acme.com"
  "User:svc-billing":          "Group:billing-services"
fallback: pass-through   # or "fail" to require every principal be mapped
```

### `vars.yaml` (optional, for `extract --from script`)

Substitutes variables found in your shell-script input. If your script contains `$TOPIC` and you don't provide a substitution, the parser refuses to guess — it will reject those lines.

```yaml
TOPIC: orders.events
ENV:   prod
```

## Safety guarantees

The tool is built around the principle that **silent failures in access-control tooling cause security incidents**. Specifically:

- **No mutation without confirmation.** Mutating commands never touch external state unless `--confirm` is on the command line or you type `yes` at an interactive prompt. `apply --dry-run` is the explicit preview mode. `delete-acls` and `delete-deny-acls` emit a shell script you inspect and run yourself — the tool itself never executes destructive Kafka calls.
- **Script-only deletion.** The most destructive operation produces a `kafka-acls --remove ...` script as an artifact you can read, edit, or abandon. The rollback script is generated symmetrically and at the same time. There is no in-process deletion path.
- **No ACL is ever silently dropped.** Every input ACL appears in exactly one of `bindings[]`, `unmapped[]`, or `rejected[]` in the plan.
- **Scope is never widened.** A `PREFIXED` ACL on `Topic:foo*` produces a binding on `Topic:foo*`, never a cluster-wide grant.
- **`apply` never deletes source ACLs.** ACL deletion is a separate, opt-in, multi-gated command.
- **Stale plans are refused.** Each mutating command checks the checksum of its input plan; mismatch aborts. The generated `delete-acls.sh` / `delete-deny-acls.sh` *also* re-hash `plan.json` at execution time and refuse to run on a mismatch — and, fail-closed, refuse if `plan.json` cannot be hashed at all (no `sha256sum`/`shasum`, or the file isn't readable where the script runs). The single documented escape hatch is `MONEDULA_SKIP_PLAN_HASH_CHECK=1`, for when the script is intentionally run somewhere the run directory isn't present (e.g. copied into a broker container). To apply an edited plan, run `plan --revalidate` to structurally re-validate the edit and refresh the checksum. Revalidation does **not** re-run the DENY/UNMAPPED analysis — see the trust-boundary note under "Editing the plan before applying".
- **`verify.json` is bound to the plan it checked.** `verify` stamps the plan's SHA-256 into `verify.json` (`plan_sha256`). `delete-acls`, `delete-deny-acls`, and the per-ACL `delete-deny-one` refuse to run if that stamp does not match the plan being deleted against — re-run `verify` against the current plan. This closes the window where a stale `verify.json` from an earlier plan vouches for a re-generated one.
- **Per-run-directory lockfile (apply-only).** Two `apply` invocations against the same run directory cannot race — the second refuses with exit code 5. Stale lockfiles (the holding process is dead) can be cleared with `--force-unlock`. The lockfile and `--force-unlock` apply only to `apply`: it is the only command that mutates external state in-process. `delete-acls` and `delete-deny-acls` produce scripts without acquiring locks — coordinating script execution is the operator's responsibility.
- **Effective-access verification.** `verify` defaults to checking that MDS reports the original `(principal, operation, resource)` tuple as allowed for each source ACL — not just that the binding row exists. `delete-acls` refuses to delete source ACLs whose effective access is `EFFECTIVE_MISSING` or `EFFECTIVE_UNKNOWN`, unless `verify --accept-unknown-verify` was used (which downgrades `EFFECTIVE_UNKNOWN` to `EFFECTIVE_OK` for environments where MDS lacks the lookup endpoint, with the downgrade recorded in each result's `Detail` field). The override is opt-in, visible in `verify.json`, and never weakens the `EFFECTIVE_MISSING` block.
- **DENY ACLs are never auto-converted.** They go to `rejected`. Removing them requires the dedicated `delete-deny-acls` command, whose generated script performs a live effective-permission re-check **per ACL at script-execution time**, not at script-generation time. Wildcard-principal DENYs (`User:*`, bare `*`, any `<Type>:*`) are classified `UNKNOWN` and are **never removable by this tool** — there is no override, since their blast radius is unbounded. The script never embeds passwords on command lines; credentials are sourced from a `runtime.env` file (mode 0600) the parent command wrote into the run directory.
- **Every invocation is auditable.** The run directory contains the input snapshot, the effective rules, the plan, all logs, rollback scripts, and a record of which credentials source was used.

## Logging

The tool emits diagnostic output via Go's `log/slog`. Two persistent
flags work on every subcommand:

- `--log-format text|json` (default `text`). Use `json` to pipe
  structured logs into your CI/observability stack.
- `--log-level debug|info|warn|error` (default `info`).

Both flags also accept env-var overrides:
`MONEDULA_ACL_RBAC_LOG_FORMAT`, `MONEDULA_ACL_RBAC_LOG_LEVEL`.

Note: this is for stderr diagnostics. Audit artefacts in the run
directory (`apply.log`, `verify.json`, `extract.log`, etc.) keep
their own structured per-line formats — they're machine-friendly
regardless of `--log-format`.

## Output formats

Commands that emit a structured summary on stdout accept `--format text|json`
by default. Commands that have a human-formatted variant extend the
list accordingly: `report` accepts `--format text|json|markdown` and
`mds list-bindings` accepts `--format text|json|yaml`. CSV is not a
supported output format on any command — use the canonical JSON shape
and post-process with `jq` (or your preferred tool) if you need CSV.

A separate `--format` axis applies to artefact-emitting commands
(`emit` and `convert`): there the value picks the output shape
(`script|cfk|mds-curl`) rather than a structured summary's encoding.

The table of contents — also reproducible via `<cmd> --help`:

| Command | `--format` values | Default |
|---|---|---|
| `apply` | `text`, `json` | `text` |
| `verify` | `text`, `json` | `text` |
| `diff` | `text`, `json` | `text` |
| `mds list-bindings` | `text`, `json`, `yaml` | `text` |
| `report` | `text`, `json`, `markdown` | `text` |
| `status` | `text`, `json` | `text` |
| `emit` | `script`, `cfk`, `mds-curl` | `script` |
| `convert` | `script`, `cfk`, `mds-curl` | `script` |

Commands not in this table (`plan`, `extract`, the `delete-*` family,
`discover`, `init`, `auth login`, `rules show`) produce a single
canonical artefact and have no `--format` switch.

## Recovery

If apply or a deletion script fails partway through, look at the run directory:

- `apply.log` — every MDS call and its result. Re-run `apply` with the same plan; it will skip bindings that already exist.
- `delete-acls.sh` / `delete-deny-acls.sh` — the generated deletion scripts. Both use `set -e`, so they stop at the first failure.
- `delete.log` / `delete-deny.log` — populated by the script as it runs. Records each ACL with `OK` / `SKIP` / `FAIL`. Re-running the script against the same `verify.json` skips ACLs already marked `OK`.
- `rollback.sh` / `rollback-deny.sh` — runnable `kafka-acls --add ...` scripts that recreate every ACL the deletion script would (or did) remove. Run them against the same cluster to undo.

To roll back RBAC bindings created by `apply`, use the Confluent CLI or MDS API directly; this tool intentionally does not delete role bindings (out of scope for v1).

## Exit codes

| Code | Meaning | Examples |
|---|---|---|
| 0 | Success | normal completion |
| 1 | Usage error | missing required flag, malformed argument, unknown subcommand |
| 2 | Input error | unparseable ACLs, missing or malformed config (rules / principals / scopes / vars files) |
| 3 | Plan has unresolved unmapped/rejected items | `plan` without `--allow-unmapped` / `--allow-rejected`; also `report` viewing such a plan |
| 4 | External system error | MDS unreachable or 401/403; Kafka unreachable or auth failure; Kubernetes API unreachable / auth / RBAC denied |
| 5 | Destructive operation refused by a guardrail, or a guardrail check reports unhealthy state | stale plan checksum (incl. the generated script's runtime re-hash; override with `MONEDULA_SKIP_PLAN_HASH_CHECK=1`), expired `verify.json`, wildcard-principal DENY (classified UNKNOWN), lockfile held by a live PID, `verify` reports any `EFFECTIVE_MISSING` / `BindingMissing` / `EFFECTIVE_UNKNOWN` result (override `EFFECTIVE_UNKNOWN` with `--accept-unknown-verify`) |

## Limitations

- v1 is read-only on RBAC: it does not reverse-migrate (RBAC → ACLs) or modify existing bindings.
- DENY ACLs cannot be represented as RBAC; the tool detects, reports, and (separately) helps you remove them, but it cannot translate their intent.
- **Scale**: designed for batches up to ~10,000 ACLs per run, held in memory. For larger sets, partition by principal (one run dir per principal batch). Streaming mode is post-v1.
- **Concurrency**: the per-run-directory lockfile catches the "I re-ran in another terminal" case, but the tool does not coordinate two operators working against the same MDS from different run directories. Assume single-operator per cluster during a migration window.
- Variable-heavy scripts (`for topic in $TOPICS; do kafka-acls ...; done`) are rejected by the script parser — the tool will not guess values. Use `--vars` or pre-expand the script.

## API stability

**The supported, semver-governed interface is the command-line tool** — its
commands, flags, exit codes, and the on-disk/stdout JSON envelopes documented
under [`schemas/`](schemas/). Those are what the 1.0.0 compatibility promise
covers.

The Go packages under `pkg/aclrbac/...` are **internal-by-convention**. They
are exported only because the CLI and its tests are split across packages, not
because they constitute a public library. Their function signatures, types, and
behaviour may change between releases **without a major version bump**. If you
need to integrate programmatically, shell out to the CLI and parse the JSON
envelopes (stable) rather than importing the packages (not stable).

## Reporting issues

Please report bugs and feature requests via [GitHub issues](https://github.com/monedula-dev/monedula-acl-rbac-converter/issues).
