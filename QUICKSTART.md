# Quickstart: convert your first ACL set in 5 minutes

This walks through a complete extract → plan → emit cycle on synthetic
data so you can see what each step produces before pointing the tool at
a real cluster.

## Prerequisites

- Go 1.26+ (only to build the binary; the binary itself has no
  runtime dependencies).
- `git`.

## Install

```sh
git clone https://github.com/monedula-dev/monedula-acl-rbac-converter
cd monedula-acl-rbac-converter
go build -o bin/monedula-acl-rbac ./cmd/monedula-acl-rbac
```

## Step 1: Scaffold a run

```sh
./bin/monedula-acl-rbac init my-first-run
```

This creates `my-first-run/scopes.yaml` and `my-first-run/rules.yaml`
with documented placeholders. Edit `scopes.yaml` and set
`kafka_cluster:` to whatever cluster ID your bindings will target
(any string works for this dry exercise — try `lkc-demo`).

## Step 2: Drop in some ACLs

For the dry run, paste this into `my-first-run/acls.txt`:

```
Current ACLs for resource `ResourcePattern(resourceType=TOPIC, name=orders, patternType=LITERAL)`:
	(principal=User:alice, host=*, operation=READ, permissionType=ALLOW)
	(principal=User:alice, host=*, operation=DESCRIBE, permissionType=ALLOW)
```

This is the same format `kafka-acls.sh --list` produces, so on a real
cluster you'd run:

```sh
kafka-acls.sh --list --bootstrap-server $BROKER > my-first-run/acls.txt
```

## Step 3: Extract → plan (writes report.txt)

```sh
./bin/monedula-acl-rbac extract --from text \
  --input my-first-run/acls.txt \
  --out my-first-run/acls.json

./bin/monedula-acl-rbac plan \
  --acls my-first-run/acls.json \
  --scopes my-first-run/scopes.yaml \
  --out my-first-run/plan.json
```

The tool prints something like:
```
plan: 1 binding(s), 0 unmapped, 0 rejected, 0 warning(s)
```

Open `my-first-run/plan.json` — you'll see a `DeveloperRead` binding
for `User:alice` on topic `orders`. That's what `apply` would create
in MDS.

## Step 4: See what would happen, without mutating

```sh
./bin/monedula-acl-rbac emit --plan my-first-run/plan.json \
  --format script --out-dir my-first-run/
cat my-first-run/script.sh
```

This is a `bash` script with `curl` calls that would create the binding
in MDS. Inspect it, hand it to a colleague, or use the binary's
machine-checked dry-run mode instead:

```sh
./bin/monedula-acl-rbac apply \
  --plan my-first-run/plan.json \
  --mds-url https://mds.example.com \
  --mds-token-file ~/.confluent/token \
  --dry-run
```

Dry-run reads MDS for the idempotency check but makes no writes;
the full request bodies it would have sent end up in
`would-apply.log` next to `plan.json`.

> **Retries:** `apply` retries transient MDS failures (5xx, 429,
> network) up to 3 times by default, with exponential backoff capped
> at 5s per attempt. WARN-level log lines appear on each retry. Pass
> `--mds-max-retries N` to pick a different count (`0` disables
> retries and restores the original fail-fast behaviour). Also configurable
> via `MONEDULA_ACL_RBAC_MDS_MAX_RETRIES`.

## Step 5: Use it for real

When you're ready to point at production:

1. `monedula-acl-rbac discover --mds-url https://mds.example.com` to
   bootstrap a proper `scopes.yaml` with real cluster IDs.
2. `extract --from live --bootstrap-server $KAFKA` (or `--from k8s` if
   you're on a managed cluster) to pull ACLs from the source.
3. `plan` → review the `report.txt` → `apply --dry-run` →
   `apply --confirm` → `verify`.
4. Wait 24+ hours so users exercise the new RBAC bindings.
5. `delete-acls` to emit a deletion script. Inspect it, run it
   piece by piece if needed.

See the [README](README.md) for the full reference.
