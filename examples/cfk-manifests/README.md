# cfk-manifests — convert CFK manifests, skipping existing bindings

**Flow path:** `extract --from cfk` → `plan` → `emit --format cfk`
**Needs Docker:** no

[Confluent for Kubernetes](https://docs.confluent.io/operator/current/overview.html)
(CFK) describes a cluster with `Kafka` and `ConfluentRolebinding` custom
resources. Point the `cfk` source at a directory of these manifests and it reads
two things:

1. **`Kafka.spec.authorization.superUsers`** — each superuser is a cluster-wide
   `ALL` ACL, which maps to the cluster-admin role **`SystemAdmin`**.
2. **existing `ConfluentRolebinding` CRs** — written to a sidecar
   `existing-bindings.json` so `plan` marks any binding that **already exists**
   as `SKIP` instead of `CREATE`. Re-running a migration is therefore
   idempotent.

[`manifests/kafka.yaml`](manifests/kafka.yaml) lists two superusers;
[`manifests/rolebindings.yaml`](manifests/rolebindings.yaml) is an existing
`SystemAdmin` binding for one of them.

## The scenario

| Source | Derived ACL / existing binding | → plan |
|---|---|---|
| `superUsers: User:svc-platform-admin` | All on Cluster | **`[CREATE]` SystemAdmin** |
| `superUsers: User:svc-orders-owner` | All on Cluster | **`[SKIP_EXISTS]` SystemAdmin** (already bound) |
| existing `ConfluentRolebinding` (svc-orders-owner / SystemAdmin) | — | recorded in `existing-bindings.json` |

Result: **2 bindings — 1 to create, 1 already exists**, 0 unmapped, 0 rejected.
Without the existing-binding sidecar, both would be `CREATE`.

## Run it

```sh
./run.sh           # extract → plan → emit (CFK), into out/
./run.sh --check   # diff out/ against committed expected/ goldens
# or, with Docker only:
docker compose run --rm converter ./run.sh --check
```

## What you get

- [`out/acls.json`](expected/acls.json) — the two superuser ALL ACLs.
- [`out/existing-bindings.json`](expected/existing-bindings.json) — the inventory
  read from the `ConfluentRolebinding` CR.
- [`out/plan.json`](expected/plan.json) + [`out/report.txt`](expected/report.txt)
  — one `CREATE`, one `SKIP_EXISTS`.
- [`out/cfk.yaml`](expected/cfk.yaml) — the new binding as a
  `ConfluentRolebinding` CR, ready to `kubectl apply`.

> This example emits the **CFK** output format; the other examples in this tree
> emit `script`. Any plan can be rendered in any of `script` / `cfk` / `mds-curl`.
