# live-mds-migration — the full pipeline against a real MDS

**Flow path:** `extract --from live` → `plan` → `apply` → `verify` → `delete-acls`
**Needs Docker:** yes (this is the flagship end-to-end example)

This is the real thing: a single-node Confluent stack with **RBAC and the
Metadata Service (MDS)**, brought up with docker-compose, against which the tool
runs the **entire migration** — reading ACLs off a live broker, applying RBAC
bindings to MDS, verifying that those bindings actually grant the original
access, and finally deleting the now-redundant source ACLs.

Nothing is mocked. `apply` and `verify` talk to a real MDS over HTTP; `extract`
and `delete-acls` talk to a real broker over SASL. The stack is the same one the
project's integration tests use (`internal/mdstest`), ported to compose.

## What's in the stack

| Service | Image | Role |
|---|---|---|
| `openldap` | `osixia/openldap:1.5.0` | MDS's identity store (holds the `mds` admin user) |
| `kafka` | `confluentinc/cp-server:8.2.1` | KRaft broker **+ MDS/RBAC** on `:8090` |
| `converter` | built from this repo | the `monedula-acl-rbac` CLI, on the same network |

## The scenario

The broker is seeded ([`seed-acls.sh`](seed-acls.sh)) with a legacy ACL set; the
migration converts it to RBAC:

| Principal | Source ACL | → RBAC binding | effective-verified? |
|---|---|---|---|
| `User:svc-orders-consumer` | Read+Describe Topic `orders` | `DeveloperRead` | ✅ |
| `User:svc-orders-consumer` | Read+Describe Group `orders-consumers` | `DeveloperRead` | ✅ |
| `User:svc-payments-producer` | Write+Describe Topic `payments` | `DeveloperWrite` | ✅ |
| `User:svc-analytics` | Read+Describe Topic `events.` **(PREFIXED)** | `DeveloperRead` (prefixed) | ✅ |
| `User:svc-fulfillment` | Read+Describe Topic `shipments` | `DeveloperRead` | ✅ |
| `User:svc-orders-relay` | Read+**Write**+Describe Topic `orders` | `DeveloperRead` **and** `DeveloperWrite` | ✅ |
| `User:legacy-importer` | **Deny** Read Topic `pii-events` | **Rejected** | n/a (never converted) |

Result: **7 bindings created, 1 DENY rejected, all 13 source operations verified
`EFFECTIVE_OK` in MDS**, then the converted principals' source ACLs deleted while
the DENY is left untouched. `svc-orders-relay` reads *and* writes `orders`, so it
becomes two bindings (`DeveloperRead` + `DeveloperWrite`) — a single Developer\*
role cannot grant both, and RBAC bindings are additive.

## Run it

```sh
./run.sh           # up → seed → migrate → verify → delete → assert (leaves stack up)
./run.sh --down    # same, then tear the stack down
```

Requires Docker + the compose plugin. The first run pulls `cp-server` (~1 GB) and
builds the converter image, so allow a few minutes. Tear down anytime with
`docker compose down -v`.

### What `run.sh` does

1. `docker compose up -d openldap kafka`, waits for MDS to report healthy.
2. [`seed-acls.sh`](seed-acls.sh) — creates the source ACLs on the broker.
3. [`pipeline.sh`](pipeline.sh) in the `converter` container:
   `extract --from live` → `plan` → `apply --confirm` →
   `verify --mode bindings-exist` → `verify --mode effective` →
   generate `delete-acls.sh`.
4. Executes the generated `delete-acls.sh` in the broker container.
5. Asserts the 5 principals' ACLs are gone and the DENY survived.

## What you get

Artifacts land in [`out/`](out/) (and committed reference copies are in
[`expected/`](expected/)):

- `acls.json` — the ACLs read off the live broker.
- `plan.json` + `report.txt` — the 7 bindings and the rejected DENY (see
  [`expected/report.txt`](expected/report.txt)).
- `verify-bindings.json` / `verify-effective.json` — proof MDS grants the access
  (`effective_ok: 10` of `10`).
- `delete-acls.sh` / `rollback.sh` / `deleted-acls.json` — the (reviewed,
  operator-run) cleanup and its symmetric undo.

> **The effective-verify step is the point.** It is stronger than "the binding
> row exists": for every source ACL it asks MDS whether that exact
> `(principal, operation, resource)` is now allowed. Only once all are
> `EFFECTIVE_OK` does `delete-acls` agree to remove the source ACLs.

## Notes

- The broker uses a **fixed KRaft `CLUSTER_ID`**, so the converted binding IDs in
  `expected/` are reproducible. `run.sh` re-derives the cluster id from MDS at
  runtime regardless.
- [`secrets/`](secrets/) holds **throwaway** local-dev credentials (an MDS token
  keypair, the LDAP seed, the `mds` password) — see [`secrets/README.md`](secrets/README.md).
- This mirrors `tests/e2e/complex_pipeline_test.go`, which runs the same flow
  across CP 7.9 (ZooKeeper) and CP 8.2 (KRaft) in CI.
