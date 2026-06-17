# text-dump — convert a `kafka-acls.sh --list` export

**Flow path:** `extract --from text` → `plan` → `emit`
**Needs Docker:** no (Docker is offered only as a no-toolchain convenience)

The most common starting point for a migration: you already have the output of

```sh
kafka-acls.sh --bootstrap-server … --command-config … --list
```

saved to a file. [`acls.txt`](acls.txt) is exactly that format — ACLs grouped by
resource, one `(principal=…, host=…, operation=…, permissionType=…)` line each.

## The scenario

A small microservices platform. The same ACL set appears in every example in
this directory's siblings, expressed through a different input source:

| Principal | Source ACL | → RBAC binding |
|---|---|---|
| `User:svc-orders-consumer` | Read+Describe Topic `orders` | `DeveloperRead` (Topic `orders`) |
| `User:svc-orders-consumer` | Read+Describe Group `orders-consumers` | `DeveloperRead` (Group `orders-consumers`) |
| `User:svc-payments-producer` | Write+Describe Topic `payments` | `DeveloperWrite` (Topic `payments`) |
| `User:svc-analytics` | Read+Describe Topic `events.` **(PREFIXED)** | `DeveloperRead` (prefixed `events.`) |
| `User:svc-orders-owner` | **All** on Topic `orders` | `ResourceOwner` (Topic `orders`) |
| `User:svc-orders-relay` | Read+**Write**+Describe Topic `orders` | `DeveloperRead` **and** `DeveloperWrite` (Topic `orders`) |
| `User:legacy-importer` | **Deny** Read Topic `pii-events` | **Rejected** — RBAC has no deny |

Result: **7 bindings, 0 unmapped, 1 rejected**. The DENY is never converted
(Confluent RBAC cannot express deny) and is surfaced in the report instead of
being silently dropped.

`svc-orders-relay` both consumes and produces the `orders` topic
(Read+Write+Describe). No single Developer\* role grants both, so the planner
emits **two** bindings — `DeveloperRead` *and* `DeveloperWrite` — which together
reproduce the original access. (A single role would drop the uncovered
operation with a `PARTIAL_RULE_COVERAGE` warning.)

## Run it

```sh
./run.sh           # extract → plan → emit, writes artifacts into out/
./run.sh --check   # additionally diff out/ against the committed expected/ goldens
```

No Go toolchain? Run the same thing in a container:

```sh
docker compose run --rm converter ./run.sh --check
```

## What you get

- [`out/acls.json`](expected/acls.json) — the canonical ACL set the text dump
  parsed into.
- [`out/plan.json`](expected/plan.json) + [`out/report.txt`](expected/report.txt)
  — the role bindings, plus the rejected DENY and DENY-safety analysis.
- [`out/script.sh`](expected/script.sh) — the bindings as
  `confluent iam rbac role-binding create …` commands you could run against MDS.

The committed [`expected/`](expected/) directory holds the same artifacts so you
can see the result without running anything, and so `./run.sh --check` can prove
the tool still produces them.

> For a one-liner (no run directory, no report), `convert` does the whole thing:
> ```sh
> monedula-acl-rbac convert --from text --input acls.txt --scopes scopes.yaml > out/script.sh
> ```
