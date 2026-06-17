# setup-script — convert a `kafka-acls --add` provisioning script

**Flow path:** `extract --from script` → `plan` → `emit`
**Needs Docker:** no

Teams often seed a cluster's ACLs with a checked-in shell script full of
`kafka-acls --add …` commands. The `script` source **parses** that script (it
never runs it), expanding `--vars` substitutions and the producer/consumer
convenience flags into canonical ACL rows.

[`setup-acls.sh`](setup-acls.sh) is such a script; [`vars.yaml`](vars.yaml)
supplies `$ORDERS_TOPIC`. The parser refuses to guess unset variables, so the
substitution is explicit and auditable.

## The scenario

| Principal | Source ACL (from the script) | → RBAC binding |
|---|---|---|
| `User:svc-orders-consumer` | Read+Describe Topic `orders` | `DeveloperRead` (Topic `orders`) |
| `User:svc-orders-consumer` | Read+Describe Group `orders-consumers` | `DeveloperRead` (Group `orders-consumers`) |
| `User:svc-payments-producer` | Write+Describe Topic `payments` | `DeveloperWrite` (Topic `payments`) |
| `User:svc-analytics` | Read+Describe Topic `events.` **(PREFIXED)** | `DeveloperRead` (prefixed `events.`) |
| `User:svc-orders-owner` | **All** on Topic `orders` | `ResourceOwner` (Topic `orders`) |
| `User:svc-orders-relay` | Read+**Write**+Describe Topic `orders` | `DeveloperRead` **and** `DeveloperWrite` (Topic `orders`) |
| `User:legacy-importer` | **Deny** Read Topic `pii-events` | **Rejected** — RBAC has no deny |

Result: **7 bindings, 0 unmapped, 1 rejected**. `svc-orders-relay` both reads
and writes `orders`; no single Developer\* role covers both, so it becomes two
bindings (`DeveloperRead` + `DeveloperWrite`) that together reproduce its access.

> The parser rejects variable-heavy control flow (`for topic in $TOPICS; do …`).
> Pre-expand such scripts or list the values in `--vars`.

## Run it

```sh
./run.sh           # extract (with --vars) → plan → emit, into out/
./run.sh --check   # diff out/ against committed expected/ goldens
# or, with Docker only:
docker compose run --rm converter ./run.sh --check
```

## What you get

`out/acls.json`, `out/plan.json`, `out/report.txt`, `out/script.sh` — committed
under [`expected/`](expected/).
