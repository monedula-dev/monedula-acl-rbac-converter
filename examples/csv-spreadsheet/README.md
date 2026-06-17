# csv-spreadsheet — convert a flat CSV ACL export

**Flow path:** `extract --from csv` → `plan` → `emit`
**Needs Docker:** no

Many teams keep their ACL inventory in a spreadsheet. Export it to CSV with the
columns the `csv` source expects and convert it directly. [`acls.csv`](acls.csv)
has the required header:

```
id,principal,host,operation,resource_type,resource_name,pattern_type,permission_type
```

one ACL per row (RFC 4180).

## The scenario

| Principal | Source ACL | → RBAC binding |
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

## Run it

```sh
./run.sh           # extract → plan → emit, into out/
./run.sh --check   # diff out/ against committed expected/ goldens
# or, with Docker only:
docker compose run --rm converter ./run.sh --check
```

## What you get

`out/acls.json`, `out/plan.json`, `out/report.txt`, `out/script.sh` — committed
under [`expected/`](expected/). CSV is supported only as an **input** format;
outputs are JSON / scripts / manifests (post-process with `jq` if you need CSV
back out).
