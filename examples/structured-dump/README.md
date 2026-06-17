# structured-dump — convert a canonical `acls.json` / `acls.yaml`

**Flow path:** `extract --from yaml|json` → `plan` → `emit`
**Needs Docker:** no

When your ACLs already live in a structured file — exported from a CMDB, an
internal inventory, or hand-authored against
[`schemas/acls.v1.json`](../../schemas/acls.v1.json) — the `json` and `yaml`
sources read it directly. Both go through the **same** adapter, so
[`acls.yaml`](acls.yaml) and [`acls.json`](acls.json) here describe the identical
ACL set; `run.sh` proves they extract to identical rows (only the recorded
`source.type` differs).

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
./run.sh           # extract (yaml + json) → plan → emit, into out/
./run.sh --check   # diff out/ against committed expected/ goldens
# or, with Docker only:
docker compose run --rm converter ./run.sh --check
```

## What you get

`out/acls.json`, `out/plan.json`, `out/report.txt`, and `out/script.sh` — see
the committed [`expected/`](expected/) directory for the exact output. The report
shows the 7 bindings plus the rejected DENY.
