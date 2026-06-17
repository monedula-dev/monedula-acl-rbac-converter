# strimzi-kafkauser — convert Strimzi `KafkaUser` CRs

**Flow path:** `extract --from strimzi` → `plan` → `emit`
**Needs Docker:** no

If your cluster is managed by [Strimzi](https://strimzi.io/), authorization
lives in `KafkaUser` custom resources. Export them
(`kubectl get kafkausers -o yaml`) and convert the file directly — no live
cluster needed (for that, see [`../k8s-live-cluster/`](../k8s-live-cluster/)).

[`kafkausers.yaml`](kafkausers.yaml) is a multi-document stream of `KafkaUser`
CRs. The principal is derived from `metadata.name` (`User:<name>`), and only
`authorization.type: simple` users produce ACLs.

## The scenario

| `KafkaUser` | `spec.authorization.acls` | → RBAC binding |
|---|---|---|
| `svc-orders-consumer` | Read+Describe topic `orders`; Read+Describe group `orders-consumers` | 2× `DeveloperRead` |
| `svc-payments-producer` | Write+Describe topic `payments` | `DeveloperWrite` |
| `svc-analytics` | Read+Describe topic `events.` **(prefix)** | `DeveloperRead` (prefixed) |
| `svc-orders-owner` | **All** on topic `orders` | `ResourceOwner` |
| `svc-orders-relay` | Read+**Write**+Describe topic `orders` | `DeveloperRead` **and** `DeveloperWrite` |
| `legacy-importer` | **deny** Read topic `pii-events` | **Rejected** — RBAC has no deny |

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
under [`expected/`](expected/).
