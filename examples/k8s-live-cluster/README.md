# k8s-live-cluster — read ACLs from a running Kubernetes cluster

**Flow path:** `extract --from k8s` → `plan` → `emit`
**Needs:** Docker + `kubectl` + [`kind`](https://kind.sigs.k8s.io)

The `k8s` source is the live counterpart of the file-based `strimzi` / `cfk`
sources: instead of reading exported YAML, it talks to a **running cluster's
Kubernetes API** and lists the relevant custom resources directly —
`KafkaUser` (Strimzi) and `Kafka` / `ConfluentRolebinding` (CFK).

This example stands up a throwaway [kind](https://kind.sigs.k8s.io) cluster,
registers the CRDs ([`crds.yaml`](crds.yaml) — just the kinds, **no operators**,
since the tool only reads CRs), applies five `KafkaUser` CRs
([`manifests/kafkausers.yaml`](manifests/kafkausers.yaml)), and converts what it
finds.

> This is the one example **not** driven by docker-compose — `kind` manages its
> own Docker container. The converter runs as your local binary because it needs
> your kubeconfig to reach the cluster.

## The scenario

The same five `KafkaUser` principals as [`../strimzi-kafkauser/`](../strimzi-kafkauser/),
but read live from the cluster:

| `KafkaUser` | authorization | → RBAC binding |
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
./run.sh          # create kind cluster → extract → plan → emit → assert → delete cluster
./run.sh --keep   # same, but leave the cluster running afterwards
```

Don't have `kind`? Install it with `go install sigs.k8s.io/kind@latest` (it is a
single binary), then re-run.

## What you get

`out/acls.json`, `out/plan.json`, `out/report.txt`, `out/script.sh` — committed
reference copies are in [`expected/`](expected/). `run.sh` asserts the result
(7 bindings, the expected roles, and the rejected DENY) rather than
diffing, since this path depends on a live cluster.

> `convert` does **not** support the `k8s` source (it needs cluster state and
> writes audit artifacts), so this example always uses the explicit
> `extract → plan → emit` pipeline — exactly as a real migration would.
