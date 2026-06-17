#!/usr/bin/env bash
# k8s-live-cluster: read ACLs from a RUNNING Kubernetes cluster.
#
# Unlike the file-based examples, the `k8s` source talks to a live cluster's API.
# This script stands up an ephemeral kind cluster, registers the CRDs, applies
# the KafkaUser CRs, then runs extract --from k8s -> plan -> emit and asserts the
# result. It tears the cluster down on exit.
#
#   ./run.sh          create cluster, convert, assert, delete cluster
#   ./run.sh --keep   leave the kind cluster running afterwards (to poke at it)
#
# Prerequisites (this is the one example not driven by docker compose):
#   * Docker
#   * kubectl
#   * kind   (go install sigs.k8s.io/kind@latest, or https://kind.sigs.k8s.io)
set -euo pipefail
cd "$(dirname "$0")"
export EXAMPLE_DIR="$PWD"
. ../lib/common.sh   # provides conv() using the host binary (needs kubeconfig)

CLUSTER=monedula-acl-rbac-demo
CTX="kind-$CLUSTER"

KIND="$(command -v kind || true)"
if [ -z "$KIND" ] && command -v go >/dev/null 2>&1 && [ -x "$(go env GOPATH)/bin/kind" ]; then
  KIND="$(go env GOPATH)/bin/kind"
fi
[ -n "$KIND" ] || { echo "kind not found. Install with: go install sigs.k8s.io/kind@latest" >&2; exit 1; }
command -v kubectl >/dev/null 2>&1 || { echo "kubectl not found." >&2; exit 1; }

keep=0; [ "${1:-}" = "--keep" ] && keep=1
cleanup() {
  if [ "$keep" = "0" ]; then
    echo "== deleting kind cluster =="
    "$KIND" delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

echo "== creating kind cluster '$CLUSTER' (first run pulls the node image) =="
"$KIND" create cluster --name "$CLUSTER" --wait 120s

echo "== registering CRDs (no operators -- the extractor only reads CRs) =="
kubectl --context "$CTX" apply -f crds.yaml
kubectl --context "$CTX" wait --for condition=established --timeout=60s \
  crd/kafkausers.kafka.strimzi.io \
  crd/kafkas.platform.confluent.io \
  crd/confluentrolebindings.platform.confluent.io

echo "== applying KafkaUser CRs =="
kubectl --context "$CTX" apply -f manifests/namespace.yaml
kubectl --context "$CTX" apply -f manifests/kafkausers.yaml

mkdir -p out
echo "== extract --from k8s (reads the CRs via the Kubernetes API) =="
conv extract --from k8s --context "$CTX" --namespace kafka --out out/acls.json
echo "== plan (--allow-rejected: the DENY becomes a rejected entry) =="
conv plan --acls out/acls.json --scopes scopes.yaml --out out/plan.json --allow-rejected
echo "== emit --format script =="
conv emit --plan out/plan.json --format script --out-dir out

echo; cat out/report.txt; echo

echo "== asserting =="
fail=0
bindings="$(grep -c 'role-binding create' out/script.sh || true)"
if [ "$bindings" = "7" ]; then echo "  ok: 7 RBAC bindings produced"; else echo "  FAIL: expected 7 bindings, got $bindings"; fail=1; fi
if grep -q 'DENY_PERMISSION' out/report.txt; then echo "  ok: the DENY KafkaUser was rejected"; else echo "  FAIL: DENY not rejected"; fail=1; fi
for r in DeveloperRead DeveloperWrite ResourceOwner; do
  if grep -q "$r" out/script.sh; then echo "  ok: produced a $r binding"; else echo "  FAIL: missing $r"; fail=1; fi
done

echo
if [ "$fail" = "0" ]; then
  echo "RESULT: read KafkaUser CRs from a live cluster and converted them to RBAC."
else
  echo "RESULT: assertions FAILED (see above)"; exit 1
fi
