#!/usr/bin/env bash
# The migration pipeline, run INSIDE the on-network `converter` container by
# run.sh (docker compose run --rm converter ./pipeline.sh). Talks to the broker
# at kafka:9094 (SASL) and to MDS at http://kafka:8090.
#
# Steps: extract (live) -> plan -> apply -> verify (bindings-exist, then
# effective) -> generate the delete-acls script. It does NOT run the deletion;
# run.sh executes the generated script in the broker container afterwards.
set -euo pipefail

MDS=http://kafka:8090
BROKER=kafka:9094
MDS_AUTH=(--mds-url "$MDS" --mds-user mds --mds-password-file secrets/mds.pw)
ALLOW_PRINCIPALS=(User:svc-orders-consumer User:svc-payments-producer User:svc-analytics User:svc-fulfillment User:svc-orders-relay)

mkdir -p out

echo "== 0. discover the kafka cluster id from MDS =="
CID="$(curl -sf "$MDS/v1/metadata/id" | sed -E 's/.*"id" *: *"([^"]+)".*/\1/')"
test -n "$CID"
printf 'kafka_cluster: %s\n' "$CID" > out/scopes.yaml
echo "   kafka_cluster=$CID"

echo "== 1. extract --from live (source ACLs off the real broker) =="
monedula-acl-rbac extract --from live \
  --bootstrap-server "$BROKER" --command-config client.properties \
  --out out/acls.json

echo "== 2. plan (DENY -> rejected) =="
monedula-acl-rbac plan --acls out/acls.json --scopes out/scopes.yaml \
  --out out/plan.json --allow-rejected
echo
cat out/report.txt
echo

echo "== 3. apply --confirm (create the RBAC bindings in MDS) =="
monedula-acl-rbac apply --plan out/plan.json --confirm "${MDS_AUTH[@]}"

# MDS's rolebinding cache lags a beat after apply; poll verify until green.
poll_verify() {
  local mode="$1" out="$2" i
  for i in $(seq 1 30); do
    if monedula-acl-rbac verify --plan out/plan.json --mode "$mode" --out "$out" "${MDS_AUTH[@]}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  # one last call, this time surfacing the output and exit code
  monedula-acl-rbac verify --plan out/plan.json --mode "$mode" --out "$out" "${MDS_AUTH[@]}"
}

echo "== 4a. verify --mode bindings-exist (rows present in MDS) =="
poll_verify bindings-exist out/verify-bindings.json
echo "    OK: all bindings present"

echo "== 4b. verify --mode effective (MDS really grants the source access) =="
poll_verify effective out/verify-effective.json
echo "    OK: every source ACL is EFFECTIVE_OK"

echo "== 5. delete-acls: generate the deletion script (gated on EFFECTIVE_OK) =="
del_args=(delete-acls --plan out/plan.json --verify out/verify-effective.json
  --bootstrap-server "$BROKER" --command-config client.properties
  --confirm --i-understand-this-is-destructive)
for p in "${ALLOW_PRINCIPALS[@]}"; do del_args+=(--principal "$p"); done
monedula-acl-rbac "${del_args[@]}"
echo "    generated out/delete-acls.sh (+ out/rollback.sh, out/deleted-acls.json)"
