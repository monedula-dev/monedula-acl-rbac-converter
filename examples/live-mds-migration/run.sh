#!/usr/bin/env bash
# End-to-end live migration against a real Confluent MDS stack, all in Docker.
#
#   ./run.sh           bring up the stack, seed source ACLs, run the full
#                      extract -> plan -> apply -> verify -> delete pipeline,
#                      and assert the outcome. Leaves the stack running.
#   ./run.sh --down    additionally tear the stack down at the end.
#
# Requires Docker + the compose plugin. First run pulls cp-server (~1GB) and
# builds the converter image, so allow a few minutes.
set -euo pipefail
cd "$(dirname "$0")"

down=0
[ "${1:-}" = "--down" ] && down=1
cleanup() {
  if [ "$down" = "1" ]; then
    echo "== tearing down =="
    docker compose down -v
  fi
}
trap cleanup EXIT

echo "== bringing up openldap + cp-server (MDS/RBAC) =="
docker compose up -d openldap kafka

echo "== waiting for MDS to report healthy (first run pulls the image) =="
for i in $(seq 1 90); do
  h="$(docker compose ps kafka --format '{{.Health}}' 2>/dev/null || true)"
  [ "$h" = "healthy" ] && break
  [ "$h" = "unhealthy" ] && { echo "kafka became unhealthy; logs:"; docker compose logs --tail=60 kafka; exit 1; }
  sleep 5
done
[ "$h" = "healthy" ] || { echo "MDS did not become healthy in time"; docker compose logs --tail=80 kafka; exit 1; }
echo "   MDS is up."

echo "== seeding the legacy source ACLs on the broker =="
bash seed-acls.sh

echo "== running the migration pipeline in the converter container =="
docker compose run --rm converter ./pipeline.sh

echo
echo "== executing the generated delete-acls.sh inside the broker container =="
# The script was generated for the converter's filesystem (paths under /work).
# Re-point command-config and the log path for the broker container, and skip
# the plan-hash integrity check (plan.json isn't mounted in the broker).
delete_script="$(sed -E \
  -e 's#client\.properties#/tmp/admin.properties#g' \
  -e 's#^LOG=.*#LOG=/tmp/delete.log#' \
  out/delete-acls.sh)"
printf '%s' "$delete_script" | docker compose exec -T -e MONEDULA_SKIP_PLAN_HASH_CHECK=1 kafka bash -s

echo
echo "== asserting the migration result on the broker =="
# Query via stdin (heredoc) rather than passing /tmp/... as a docker argument:
# on Git Bash for Windows, MSYS rewrites a leading-slash arg into a Windows path.
remaining="$(docker compose exec -T kafka bash -s <<'LIST'
kafka-acls --bootstrap-server kafka:9094 --command-config /tmp/admin.properties --list 2>/dev/null
LIST
)"

fail=0
for p in svc-orders-consumer svc-payments-producer svc-analytics svc-fulfillment svc-orders-relay; do
  if printf '%s' "$remaining" | grep -q "User:$p"; then
    echo "  FAIL: source ACLs for User:$p should be deleted but remain"; fail=1
  else
    echo "  ok: User:$p source ACLs removed"
  fi
done
if printf '%s' "$remaining" | grep -q "User:legacy-importer"; then
  echo "  ok: the DENY for User:legacy-importer survived (never touched by delete-acls)"
else
  echo "  FAIL: the DENY for User:legacy-importer should have survived"; fail=1
fi

echo
if [ "$fail" = "0" ]; then
  echo "RESULT: migration verified end to end -- ACLs converted to RBAC, effective"
  echo "access confirmed in MDS, and the converted source ACLs cleaned up."
else
  echo "RESULT: assertions FAILED (see above)"; exit 1
fi

echo
echo "Artifacts are in ./out/ (acls.json, plan.json, report.txt, verify-*.json,"
echo "delete-acls.sh, rollback.sh). The stack is still running; re-run with"
echo "'./run.sh --down' or 'docker compose down -v' to stop it."
