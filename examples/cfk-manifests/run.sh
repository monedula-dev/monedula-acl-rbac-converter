#!/usr/bin/env bash
# cfk-manifests: convert CFK (Confluent for Kubernetes) manifests on disk.
# The Kafka CR's superUsers become cluster-wide ALL ACLs (-> SystemAdmin), and
# any existing ConfluentRolebinding CRs are read into existing-bindings.json so
# `plan` marks already-present bindings as SKIP instead of CREATE.
#
#   ./run.sh           extract -> plan -> emit, writing artifacts into out/
#   ./run.sh --check   also diff out/ against the committed expected/ goldens
#
# With Docker only (no Go toolchain installed):
#   docker compose run --rm converter ./run.sh --check
set -euo pipefail
cd "$(dirname "$0")"
export EXAMPLE_DIR="$PWD"
. ../lib/common.sh

mkdir -p out
echo "==> extract --from cfk (writes out/acls.json + out/existing-bindings.json)"
conv extract --from cfk --input manifests/ --out out/acls.json
echo "==> plan (reads the existing-bindings sidecar next to acls.json)"
conv plan --acls out/acls.json --scopes scopes.yaml --out out/plan.json
echo "==> emit --format cfk (ConfluentRolebinding CRs for the new bindings)"
conv emit --plan out/plan.json --format cfk --out-dir out --cfk-namespace confluent

echo; cat out/report.txt

if [ "${1:-}" = "--check" ]; then
  echo; echo "==> checking out/ against committed goldens"
  rc=0
  check_file acls.json             || rc=1
  check_file existing-bindings.json || rc=1
  check_file plan.json             || rc=1
  check_file report.txt            || rc=1
  check_file cfk.yaml              || rc=1
  if [ $rc -eq 0 ]; then echo "ALL GOLDENS MATCH"; else echo "GOLDEN DRIFT" >&2; exit 1; fi
fi
