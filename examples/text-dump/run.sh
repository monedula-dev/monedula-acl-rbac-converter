#!/usr/bin/env bash
# text-dump: convert a `kafka-acls.sh --list` text export into RBAC.
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
echo "==> extract --from text"
conv extract --from text --input acls.txt --out out/acls.json
echo "==> plan (--allow-rejected: the DENY becomes a rejected entry)"
conv plan --acls out/acls.json --scopes scopes.yaml --out out/plan.json --allow-rejected
echo "==> emit --format script"
conv emit --plan out/plan.json --format script --out-dir out

echo; cat out/report.txt

if [ "${1:-}" = "--check" ]; then
  echo; echo "==> checking out/ against committed goldens"
  rc=0
  check_file acls.json  || rc=1
  check_file plan.json  || rc=1
  check_file report.txt || rc=1
  check_file script.sh  || rc=1
  if [ $rc -eq 0 ]; then echo "ALL GOLDENS MATCH"; else echo "GOLDEN DRIFT" >&2; exit 1; fi
fi
