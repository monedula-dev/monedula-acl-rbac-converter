#!/usr/bin/env bash
# structured-dump: convert a canonical acls.{yaml,json} dump into RBAC.
# Both files describe the same ACL set and use the same jsonyaml adapter; this
# script proves they extract to identical ACL rows (only the recorded
# source.type differs: "yaml" vs "json").
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
echo "==> extract --from yaml"
conv extract --from yaml --input acls.yaml --out out/acls.json
echo "==> extract --from json (same rows; only source.type differs)"
conv extract --from json --input acls.json --out out/acls-from-json.json
# Ignore the source.type field ("yaml" vs "json"); compare the ACL rows.
nosrc() { sed -E 's/"type": "(yaml|json)"/"type": "<src>"/' "$1"; }
if diff -q <(nosrc out/acls.json) <(nosrc out/acls-from-json.json) >/dev/null; then
  echo "  ok: yaml and json inputs produced identical ACL rows"
else
  echo "  ERROR: yaml and json extracts differ beyond source.type" >&2; exit 1
fi
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
