# Shared helpers for the file-based examples. Source it from an example's
# run.sh:  . "$(dirname "$0")/../lib/common.sh"
#
# It resolves a `monedula-acl-rbac` binary to run as `conv ...`, and provides
# golden-comparison helpers that normalise the only volatile field the tool
# emits (the plan/report `generated_at` timestamp) before diffing.
#
# Binary resolution order:
#   1. $CONVERTER_BIN, if set and executable
#   2. `monedula-acl-rbac` on PATH   (this is the case inside the converter image)
#   3. <repo>/bin/monedula-acl-rbac[.exe]
#   4. `go build` into <repo>/bin     (if Go is installed)
# If none work, it prints how to get one (including the docker-compose path).

set -euo pipefail

# repo_root walks up from the example directory until it finds go.mod.
repo_root() {
  local d="${EXAMPLE_DIR:-$PWD}"
  while [ "$d" != "/" ] && [ -n "$d" ]; do
    if [ -f "$d/go.mod" ]; then printf '%s\n' "$d"; return 0; fi
    d="$(dirname "$d")"
  done
  return 1
}

_resolve_conv() {
  if [ -n "${CONVERTER_BIN:-}" ] && [ -x "${CONVERTER_BIN}" ]; then
    CONV="${CONVERTER_BIN}"; return 0
  fi
  if command -v monedula-acl-rbac >/dev/null 2>&1; then
    CONV="monedula-acl-rbac"; return 0
  fi
  local root; root="$(repo_root || true)"
  if [ -n "$root" ]; then
    for c in "$root/bin/monedula-acl-rbac" "$root/bin/monedula-acl-rbac.exe"; do
      if [ -x "$c" ]; then CONV="$c"; return 0; fi
    done
    if command -v go >/dev/null 2>&1; then
      echo "common.sh: building monedula-acl-rbac (one-time)..." >&2
      ( cd "$root" && go build -o "bin/monedula-acl-rbac" ./cmd/monedula-acl-rbac )
      CONV="$root/bin/monedula-acl-rbac"; return 0
    fi
  fi
  cat >&2 <<'MSG'
common.sh: could not find or build the monedula-acl-rbac binary.

Options:
  * Build it:        make build          (then re-run ./run.sh)
  * Set the path:    CONVERTER_BIN=/path/to/monedula-acl-rbac ./run.sh
  * Use Docker:      docker compose run --rm converter ./run.sh --check
MSG
  return 1
}

_resolve_conv
conv() { "$CONV" "$@"; }

# normalize copies a plan.json / report.txt / acls.json to stdout with the
# volatile fields replaced by fixed tokens, so committed goldens stay diffable.
# Volatile fields: the extract/plan `generated_at` timestamp (stamped at run
# time for non-json/yaml sources) and `acls_sha256` (a hash over the timestamped
# acls.json, so it moves with the timestamp).
normalize() {
  sed -E \
    -e 's/"generated_at": "[^"]*"/"generated_at": "<NORMALIZED>"/' \
    -e 's/"acls_sha256": "[0-9a-f]*"/"acls_sha256": "<NORMALIZED>"/' \
    -e 's/^Plan generated at .*/Plan generated at <NORMALIZED>/' \
    "$1"
}

# check_file compares a freshly produced file in out/ against expected/, after
# normalisation. Returns non-zero (and prints a unified diff) on drift.
check_file() {
  local rel="$1"
  local got="out/$rel" want="expected/$rel"
  if [ ! -f "$want" ]; then echo "MISSING golden: $want" >&2; return 1; fi
  if [ ! -f "$got" ];  then echo "MISSING output: $got"  >&2; return 1; fi
  if diff -u <(normalize "$want") <(normalize "$got"); then
    echo "  ok: $rel"
  else
    echo "  DRIFT: $rel (actual differs from committed golden)" >&2
    return 1
  fi
}
