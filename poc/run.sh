#!/usr/bin/env bash
# Validate the policies, prove the broken policy is rejected, replay every trace
# against its expected verdicts, then run the Rust SDK demo.
#   DOGWOOD_BIN=/path/to/dogwood   use an existing CLI binary
#   DOGWOOD_SRC=/path/to/checkout  use an existing Dogwood checkout (built if needed)
#   SKIP_RUST_DEMO=1               skip the rust-demo step
set -uo pipefail
cd "$(dirname "$0")"
POC=$PWD
REV=996d756de1013b7ae209a14f566a80375a59f2f0   # keep in sync with rust-demo/Cargo.toml
SCHEMA=schema/gateway.cedarschema
POLICY=policies/gateway.dw

if [ -z "${DOGWOOD_BIN:-}" ]; then
  SRC=${DOGWOOD_SRC:-$POC/.dogwood-src}
  if [ ! -d "$SRC/.git" ]; then
    echo ">> cloning dogwood-policy/dogwood @ ${REV:0:8} into $SRC"
    git clone -q https://github.com/dogwood-policy/dogwood "$SRC" && git -C "$SRC" checkout -q "$REV" || exit 1
  fi
  echo ">> building dogwood CLI (cached after first run)"
  (cd "$SRC" && cargo build -q -p dogwood-cli) || exit 1
  DOGWOOD_BIN=$SRC/target/debug/dogwood
fi

fail=0
bad() { echo "FAIL: $*"; fail=1; }

echo; echo "== validate $POLICY"
"$DOGWOOD_BIN" validate "$POLICY" --policy-schema "$SCHEMA" || bad "good policy rejected"

echo; echo "== validate negative/*.dw (each must be rejected with exit 2)"
for n in negative/*.dw; do
  "$DOGWOOD_BIN" validate "$n" --policy-schema "$SCHEMA"; rc=$?
  if [ "$rc" -eq 2 ]; then echo "ok: $n rejected as expected"; else bad "$n exited $rc, expected 2"; fi
done

echo; echo "== replay traces"
printf '%-24s %-7s %-14s %-6s %-6s %s\n' TRACE TIME EVENT GOT WANT RESULT
for t in traces/*.log; do
  name=$(basename "$t" .log)
  got=$("$DOGWOOD_BIN" replay "$POLICY" --policy-schema "$SCHEMA" --trace "$t") || bad "$name: replay failed"
  # Decision points = the trace's `::request(` lines, in order.
  mapfile -t evs < <(grep '::request(' "$t" | sed -E 's/^@([0-9]+) .*Action::"([A-Za-z]+)"::request.*sensitivity: "([a-z]+)".*/\1 \2(\3)/; t; s/^@([0-9]+) .*Action::"([A-Za-z]+)"::request.*/\1 \2/')
  mapfile -t g < <(printf '%s\n' "$got")
  mapfile -t w < <(cat "traces/$name.expected")
  for i in "${!w[@]}"; do
    gd=$(sed -E 's/.*: (ALLOW|DENY).*/\1/' <<<"${g[$i]:-?}")
    wd=$(sed -E 's/.*: (ALLOW|DENY).*/\1/' <<<"${w[$i]}")
    res=ok; [ "${g[$i]:-}" = "${w[$i]}" ] || res=MISMATCH
    read -r tm ev <<<"${evs[$i]:-? ?}"
    printf '%-24s %-7s %-14s %-6s %-6s %s\n' "$name" "@$tm" "$ev" "$gd" "$wd" "$res"
  done
  if [ "$got" != "$(cat "traces/$name.expected")" ]; then
    bad "$name: verdicts differ from expected"; diff <(echo "$got") "traces/$name.expected"
  fi
done

if [ -z "${SKIP_RUST_DEMO:-}" ]; then
  echo; echo "== rust-demo"
  (cd rust-demo && cargo run -q) || bad "rust-demo failed"
fi

echo
if [ "$fail" -eq 0 ]; then echo "ALL CHECKS PASSED"; else echo "SOME CHECKS FAILED"; fi
exit "$fail"
