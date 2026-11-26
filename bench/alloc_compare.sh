#!/usr/bin/env bash
# Compare the system allocator with mimalloc (the default for the `velox` binary).
#
#   bench/alloc_compare.sh [seconds-per-run] [connections] [rounds]
#
# Builds the release binary twice (separate target dirs), then alternates the two
# variants across scenarios so drift in machine load does not favour either, and
# prints requests/second plus the proxy's resident memory after each run.
# Needs `ab` (ApacheBench). Absolute numbers depend on the machine; compare the
# ratio, and remember that on loopback the kernel's socket work often dominates.
set -euo pipefail
cd "$(dirname "$0")/.."

SECS="${1:-6}"
CONNS="${2:-64}"
ROUNDS="${3:-3}"
command -v ab >/dev/null || { echo "install ab (ApacheBench)" >&2; exit 1; }

echo ">> building system-allocator and mimalloc variants (release, fat LTO)..." >&2
cargo build --release -p velox-cli --no-default-features --bin velox --target-dir target/alloc-sys >/dev/null
cargo build --release -p velox-cli --bin velox --example bench_backend --target-dir target/alloc-mi >/dev/null
BIN_SYS=target/alloc-sys/release/velox
BIN_MI=target/alloc-mi/release/velox
BACKEND=target/alloc-mi/release/examples/bench_backend

pids=()
cleanup() { for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT
"$BACKEND" 127.0.0.1:3000 2>/dev/null & pids+=($!)
"$BACKEND" 127.0.0.1:3001 2>/dev/null & pids+=($!)
sleep 0.5

run() { # <label> <binary> <path>
  local label="$1" bin="$2" path="$3"
  "$bin" start -c bench/velox.alloc.toml >/dev/null 2>&1 &
  local pid=$!
  sleep 1
  ab -k -q -c 8 -t 1 -n 100000000 "http://127.0.0.1:8080$path" >/dev/null 2>&1 || true   # warm-up
  local out rps
  out=$(ab -k -q -c "$CONNS" -t "$SECS" -n 100000000 "http://127.0.0.1:8080$path" 2>&1)
  rps=$(echo "$out" | awk '/Requests per second/ {print $4}')
  local failed; failed=$(echo "$out" | awk '/Failed requests/ {print $3}')
  local rss; rss=$(ps -o rss= -p "$pid" | tr -d ' ')
  kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true
  printf '%-10s %-12s %12s req/s   rss %7s KiB   failed %s\n' "$label" "$path" "$rps" "$rss" "$failed"
  echo "$label $path $rps $rss" >> "$RESULTS"
}

RESULTS=$(mktemp)
for path in / /big /big-cached; do
  echo "== scenario: $path (${CONNS} connections, ${SECS}s, ${ROUNDS} rounds, alternating)"
  for r in $(seq 1 "$ROUNDS"); do
    if (( r % 2 )); then run system "$BIN_SYS" "$path"; run mimalloc "$BIN_MI" "$path"
    else run mimalloc "$BIN_MI" "$path"; run system "$BIN_SYS" "$path"; fi
  done
done

echo
echo "== summary (median of ${ROUNDS})"
for path in / /big /big-cached; do
  for label in system mimalloc; do
    awk -v l="$label" -v p="$path" '$1==l && $2==p {print $3, $4}' "$RESULTS" | sort -n | awk -v l="$label" -v p="$path" '{r[NR]=$1; m[NR]=$2} END {i=int((NR+1)/2); printf "%-10s %-12s %12.0f req/s   rss %7d KiB\n", l, p, r[i], m[i]}'
  done
done
rm -f "$RESULTS"
