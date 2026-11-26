#!/usr/bin/env bash
# End-to-end throughput/latency harness.
#
#   bench/run.sh [duration-seconds] [connections]
#
# Starts two backends and Velox, then drives load with the best tool found
# (oha > wrk > ab), once directly against a backend (baseline) and once through
# Velox. Results depend heavily on the machine; compare the *ratio*.
set -euo pipefail
cd "$(dirname "$0")/.."

DURATION="${1:-10}"
CONNS="${2:-64}"

cargo build --release -p velox-cli --bin velox --example bench_backend >/dev/null
BIN=target/release

pids=()
cleanup() { for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

"$BIN/examples/bench_backend" 127.0.0.1:3000 2>/dev/null & pids+=($!)
"$BIN/examples/bench_backend" 127.0.0.1:3001 2>/dev/null & pids+=($!)
"$BIN/velox" start -c bench/velox.bench.toml >/dev/null 2>&1 & pids+=($!)
sleep 1

drive() {
  local url="$1"
  if command -v oha >/dev/null; then
    oha -z "${DURATION}s" -c "$CONNS" --no-tui "$url"
  elif command -v wrk >/dev/null; then
    wrk -t"$(( $(sysctl -n hw.ncpu 2>/dev/null || nproc) / 2 ))" -c "$CONNS" -d "${DURATION}s" --latency "$url"
  elif command -v ab >/dev/null; then
    ab -k -q -c "$CONNS" -t "$DURATION" -n 100000000 "$url" 2>&1 | grep -E "Requests per second|Time per request|Failed requests|50%|99%"
  else
    echo "install oha, wrk or ab to run the load test" >&2; exit 1
  fi
}

echo "=== baseline: client -> backend (no proxy)"
drive http://127.0.0.1:3000/
echo
echo "=== client -> Velox (least_conn, 2 backends)"
drive http://127.0.0.1:8080/
