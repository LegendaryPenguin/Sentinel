#!/usr/bin/env bash
#
# End-to-end demonstration: build, serve, append, audit, and then catch a
# tampered log.
#
# The last step is the one worth watching. Everything before it shows the
# happy path, which only proves the auditor accepts honest answers. Step 6
# rewrites a byte inside the log file and shows the server refusing to start
# — the log declining to serve a history it cannot vouch for.

set -euo pipefail

cd "$(dirname "$0")/.."
ROOT=$(pwd)
WORK=$(mktemp -d)
trap 'kill "${SERVER_PID:-}" 2>/dev/null || true; rm -rf "$WORK"' EXIT

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

say "1. Build the Rust core and the Go binaries"
(cd sentinel-core && cargo build --release --quiet)
(cd go && go build -o "$WORK/sentinel-server" ./cmd/sentinel-server)
# The auditor builds with cgo disabled on purpose: it must be a binary you can
# hand to someone who does not run the log.
(cd go && CGO_ENABLED=0 go build -o "$WORK/sentinel-verify" ./cmd/sentinel-verify)
echo "   sentinel-verify is $(du -h "$WORK/sentinel-verify" | cut -f1), statically linked, no Rust"

say "2. Start the server on a fresh log"
LOG="$WORK/demo.log"
"$WORK/sentinel-server" -addr 127.0.0.1:8099 -log "$LOG" >"$WORK/server.out" 2>&1 &
SERVER_PID=$!
for _ in $(seq 50); do
    curl -sf http://127.0.0.1:8099/health >/dev/null 2>&1 && break
    sleep 0.1
done
curl -sf http://127.0.0.1:8099/health >/dev/null || { cat "$WORK/server.out"; exit 1; }

say "3. Record the empty root, then append 25 entries"
EMPTY=$("$WORK/sentinel-verify" root -server http://127.0.0.1:8099 | awk '/^root/ {print $2}')
echo "   root at size 0: $EMPTY"
for i in $(seq 1 25); do
    "$WORK/sentinel-verify" append -server http://127.0.0.1:8099 -data "record-$i" >/dev/null
done
"$WORK/sentinel-verify" root -server http://127.0.0.1:8099

say "4. Audit every entry independently"
"$WORK/sentinel-verify" audit -server http://127.0.0.1:8099

say "5. Monitor: prove the log still extends the root we saved in step 3"
"$WORK/sentinel-verify" monitor -server http://127.0.0.1:8099 -size 0 -root "$EMPTY"

say "6. Tamper with the log file and restart"
kill "$SERVER_PID"; wait "$SERVER_PID" 2>/dev/null || true
# Flip one bit a third of the way into the file: inside an early record's
# payload, where the framing still parses and only the CRC objects.
python3 - "$LOG" <<'PY'
import sys
p = sys.argv[1]
b = bytearray(open(p, 'rb').read())
i = len(b) // 3
b[i] ^= 0x40
open(p, 'wb').write(b)
print(f"   flipped bit 6 of byte {i} of {len(b)}")
PY
if "$WORK/sentinel-server" -addr 127.0.0.1:8099 -log "$LOG" >"$WORK/tampered.out" 2>&1; then
    echo "   FAIL: the server started on a tampered log"
    exit 1
fi
echo "   the server refused to start:"
sed 's/^/   | /' "$WORK/tampered.out"

say "Done"
echo "A tampered entry is not a degraded read — it is a refusal to serve."
