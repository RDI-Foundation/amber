#!/bin/sh
# Minimal repro: component with an external HTTP slot tries to resolve
# an external hostname.  On Docker Desktop (macOS/Windows) this succeeds
# because the VM forwards DNS for all containers.  On native Linux Docker
# the sidecar is only on amber_mesh, which has no external DNS, so
# nslookup fails with "Temporary failure in name resolution".
#
# Expected: DNS resolution should work when a component declares an
# external HTTP slot, even without `amber proxy --slot` binding.

set -eu

HOST="openrouter.ai"
PASS=0
FAIL=0

while true; do
  if nslookup "$HOST" >/dev/null 2>&1; then
    PASS=$((PASS + 1))
    echo "OK  nslookup $HOST (pass=$PASS fail=$FAIL)"
  else
    FAIL=$((FAIL + 1))
    echo "FAIL nslookup $HOST (pass=$PASS fail=$FAIL)"
  fi
  sleep 5
done
