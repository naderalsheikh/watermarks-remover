#!/usr/bin/env bash
set -uo pipefail

# Validate the default CounselClear compose stack. Minimal output; exit code
# only:
#   0 = every default-stack service passes, 1 = any service fails.
#
#   cc-api -> HTTP /health/ready must answer
#
# Research harnesses and the upstream wr-core utility are intentionally not
# part of this default check. They remain explicit opt-in surfaces.

BASE_URL="${COUNSELCLEAR_BASE_URL:-http://127.0.0.1:8443}"
FAIL=0

if curl -fsS "$BASE_URL/health/ready" >/dev/null 2>&1; then
  echo "cc-api: OK"
else
  echo "cc-api: FAIL (no /health/ready at $BASE_URL)"
  FAIL=1
fi

exit "$FAIL"
