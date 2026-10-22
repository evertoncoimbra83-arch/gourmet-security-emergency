#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/redis-common.sh"

if [ "$#" -ne 1 ]; then
  echo "REDIS_PREFLIGHT=FAIL"
  exit 1
fi
if [ "$1" = production ]; then
  echo "PRODUCTION_PREFLIGHT=BLOCKED"
  echo "REDIS_PREFLIGHT=FAIL"
  exit 1
fi
if [ "$1" != staging ]; then
  echo "REDIS_PREFLIGHT=FAIL"
  exit 1
fi
redis_run_readonly
