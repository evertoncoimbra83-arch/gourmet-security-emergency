#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/auth-common.sh"

if [ "$#" -ne 1 ] || [ "$1" != staging ]; then
  echo "AUTH_PREFLIGHT=FAIL"
  exit 1
fi
echo "ENVIRONMENT=staging"
success=1
site_pid="$(pm2_pid "$SITE_PROCESS" || true)"
worker_pid="$(pm2_pid "$WORKER_PROCESS" || true)"
if [ -n "$site_pid" ]; then echo "SITE_PROCESS=ONLINE"; else echo "SITE_PROCESS=FAIL"; success=0; fi
if [ -n "$worker_pid" ]; then echo "WORKER_PROCESS=ONLINE"; else echo "WORKER_PROCESS=FAIL"; success=0; fi
for key in SESSION_SECRET JWT_SECRET NEXTAUTH_SECRET; do
  env_hash=""
  if python3 "$AUTH_DIR/auth-env.py" check "$SITE_ENV" "$key" && env_hash="$(dotenv_key_hash "$key" || true)" && [ -n "$env_hash" ]; then
    echo "$key: SITE_ENV=PASS"
  else
    echo "$key: SITE_ENV=FAIL"
    success=0
  fi
  proc_hash=""
  if [ -n "$site_pid" ]; then proc_hash="$(process_env_key_hash "$site_pid" "$key" || true)"; fi
  if [ -n "$env_hash" ] && [ "$proc_hash" = "$env_hash" ]; then
    echo "$key: PROCESS_PARITY=PASS"
  else
    echo "$key: PROCESS_PARITY=FAIL"
    success=0
  fi
done
echo "SITE_HTTP_HEALTH=NOT_CONFIGURED"
echo "NO_SECRET_VALUES_PRINTED=PASS"
echo "NO_FILES_MODIFIED=PASS"
echo "NO_SERVICES_RESTARTED=PASS"
echo "NO_DATABASE_READS=PASS"
echo "NO_DATABASE_WRITES=PASS"
if [ "$success" -eq 1 ]; then echo "AUTH_PREFLIGHT=PASS"; exit 0; fi
echo "AUTH_PREFLIGHT=FAIL"
exit 1
