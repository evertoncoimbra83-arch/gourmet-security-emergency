#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/auth-common.sh"

fail() { echo "AUTH_ROTATION_EXECUTE=FAIL"; exit 1; }
[ "$#" -eq 4 ] || fail
INCIDENT_ID="$1"
ENVIRONMENT="$2"
TARGET_SECRET="$3"
EXECUTE_FLAG="$4"
if ! [[ "$INCIDENT_ID" =~ ^GSE-[0-9]{8}T[0-9]{6}Z$ ]]; then echo "incident_id_validation=FAIL"; fail; fi
if [ "$ENVIRONMENT" = production ]; then echo "PRODUCTION_EXECUTION=BLOCKED"; fail; fi
[ "$ENVIRONMENT" = staging ] || fail
case "$TARGET_SECRET" in SESSION_SECRET|JWT_SECRET|NEXTAUTH_SECRET) ;; *) echo "SECRET_INVALID=FAIL"; fail;; esac
if [ "$EXECUTE_FLAG" != --execute ]; then echo "EXECUTE_FLAG_REQUIRED=FAIL"; fail; fi

# All gates below precede the first filesystem mutation.
[ -d "$SITE_DIR" ] && [ -f "$SITE_ENV" ] || fail
for tool in python3 node pm2; do command -v "$tool" >/dev/null 2>&1 || fail; done
env -C "$SITE_DIR" node -e "require.resolve('dotenv')" >/dev/null 2>&1 || fail
site_pid_before="$(pm2_pid "$SITE_PROCESS" || true)"
worker_pid_before="$(pm2_pid "$WORKER_PROCESS" || true)"
[ -n "$site_pid_before" ] && [ -n "$worker_pid_before" ] || fail
bash "$SCRIPT_DIR/auth-preflight.sh" staging || fail
python3 "$SCRIPT_DIR/auth-env.py" check "$SITE_ENV" "$TARGET_SECRET" || fail
old_hash="$(dotenv_key_hash "$TARGET_SECRET")" || fail
[ -n "$old_hash" ] || fail
BACKUP_DIR="/home/gsadmin/backups/gse/${INCIDENT_ID}/auth/${TARGET_SECRET}"
BACKUP_SITE_ENV="$BACKUP_DIR/.env.staging"
original_mode="$(stat -c '%a' "$SITE_ENV")" || fail
if [ -e "$BACKUP_DIR" ]; then echo "backup_already_exists=FAIL"; fail; fi

MUTATION_STARTED=0
finished=0
rollback_mutation() {
  local status=$?
  trap - EXIT
  [ "$finished" -eq 0 ] || return 0
  echo "FAILURE_DETECTED=YES"
  if [ "$MUTATION_STARTED" -eq 1 ]; then
    echo "ROLLBACK_STARTED=YES"
    local ok=1 restored_hash="" restored_pid="" worker_now="" proc_hash=""
    if cp -p "$BACKUP_SITE_ENV" "$SITE_ENV" && chmod "$original_mode" "$SITE_ENV"; then echo "ROLLBACK_SITE_ENV=PASS"; else echo "ROLLBACK_SITE_ENV=FAIL"; ok=0; fi
    if restart_site_api; then echo "ROLLBACK_SITE_PROCESS=PASS"; else echo "ROLLBACK_SITE_PROCESS=FAIL"; ok=0; fi
    restored_hash="$(dotenv_key_hash "$TARGET_SECRET" || true)"
    restored_pid="$(pm2_pid "$SITE_PROCESS" || true)"
    if [ -n "$restored_pid" ]; then proc_hash="$(process_env_key_hash "$restored_pid" "$TARGET_SECRET" || true)"; fi
    if [ "$restored_hash" = "$old_hash" ] && [ "$proc_hash" = "$old_hash" ]; then echo "ROLLBACK_OLD_HASH_RESTORED=PASS"; else echo "ROLLBACK_OLD_HASH_RESTORED=FAIL"; ok=0; fi
    worker_now="$(pm2_pid "$WORKER_PROCESS" || true)"
    if [ "$worker_now" = "$worker_pid_before" ]; then echo "ROLLBACK_WORKER_UNTOUCHED=PASS"; else echo "ROLLBACK_WORKER_UNTOUCHED=FAIL"; ok=0; fi
    if [ "$ok" -eq 1 ]; then echo "ROLLBACK_FINISHED=PASS"; else echo "ROLLBACK_FINISHED=FAIL"; fi
  fi
  echo "AUTH_ROTATION_EXECUTE=FAIL"
  [ "$status" -ne 0 ] || status=1
  exit "$status"
}
trap rollback_mutation EXIT

mkdir -p -m 700 "$(dirname "$BACKUP_DIR")"
mkdir -m 700 "$BACKUP_DIR"
cp -p "$SITE_ENV" "$BACKUP_SITE_ENV"
chmod 600 "$BACKUP_SITE_ENV"
original_file_hash="$(sha256sum "$SITE_ENV" | awk '{print $1}')"
backup_file_hash="$(sha256sum "$BACKUP_SITE_ENV" | awk '{print $1}')"
[ "$original_file_hash" = "$backup_file_hash" ] || exit 1
echo "backup_directory=$BACKUP_DIR"
echo "backup_site_env=PASS"
echo "rollback_ready=PASS"

MUTATION_STARTED=1
new_hash="$(python3 "$SCRIPT_DIR/auth-env.py" update "$SITE_ENV" "$TARGET_SECRET")" || exit 1
[[ "$new_hash" =~ ^[0-9a-f]{64}$ ]] && [ "$new_hash" != "$old_hash" ] || exit 1
[ "$(dotenv_key_hash "$TARGET_SECRET")" = "$new_hash" ] || exit 1
restart_site_api || exit 1
site_pid_after="$(pm2_pid "$SITE_PROCESS" || true)"
worker_pid_after="$(pm2_pid "$WORKER_PROCESS" || true)"
[ -n "$site_pid_after" ] && [ "$site_pid_after" != "$site_pid_before" ] || exit 1
[ "$worker_pid_after" = "$worker_pid_before" ] || exit 1
[ "$(process_env_key_hash "$site_pid_after" "$TARGET_SECRET")" = "$new_hash" ] || exit 1
echo "site_env_parity=PASS"
echo "site_process_parity=PASS"
echo "worker_untouched=PASS"
echo "SITE_HTTP_HEALTH=NOT_CONFIGURED"
echo "DATABASE_TOUCHED=NO"
echo "PM2_SAVE_RUN=NO"
if [ "$TARGET_SECRET" = JWT_SECRET ]; then echo "EXPECTED_TOKEN_INVALIDATION=YES"; else echo "EXPECTED_SESSION_INVALIDATION=YES"; fi
echo "AUTH_SECRET_ROTATION=PASS"
echo "secret=$TARGET_SECRET"
echo "environment=staging"
echo "OLD_HASH=$old_hash"
echo "NEW_HASH=$new_hash"
echo "AUTH_ROTATION_EXECUTE=PASS"
finished=1
trap - EXIT
