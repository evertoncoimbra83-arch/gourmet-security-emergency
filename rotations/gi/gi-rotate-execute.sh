#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# GSE-02C: GI Rotation Executor (STAGING-ONLY)
# ==============================================================================
# RISK: HIGH
# Mandatory: --execute flag
# Production is strictly BLOCKED.
# Worker is NEVER restarted.
# Process state persistence is NEVER executed.
# Secrets are NEVER printed.
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=rotations/gi/gi-common.sh
source "${SCRIPT_DIR}/gi-common.sh"

echo "========================================"
echo "GSE GI ROTATION EXECUTOR"
echo "MODE=EXECUTE"
echo "RISK=HIGH"
echo "========================================"
echo

# ------------------------------------------------------------------------------
# 1. Argument Parsing & Safety Gates
# ------------------------------------------------------------------------------
if [ "$#" -ne 4 ]; then
  echo "Usage: $0 <incident-id> <environment> <token> --execute"
  echo "GI_ROTATION_EXECUTE=FAIL"
  exit 1
fi

INCIDENT_ID="$1"
ENVIRONMENT="$2"
TARGET_TOKEN="$3"
EXECUTE_FLAG="$4"

# Validate INCIDENT_ID regex
if ! [[ "$INCIDENT_ID" =~ ^GSE-[0-9]{8}T[0-9]{6}Z$ ]]; then
  echo "incident_id_validation=FAIL"
  echo "GI_ROTATION_EXECUTE=FAIL"
  exit 1
fi

# Hard block production
if [ "$ENVIRONMENT" = "production" ]; then
  echo "PRODUCTION_EXECUTION=BLOCKED"
  echo "GI_ROTATION_EXECUTE=FAIL"
  exit 1
fi

if [ "$ENVIRONMENT" != "staging" ]; then
  echo "ENVIRONMENT_INVALID=FAIL"
  echo "GI_ROTATION_EXECUTE=FAIL"
  exit 1
fi

# Validate Token
case "$TARGET_TOKEN" in
  GI_ATTENTION_READ_TOKEN|GI_RECOMMENDATION_READ_TOKEN|GI_PROPOSAL_READ_TOKEN|GI_SITE_PRE_PREPARE_TOKEN)
    ;;
  *)
    echo "TOKEN_INVALID=FAIL"
    echo "GI_ROTATION_EXECUTE=FAIL"
    exit 1
    ;;
esac

# Validate --execute flag
if [ "$EXECUTE_FLAG" != "--execute" ]; then
  echo "EXECUTE_FLAG_REQUIRED=FAIL"
  echo "GI_ROTATION_EXECUTE=FAIL"
  exit 1
fi

echo "incident_id=${INCIDENT_ID}"
echo "environment=${ENVIRONMENT}"
echo "token=${TARGET_TOKEN}"
echo

# ------------------------------------------------------------------------------
# 2. Environment & Token Configuration
# ------------------------------------------------------------------------------
SITE_DIR="/var/www/gourmet-staging"
SITE_ENV="/home/gsadmin/secure-env/.env.staging"
SITE_PROCESS="gourmet-novo-staging"
WORKER_PROCESS="gourmet-worker-staging"
SECRET_BASE="/home/gsadmin/secure-env/gourmet-intelligence-staging"

REQUIRED_IN_SITE_ENV="no"
MOUNT_PATH=""
SECRET_FILENAME=""

case "$TARGET_TOKEN" in
  "GI_ATTENTION_READ_TOKEN")
    SECRET_FILENAME="attention-read-token.secret"
    REQUIRED_IN_SITE_ENV="yes"
    MOUNT_PATH="/run/secrets/gi_attention_read_token"
    CONTAINERS=(
      "gi_staging_http"
      "gi_staging_http_03c_shadow"
      "gi_staging_http_03c_f3b3b2_shadow"
    )
    ;;
  "GI_RECOMMENDATION_READ_TOKEN")
    SECRET_FILENAME="recommendation-read-token.secret"
    REQUIRED_IN_SITE_ENV="yes"
    MOUNT_PATH="/run/secrets/gi_recommendation_read_token"
    CONTAINERS=(
      "gi_staging_http"
      "gi_staging_http_03c_shadow"
      "gi_staging_http_03c_f3b3b2_shadow"
    )
    ;;
  "GI_PROPOSAL_READ_TOKEN")
    SECRET_FILENAME="proposal-read-token.secret"
    REQUIRED_IN_SITE_ENV="yes"
    MOUNT_PATH="/run/secrets/gi_proposal_read_token"
    CONTAINERS=(
      "gi_staging_http"
      "gi_staging_http_03c_shadow"
      "gi_staging_http_03c_f3b3b2_shadow"
    )
    ;;
  "GI_SITE_PRE_PREPARE_TOKEN")
    SECRET_FILENAME="site-pre-prepare-token.secret"
    REQUIRED_IN_SITE_ENV="no"
    MOUNT_PATH="/run/secrets/gi_site_pre_prepare_token"
    CONTAINERS=(
      "gi_staging_http_03c_f3b3b2_shadow"
    )
    ;;
esac

SECRET_FILE="${SECRET_BASE}/${SECRET_FILENAME}"

# ------------------------------------------------------------------------------
# 3. Shared Helpers
# ------------------------------------------------------------------------------
restart_site_api() {
  local target_site_dir="$1"
  local target_site_env="$2"
  local target_site_proc="$3"

  if [ ! -d "$target_site_dir" ] || [ ! -f "$target_site_env" ]; then
    return 1
  fi

  env -C "$target_site_dir" node -e '
    const fs = require("fs");
    const { spawnSync } = require("child_process");
    const dotenv = require("dotenv");

    const envFile = process.argv[1];
    const procName = process.argv[2];

    const envConfig = dotenv.parse(fs.readFileSync(envFile));
    const env = { ...process.env, ...envConfig };

    const res = spawnSync("pm2", ["restart", procName, "--update-env"], {
      cwd: process.cwd(),
      env: env,
      stdio: "ignore"
    });
    process.exit(res.status || 0);
  ' "$target_site_env" "$target_site_proc"
}

# ------------------------------------------------------------------------------
# 4. Tool & Dependency Verification (Pre-check)
# ------------------------------------------------------------------------------
echo "=== TOOL & DEPENDENCY VERIFICATION ==="
for tool in python3 node pm2 docker; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "tool_${tool}=ABSENT"
    echo "GI_ROTATION_EXECUTE=FAIL"
    exit 1
  fi
  echo "tool_${tool}=AVAILABLE"
done

if [ "$REQUIRED_IN_SITE_ENV" = "yes" ]; then
  if [ ! -d "$SITE_DIR" ]; then
    echo "site_directory=ABSENT"
    echo "SITE_RESTART_DEPENDENCY=FAIL"
    echo "GI_ROTATION_EXECUTE=FAIL"
    exit 1
  fi

  if [ ! -f "$SITE_ENV" ]; then
    echo "site_env=ABSENT"
    echo "SITE_RESTART_DEPENDENCY=FAIL"
    echo "GI_ROTATION_EXECUTE=FAIL"
    exit 1
  fi

  # Validate dotenv dependency resolution directly inside SITE_DIR without printing path
  if env -C "$SITE_DIR" node -e "require.resolve('dotenv')" >/dev/null 2>&1; then
    echo "site_restart_dotenv_dependency=PASS"
  else
    echo "site_restart_dotenv_dependency=FAIL"
    echo "SITE_RESTART_DEPENDENCY=FAIL"
    echo "GI_ROTATION_EXECUTE=FAIL"
    exit 1
  fi
fi
echo

# ------------------------------------------------------------------------------
# 5. Precheck & Initial Parity Validation
# ------------------------------------------------------------------------------
echo "=== INITIAL PRECHECK ==="

if [ ! -f "$SECRET_FILE" ]; then
  echo "secret_file=ABSENT"
  echo "GI_ROTATION_EXECUTE=FAIL"
  exit 1
fi

sec_mode="$(file_mode "$SECRET_FILE")"
if [ "$sec_mode" != "600" ]; then
  echo "secret_file_mode=FAIL (${sec_mode})"
  echo "GI_ROTATION_EXECUTE=FAIL"
  exit 1
fi
echo "secret_file_presence=PASS"

if [ "$REQUIRED_IN_SITE_ENV" = "yes" ]; then
  echo "site_env_presence=PASS"

  # Reject duplicate keys in SITE_ENV before mutation
  key_count="$(grep -E "^[[:space:]]*(export[[:space:]]+)?${TARGET_TOKEN}=" "$SITE_ENV" 2>/dev/null | wc -l || true)"
  if [ "$key_count" -gt 1 ]; then
    echo "duplicate_key_in_site_env=FAIL (count=${key_count})"
    echo "GI_ROTATION_EXECUTE=FAIL"
    exit 1
  fi
fi

site_pid_before="$(pm2_pid "$SITE_PROCESS" || true)"
if [ -z "$site_pid_before" ]; then
  echo "site_process=NOT_RUNNING"
  echo "GI_ROTATION_EXECUTE=FAIL"
  exit 1
fi
echo "site_process_pid_before=${site_pid_before}"

worker_pid_before="$(pm2_pid "$WORKER_PROCESS" || true)"
if [ -z "$worker_pid_before" ]; then
  echo "worker_process=NOT_RUNNING"
  echo "GI_ROTATION_EXECUTE=FAIL"
  exit 1
fi
echo "worker_process_pid_before=${worker_pid_before}"

for c in "${CONTAINERS[@]}"; do
  c_status="$(docker_health "$c")"
  if [ "$c_status" != "healthy" ] && [ "$c_status" != "running" ]; then
    echo "container_${c}=UNHEALTHY (${c_status})"
    echo "GI_ROTATION_EXECUTE=FAIL"
    exit 1
  fi
  echo "container_${c}_status=${c_status}"
done

old_hash="$(secret_file_value_hash "$SECRET_FILE" || true)"
if [ -z "$old_hash" ]; then
  echo "old_hash_calculation=FAIL"
  echo "GI_ROTATION_EXECUTE=FAIL"
  exit 1
fi
echo "OLD_HASH=${old_hash}"

if [ "$REQUIRED_IN_SITE_ENV" = "yes" ]; then
  old_env_hash="$(dotenv_key_hash "$SITE_ENV" "$TARGET_TOKEN" || true)"
  if [ "$old_env_hash" != "$old_hash" ]; then
    echo "initial_site_env_parity=FAIL"
    echo "GI_ROTATION_EXECUTE=FAIL"
    exit 1
  fi
  echo "initial_site_env_parity=PASS"

  old_proc_hash="$(process_env_key_hash "$site_pid_before" "$TARGET_TOKEN" || true)"
  if [ "$old_proc_hash" != "$old_hash" ]; then
    echo "initial_site_process_parity=FAIL"
    echo "GI_ROTATION_EXECUTE=FAIL"
    exit 1
  fi
  echo "initial_site_process_parity=PASS"
fi

for c in "${CONTAINERS[@]}"; do
  c_hash="$(container_secret_hash "$c" "$MOUNT_PATH" || true)"
  if [ "$c_hash" != "$old_hash" ]; then
    echo "initial_container_parity_${c}=FAIL"
    echo "GI_ROTATION_EXECUTE=FAIL"
    exit 1
  fi
  echo "initial_container_parity_${c}=PASS"
done

echo "INITIAL_PREFLIGHT=PASS"
echo

# ------------------------------------------------------------------------------
# 6. Backup Creation & Verification
# ------------------------------------------------------------------------------
echo "=== BACKUP CREATION ==="
BACKUP_DIR="/home/gsadmin/backups/gse/${INCIDENT_ID}/gi/${TARGET_TOKEN}"
if [[ "$BACKUP_DIR" =~ \.\. ]]; then
  echo "backup_path_traversal=FAIL"
  echo "GI_ROTATION_EXECUTE=FAIL"
  exit 1
fi

mkdir -p -m 700 "$BACKUP_DIR"
echo "backup_directory=${BACKUP_DIR}"

BACKUP_SECRET_FILE="${BACKUP_DIR}/secret_file.bak"
if [ -f "$BACKUP_SECRET_FILE" ]; then
  echo "backup_already_exists=FAIL (destination ${BACKUP_SECRET_FILE} already exists)"
  echo "GI_ROTATION_EXECUTE=FAIL"
  exit 1
fi

cp -p "$SECRET_FILE" "$BACKUP_SECRET_FILE"
chmod 600 "$BACKUP_SECRET_FILE"

bak_sec_hash="$(secret_file_value_hash "$BACKUP_SECRET_FILE" || true)"
if [ "$bak_sec_hash" != "$old_hash" ]; then
  echo "backup_secret_file_integrity=FAIL"
  echo "GI_ROTATION_EXECUTE=FAIL"
  exit 1
fi
echo "backup_secret_file=PASS"

BACKUP_SITE_ENV="${BACKUP_DIR}/site_env.bak"
if [ "$REQUIRED_IN_SITE_ENV" = "yes" ]; then
  if [ -f "$BACKUP_SITE_ENV" ]; then
    echo "backup_already_exists=FAIL (destination ${BACKUP_SITE_ENV} already exists)"
    echo "GI_ROTATION_EXECUTE=FAIL"
    exit 1
  fi

  cp -p "$SITE_ENV" "$BACKUP_SITE_ENV"
  chmod 600 "$BACKUP_SITE_ENV"

  bak_env_hash="$(dotenv_key_hash "$BACKUP_SITE_ENV" "$TARGET_TOKEN" || true)"
  if [ "$bak_env_hash" != "$old_hash" ]; then
    echo "backup_site_env_integrity=FAIL"
    echo "GI_ROTATION_EXECUTE=FAIL"
    exit 1
  fi
  echo "backup_site_env=PASS"
else
  echo "backup_site_env=NOT_REQUIRED"
fi

echo "rollback_ready=PASS"
echo

# ------------------------------------------------------------------------------
# 7. Automatic Rollback Handler Setup
# ------------------------------------------------------------------------------
MUTATION_STARTED=0
ROTATION_SUCCEEDED=0

rollback_mutation() {
  # Disarm trap immediately to avoid recursive invocation and loops
  trap - ERR EXIT
  set +e

  if [ "$ROTATION_SUCCEEDED" -eq 1 ] || [ "$MUTATION_STARTED" -eq 0 ]; then
    return
  fi

  echo
  echo "========================================"
  echo "FAILURE_DETECTED=YES"
  echo "ROLLBACK_STARTED=YES"
  echo "========================================"

  # 1. Restore secret file
  if [ -f "$BACKUP_SECRET_FILE" ]; then
    cp -p "$BACKUP_SECRET_FILE" "$SECRET_FILE"
    chmod 600 "$SECRET_FILE"
    echo "ROLLBACK_SECRET=PASS"
  else
    echo "ROLLBACK_SECRET=FAIL"
  fi

  # 2. Restore site env
  if [ "$REQUIRED_IN_SITE_ENV" = "yes" ] && [ -f "$BACKUP_SITE_ENV" ]; then
    cp -p "$BACKUP_SITE_ENV" "$SITE_ENV"
    chmod 600 "$SITE_ENV"
    echo "ROLLBACK_SITE_ENV=PASS"
  else
    echo "ROLLBACK_SITE_ENV=NOT_REQUIRED"
  fi

  # 3. Restart GI containers
  local rollback_containers_ok=1
  for c in "${CONTAINERS[@]}"; do
    docker restart "$c" >/dev/null 2>&1 || true
    local healthy=0
    for _ in $(seq 1 20); do
      local s
      s="$(docker_health "$c")"
      if [ "$s" = "healthy" ] || [ "$s" = "running" ]; then
        healthy=1
        break
      fi
      sleep 3
    done
    if [ "$healthy" -ne 1 ]; then
      rollback_containers_ok=0
    fi
  done

  if [ "$rollback_containers_ok" -eq 1 ]; then
    echo "ROLLBACK_CONTAINERS=PASS"
  else
    echo "ROLLBACK_CONTAINERS=FAIL"
  fi

  # 4. Restart Site API if needed using the exact same shared helper
  local cur_site_pid=""
  if [ "$REQUIRED_IN_SITE_ENV" = "yes" ]; then
    if restart_site_api "$SITE_DIR" "$SITE_ENV" "$SITE_PROCESS"; then
      cur_site_pid="$(pm2_pid "$SITE_PROCESS" || true)"
      if [ -n "$cur_site_pid" ]; then
        echo "ROLLBACK_SITE_PROCESS=PASS"
      else
        echo "ROLLBACK_SITE_PROCESS=FAIL"
      fi
    else
      echo "ROLLBACK_SITE_PROCESS=FAIL"
    fi
  else
    echo "ROLLBACK_SITE_PROCESS=NOT_REQUIRED"
  fi

  # 5. Check worker untouched
  local cur_worker_pid
  cur_worker_pid="$(pm2_pid "$WORKER_PROCESS" || true)"
  if [ "$cur_worker_pid" = "$worker_pid_before" ]; then
    echo "ROLLBACK_WORKER_UNTOUCHED=PASS"
  else
    echo "ROLLBACK_WORKER_UNTOUCHED=FAIL"
  fi

  # 6. Revalidate old_hash restoration
  local restored_sec_hash
  restored_sec_hash="$(secret_file_value_hash "$SECRET_FILE" || true)"
  if [ "$restored_sec_hash" = "$old_hash" ]; then
    echo "ROLLBACK_OLD_HASH_RESTORED=PASS"
  else
    echo "ROLLBACK_OLD_HASH_RESTORED=FAIL"
  fi

  echo "ROLLBACK_FINISHED=PASS"
  echo "GI_ROTATION_EXECUTE=FAIL"
  exit 1
}

trap rollback_mutation ERR EXIT

# ------------------------------------------------------------------------------
# 8. Generation of New Token & Atomic Writing
# ------------------------------------------------------------------------------
echo "=== TOKEN GENERATION & ATOMIC WRITING ==="
MUTATION_STARTED=1

new_hash="$(python3 -c '
import hashlib, os, secrets, sys, tempfile

secret_file = sys.argv[1]
site_env = sys.argv[2]
update_site = (sys.argv[3] == "yes")
target_key = sys.argv[4]

new_token = secrets.token_urlsafe(48)
digest = hashlib.sha256(new_token.encode("utf-8")).hexdigest()

# Atomic write to secret_file
sec_dir = os.path.dirname(os.path.abspath(secret_file))
fd, tmp_sec = tempfile.mkstemp(dir=sec_dir, prefix=".tmp_sec_")
try:
    with os.fdopen(fd, "wb") as f:
        f.write((new_token + "\n").encode("utf-8"))
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp_sec, 0o600)
    os.replace(tmp_sec, secret_file)
except Exception:
    if os.path.exists(tmp_sec):
        os.unlink(tmp_sec)
    raise

# Atomic write to site_env if required
if update_site:
    env_dir = os.path.dirname(os.path.abspath(site_env))
    fd, tmp_env = tempfile.mkstemp(dir=env_dir, prefix=".tmp_env_")
    found_count = 0
    try:
        with open(site_env, "r", encoding="utf-8", errors="replace") as rf:
            lines = rf.readlines()

        # Check for duplicates before writing
        for line in lines:
            stripped = line.lstrip()
            remainder = stripped[7:].lstrip() if stripped.startswith("export ") else stripped
            if remainder.startswith(target_key + "="):
                found_count += 1

        if found_count > 1:
            raise ValueError("DUPLICATE_KEY_IN_ENV")
        if found_count == 0:
            raise KeyError("TARGET_KEY_NOT_FOUND_IN_ENV")

        with os.fdopen(fd, "w", encoding="utf-8") as wf:
            for line in lines:
                stripped = line.lstrip()
                prefix = ""
                if stripped.startswith("export "):
                    prefix = "export "
                    remainder = stripped[7:].lstrip()
                else:
                    remainder = stripped

                if remainder.startswith(target_key + "="):
                    wf.write(f"{prefix}{target_key}={new_token}\n")
                else:
                    wf.write(line)
            wf.flush()
            os.fsync(wf.fileno())

        os.chmod(tmp_env, 0o600)
        os.replace(tmp_env, site_env)
    except Exception:
        if os.path.exists(tmp_env):
            os.unlink(tmp_env)
        raise

print(digest)
' "$SECRET_FILE" "$SITE_ENV" "$REQUIRED_IN_SITE_ENV" "$TARGET_TOKEN")"

if [ -z "$new_hash" ] || [ "${#new_hash}" -ne 64 ]; then
  echo "token_generation=FAIL"
  exit 1
fi

if [ "$new_hash" = "$old_hash" ]; then
  echo "new_hash_collision=FAIL"
  exit 1
fi

echo "NEW_HASH=${new_hash}"

# Validate file parity immediately
ver_sec_hash="$(secret_file_value_hash "$SECRET_FILE" || true)"
if [ "$ver_sec_hash" != "$new_hash" ]; then
  echo "secret_file_parity=FAIL"
  exit 1
fi
echo "secret_file_parity=PASS"

if [ "$REQUIRED_IN_SITE_ENV" = "yes" ]; then
  ver_env_hash="$(dotenv_key_hash "$SITE_ENV" "$TARGET_TOKEN" || true)"
  if [ "$ver_env_hash" != "$new_hash" ]; then
    echo "site_env_parity=FAIL"
    exit 1
  fi
  echo "site_env_parity=PASS"
else
  echo "site_env_parity=NOT_REQUIRED"
fi
echo

# ------------------------------------------------------------------------------
# 9. Restart Affected GI Containers
# ------------------------------------------------------------------------------
echo "=== RESTART GI CONTAINERS ==="
for c in "${CONTAINERS[@]}"; do
  echo "restarting_container=${c}"
  docker restart "$c" >/dev/null

  healthy=0
  for _ in $(seq 1 20); do
    s="$(docker_health "$c")"
    if [ "$s" = "healthy" ] || [ "$s" = "running" ]; then
      healthy=1
      break
    fi
    sleep 3
  done

  if [ "$healthy" -ne 1 ]; then
    echo "container_health_${c}=FAIL"
    exit 1
  fi
  echo "container_health_${c}=PASS"
done

# Internal GI HTTP Health
primary_container="${CONTAINERS[0]}"
gi_health_code="$(docker exec "$primary_container" node -e "fetch('http://127.0.0.1:3002/api/health').then(r=>console.log(r.status)).catch(()=>console.log(0))" 2>/dev/null | tr -d '[:space:]' || true)"
if [ "$gi_health_code" = "200" ]; then
  echo "GI_INTERNAL_HTTP_HEALTH=PASS (status=200)"
else
  echo "GI_INTERNAL_HTTP_HEALTH=FAIL (status=${gi_health_code})"
  exit 1
fi

# Verify container mounts match new_hash
for c in "${CONTAINERS[@]}"; do
  c_mount_hash="$(container_secret_hash "$c" "$MOUNT_PATH" || true)"
  if [ "$c_mount_hash" != "$new_hash" ]; then
    echo "container_parity_${c}=FAIL"
    exit 1
  fi
done
echo "container_parity=PASS"
echo

# ------------------------------------------------------------------------------
# 10. Restart Site API (if required)
# ------------------------------------------------------------------------------
echo "=== RESTART SITE API ==="
if [ "$REQUIRED_IN_SITE_ENV" = "yes" ]; then
  echo "restarting_site_api=${SITE_PROCESS}"
  if ! restart_site_api "$SITE_DIR" "$SITE_ENV" "$SITE_PROCESS"; then
    echo "site_process_restart=FAIL (restart helper failed)"
    exit 1
  fi

  site_pid_after="$(pm2_pid "$SITE_PROCESS" || true)"
  if [ -z "$site_pid_after" ] || [ "$site_pid_after" = "$site_pid_before" ]; then
    echo "site_process_restart=FAIL (pid=${site_pid_after:-0})"
    exit 1
  fi
  echo "site_process_pid_after=${site_pid_after}"

  # Verify process parity
  proc_new_hash="$(process_env_key_hash "$site_pid_after" "$TARGET_TOKEN" || true)"
  if [ "$proc_new_hash" != "$new_hash" ]; then
    echo "site_process_parity=FAIL"
    exit 1
  fi
  echo "site_process_parity=PASS"
else
  echo "site_process_restart=NOT_REQUIRED"
  echo "site_process_parity=NOT_REQUIRED"
fi

# Assert worker untouched
worker_pid_now="$(pm2_pid "$WORKER_PROCESS" || true)"
if [ "$worker_pid_now" != "$worker_pid_before" ]; then
  echo "worker_untouched=FAIL (changed from ${worker_pid_before} to ${worker_pid_now})"
  exit 1
fi
echo "worker_untouched=PASS"

echo "SITE_HTTP_HEALTH=NOT_CONFIGURED"
echo

# ------------------------------------------------------------------------------
# 11. Final Report & Success
# ------------------------------------------------------------------------------
ROTATION_SUCCEEDED=1
trap - ERR EXIT

echo "========================================"
echo "TOKEN_ROTATION=PASS"
echo "token=${TARGET_TOKEN}"
echo "environment=staging"
echo
echo "OLD_HASH=${old_hash}"
echo "NEW_HASH=${new_hash}"
echo
echo "secret_file_parity=PASS"
if [ "$REQUIRED_IN_SITE_ENV" = "yes" ]; then
  echo "site_env_parity=PASS"
  echo "site_process_parity=PASS"
else
  echo "site_env_parity=NOT_REQUIRED"
  echo "site_process_parity=NOT_REQUIRED"
fi
echo "container_parity=PASS"
echo "worker_untouched=PASS"
echo
echo "DATABASE_TOUCHED=NO"
echo "PM2_SAVE_RUN=NO"
echo "GI_ROTATION_EXECUTE=PASS"
exit 0
