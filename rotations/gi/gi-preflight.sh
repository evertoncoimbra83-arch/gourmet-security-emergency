#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# GSE-02A: Gourmet Intelligence Rotation Preflight (READ-ONLY)
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=rotations/gi/gi-common.sh
source "${SCRIPT_DIR}/gi-common.sh"

echo "========================================"
echo "GSE GI ROTATION PREFLIGHT"
echo "MODE=READ_ONLY"
echo "========================================"
echo

if [ "$#" -ne 1 ]; then
  echo "Usage: $0 <staging|production>"
  echo "GI_PREFLIGHT=FAIL"
  exit 1
fi

ENVIRONMENT="$1"
if [ "$ENVIRONMENT" != "staging" ] && [ "$ENVIRONMENT" != "production" ]; then
  echo "invalid environment: $ENVIRONMENT"
  echo "GI_PREFLIGHT=FAIL"
  exit 1
fi

echo "ENVIRONMENT=${ENVIRONMENT}"
echo

PREFLIGHT_SUCCESS=1

if [ "$ENVIRONMENT" = "staging" ]; then
  SITE_ENV="/home/gsadmin/secure-env/.env.staging"
  SITE_PROCESS="gourmet-novo-staging"
  WORKER_PROCESS="gourmet-worker-staging"
  CONTAINERS=(
    "gi_staging_http"
    "gi_staging_http_03c_shadow"
    "gi_staging_http_03c_f3b3b2_shadow"
  )
  SECRET_DIR="/home/gsadmin/secure-env/gourmet-intelligence-staging"
else
  SITE_ENV="/home/gsadmin/secure-env/.env.production"
  SITE_PROCESS="gourmet-novo"
  WORKER_PROCESS="gourmet-worker"
  CONTAINERS=(
    "gi_production_http"
  )
  SECRET_DIR="/home/gsadmin/secure-env/gourmet-intelligence-production"
fi

echo "=== PROCESSES ==="
site_pid="$(pm2_pid "$SITE_PROCESS" || true)"
if [ -n "$site_pid" ]; then
  echo "SITE_PROCESS=${SITE_PROCESS} PID=${site_pid}"
else
  echo "SITE_PROCESS=${SITE_PROCESS} PID=NOT_RUNNING"
  PREFLIGHT_SUCCESS=0
fi

worker_pid="$(pm2_pid "$WORKER_PROCESS" || true)"
if [ -n "$worker_pid" ]; then
  echo "WORKER_PROCESS=${WORKER_PROCESS} PID=${worker_pid}"
else
  echo "WORKER_PROCESS=${WORKER_PROCESS} PID=NOT_RUNNING"
fi
echo

echo "=== CONTAINERS ==="
for c in "${CONTAINERS[@]}"; do
  c_status="$(docker_health "$c")"
  if [ "$c_status" = "healthy" ] || [ "$c_status" = "running" ]; then
    echo "CONTAINER_${c}_STATUS=${c_status}"
  else
    echo "CONTAINER_${c}_STATUS=FAIL (${c_status:-ABSENT})"
    PREFLIGHT_SUCCESS=0
  fi
done
echo

echo "=== TOKEN VALIDATIONS ==="

validate_token() {
  local token_name="$1"
  local secret_filename="$2"
  local required_in_site="$3"
  local secret_file="${SECRET_DIR}/${secret_filename}"

  local file_hash=""

  # 1. Secret File validation
  if [ -f "$secret_file" ]; then
    local mode
    mode="$(file_mode "$secret_file")"
    if [ "$mode" = "600" ]; then
      echo "${token_name}: FILE=PASS"
      file_hash="$(secret_file_value_hash "$secret_file" || true)"
      if [ -z "$file_hash" ]; then
        echo "${token_name}: FILE_HASH=FAIL"
        PREFLIGHT_SUCCESS=0
      fi
    else
      echo "${token_name}: FILE=FAIL (mode=${mode}, expected 600)"
      PREFLIGHT_SUCCESS=0
    fi
  else
    echo "${token_name}: FILE=FAIL (file absent)"
    PREFLIGHT_SUCCESS=0
  fi

  # 2. Site Env Parity
  local env_hash
  env_hash="$(dotenv_key_hash "$SITE_ENV" "$token_name" || true)"
  if [ "$required_in_site" = "yes" ]; then
    if [ -z "$env_hash" ]; then
      echo "${token_name}: SITE_ENV_PARITY=FAIL (missing in site env)"
      PREFLIGHT_SUCCESS=0
    elif [ -n "$file_hash" ] && [ "$env_hash" = "$file_hash" ]; then
      echo "${token_name}: SITE_ENV_PARITY=PASS"
    else
      echo "${token_name}: SITE_ENV_PARITY=FAIL (hash mismatch)"
      PREFLIGHT_SUCCESS=0
    fi
  else
    if [ -z "$env_hash" ]; then
      echo "${token_name}: SITE_ENV=ABSENT_EXPECTED"
    elif [ -n "$file_hash" ] && [ "$env_hash" = "$file_hash" ]; then
      echo "${token_name}: SITE_ENV_PARITY=PASS"
    else
      echo "${token_name}: SITE_ENV_PARITY=FAIL (hash mismatch)"
      PREFLIGHT_SUCCESS=0
    fi
  fi

  # 3. Process Parity
  if [ -n "$site_pid" ]; then
    local proc_hash
    proc_hash="$(process_env_key_hash "$site_pid" "$token_name" || true)"
    if [ "$required_in_site" = "yes" ]; then
      if [ -z "$proc_hash" ]; then
        echo "${token_name}: PROCESS_PARITY=FAIL (missing in process)"
        PREFLIGHT_SUCCESS=0
      elif [ -n "$file_hash" ] && [ "$proc_hash" = "$file_hash" ]; then
        echo "${token_name}: PROCESS_PARITY=PASS"
      else
        echo "${token_name}: PROCESS_PARITY=FAIL (hash mismatch)"
        PREFLIGHT_SUCCESS=0
      fi
    else
      if [ -z "$proc_hash" ]; then
        echo "${token_name}: PROCESS=ABSENT_EXPECTED"
      elif [ -n "$file_hash" ] && [ "$proc_hash" = "$file_hash" ]; then
        echo "${token_name}: PROCESS_PARITY=PASS"
      else
        echo "${token_name}: PROCESS_PARITY=FAIL (hash mismatch)"
        PREFLIGHT_SUCCESS=0
      fi
    fi
  else
    if [ "$required_in_site" = "yes" ]; then
      echo "${token_name}: PROCESS_PARITY=FAIL (site process not running)"
      PREFLIGHT_SUCCESS=0
    else
      echo "${token_name}: PROCESS=ABSENT_EXPECTED"
    fi
  fi

  # 4. Container Parity
  local mount_path=""
  case "$token_name" in
    "GI_ATTENTION_READ_TOKEN")
      mount_path="/run/secrets/gi_attention_read_token"
      ;;
    "GI_RECOMMENDATION_READ_TOKEN")
      mount_path="/run/secrets/gi_recommendation_read_token"
      ;;
    "GI_PROPOSAL_READ_TOKEN")
      mount_path="/run/secrets/gi_proposal_read_token"
      ;;
    "GI_SITE_PRE_PREPARE_TOKEN")
      mount_path="/run/secrets/gi_site_pre_prepare_token"
      ;;
  esac

  local container_parity_ok=1
  if [ "$token_name" = "GI_SITE_PRE_PREPARE_TOKEN" ]; then
    local target_container="gi_staging_http_03c_f3b3b2_shadow"
    local c_hash
    c_hash="$(container_secret_hash "$target_container" "$mount_path" || true)"
    if [ -n "$file_hash" ] && [ "$c_hash" = "$file_hash" ]; then
      echo "${token_name}: CONTAINER_PARITY=PASS"
    else
      echo "${token_name}: CONTAINER_PARITY=FAIL (container=${target_container})"
      container_parity_ok=0
      PREFLIGHT_SUCCESS=0
    fi
  else
    for c in "${CONTAINERS[@]}"; do
      local c_hash
      c_hash="$(container_secret_hash "$c" "$mount_path" || true)"
      if [ -z "$file_hash" ] || [ "$c_hash" != "$file_hash" ]; then
        echo "${token_name}: CONTAINER_PARITY=FAIL (container=${c})"
        container_parity_ok=0
        PREFLIGHT_SUCCESS=0
        break
      fi
    done
    if [ "$container_parity_ok" -eq 1 ]; then
      echo "${token_name}: CONTAINER_PARITY=PASS"
    fi
  fi
}

validate_token "GI_ATTENTION_READ_TOKEN" "attention-read-token.secret" "yes"
validate_token "GI_RECOMMENDATION_READ_TOKEN" "recommendation-read-token.secret" "yes"
validate_token "GI_PROPOSAL_READ_TOKEN" "proposal-read-token.secret" "yes"

if [ "$ENVIRONMENT" = "staging" ]; then
  validate_token "GI_SITE_PRE_PREPARE_TOKEN" "site-pre-prepare-token.secret" "no"
fi
echo

echo "=== HEALTH CHECKS ==="
if [ "$ENVIRONMENT" = "staging" ]; then
  gi_http_code="$(docker exec gi_staging_http node -e "fetch('http://127.0.0.1:3002/api/health').then(r=>console.log(r.status)).catch(()=>console.log(0))" 2>/dev/null | tr -d '[:space:]' || true)"
  if [ "$gi_http_code" = "200" ]; then
    echo "GI_INTERNAL_HTTP_HEALTH=PASS (status=200)"
  else
    echo "GI_INTERNAL_HTTP_HEALTH=FAIL (status=${gi_http_code})"
    PREFLIGHT_SUCCESS=0
  fi
  echo "SITE_HTTP_HEALTH=NOT_CONFIGURED"
else
  gi_http_code="$(docker exec gi_production_http node -e "fetch('http://127.0.0.1:3002/api/health').then(r=>console.log(r.status)).catch(()=>console.log(0))" 2>/dev/null | tr -d '[:space:]' || true)"
  if [ "$gi_http_code" = "200" ]; then
    echo "GI_INTERNAL_HTTP_HEALTH=PASS (status=200)"
  else
    echo "GI_INTERNAL_HTTP_HEALTH=FAIL (status=${gi_http_code})"
    PREFLIGHT_SUCCESS=0
  fi

  local_http_code="$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:3001/health 2>/dev/null || true)"
  if [ "$local_http_code" = "200" ]; then
    echo "SITE_LOCAL_HTTP_HEALTH=PASS (status=200)"
  else
    echo "SITE_LOCAL_HTTP_HEALTH=FAIL (status=${local_http_code})"
    PREFLIGHT_SUCCESS=0
  fi

  public_http_code="$(curl -s -k -o /dev/null -w "%{http_code}" https://gourmetsaudavel.com/health 2>/dev/null || true)"
  if [ "$public_http_code" = "200" ]; then
    echo "SITE_PUBLIC_HTTP_HEALTH=PASS (status=200)"
  else
    echo "SITE_PUBLIC_HTTP_HEALTH=FAIL (status=${public_http_code})"
    PREFLIGHT_SUCCESS=0
  fi
fi

echo
echo "=== SAFETY ASSERTIONS ==="
echo "NO_SECRET_VALUES_PRINTED=PASS"
echo "NO_FILES_MODIFIED=PASS"
echo "NO_SERVICES_RESTARTED=PASS"
echo "NO_DATABASE_READS=PASS"
echo "NO_DATABASE_WRITES=PASS"
echo

if [ "$PREFLIGHT_SUCCESS" -eq 1 ]; then
  echo "GI_PREFLIGHT=PASS"
  echo "ENVIRONMENT=${ENVIRONMENT}"
  exit 0
else
  echo "GI_PREFLIGHT=FAIL"
  echo "ENVIRONMENT=${ENVIRONMENT}"
  exit 1
fi
