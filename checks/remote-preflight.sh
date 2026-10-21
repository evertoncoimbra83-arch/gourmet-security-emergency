#!/usr/bin/env bash
set -euo pipefail

echo "========================================"
echo "GSE REMOTE PREFLIGHT SANDBOX"
echo "MODE=READ_ONLY"
echo "========================================"
echo

echo "=== IDENTITY ==="
echo "user=$(id -un)"
echo "uid=$(id -u)"
echo "hostname=$(hostname)"
echo "kernel=$(uname -sr)"
echo

echo "=== RUNTIME TOOLS ==="

if command -v python3 >/dev/null 2>&1; then
  echo "python3=AVAILABLE"
  python3 --version 2>&1 | sed 's/^/python3_version=/'
else
  echo "python3=ABSENT"
fi

if command -v node >/dev/null 2>&1; then
  echo "node=AVAILABLE"
  echo "node_version=$(node --version)"
else
  echo "node=ABSENT"
fi

if command -v npm >/dev/null 2>&1; then
  echo "npm=AVAILABLE"
else
  echo "npm=ABSENT"
fi

if command -v pnpm >/dev/null 2>&1; then
  echo "pnpm=AVAILABLE"
else
  echo "pnpm=ABSENT"
fi

if command -v pm2 >/dev/null 2>&1; then
  echo "pm2=AVAILABLE"
else
  echo "pm2=ABSENT"
fi

if command -v docker >/dev/null 2>&1; then
  echo "docker=AVAILABLE"
else
  echo "docker=ABSENT"
fi

if command -v mysql >/dev/null 2>&1; then
  echo "mysql_client=AVAILABLE"
elif command -v mariadb >/dev/null 2>&1; then
  echo "mariadb_client=AVAILABLE"
else
  echo "mysql_client=ABSENT"
fi

echo
echo "=== EXPECTED DIRECTORIES ==="

check_dir() {
  local path="$1"
  local label="$2"

  if [ -d "$path" ]; then
    echo "$label=PASS path=$path"
  else
    echo "$label=ABSENT path=$path"
  fi
}

check_dir "/var/www/gourmet-novo" "site_production_dir"
check_dir "/var/www/gourmet-staging" "site_staging_dir"
check_dir "/home/gsadmin/secure-env" "secure_env_dir"

echo
echo "=== PM2 PROCESS SUMMARY ==="

if command -v pm2 >/dev/null 2>&1; then
  for name in \
    gourmet-novo \
    gourmet-worker \
    gourmet-novo-staging \
    gourmet-worker-staging \
    refeicao-saudavel \
    refeicao-saudavel-worker \
    refeicao-saudavel-staging
  do
    pid="$(pm2 pid "$name" 2>/dev/null || true)"

    if [ -n "$pid" ] && [ "$pid" != "0" ]; then
      echo "$name=ONLINE pid=$pid"
    else
      echo "$name=NOT_RUNNING"
    fi
  done
else
  echo "pm2_summary=SKIPPED"
fi

echo
echo "=== DOCKER CONTAINER SUMMARY ==="

if command -v docker >/dev/null 2>&1; then
  docker ps \
    --format '{{.Names}}|{{.Status}}' \
    2>/dev/null \
    | grep -E \
      '^(gi_|gourmet|redis|mariadb|mysql|postgres)' \
    || true
else
  echo "docker_summary=SKIPPED"
fi

echo
echo "=== SAFETY ASSERTIONS ==="
echo "PM2_ENV_READ=NO"
echo "PM2_JLIST_READ=NO"
echo "PROCESS_ENV_READ=NO"
echo "DOTENV_VALUES_READ=NO"
echo "DATABASE_READ=NO"
echo "DATABASE_WRITE=NO"
echo "PM2_RESTART=NO"
echo "DOCKER_RESTART=NO"
echo "FILES_MODIFIED=NO"
echo

echo "REMOTE_PREFLIGHT=PASS"