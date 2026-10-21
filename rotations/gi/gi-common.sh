#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# GSE-02A: Gourmet Intelligence Common Functions (READ-ONLY)
# ==============================================================================
# Safety rules:
# - NEVER print secret values
# - NEVER dump full environment
# - NEVER alter files or restart services
# ==============================================================================

sha256_file() {
  local target_file="$1"
  if [ ! -f "$target_file" ]; then
    return 1
  fi

  local hash
  hash="$(sha256sum "$target_file" 2>/dev/null | awk '{print $1}')"
  if [ -z "$hash" ] || [ "${#hash}" -ne 64 ]; then
    return 1
  fi

  printf '%s\n' "$hash"
}

secret_file_value_hash() {
  local target_file="$1"
  if [ ! -f "$target_file" ]; then
    return 1
  fi

  local hash
  if command -v python3 >/dev/null 2>&1; then
    hash="$(python3 -c '
import sys, hashlib
try:
    with open(sys.argv[1], "rb") as f:
        data = f.read().rstrip(b"\r\n")
    print(hashlib.sha256(data).hexdigest())
except Exception:
    sys.exit(1)
' "$target_file" 2>/dev/null || true)"
  else
    local raw_val
    raw_val="$(tr -d '\r\n' < "$target_file" 2>/dev/null || true)"
    hash="$(printf '%s' "$raw_val" | sha256sum 2>/dev/null | awk '{print $1}' || true)"
  fi

  if [ -z "$hash" ] || [ "${#hash}" -ne 64 ]; then
    return 1
  fi

  printf '%s\n' "$hash"
}

dotenv_key_hash() {
  local env_file="$1"
  local target_key="$2"

  if [ ! -f "$env_file" ]; then
    return 1
  fi

  local line
  line="$(grep -E "^[[:space:]]*(export[[:space:]]+)?${target_key}=" "$env_file" 2>/dev/null | head -n 1 || true)"
  if [ -z "$line" ]; then
    return 1
  fi

  local raw_val="${line#*=}"
  raw_val="${raw_val%$'\r'}"

  if [[ "$raw_val" =~ ^\"(.*)\"$ ]]; then
    raw_val="${BASH_REMATCH[1]}"
  elif [[ "$raw_val" =~ ^\'(.*)\'$ ]]; then
    raw_val="${BASH_REMATCH[1]}"
  fi

  local hash
  hash="$(printf '%s' "$raw_val" | sha256sum 2>/dev/null | awk '{print $1}')"
  if [ -z "$hash" ] || [ "${#hash}" -ne 64 ]; then
    return 1
  fi

  printf '%s\n' "$hash"
}

process_env_key_hash() {
  local target_pid="$1"
  local target_key="$2"
  local environ_file="/proc/${target_pid}/environ"

  if [ ! -r "$environ_file" ]; then
    return 1
  fi

  if command -v python3 >/dev/null 2>&1; then
    python3 -c '
import sys, hashlib
pid = sys.argv[1]
key = sys.argv[2]
try:
    with open(f"/proc/{pid}/environ", "rb") as f:
        data = f.read()
except OSError:
    sys.exit(1)
prefix = (key + "=").encode("utf-8")
for item in data.split(b"\x00"):
    if item.startswith(prefix):
        val = item[len(prefix):]
        print(hashlib.sha256(val).hexdigest())
        sys.exit(0)
sys.exit(1)
' "$target_pid" "$target_key" 2>/dev/null
  else
    local match
    match="$(grep -z -a "^${target_key}=" "$environ_file" 2>/dev/null | tr -d '\0' || true)"
    if [ -z "$match" ]; then
      return 1
    fi
    local raw_val="${match#*=}"
    local hash
    hash="$(printf '%s' "$raw_val" | sha256sum 2>/dev/null | awk '{print $1}')"
    if [ -z "$hash" ] || [ "${#hash}" -ne 64 ]; then
      return 1
    fi
    printf '%s\n' "$hash"
  fi
}

container_secret_hash() {
  local container="$1"
  local secret_path="$2"

  local hash=""
  hash="$(docker exec "$container" sh -c '
if command -v python3 >/dev/null 2>&1; then
  python3 -c '\''
import sys, hashlib
try:
    with open(sys.argv[1], "rb") as f:
        data = f.read().rstrip(b"\r\n")
    print(hashlib.sha256(data).hexdigest())
except Exception:
    sys.exit(1)
'\'' "$1"
elif command -v node >/dev/null 2>&1; then
  node -e '\''
const fs = require("fs");
const crypto = require("crypto");
try {
  let b = fs.readFileSync(process.argv[1]);
  while (b.length > 0 && (b[b.length - 1] === 10 || b[b.length - 1] === 13)) {
    b = b.subarray(0, b.length - 1);
  }
  console.log(crypto.createHash("sha256").update(b).digest("hex"));
} catch (e) {
  process.exit(1);
}
'\'' "$1"
fi
' sh "$secret_path" 2>/dev/null | tr -d '[:space:]' || true)"

  if [ -z "$hash" ] || [ "${#hash}" -ne 64 ]; then
    return 1
  fi

  printf '%s\n' "$hash"
}

pm2_pid() {
  local process_name="$1"
  local pid
  pid="$(pm2 pid "$process_name" 2>/dev/null | tr -d '[:space:]' || true)"
  if [ -z "$pid" ] || [ "$pid" = "0" ] || ! [[ "$pid" =~ ^[0-9]+$ ]]; then
    return 1
  fi

  printf '%s\n' "$pid"
}

docker_health() {
  local container_name="$1"
  docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container_name" 2>/dev/null || true
}

file_mode() {
  local target_file="$1"
  stat -c '%a' "$target_file" 2>/dev/null || true
}
