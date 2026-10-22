#!/usr/bin/env bash
# Shared Auth helpers; no secret value leaves the helper process.
SITE_DIR=/var/www/gourmet-staging
SITE_ENV=/home/gsadmin/secure-env/.env.staging
SITE_PROCESS=gourmet-novo-staging
WORKER_PROCESS=gourmet-worker-staging
AUTH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

pm2_pid() {
  local pid
  pid="$(pm2 pid "$1" 2>/dev/null | tr -d '[:space:]' || true)"
  [[ "$pid" =~ ^[0-9]+$ ]] && [ "$pid" -gt 0 ] || return 1
  printf '%s\n' "$pid"
}

dotenv_key_hash() {
  env -C "$SITE_DIR" node -e '
    const fs = require("fs");
    const crypto = require("crypto");
    const dotenv = require("dotenv");
    const parsed = dotenv.parse(fs.readFileSync(process.argv[1]));
    const value = parsed[process.argv[2]];
    if (typeof value !== "string") process.exit(1);
    process.stdout.write(crypto.createHash("sha256").update(value).digest("hex") + "\n");
  ' "$SITE_ENV" "$1" 2>/dev/null
}

process_env_key_hash() {
  python3 -c '
import hashlib, sys
try:
    with open("/proc/" + sys.argv[1] + "/environ", "rb") as stream:
        data = stream.read()
    prefix = (sys.argv[2] + "=").encode()
    matches = [part[len(prefix):] for part in data.split(b"\0") if part.startswith(prefix)]
    if len(matches) != 1:
        raise ValueError("missing or duplicate process key")
    print(hashlib.sha256(matches[0]).hexdigest())
except Exception:
    sys.exit(1)
  ' "$1" "$2" 2>/dev/null
}

restart_site_api() {
  env -C "$SITE_DIR" node -e '
    const fs = require("fs");
    const { spawnSync } = require("child_process");
    const dotenv = require("dotenv");
    const parsed = dotenv.parse(fs.readFileSync(process.argv[1]));
    const result = spawnSync("pm2", ["restart", process.argv[2], "--update-env"], {
      cwd: process.cwd(), env: { ...process.env, ...parsed }, stdio: "ignore"
    });
    process.exit(result.status === 0 ? 0 : 1);
  ' "$SITE_ENV" "$SITE_PROCESS" >/dev/null 2>&1
}
