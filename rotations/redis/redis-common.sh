#!/usr/bin/env bash
# Redis discovery entry point. It performs only local reads in the future sandbox.
redis_run_readonly() {
  local script_dir
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  python3 "$script_dir/redis-discovery.py" --runtime staging
}
