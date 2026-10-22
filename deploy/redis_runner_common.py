"""Read-only Redis preflight transport for an existing incident sandbox."""
import argparse
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CURRENT_INCIDENT = ROOT / "runtime" / "current-incident.txt"
CONFIG_PATH = ROOT / "config" / "transport.json"
INCIDENT_RE = re.compile(r"^GSE-[0-9]{8}T[0-9]{6}Z$")
MARKER = "REDIS_PREFLIGHT_REMOTE_RUN"


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--environment", required=True)
    args = parser.parse_args(argv)
    if args.environment == "production":
        print("PRODUCTION_PREFLIGHT=BLOCKED")
        print(f"{MARKER}=FAIL")
        return 1
    if args.environment != "staging":
        print(f"{MARKER}=FAIL")
        return 1
    try:
        incident = CURRENT_INCIDENT.read_text(encoding="utf-8").strip()
        if not INCIDENT_RE.fullmatch(incident):
            raise ValueError("invalid incident")
        transport = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        host, base = transport["ssh_host"], transport["remote_base"]
        if not isinstance(host, str) or not host or not isinstance(base, str) or not base.startswith("/"):
            raise ValueError("invalid transport")
        remote = f"{base.rstrip('/')}/{incident}/package/rotations/redis/redis-preflight.sh"
        check = subprocess.run(
            ["ssh", host, "test", "-f", remote], cwd=ROOT,
            capture_output=True, text=True, check=False, shell=False,
        )
        if check.returncode:
            print("REMOTE_SANDBOX=ABSENT")
            print(f"{MARKER}=FAIL")
            return 1
        result = subprocess.run(
            ["ssh", host, "bash", remote, "staging"],
            cwd=ROOT, check=False, shell=False,
        )
    except (OSError, ValueError, KeyError, TypeError):
        print("incident_or_transport_validation=FAIL")
        print(f"{MARKER}=FAIL")
        return 1
    print(f"{MARKER}={'PASS' if result.returncode == 0 else 'FAIL'}")
    return 0 if result.returncode == 0 else 1
