"""Transport for staged Auth scripts in an already extracted incident sandbox."""
import argparse
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CURRENT_INCIDENT = ROOT / "runtime" / "current-incident.txt"
CONFIG_PATH = ROOT / "config" / "transport.json"
INCIDENT_RE = re.compile(r"^GSE-[0-9]{8}T[0-9]{6}Z$")
SECRETS = {"SESSION_SECRET", "JWT_SECRET", "NEXTAUTH_SECRET"}
SCRIPTS = {
    "preflight": ("auth-preflight.sh", "bash", "AUTH_PREFLIGHT_REMOTE_RUN"),
    "plan": ("auth-rotate-plan.py", "python3", "AUTH_ROTATION_REMOTE_PLAN"),
    "execute": ("auth-rotate-execute.sh", "bash", "AUTH_ROTATION_REMOTE_EXECUTE"),
}


def main(mode, argv=None):
    script, interpreter, marker = SCRIPTS[mode]
    parser = argparse.ArgumentParser()
    parser.add_argument("--environment", required=True)
    if mode != "preflight":
        parser.add_argument("--secret", required=True)
    if mode == "plan":
        parser.add_argument("--dry-run", action="store_true")
    if mode == "execute":
        parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)

    # This gate must remain before configuration reads and the first SSH call.
    if args.environment == "production":
        print("PRODUCTION_EXECUTION=BLOCKED")
        print(f"{marker}=FAIL")
        return 1
    if args.environment != "staging":
        print(f"{marker}=FAIL")
        return 1
    if mode != "preflight" and args.secret not in SECRETS:
        print("SECRET_INVALID=FAIL")
        print(f"{marker}=FAIL")
        return 1
    if mode == "plan" and not args.dry_run:
        print("DRY_RUN_REQUIRED=FAIL")
        print(f"{marker}=FAIL")
        return 1
    if mode == "execute" and not args.execute:
        print("EXECUTE_FLAG_REQUIRED=FAIL")
        print(f"{marker}=FAIL")
        return 1
    try:
        incident_id = CURRENT_INCIDENT.read_text(encoding="utf-8").strip()
        if not INCIDENT_RE.fullmatch(incident_id):
            raise ValueError("invalid incident")
        config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        host = config["ssh_host"]
        base = config["remote_base"]
        if not isinstance(host, str) or not host or not isinstance(base, str) or not base.startswith("/"):
            raise ValueError("invalid transport")
    except (OSError, KeyError, ValueError, TypeError):
        print("incident_or_transport_validation=FAIL")
        print(f"{marker}=FAIL")
        return 1
    remote = f"{base.rstrip('/')}/{incident_id}/package/rotations/auth/{script}"
    check = subprocess.run(["ssh", host, "test", "-f", remote], cwd=ROOT, check=False)
    if check.returncode:
        print("REMOTE_SANDBOX=ABSENT")
        print(f"{marker}=FAIL")
        return 1
    if mode == "preflight":
        command = ["ssh", host, interpreter, remote, "staging"]
    elif mode == "plan":
        command = ["ssh", host, interpreter, remote, "--environment", "staging", "--secret", args.secret, "--dry-run"]
    else:
        command = ["ssh", host, interpreter, remote, incident_id, "staging", args.secret, "--execute"]
    result = subprocess.run(command, cwd=ROOT, check=False)
    print(f"{marker}={'PASS' if result.returncode == 0 else 'FAIL'}")
    return 0 if result.returncode == 0 else 1
