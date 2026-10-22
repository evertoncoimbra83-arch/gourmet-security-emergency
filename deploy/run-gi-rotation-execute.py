from pathlib import Path
import argparse
import json
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent

CONFIG_PATH = ROOT / "config" / "transport.json"

CURRENT_INCIDENT = (
    ROOT
    / "runtime"
    / "current-incident.txt"
)

INCIDENT_RE = re.compile(
    r"^GSE-[0-9]{8}T[0-9]{6}Z$"
)

ALLOWED_ENVIRONMENTS = {
    "staging",
}

VALID_TOKENS = {
    "GI_ATTENTION_READ_TOKEN",
    "GI_RECOMMENDATION_READ_TOKEN",
    "GI_PROPOSAL_READ_TOKEN",
    "GI_SITE_PRE_PREPARE_TOKEN",
}


def load_config():
    with CONFIG_PATH.open(
        "r",
        encoding="utf-8",
    ) as f:
        config = json.load(f)

    host = config.get("ssh_host")
    remote_base = config.get("remote_base")

    if not isinstance(host, str) or not host:
        raise ValueError("invalid ssh_host")

    if (
        not isinstance(remote_base, str)
        or not remote_base.startswith("/")
    ):
        raise ValueError("invalid remote_base")

    return host, remote_base.rstrip("/")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Run remote GI rotation execution (STAGING-ONLY, HIGH RISK)"
    )
    parser.add_argument(
        "--environment",
        required=True,
        help="Target environment (strictly 'staging')",
    )
    parser.add_argument(
        "--token",
        required=True,
        choices=sorted(VALID_TOKENS),
        help="Target GI token to rotate",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        default=False,
        help="Mandatory execution flag",
    )
    return parser.parse_args(argv)


def main(argv=None) -> int:
    # Custom pre-check for production to ensure clear blocker output before full argparse failure
    raw_args = argv if argv is not None else sys.argv[1:]
    if "--environment" in raw_args:
        idx = raw_args.index("--environment")
        if idx + 1 < len(raw_args) and raw_args[idx + 1] == "production":
            print("PRODUCTION_EXECUTION=BLOCKED")
            print("GI_ROTATION_REMOTE_EXECUTE=FAIL")
            return 1

    args = parse_args(argv)

    if args.environment == "production":
        print("PRODUCTION_EXECUTION=BLOCKED")
        print("GI_ROTATION_REMOTE_EXECUTE=FAIL")
        return 1

    if args.environment not in ALLOWED_ENVIRONMENTS:
        print(f"INVALID_ENVIRONMENT: {args.environment} is not permitted")
        print("GI_ROTATION_REMOTE_EXECUTE=FAIL")
        return 1

    if not args.execute:
        print("EXECUTE_FLAG_REQUIRED: --execute must be explicitly specified")
        print("GI_ROTATION_REMOTE_EXECUTE=FAIL")
        return 1

    environment = args.environment
    token = args.token

    print("========================================")
    print("GSE REMOTE GI ROTATION EXECUTOR")
    print("RISK=HIGH")
    print(f"ENVIRONMENT={environment}")
    print(f"TOKEN={token}")
    print("========================================")
    print()

    if not CURRENT_INCIDENT.is_file():
        print("current_incident=ABSENT")
        print("GI_ROTATION_REMOTE_EXECUTE=FAIL")
        return 1

    incident_id = CURRENT_INCIDENT.read_text(
        encoding="utf-8"
    ).strip()

    if not INCIDENT_RE.fullmatch(incident_id):
        print("incident_id_validation=FAIL")
        print("GI_ROTATION_REMOTE_EXECUTE=FAIL")
        return 1

    host, remote_base = load_config()

    remote_dir = f"{remote_base}/{incident_id}"
    remote_extract = f"{remote_dir}/package"
    remote_executor = (
        f"{remote_extract}/"
        "rotations/gi/gi-rotate-execute.sh"
    )

    print(f"incident_id={incident_id}")
    print(f"environment={environment}")
    print(f"token={token}")
    print(f"remote_dir={remote_dir}")
    print()

    print("step=verify-sandbox-presence")

    check_res = subprocess.run(
        [
            "ssh",
            host,
            "test",
            "-f",
            remote_executor,
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )

    if check_res.returncode != 0:
        print("REMOTE_SANDBOX=ABSENT")
        print("GI_ROTATION_REMOTE_EXECUTE=FAIL")
        return 1

    print("sandbox_presence=PASS")
    print()

    print("step=execute-rotation")
    print()

    result = subprocess.run(
        [
            "ssh",
            host,
            "bash",
            remote_executor,
            incident_id,
            environment,
            token,
            "--execute",
        ],
        cwd=str(ROOT),
        check=False,
    )

    print()

    if result.returncode != 0:
        print("GI_ROTATION_REMOTE_EXECUTE=FAIL")
        return 1

    print("GI_ROTATION_REMOTE_EXECUTE=PASS")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(
            f"GI_ROTATION_EXECUTE_ERROR="
            f"{type(exc).__name__}"
        )
        print("GI_ROTATION_REMOTE_EXECUTE=FAIL")
        sys.exit(1)
