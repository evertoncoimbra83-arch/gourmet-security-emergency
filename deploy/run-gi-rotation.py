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

VALID_ENVIRONMENTS = {
    "staging",
    "production",
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
        description="Run remote GI rotation plan (DRY-RUN ONLY)"
    )
    parser.add_argument(
        "--environment",
        required=True,
        choices=sorted(VALID_ENVIRONMENTS),
        help="Target environment (staging or production)",
    )
    parser.add_argument(
        "--token",
        required=True,
        choices=sorted(VALID_TOKENS),
        help="Target GI token to rotate",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Mandatory dry-run flag",
    )
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)

    if not args.dry_run:
        print("DRY_RUN_REQUIRED: --dry-run must be explicitly specified")
        print("GI_ROTATION_REMOTE_PLAN=FAIL")
        return 1

    environment = args.environment
    token = args.token

    print("========================================")
    print("GSE REMOTE GI ROTATION")
    print("MODE=DRY_RUN")
    print("========================================")
    print()

    if not CURRENT_INCIDENT.is_file():
        print("current_incident=ABSENT")
        print("GI_ROTATION_REMOTE_PLAN=FAIL")
        return 1

    incident_id = CURRENT_INCIDENT.read_text(
        encoding="utf-8"
    ).strip()

    if not INCIDENT_RE.fullmatch(incident_id):
        print("incident_id_validation=FAIL")
        print("GI_ROTATION_REMOTE_PLAN=FAIL")
        return 1

    host, remote_base = load_config()

    remote_dir = f"{remote_base}/{incident_id}"
    remote_extract = f"{remote_dir}/package"
    remote_plan_script = (
        f"{remote_extract}/"
        "rotations/gi/gi-rotate-plan.py"
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
            remote_plan_script,
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )

    if check_res.returncode != 0:
        print("REMOTE_SANDBOX=ABSENT")
        print("GI_ROTATION_REMOTE_PLAN=FAIL")
        return 1

    print("sandbox_presence=PASS")
    print()

    print("step=generate-rotation-plan")
    print()

    result = subprocess.run(
        [
            "ssh",
            host,
            "python3",
            remote_plan_script,
            "--environment",
            environment,
            "--token",
            token,
            "--dry-run",
        ],
        cwd=str(ROOT),
        check=False,
    )

    print()

    if result.returncode != 0:
        print("GI_ROTATION_REMOTE_PLAN=FAIL")
        return 1

    print("GI_ROTATION_REMOTE_PLAN=PASS")
    print("ACTUAL_CHANGES=NO")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(
            f"GI_ROTATION_ERROR="
            f"{type(exc).__name__}"
        )
        print("GI_ROTATION_REMOTE_PLAN=FAIL")
        sys.exit(1)
