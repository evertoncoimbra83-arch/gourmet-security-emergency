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


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run remote GI rotation preflight (READ-ONLY)"
    )
    parser.add_argument(
        "--environment",
        required=True,
        choices=sorted(VALID_ENVIRONMENTS),
        help="Target environment (staging or production)",
    )
    return parser.parse_args()


def main():
    print("========================================")
    print("GSE REMOTE GI PREFLIGHT RUNNER")
    print("MODE=READ_ONLY")
    print("========================================")
    print()

    args = parse_args()
    environment = args.environment

    if not CURRENT_INCIDENT.is_file():
        print("current_incident=ABSENT")
        print("GI_PREFLIGHT_REMOTE_RUN=FAIL")
        return 1

    incident_id = CURRENT_INCIDENT.read_text(
        encoding="utf-8"
    ).strip()

    if not INCIDENT_RE.fullmatch(incident_id):
        print("incident_id_validation=FAIL")
        print("GI_PREFLIGHT_REMOTE_RUN=FAIL")
        return 1

    host, remote_base = load_config()

    remote_dir = f"{remote_base}/{incident_id}"
    remote_extract = f"{remote_dir}/package"
    remote_preflight = (
        f"{remote_extract}/"
        "rotations/gi/gi-preflight.sh"
    )

    print(f"incident_id={incident_id}")
    print(f"environment={environment}")
    print(f"remote_dir={remote_dir}")
    print()

    print("step=verify-sandbox-presence")

    check_res = subprocess.run(
        [
            "ssh",
            host,
            "test",
            "-f",
            remote_preflight,
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )

    if check_res.returncode != 0:
        print("REMOTE_SANDBOX=ABSENT")
        print("GI_PREFLIGHT_REMOTE_RUN=FAIL")
        return 1

    print("sandbox_presence=PASS")
    print()

    print("step=run-gi-preflight")
    print()

    result = subprocess.run(
        [
            "ssh",
            host,
            "bash",
            remote_preflight,
            environment,
        ],
        cwd=str(ROOT),
        check=False,
    )

    print()

    if result.returncode != 0:
        print("GI_PREFLIGHT_REMOTE_SCRIPT=FAIL")
        print("GI_PREFLIGHT_REMOTE_RUN=FAIL")
        return 1

    print("GI_PREFLIGHT_REMOTE_SCRIPT=PASS")
    print("GI_PREFLIGHT_REMOTE_RUN=PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(
            f"GI_PREFLIGHT_ERROR="
            f"{type(exc).__name__}"
        )
        print("GI_PREFLIGHT_REMOTE_RUN=FAIL")
        raise SystemExit(1)
