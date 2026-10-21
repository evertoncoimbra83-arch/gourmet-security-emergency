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


def load_config():
    with CONFIG_PATH.open(
        "r",
        encoding="utf-8",
    ) as f:
        config = json.load(f)

    return (
        config["ssh_host"],
        config["remote_base"].rstrip("/"),
    )


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--execute",
        action="store_true",
    )

    args = parser.parse_args()

    if not CURRENT_INCIDENT.is_file():
        print("current_incident=ABSENT")
        return 1

    incident_id = CURRENT_INCIDENT.read_text(
        encoding="utf-8"
    ).strip()

    if not INCIDENT_RE.fullmatch(
        incident_id
    ):
        print("incident_id_validation=FAIL")
        return 1

    host, remote_base = load_config()

    remote_dir = (
        f"{remote_base}/{incident_id}"
    )

    print("========================================")
    print("GSE REMOTE CLEANUP")
    print("========================================")
    print()

    print(f"incident_id={incident_id}")
    print(f"remote_dir={remote_dir}")

    if not args.execute:
        print()
        print("MODE=DRY_RUN")
        print("REMOTE_DELETE=NO")
        print()
        print(
            "Use --execute to remove "
            "this exact incident directory."
        )
        return 0

    result = subprocess.run(
        [
            "ssh",
            host,
            "rm",
            "-rf",
            "--",
            remote_dir,
        ],
        check=False,
    )

    if result.returncode != 0:
        print("REMOTE_CLEANUP=FAIL")
        return 1

    CURRENT_INCIDENT.unlink(
        missing_ok=True
    )

    print()
    print("REMOTE_CLEANUP=PASS")
    print("CURRENT_INCIDENT_CLEARED=PASS")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())