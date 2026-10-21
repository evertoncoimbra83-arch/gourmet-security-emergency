from pathlib import Path
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


def run(command, *, capture=False):
    result = subprocess.run(
        command,
        cwd=str(ROOT),
        text=True,
        capture_output=capture,
        check=False,
    )

    if result.returncode != 0:
        if capture:
            print(result.stdout)
            print(result.stderr)

        raise RuntimeError(
            f"command failed: {command[0]}"
        )

    return result


def main():
    print("========================================")
    print("GSE REMOTE PREFLIGHT RUNNER")
    print("========================================")
    print()

    if not CURRENT_INCIDENT.is_file():
        print("current_incident=ABSENT")
        print("REMOTE_PREFLIGHT_RUN=FAIL")
        return 1

    incident_id = CURRENT_INCIDENT.read_text(
        encoding="utf-8"
    ).strip()

    if not INCIDENT_RE.fullmatch(
        incident_id
    ):
        print("incident_id_validation=FAIL")
        print("REMOTE_PREFLIGHT_RUN=FAIL")
        return 1

    host, remote_base = load_config()

    remote_dir = (
        f"{remote_base}/{incident_id}"
    )

    remote_zip = (
        f"{remote_dir}/gse-package.zip"
    )

    remote_manifest = (
        f"{remote_dir}/manifest.sha256"
    )

    remote_extract = (
        f"{remote_dir}/package"
    )

    print(f"incident_id={incident_id}")
    print(f"remote_dir={remote_dir}")
    print()

    print("step=verify-upload-presence")

    result = run(
        [
            "ssh",
            host,
            "test",
            "-f",
            remote_zip,
            "-a",
            "-f",
            remote_manifest,
        ],
        capture=True,
    )

    print("upload_presence=PASS")

    print("step=prepare-sandbox")

    run(
        [
            "ssh",
            host,
            "mkdir",
            "-m",
            "700",
            "-p",
            remote_extract,
        ]
    )

    print("sandbox_directory=PASS")

    print("step=extract-package")

    remote_command = (
        "python3 - "
        f"{remote_zip} "
        f"{remote_extract}"
    )

    extraction_script = r'''
from pathlib import Path, PurePosixPath
import sys
import zipfile

zip_path = Path(sys.argv[1])
target = Path(sys.argv[2])

with zipfile.ZipFile(zip_path, "r") as archive:
    for info in archive.infolist():
        name = info.filename.replace("\\", "/")
        path = PurePosixPath(name)

        if (
            not name
            or name.startswith("/")
            or path.is_absolute()
            or ".." in path.parts
            or ":" in path.parts[0]
        ):
            raise SystemExit(
                "unsafe archive path"
            )

    archive.extractall(target)

print("REMOTE_EXTRACTION=PASS")
'''

    result = subprocess.run(
        [
            "ssh",
            host,
            remote_command,
        ],
        input=extraction_script,
        text=True,
        cwd=str(ROOT),
        check=False,
    )

    if result.returncode != 0:
        print("REMOTE_EXTRACTION=FAIL")
        print("REMOTE_PREFLIGHT_RUN=FAIL")
        return 1

    print("step=verify-extracted-files")

    verifier = (
        f"{remote_extract}/"
        "deploy/verify-package.py"
    )

    run(
        [
            "ssh",
            host,
            "python3",
            verifier,
            "--zip",
            remote_zip,
            "--manifest",
            remote_manifest,
        ]
    )

    print("remote_package_verify=PASS")

    preflight = (
        f"{remote_extract}/"
        "checks/remote-preflight.sh"
    )

    print("step=run-read-only-preflight")
    print()

    result = subprocess.run(
        [
            "ssh",
            host,
            "bash",
            preflight,
        ],
        cwd=str(ROOT),
        check=False,
    )

    print()

    if result.returncode != 0:
        print("REMOTE_PREFLIGHT_SCRIPT=FAIL")
        print("REMOTE_PREFLIGHT_RUN=FAIL")
        return 1

    print("REMOTE_PREFLIGHT_SCRIPT=PASS")
    print("SECRETS_READ=NO")
    print("SERVICES_RESTARTED=NO")
    print("DATABASE_WRITES=NO")
    print("REMOTE_PREFLIGHT_RUN=PASS")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(
            f"REMOTE_PREFLIGHT_ERROR="
            f"{type(exc).__name__}"
        )
        print("REMOTE_PREFLIGHT_RUN=FAIL")
        raise SystemExit(1)