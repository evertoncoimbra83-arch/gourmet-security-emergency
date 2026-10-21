from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parent.parent

CONFIG_PATH = ROOT / "config" / "transport.json"

ZIP_PATH = ROOT / "dist" / "gse-package.zip"
MANIFEST_PATH = ROOT / "dist" / "manifest.sha256"

RUNTIME_DIR = ROOT / "runtime"
CURRENT_INCIDENT = RUNTIME_DIR / "current-incident.txt"

INCIDENT_RE = re.compile(
    r"^GSE-[0-9]{8}T[0-9]{6}Z$"
)


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


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)

            if not chunk:
                break

            digest.update(chunk)

    return digest.hexdigest()


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


def make_incident_id():
    value = datetime.now(
        timezone.utc
    ).strftime("GSE-%Y%m%dT%H%M%SZ")

    if not INCIDENT_RE.fullmatch(value):
        raise RuntimeError(
            "generated incident id is invalid"
        )

    return value


def remote_hash(host, remote_path):
    result = run(
        [
            "ssh",
            host,
            "sha256sum",
            "--",
            remote_path,
        ],
        capture=True,
    )

    output = result.stdout.strip()

    if not output:
        raise RuntimeError(
            "remote sha256 returned empty output"
        )

    digest = output.split()[0].lower()

    if not re.fullmatch(
        r"[0-9a-f]{64}",
        digest,
    ):
        raise RuntimeError(
            "invalid remote sha256"
        )

    return digest


def main():
    print("========================================")
    print("GSE SAFE TRANSPORT")
    print("========================================")
    print()

    host, remote_base = load_config()

    print("step=self-check")

    run(
        [
            sys.executable,
            str(ROOT / "bin" / "gse.py"),
            "self-check",
        ]
    )

    print("self-check=PASS")
    print()

    print("step=build-package")

    run(
        [
            sys.executable,
            str(
                ROOT
                / "deploy"
                / "build-package.py"
            ),
        ]
    )

    print("build-package=PASS")
    print()

    print("step=verify-local-package")

    run(
        [
            sys.executable,
            str(
                ROOT
                / "deploy"
                / "verify-package.py"
            ),
            "--zip",
            str(ZIP_PATH),
            "--manifest",
            str(MANIFEST_PATH),
        ]
    )

    print("verify-local-package=PASS")
    print()

    zip_hash = sha256_file(ZIP_PATH)
    manifest_hash = sha256_file(
        MANIFEST_PATH
    )

    incident_id = make_incident_id()

    remote_dir = (
        f"{remote_base}/{incident_id}"
    )

    remote_zip = (
        f"{remote_dir}/gse-package.zip"
    )

    remote_manifest = (
        f"{remote_dir}/manifest.sha256"
    )

    print(f"incident_id={incident_id}")
    print(f"ssh_host={host}")
    print(f"remote_dir={remote_dir}")
    print()

    print("step=create-remote-directory")

    run(
        [
            "ssh",
            host,
            "mkdir",
            "-m",
            "700",
            "-p",
            remote_dir,
        ]
    )

    print("remote_directory=PASS")

    print("step=upload")

    run(
        [
            "scp",
            str(ZIP_PATH),
            f"{host}:{remote_zip}",
        ]
    )

    run(
        [
            "scp",
            str(MANIFEST_PATH),
            f"{host}:{remote_manifest}",
        ]
    )

    print("upload=PASS")

    print("step=protect-remote-files")

    run(
        [
            "ssh",
            host,
            "chmod",
            "600",
            remote_zip,
            remote_manifest,
        ]
    )

    print("remote_permissions=PASS")

    print("step=remote-integrity")

    remote_zip_hash = remote_hash(
        host,
        remote_zip,
    )

    remote_manifest_hash = remote_hash(
        host,
        remote_manifest,
    )

    if remote_zip_hash != zip_hash:
        raise RuntimeError(
            "remote ZIP hash mismatch"
        )

    if remote_manifest_hash != manifest_hash:
        raise RuntimeError(
            "remote manifest hash mismatch"
        )

    print("zip_hash_parity=PASS")
    print("manifest_hash_parity=PASS")

    RUNTIME_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    CURRENT_INCIDENT.write_text(
        incident_id + "\n",
        encoding="utf-8",
    )

    print()
    print("PACKAGE_EXECUTED=NO")
    print("PACKAGE_EXTRACTED=NO")
    print("SERVER_SECRETS_READ=NO")
    print("PM2_TOUCHED=NO")
    print("DOCKER_TOUCHED=NO")
    print("DATABASE_TOUCHED=NO")
    print("GSE_UPLOAD=PASS")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print()
        print(
            f"UPLOAD_ERROR="
            f"{type(exc).__name__}"
        )
        print("GSE_UPLOAD=FAIL")
        raise SystemExit(1)