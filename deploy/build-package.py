from pathlib import Path
import hashlib
import shutil
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parent.parent
DIST = ROOT / "dist"
PACKAGE_ROOT = DIST / "gse-package"
ZIP_PATH = DIST / "gse-package.zip"
MANIFEST_PATH = DIST / "manifest.sha256"

INCLUDED_PATHS = [
    "bin",
    "checks",
    "config",
    "lib",
    "rotations",
    "deploy",
    "docs",
    "README.md",
]

EXCLUDED_DIRS = {
    ".git",
    "__pycache__",
    "dist",
    "runtime",
    "backups",
    "incidents",
    "node_modules",
}

EXCLUDED_SUFFIXES = {
    ".secret",
    ".pem",
    ".key",
    ".p12",
    ".pfx",
}

EXCLUDED_NAMES = {
    ".env",
    ".env.production",
    ".env.staging",
}


def run_self_check():
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "bin" / "gse.py"),
            "self-check",
        ],
        cwd=str(ROOT),
        check=False,
    )

    if result.returncode != 0:
        raise SystemExit(
            "PACKAGE_BLOCKED: self-check failed"
        )


def forbidden(path: Path) -> bool:
    relative = path.relative_to(ROOT)

    if any(part in EXCLUDED_DIRS for part in relative.parts):
        return True

    if path.name.lower() in EXCLUDED_NAMES:
        return True

    if path.suffix.lower() in EXCLUDED_SUFFIXES:
        return True

    return False


def clean_dist():
    if DIST.exists():
        shutil.rmtree(DIST)

    PACKAGE_ROOT.mkdir(parents=True)


def copy_file(source: Path, destination: Path):
    destination.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    if source.suffix.lower() == ".sh":
        content = source.read_text(
            encoding="utf-8",
        )

        content = content.replace(
            "\r\n",
            "\n",
        ).replace(
            "\r",
            "\n",
        )

        destination.write_text(
            content,
            encoding="utf-8",
            newline="\n",
        )

        return

    shutil.copy2(
        source,
        destination,
    )


def copy_source():
    for item_name in INCLUDED_PATHS:
        source = ROOT / item_name

        if not source.exists():
            continue

        if source.is_file():
            if forbidden(source):
                continue

            destination = (
                PACKAGE_ROOT / item_name
            )

            copy_file(
                source,
                destination,
            )

            continue

        for source_file in source.rglob("*"):
            if not source_file.is_file():
                continue

            if forbidden(source_file):
                continue

            relative = source_file.relative_to(
                ROOT
            )

            destination = (
                PACKAGE_ROOT / relative
            )

            copy_file(
                source_file,
                destination,
            )

def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)

            if not chunk:
                break

            digest.update(chunk)

    return digest.hexdigest()


def write_manifest():
    lines = []

    for path in sorted(PACKAGE_ROOT.rglob("*")):
        if not path.is_file():
            continue

        relative = path.relative_to(PACKAGE_ROOT)
        digest = sha256_file(path)

        lines.append(
            f"{digest}  {relative.as_posix()}"
        )

    MANIFEST_PATH.write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )

    return len(lines)


def create_zip():
    with zipfile.ZipFile(
        ZIP_PATH,
        "w",
        compression=zipfile.ZIP_DEFLATED,
    ) as archive:
        for path in sorted(PACKAGE_ROOT.rglob("*")):
            if not path.is_file():
                continue

            relative = path.relative_to(PACKAGE_ROOT)

            archive.write(
                path,
                arcname=relative.as_posix(),
            )


def main():
    print("========================================")
    print("GSE SAFE PACKAGE BUILDER")
    print("========================================")
    print()

    print("step=self-check")
    run_self_check()
    print("self-check=PASS")
    print()

    print("step=clean-dist")
    clean_dist()
    print("clean-dist=PASS")

    print("step=copy-source")
    copy_source()
    print("copy-source=PASS")

    print("step=manifest")
    file_count = write_manifest()
    print(f"manifest_files={file_count}")
    print("manifest=PASS")

    print("step=zip")
    create_zip()
    print("zip=PASS")

    print()
    print(f"package={ZIP_PATH}")
    print(f"manifest={MANIFEST_PATH}")
    print("secret_values_stored=NO")
    print("PACKAGE_BUILD=PASS")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())