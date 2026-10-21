from pathlib import Path, PurePosixPath
import argparse
import hashlib
import re
import sys
import zipfile


HASH_RE = re.compile(
    r"^([0-9a-fA-F]{64})  (.+)$"
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


def safe_archive_name(name: str) -> bool:
    if not name:
        return False

    normalized = name.replace("\\", "/")

    if normalized.startswith("/"):
        return False

    if ":" in normalized.split("/")[0]:
        return False

    path = PurePosixPath(normalized)

    if path.is_absolute():
        return False

    if ".." in path.parts:
        return False

    return True


def load_manifest(path: Path):
    entries = {}

    for line_number, raw_line in enumerate(
        path.read_text(
            encoding="utf-8",
        ).splitlines(),
        start=1,
    ):
        line = raw_line.strip()

        if not line:
            continue

        match = HASH_RE.match(line)

        if not match:
            raise ValueError(
                f"invalid manifest line {line_number}"
            )

        digest = match.group(1).lower()
        filename = match.group(2).replace("\\", "/")

        if not safe_archive_name(filename):
            raise ValueError(
                f"unsafe manifest path at line {line_number}"
            )

        if filename in entries:
            raise ValueError(
                f"duplicate manifest entry: {filename}"
            )

        entries[filename] = digest

    if not entries:
        raise ValueError("manifest is empty")

    return entries


def hash_zip_member(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
) -> str:
    digest = hashlib.sha256()

    with archive.open(info, "r") as source:
        while True:
            chunk = source.read(1024 * 1024)

            if not chunk:
                break

            digest.update(chunk)

    return digest.hexdigest()


def verify(zip_path: Path, manifest_path: Path):
    expected = load_manifest(manifest_path)

    with zipfile.ZipFile(zip_path, "r") as archive:
        infos = [
            info
            for info in archive.infolist()
            if not info.is_dir()
        ]

        actual = {}

        for info in infos:
            name = info.filename.replace("\\", "/")

            if not safe_archive_name(name):
                raise ValueError(
                    f"unsafe archive path: {name}"
                )

            if name in actual:
                raise ValueError(
                    f"duplicate archive entry: {name}"
                )

            actual[name] = info

        expected_names = set(expected)
        actual_names = set(actual)

        missing = sorted(
            expected_names - actual_names
        )

        unexpected = sorted(
            actual_names - expected_names
        )

        if missing:
            raise ValueError(
                f"missing archive files: {len(missing)}"
            )

        if unexpected:
            raise ValueError(
                f"unexpected archive files: "
                f"{len(unexpected)}"
            )

        for name in sorted(expected):
            calculated = hash_zip_member(
                archive,
                actual[name],
            )

            if calculated != expected[name]:
                raise ValueError(
                    f"hash mismatch: {name}"
                )

    return len(expected)


def main():
    parser = argparse.ArgumentParser(
        description="Verify GSE package integrity"
    )

    parser.add_argument(
        "--zip",
        dest="zip_path",
        required=True,
    )

    parser.add_argument(
        "--manifest",
        dest="manifest_path",
        required=True,
    )

    args = parser.parse_args()

    zip_path = Path(args.zip_path).resolve()
    manifest_path = Path(
        args.manifest_path
    ).resolve()

    print("========================================")
    print("GSE PACKAGE INTEGRITY VERIFIER")
    print("========================================")
    print()

    if not zip_path.is_file():
        print("zip_present=FAIL")
        print("PACKAGE_VERIFY=FAIL")
        return 1

    print("zip_present=PASS")

    if not manifest_path.is_file():
        print("manifest_present=FAIL")
        print("PACKAGE_VERIFY=FAIL")
        return 1

    print("manifest_present=PASS")

    try:
        file_count = verify(
            zip_path,
            manifest_path,
        )
    except (
        OSError,
        ValueError,
        zipfile.BadZipFile,
    ) as exc:
        print(
            f"verification_error="
            f"{type(exc).__name__}"
        )
        print("PACKAGE_VERIFY=FAIL")
        return 1

    package_hash = sha256_file(zip_path)

    print(f"verified_files={file_count}")
    print("archive_paths=SAFE")
    print("file_hashes=PASS")
    print(f"package_sha256={package_hash}")
    print("PACKAGE_VERIFY=PASS")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())