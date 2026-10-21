from pathlib import Path
import shutil
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "dist" / "gse-package-tampered.zip"


def main():
    if not SOURCE.is_file():
        raise SystemExit("tampered zip not found")

    with tempfile.TemporaryDirectory() as temp_dir:
        temp = Path(temp_dir)

        with zipfile.ZipFile(SOURCE, "r") as archive:
            archive.extractall(temp)

        readme = temp / "README.md"

        if not readme.is_file():
            raise SystemExit("README.md not found in package")

        with readme.open("a", encoding="utf-8") as f:
            f.write(
                "\nTAMPER_TEST=THIS_PACKAGE_WAS_MODIFIED\n"
            )

        new_zip = temp / "rebuilt.zip"

        with zipfile.ZipFile(
            new_zip,
            "w",
            compression=zipfile.ZIP_DEFLATED,
        ) as archive:
            for path in sorted(temp.rglob("*")):
                if not path.is_file():
                    continue

                if path == new_zip:
                    continue

                relative = path.relative_to(temp)

                archive.write(
                    path,
                    arcname=relative.as_posix(),
                )

        shutil.copy2(new_zip, SOURCE)

    print("TAMPER_TEST_PACKAGE_CREATED=PASS")


if __name__ == "__main__":
    main()