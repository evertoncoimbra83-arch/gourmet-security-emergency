from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parent.parent

IGNORED_DIRS = {
    ".git",
    "__pycache__",
    "runtime",
    "backups",
    "node_modules",
}

ALLOWED_SUFFIXES = {
    ".py",
    ".json",
    ".md",
    ".txt",
    ".cmd",
    ".bat",
    ".sh",
    ".yaml",
    ".yml",
}

SECRET_ASSIGNMENT = re.compile(
    r"""
    (?ix)
    \b(
        DATABASE_URL
        |DB_PASS
        |DB_PASSWORD
        |WC_DB_PASSWORD
        |SESSION_SECRET
        |JWT_SECRET
        |NEXTAUTH_SECRET
        |REDIS_PASSWORD
        |REDIS_URL
        |RESEND_API_KEY
        |CLOUDINARY_API_SECRET
        |ENCRYPTION_KEY
        |DB_ENCRYPTION_KEY
        |PII_PEPPER
        |API_KEY_PEPPER
        |LOCKBOX_MASTER_SECRET
        |GI_ATTENTION_READ_TOKEN
        |GI_RECOMMENDATION_READ_TOKEN
        |GI_PROPOSAL_READ_TOKEN
        |GI_SITE_PRE_PREPARE_TOKEN
    )
    \s*=
    \s*
    ["']?
    ([^\s"'<>]+)
    """,
    re.VERBOSE,
)

PLACEHOLDER_VALUES = {
    "",
    "example",
    "placeholder",
    "changeme",
    "redacted",
    "<redacted>",
    "***",
}

FORBIDDEN_FILENAMES = {
    ".env",
    ".env.production",
    ".env.staging",
}

FORBIDDEN_SUFFIXES = {
    ".secret",
    ".pem",
    ".p12",
    ".pfx",
}


def ignored(path: Path) -> bool:
    return any(part in IGNORED_DIRS for part in path.parts)


def looks_forbidden_file(path: Path) -> bool:
    name = path.name.lower()

    if name in FORBIDDEN_FILENAMES:
        return True

    if path.suffix.lower() in FORBIDDEN_SUFFIXES:
        return True

    if path.suffix.lower() == ".key":
        return True

    return False


def scan():
    findings = []

    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue

        relative = path.relative_to(ROOT)

        if ignored(relative):
            continue

        if looks_forbidden_file(relative):
            findings.append(
                (
                    str(relative),
                    "FORBIDDEN_SECRET_FILE",
                )
            )
            continue

        if path.suffix.lower() not in ALLOWED_SUFFIXES:
            continue

        try:
            content = path.read_text(
                encoding="utf-8",
                errors="replace",
            )
        except OSError:
            findings.append(
                (
                    str(relative),
                    "UNREADABLE_FILE",
                )
            )
            continue

        for match in SECRET_ASSIGNMENT.finditer(content):
            key = match.group(1)
            value = match.group(2).strip().lower()

            if value in PLACEHOLDER_VALUES:
                continue

            findings.append(
                (
                    str(relative),
                    f"POSSIBLE_SECRET_ASSIGNMENT:{key}",
                )
            )

    return findings


def main():
    findings = scan()

    print("========================================")
    print("GSE SECURITY SELF-SCAN")
    print("========================================")
    print()

    if findings:
        print("SELF_SCAN=FAIL")
        print(f"findings={len(findings)}")

        for path, finding in findings:
            print(f"{path}: {finding}")

        print()
        print("SECRET_VALUES_PRINTED=NO")
        return 1

    print("findings=0")
    print("SECRET_VALUES_PRINTED=NO")
    print("SELF_SCAN=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())