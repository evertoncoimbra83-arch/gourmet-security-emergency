from pathlib import Path
import json
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
REGISTRY = ROOT / "config" / "secret-registry.json"
SECURITY_SCAN = ROOT / "checks" / "security_scan.py"

VERSION = "0.2.0"

VALID_CLASSIFICATIONS = {
    "AUTO_ROTATE",
    "COORDINATED_ROTATE",
    "PROVIDER_ACTION_REQUIRED",
    "MANUAL_MIGRATION_REQUIRED",
    "MANUAL_REVIEW_REQUIRED",
}

VALID_RISKS = {
    "low",
    "medium",
    "high",
    "critical",
}


def load_registry():
    with REGISTRY.open("r", encoding="utf-8") as f:
        return json.load(f)


def validate_registry():
    registry = load_registry()

    if not isinstance(registry, dict):
        raise ValueError("registry must be an object")

    if not isinstance(registry.get("version"), int):
        raise ValueError("registry.version must be integer")

    secrets = registry.get("secrets")

    if not isinstance(secrets, dict):
        raise ValueError("registry.secrets must be an object")

    if not secrets:
        raise ValueError("registry.secrets cannot be empty")

    for name, info in secrets.items():
        if not isinstance(name, str) or not name:
            raise ValueError("invalid secret name")

        if not isinstance(info, dict):
            raise ValueError(
                f"{name}: definition must be object"
            )

        classification = info.get("classification")
        risk = info.get("risk")

        if classification not in VALID_CLASSIFICATIONS:
            raise ValueError(
                f"{name}: invalid classification"
            )

        if risk not in VALID_RISKS:
            raise ValueError(
                f"{name}: invalid risk"
            )

    return registry


def command_status():
    registry = validate_registry()

    print("========================================")
    print("GOURMET SECURITY EMERGENCY")
    print(f"VERSION={VERSION}")
    print("MODE=OFFLINE")
    print("========================================")
    print()

    groups = {}

    for name, info in registry["secrets"].items():
        classification = info["classification"]

        groups.setdefault(classification, [])
        groups[classification].append(name)

    for classification, names in groups.items():
        print(classification)

        for name in sorted(names):
            print(f"  - {name}")

        print()


def command_audit():
    registry = validate_registry()

    print("========================================")
    print("GSE OFFLINE AUDIT")
    print("========================================")
    print()

    print(f"registry_version={registry['version']}")
    print(f"registered_secrets={len(registry['secrets'])}")
    print("secret_values_loaded=NO")
    print("server_contact=NO")
    print("production_contact=NO")
    print("audit=PASS")


def command_self_check():
    print("========================================")
    print("GSE SELF CHECK")
    print("========================================")
    print()

    try:
        registry = validate_registry()
    except Exception as exc:
        print("registry_validation=FAIL")
        print(f"reason={type(exc).__name__}")
        print("SELF_CHECK=FAIL")
        return 1

    print("registry_validation=PASS")
    print(f"registry_version={registry['version']}")
    print(
        f"registered_secrets="
        f"{len(registry['secrets'])}"
    )

    if not SECURITY_SCAN.is_file():
        print("security_scan_present=FAIL")
        print("SELF_CHECK=FAIL")
        return 1

    print("security_scan_present=PASS")
    print()

    result = subprocess.run(
        [
            sys.executable,
            str(SECURITY_SCAN),
        ],
        cwd=str(ROOT),
        check=False,
    )

    print()

    if result.returncode != 0:
        print("security_scan_execution=FAIL")
        print("SELF_CHECK=FAIL")
        return 1

    print("security_scan_execution=PASS")
    print("server_contact=NO")
    print("production_contact=NO")
    print("SELF_CHECK=PASS")

    return 0


def usage():
    print("Usage:")
    print(r"  python bin\gse.py status")
    print(r"  python bin\gse.py audit")
    print(r"  python bin\gse.py self-check")


def main():
    if len(sys.argv) != 2:
        usage()
        return 1

    command = sys.argv[1].lower()

    if command == "status":
        command_status()
        return 0

    if command == "audit":
        command_audit()
        return 0

    if command == "self-check":
        return command_self_check()

    usage()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())