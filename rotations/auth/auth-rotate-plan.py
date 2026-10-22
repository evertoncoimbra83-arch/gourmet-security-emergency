import argparse
import json
from pathlib import Path

REGISTRY = Path(__file__).with_name("auth-registry.json")
IMPACTS = {
    "SESSION_SECRET": "ACTIVE_SESSIONS_MAY_BE_INVALIDATED",
    "JWT_SECRET": "ACTIVE_JWTS_MAY_BE_INVALIDATED",
    "NEXTAUTH_SECRET": "NEXTAUTH_SESSIONS_OR_TOKENS_MAY_BE_INVALIDATED",
}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--environment", required=True)
    parser.add_argument("--secret", required=True)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    if not args.dry_run:
        print("DRY_RUN_REQUIRED=FAIL")
        return 1
    if args.environment != "staging" or args.secret not in IMPACTS:
        print("AUTH_ROTATION_PLAN=FAIL")
        return 1
    config = json.loads(REGISTRY.read_text(encoding="utf-8"))["staging"]
    if args.secret not in config["secrets"]:
        print("AUTH_ROTATION_PLAN=FAIL")
        return 1
    for key, value in (
        ("environment", args.environment), ("secret", args.secret),
        ("preflight_required", "YES"), ("backup_required", "YES"),
        ("rollback_required", "YES"),
        ("site_env_configured", "YES" if config.get("site_env") else "NO"),
        ("site_process_configured", "YES" if config.get("site_process") else "NO"),
        ("worker_process_configured", "YES" if config.get("worker_process") else "NO"),
        ("WOULD_GENERATE_NEW_SECRET", "YES"),
        ("WOULD_BACKUP_SITE_ENV", "YES"),
        ("WOULD_UPDATE_SITE_ENV", "YES"),
        ("WOULD_RESTART_SITE_API", "YES"),
        ("WOULD_RESTART_WORKER", "NO"),
        ("EXPECTED_IMPACT", IMPACTS[args.secret]),
        ("ACTUAL_SECRET_GENERATED", "NO"),
        ("ACTUAL_FILES_CHANGED", "NO"),
        ("ACTUAL_SERVICES_RESTARTED", "NO"),
        ("ACTUAL_DATABASE_TOUCHED", "NO"),
        ("AUTH_ROTATION_PLAN", "PASS"),
    ):
        print(f"{key}={value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
