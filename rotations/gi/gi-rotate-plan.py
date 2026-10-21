from pathlib import Path
import argparse
import json
import sys

ROOT = Path(__file__).resolve().parent.parent.parent
REGISTRY_PATH = ROOT / "rotations" / "gi" / "gi-registry.json"

ALLOWED_ENVIRONMENTS = {
    "staging",
    "production",
}

ALLOWED_TOKENS = {
    "GI_ATTENTION_READ_TOKEN",
    "GI_RECOMMENDATION_READ_TOKEN",
    "GI_PROPOSAL_READ_TOKEN",
    "GI_SITE_PRE_PREPARE_TOKEN",
}


def load_registry():
    if not REGISTRY_PATH.is_file():
        raise FileNotFoundError(f"Registry not found: {REGISTRY_PATH}")
    with REGISTRY_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)


def build_rotation_plan(environment: str, token: str, dry_run: bool) -> dict:
    if not dry_run:
        raise ValueError("DRY_RUN_REQUIRED")

    if environment not in ALLOWED_ENVIRONMENTS:
        raise ValueError(f"Invalid environment: {environment}")

    if token not in ALLOWED_TOKENS:
        raise ValueError(f"Invalid token: {token}")

    registry = load_registry()
    env_config = registry.get(environment)
    if not env_config or not isinstance(env_config, dict):
        raise ValueError(f"Environment not configured: {environment}")

    tokens_config = env_config.get("tokens", {})
    if token not in tokens_config:
        raise KeyError("TOKEN_NOT_AVAILABLE_IN_ENVIRONMENT")

    token_meta = tokens_config[token]
    required_in_site = bool(token_meta.get("required_in_site_env", False))

    secret_file = token_meta.get("secret_file")
    site_env = env_config.get("site_env")
    site_process = env_config.get("site_process")
    worker_process = env_config.get("worker_process")

    # Determine affected containers
    if token == "GI_SITE_PRE_PREPARE_TOKEN":
        affected_containers = ["gi_staging_http_03c_f3b3b2_shadow"]
    else:
        affected_containers = list(env_config.get("containers", []))

    return {
        "environment": environment,
        "token": token,
        "secret_file": secret_file,
        "site_env": site_env,
        "site_process": site_process,
        "worker_process": worker_process,
        "required_in_site_env": required_in_site,
        "containers": affected_containers,
        "would_generate_new_token": True,
        "would_backup_secret_file": True,
        "would_backup_site_env": required_in_site,
        "would_update_secret_file": True,
        "would_update_site_env": required_in_site,
        "would_restart_gi_containers": True,
        "would_restart_site_api": required_in_site,
        "would_restart_worker": False,
        "rollback_strategy": "RESTORE_FILES_AND_RESTART_AFFECTED_SERVICES",
    }


def print_rotation_plan(plan: dict):
    print("========================================")
    print("GSE GI ROTATION PLAN")
    print("MODE=DRY_RUN")
    print("========================================")
    print()
    print(f"environment={plan['environment']}")
    print(f"token={plan['token']}")
    print()
    print("preflight_required=YES")
    print("backup_required=YES")
    print("rollback_required=YES")
    print()
    print(f"secret_file_configured={'YES' if plan['secret_file'] else 'NO'}")
    print(f"site_env_configured={'YES' if plan['site_env'] else 'NO'}")
    print(f"site_process_configured={'YES' if plan['site_process'] else 'NO'}")
    print(f"worker_process_configured={'YES' if plan['worker_process'] else 'NO'}")
    print()
    print(f"required_in_site_env={'YES' if plan['required_in_site_env'] else 'NO'}")
    print()
    print(f"containers_count={len(plan['containers'])}")
    for c in plan["containers"]:
        print(f"container={c}")
    print()
    print(f"WOULD_GENERATE_NEW_TOKEN={'YES' if plan['would_generate_new_token'] else 'NO'}")
    print(f"WOULD_BACKUP_SECRET_FILE={'YES' if plan['would_backup_secret_file'] else 'NO'}")
    print(f"WOULD_BACKUP_SITE_ENV={'YES' if plan['would_backup_site_env'] else 'NO'}")
    print(f"WOULD_UPDATE_SECRET_FILE={'YES' if plan['would_update_secret_file'] else 'NO'}")
    print(f"WOULD_UPDATE_SITE_ENV={'YES' if plan['would_update_site_env'] else 'NO'}")
    print(f"WOULD_RESTART_GI_CONTAINERS={'YES' if plan['would_restart_gi_containers'] else 'NO'}")
    print(f"WOULD_RESTART_SITE_API={'YES' if plan['would_restart_site_api'] else 'NO'}")
    print(f"WOULD_RESTART_WORKER={'YES' if plan['would_restart_worker'] else 'NO'}")
    print()
    print(f"rollback_strategy={plan['rollback_strategy']}")
    print()
    print("ACTUAL_SECRET_GENERATED=NO")
    print("ACTUAL_FILES_CHANGED=NO")
    print("ACTUAL_SERVICES_RESTARTED=NO")
    print("ACTUAL_DATABASE_TOUCHED=NO")
    print()
    print("GI_ROTATION_PLAN=PASS")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="GSE GI Rotation Plan Generator (DRY-RUN ONLY)"
    )
    parser.add_argument(
        "--environment",
        required=True,
        choices=sorted(ALLOWED_ENVIRONMENTS),
        help="Target environment (staging or production)",
    )
    parser.add_argument(
        "--token",
        required=True,
        choices=sorted(ALLOWED_TOKENS),
        help="Target GI token to rotate",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Mandatory dry-run flag",
    )
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)

    if not args.dry_run:
        print("DRY_RUN_REQUIRED: --dry-run must be explicitly specified")
        return 1

    try:
        plan = build_rotation_plan(
            environment=args.environment,
            token=args.token,
            dry_run=args.dry_run,
        )
    except KeyError as exc:
        if str(exc) == "'TOKEN_NOT_AVAILABLE_IN_ENVIRONMENT'":
            print("TOKEN_NOT_AVAILABLE_IN_ENVIRONMENT")
        else:
            print(f"ERROR: {exc}")
        return 1
    except Exception as exc:
        print(f"ERROR: {exc}")
        return 1

    print_rotation_plan(plan)
    return 0


if __name__ == "__main__":
    sys.exit(main())
