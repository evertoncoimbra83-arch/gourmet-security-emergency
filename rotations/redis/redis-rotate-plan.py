"""GSE-03B5A Redis staging rotation model. Dry-run and synthetic fixtures only.

No remote transport, Redis command, service control, or real target write exists
in this module. The atomic-write helper is confined to a temporary fixture copy.
"""
import argparse
import json
import os
import re
import secrets
import shlex
import shutil
import stat
import tempfile
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit, urlunsplit

REGISTRY = Path(__file__).with_name("redis-registry.json")
INCIDENT_RE = re.compile(r"GSE-[0-9]{8}T[0-9]{6}Z\Z")
FIXTURE_MARKER = b"# GSE_SYNTHETIC_FIXTURE"
PLAN_STEPS = (
    "BACKUP_SITE_ENV", "BACKUP_REDIS_CONFIG", "GENERATE_NEW_REDIS_PASSWORD",
    "UPDATE_REDIS_REQUIREPASS", "UPDATE_REDIS_URL",
    "UPDATE_REDUNDANT_REDIS_PASSWORD", "VALIDATE_UPDATED_FILES",
    "RESTART_REDIS", "VERIFY_REDIS_PING", "RESTART_SITE_API",
    "RESTART_SITE_WORKER", "VERIFY_APPLICATION_HEALTH",
    "POST_ROTATION_PARITY_CHECK", "CLEANUP_TEMP_FILES",
)
ROLLBACK_STEPS = (
    "RESTORE_REDIS_CONFIG", "RESTORE_SITE_ENV",
    "RESTART_REDIS_WITH_OLD_CONFIG", "RESTART_SITE_API",
    "RESTART_SITE_WORKER", "VERIFY_OLD_REDIS_PING",
    "VERIFY_APPLICATION_HEALTH",
)
FAULT_CHECKPOINTS = (
    "BACKUP_SITE_ENV", "BACKUP_REDIS_CONFIG", "UPDATE_REDIS_REQUIREPASS",
    "UPDATE_REDUNDANT_REDIS_PASSWORD", "RESTART_REDIS", "VERIFY_REDIS_PING",
    "RESTART_SITE_API", "RESTART_SITE_WORKER", "VERIFY_APPLICATION_HEALTH",
)
EVIDENCE_EXPECTED = {
    "redis_discovery_contract_version": "2",
    "redis_config_authority_required": "YES",
    "redis_config_authority": "PM2_SCRIPT_ARGUMENT",
    "active_requirepass_vs_redis_url": "SAME",
    "active_requirepass_vs_redis_password": "DIFFERENT",
    "redis_url_vs_redis_password": "DIFFERENT",
    "ROTATION_READINESS": "READY", "FUTURE_ROTATION_SEQUENCE": "KNOWN",
    "redis_target_host": "127.0.0.1", "redis_target_port": "6380",
    "redis_target_db": "0", "SITE_REDIS_SERVER_IDENTIFIED": "YES",
    "site_redis_server_type": "LOCAL_PROCESS", "redis_active_config_match": "YES",
    "redis_process_user": "gsadmin", "redis_managed_by_pm2": "YES",
    "redis_credential_source": "REDIS_CONF", "redis_server_auth_model": "REQUIREPASS",
    "config_requirepass_present": "YES", "config_aclfile_present": "NO",
    "CONNECTIVITY_WITH_REDIS_URL_CREDENTIAL": "PASS",
    "CONNECTIVITY_WITH_REDIS_PASSWORD": "FAIL", "REDIS_CONNECTIVITY": "PASS",
    "redis_password_url_parity": "FAIL",
    "REDIS_CREDENTIAL_RELATIONSHIP": "INCONSISTENT_CONFIGURATION",
    "SITE_API_USES_REDIS": "YES", "SITE_WORKER_USES_REDIS": "YES",
    "SITE_API_RESTART_REQUIRED_ON_ROTATION": "YES",
    "SITE_WORKER_RESTART_REQUIRED_ON_ROTATION": "YES",
    "future_backup_targets": "2", "future_restart_targets": "2",
}


class PlanBlocked(Exception):
    """Only fixed, non-sensitive reason codes may be raised."""


def fail(code):
    raise PlanBlocked(code)


def load_evidence(path):
    """Read only named metadata; discard all unrecognized preflight lines."""
    if Path(path).stat().st_size > 128 * 1024:
        fail("EVIDENCE_TOO_LARGE")
    return parse_evidence_text(Path(path).read_text(encoding="utf-8", errors="replace"))


def parse_evidence_text(raw):
    """Parse captured preflight metadata without storing it on disk."""
    if len(raw) > 128 * 1024:
        fail("EVIDENCE_TOO_LARGE")
    accepted = set(EVIDENCE_EXPECTED) | {
        "redis_config_path", "redis_executable", "redis_process_cwd",
        "site_redis_server_name", "future_backup_target",
        "redis_socket_listening", "redis_socket_address_match",
        "redis_listener_owner_visible", "redis_listener_pid",
        "redis_auth_ping", "requirepass_status",
        "config_port", "config_bind", "config_dir", "config_dbfilename",
    }
    evidence = {}
    backups = []
    for line in raw.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key not in accepted:
            continue
        if key == "future_backup_target":
            backups.append(value)
        elif key in evidence:
            fail("DUPLICATE_EVIDENCE_KEY")
        else:
            evidence[key] = value
    evidence["future_backup_target"] = backups
    return evidence


def validate_evidence(evidence, config):
    if any(evidence.get(key) != value for key, value in EVIDENCE_EXPECTED.items()):
        fail("READINESS_PRECONDITION_FAILED")
    expected_config = config.get("expected_config_candidates", [])
    if len(expected_config) != 1 or evidence.get("redis_config_path") != expected_config[0]:
        fail("CONFIG_TARGET_MISMATCH")
    if evidence.get("future_backup_target") != [config.get("site_env"), expected_config[0]]:
        fail("BACKUP_TARGET_MISMATCH")
    if (evidence.get("redis_executable") != "/usr/bin/redis-server"
            or evidence.get("redis_process_cwd") != "/home/gsadmin/redis-staging/data"
            or evidence.get("site_redis_server_name") != "redis-server"
            or evidence.get("redis_socket_listening") != "YES"
            or evidence.get("redis_socket_address_match") != "YES"
            or evidence.get("redis_listener_owner_visible") != "YES"
            or evidence.get("redis_auth_ping") != "PASS"
            or evidence.get("requirepass_status") != "CONFIGURED"
            or evidence.get("config_port") != "6380"
            or "127.0.0.1" not in evidence.get("config_bind", "").split(",")
            or evidence.get("config_dir") != evidence.get("redis_process_cwd")):
        fail("TOPOLOGY_PRECONDITION_FAILED")
    if (config.get("site_process") != "gourmet-novo-staging"
            or config.get("worker_process") != "gourmet-worker-staging"
            or config.get("required_config_authority") != "PM2_SCRIPT_ARGUMENT"
            or config.get("redis_discovery_contract_version") != 2
            or config.get("expected_pm2_process") != "redis-staging"
            or config.get("expected_host") != "127.0.0.1"
            or config.get("expected_port") != 6380):
        fail("REGISTRY_PRECONDITION_FAILED")


def backup_plan(backup_root, incident_id, seen_incidents=None):
    if not INCIDENT_RE.fullmatch(incident_id):
        fail("INVALID_INCIDENT_ID")
    root = Path(backup_root)
    if not root.is_absolute():
        fail("BACKUP_ROOT_NOT_ABSOLUTE")
    incident_dir = root / incident_id
    if incident_dir.exists():
        fail("BACKUP_COLLISION")
    if seen_incidents is not None:
        if incident_id in seen_incidents:
            fail("DUPLICATE_EXECUTION")
        seen_incidents.add(incident_id)
    return {"site": str(incident_dir / "site-env.before"),
            "redis": str(incident_dir / "redis-staging.conf.before")}


def _decode(data):
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        fail("INVALID_FILE_ENCODING")


def _lines(text):
    return text.splitlines(keepends=True)


def _parse_redis_directives(lines):
    found = {key: [] for key in ("requirepass", "port", "bind", "dir", "aclfile", "include")}
    for index, line in enumerate(lines):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        try:
            tokens = shlex.split(line, comments=True)
        except ValueError:
            fail("REDIS_CONFIG_PARSE_FAILED")
        if tokens and tokens[0].lower() in found:
            found[tokens[0].lower()].append((index, tokens[1:]))
    return found


def edit_redis_config(data, new_credential, expected_dir, expected_mode=None,
                      actual_mode=None, expected_owner=None, actual_owner=None):
    """Return edited bytes; only the unique active requirepass value changes."""
    if expected_mode is not None and expected_mode != actual_mode:
        fail("REDIS_CONFIG_MODE_MISMATCH")
    if expected_owner is not None and expected_owner != actual_owner:
        fail("REDIS_CONFIG_OWNER_MISMATCH")
    if not re.fullmatch(r"[A-Za-z0-9_-]{32,}", new_credential):
        fail("INVALID_NEW_CREDENTIAL")
    lines = _lines(_decode(data))
    fields = _parse_redis_directives(lines)
    if len(fields["requirepass"]) != 1:
        fail("REQUIREPASS_NOT_UNIQUE")
    if (len(fields["port"]) != 1 or fields["port"][0][1] != ["6380"]
            or len(fields["bind"]) != 1
            or "127.0.0.1" not in fields["bind"][0][1]
            or len(fields["dir"]) != 1 or fields["dir"][0][1] != [expected_dir]
            or fields["aclfile"] or fields["include"]):
        fail("REDIS_CONFIG_ENDPOINT_MISMATCH")
    index, args = fields["requirepass"][0]
    if len(args) != 1:
        fail("REQUIREPASS_PARSE_FAILED")
    if args[0] == new_credential:
        fail("REDIS_CONFIG_ALREADY_UPDATED")
    original = lines[index]
    match = re.fullmatch(r'([ \t]*requirepass[ \t]+)("[^"\r\n]*"|\'[^\'\r\n]*\'|[^\s#]+)([ \t]*(?:\#[^\r\n]*)?)(\r\n|\n|\r|)', original, re.I)
    if not match:
        fail("REQUIREPASS_PARSE_FAILED")
    old_token = match.group(2)
    quote_char = old_token[0] if old_token[0] in {"'", '"'} else ""
    replacement = quote_char + new_credential + quote_char
    lines[index] = match.group(1) + replacement + match.group(3) + match.group(4)
    return "".join(lines).encode("utf-8")


def _env_value(value_field):
    match = re.fullmatch(r'([ \t]*)(["\'])(.*)\2([ \t]*(?:\#.*)?)', value_field)
    if match:
        return match.group(3), match.group(1), match.group(2), match.group(4)
    match = re.fullmatch(r'([ \t]*)([^\s#]+)([ \t]*(?:\#.*)?)', value_field)
    if not match:
        fail("SITE_ENV_VALUE_PARSE_FAILED")
    return match.group(2), match.group(1), "", match.group(3)


def _new_redis_url(old_url, new_credential):
    try:
        parsed = urlsplit(old_url)
        if (parsed.scheme != "redis" or parsed.hostname != "127.0.0.1"
                or parsed.port != 6380 or parsed.path not in {"", "/0"}
                or parsed.fragment or parsed.password is None or "@" not in parsed.netloc):
            fail("REDIS_URL_ENDPOINT_MISMATCH")
        if unquote(parsed.password) == new_credential:
            fail("REDIS_URL_ALREADY_UPDATED")
        userinfo, hostpart = parsed.netloc.rsplit("@", 1)
        username = userinfo.rsplit(":", 1)[0]
        netloc = username + ":" + quote(new_credential, safe="") + "@" + hostpart
        return urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, ""))
    except ValueError:
        fail("REDIS_URL_ENDPOINT_MISMATCH")


def site_env_values(data):
    """Return only the two selected values in memory for parity validation."""
    values = {}
    for line in _lines(_decode(data)):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = re.fullmatch(r'([ \t]*(?:export[ \t]+)?(REDIS_URL|REDIS_PASSWORD)[ \t]*=)([^\r\n]*)(\r\n|\n|\r|)', line)
        if match:
            if match.group(2) in values:
                fail("DUPLICATE_SITE_ENV_KEY")
            values[match.group(2)] = _env_value(match.group(3))[0]
    if set(values) != {"REDIS_URL", "REDIS_PASSWORD"}:
        fail("SITE_ENV_KEYS_MISSING")
    return values


def edit_site_env(data, new_credential):
    """Return edited bytes with only REDIS_URL and REDIS_PASSWORD replaced."""
    if not re.fullmatch(r"[A-Za-z0-9_-]{32,}", new_credential):
        fail("INVALID_NEW_CREDENTIAL")
    lines = _lines(_decode(data))
    targets = {}
    for index, line in enumerate(lines):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = re.fullmatch(r'([ \t]*(?:export[ \t]+)?(REDIS_URL|REDIS_PASSWORD)[ \t]*=)([^\r\n]*)(\r\n|\n|\r|)', line)
        if not match:
            continue
        key = match.group(2)
        if key in targets:
            fail("DUPLICATE_SITE_ENV_KEY")
        targets[key] = (index, match)
    if set(targets) != {"REDIS_URL", "REDIS_PASSWORD"}:
        fail("SITE_ENV_KEYS_MISSING")
    password_index, password_match = targets["REDIS_PASSWORD"]
    old_password, leading, quote_char, suffix = _env_value(password_match.group(3))
    if old_password == new_credential:
        fail("SITE_ENV_ALREADY_UPDATED")
    url_index, url_match = targets["REDIS_URL"]
    old_url, url_leading, url_quote, url_suffix = _env_value(url_match.group(3))
    new_url = _new_redis_url(old_url, new_credential)
    if unquote(urlsplit(old_url).password) == old_password:
        fail("UNEXPECTED_EXISTING_PARITY")
    lines[password_index] = password_match.group(1) + leading + quote_char + new_credential + quote_char + suffix + password_match.group(4)
    lines[url_index] = url_match.group(1) + url_leading + url_quote + new_url + url_quote + url_suffix + url_match.group(4)
    return "".join(lines).encode("utf-8")


def validate_fixture(path):
    path = Path(path)
    if not path.is_file() or path.stat().st_size > 1024 * 1024:
        fail("FIXTURE_UNAVAILABLE")
    data = path.read_bytes()
    if not data.startswith(FIXTURE_MARKER):
        fail("SYNTHETIC_FIXTURE_REQUIRED")
    return data


def atomic_replace_fixture_copy(destination, content, sandbox_dir):
    """Write only an existing file directly inside an ephemeral sandbox."""
    destination = Path(destination)
    sandbox_dir = Path(sandbox_dir)
    temporary_root = Path(tempfile.gettempdir()).resolve()
    if (not sandbox_dir.name.startswith("gse-redis-dry-run-")
            or sandbox_dir.is_symlink()
            or sandbox_dir.resolve().parent != temporary_root
            or destination.parent.resolve() != sandbox_dir.resolve()
            or destination.name not in {"site-env.fixture", "redis-config.fixture"}
            or destination.is_symlink()
            or not destination.is_file()
            or not destination.read_bytes().startswith(FIXTURE_MARKER)):
        fail("ATOMIC_WRITE_SANDBOX_REQUIRED")
    previous = destination.stat()
    fd, temp_path = tempfile.mkstemp(prefix=".gse-redis-", dir=sandbox_dir)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temp_path, stat.S_IMODE(previous.st_mode))
        temp_stat = os.stat(temp_path)
        if (temp_stat.st_uid, temp_stat.st_gid) != (previous.st_uid, previous.st_gid):
            if not hasattr(os, "chown"):
                fail("ATOMIC_WRITE_OWNER_MISMATCH")
            os.chown(temp_path, previous.st_uid, previous.st_gid)
        os.replace(temp_path, destination)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def simulate_fixture_updates(site_path, redis_path, site_updated, redis_updated):
    """Never write source fixtures; exercise atomic writes on disposable copies."""
    with tempfile.TemporaryDirectory(prefix="gse-redis-dry-run-") as directory:
        site_copy = Path(directory) / "site-env.fixture"
        redis_copy = Path(directory) / "redis-config.fixture"
        shutil.copy2(site_path, site_copy)
        shutil.copy2(redis_path, redis_copy)
        atomic_replace_fixture_copy(site_copy, site_updated, directory)
        atomic_replace_fixture_copy(redis_copy, redis_updated, directory)
        if site_copy.read_bytes() != site_updated or redis_copy.read_bytes() != redis_updated:
            fail("ATOMIC_WRITE_MODEL_FAILED")


def simulate_fault(checkpoint):
    if checkpoint is None:
        return {"rollback_required": "NO", "simulated_execution": "NOT_EXECUTED",
                "rotation_success": "NOT_EXECUTED", "completed_steps": 0}
    if checkpoint not in FAULT_CHECKPOINTS:
        fail("UNKNOWN_FAULT_CHECKPOINT")
    return {"rollback_required": "YES", "simulated_execution": "FAIL",
            "rotation_success": "NO", "completed_steps": PLAN_STEPS.index(checkpoint) + 1}


def build_dry_run_plan(evidence, config, site_fixture, redis_fixture, incident_id,
                       backup_root, fault_after=None, seen_incidents=None,
                       credential_factory=None):
    validate_evidence(evidence, config)
    backups = backup_plan(backup_root, incident_id, seen_incidents)
    site_before = validate_fixture(site_fixture)
    redis_before = validate_fixture(redis_fixture)
    factory = credential_factory or secrets.token_urlsafe
    new_credential = factory(48)
    if not isinstance(new_credential, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,}", new_credential):
        fail("CREDENTIAL_GENERATION_FAILED")
    redis_path = Path(redis_fixture)
    file_stat = redis_path.stat()
    redis_updated = edit_redis_config(
        redis_before, new_credential, evidence["redis_process_cwd"],
        actual_mode=stat.S_IMODE(file_stat.st_mode), actual_owner=file_stat.st_uid,
    )
    site_updated = edit_site_env(site_before, new_credential)
    # Parity is checked in memory. Neither the credential nor either edited
    # document leaves this function or enters the returned plan.
    values = site_env_values(site_updated)
    if values.get("REDIS_PASSWORD") != new_credential or unquote(urlsplit(values.get("REDIS_URL", "")).password or "") != new_credential:
        fail("POST_ROTATION_PARITY_MODEL_FAILED")
    simulate_fixture_updates(site_fixture, redis_fixture, site_updated, redis_updated)
    fault = simulate_fault(fault_after)
    result = {"incident_id": incident_id, "backup_site": backups["site"],
              "backup_redis": backups["redis"], "new_credential_length": len(new_credential),
              "application_http_health": "PLANNED" if config.get("application_health_url") else "NOT_CONFIGURED",
              "post_rotation_parity_model": "PASS", "fault": fault}
    del new_credential, site_updated, redis_updated
    return result


def print_plan(plan):
    print("environment=staging")
    print("MODE=DRY_RUN")
    print("ROTATION_PLAN=PASS")
    print("new_credential_generated=YES")
    print(f"new_credential_length={plan['new_credential_length']}")
    print("backup_site_env_planned=YES")
    print("backup_redis_config_planned=YES")
    print("backup_targets=2")
    print(f"backup_site_env_path={plan['backup_site']}")
    print(f"backup_redis_config_path={plan['backup_redis']}")
    print("redis_restart_strategy=PM2_MANAGED_PROCESS")
    print("atomic_write_model=PASS")
    print("atomic_write_scope=SYNTHETIC_TEMP_COPIES")
    print("IDEMPOTENCY=DRY_RUN_REPLAY_NO_STATE_CHANGE")
    print("site_api_restart_required=YES")
    print("site_worker_restart_required=YES")
    print("verify_new_redis_ping=PLANNED_VIA_REDISCLI_AUTH")
    print("verify_old_credential_rejected=PLANNED")
    print("verify_site_api_online=PLANNED")
    print("verify_site_worker_online=PLANNED")
    print(f"APPLICATION_HTTP_HEALTH={plan['application_http_health']}")
    print("post_rotation_preflight_parity=PLANNED")
    print(f"post_rotation_parity_model={plan['post_rotation_parity_model']}")
    for index, step in enumerate(PLAN_STEPS, 1):
        print(f"step_{index}={step}")
    for index, step in enumerate(ROLLBACK_STEPS, 1):
        print(f"rollback_{index}={step}")
    print(f"ROLLBACK_REQUIRED={plan['fault']['rollback_required']}")
    print(f"SIMULATED_EXECUTION={plan['fault']['simulated_execution']}")
    print(f"ROTATION_SUCCESS={plan['fault']['rotation_success']}")
    print("ACTUAL_FILES_CHANGED=NO")
    print("ACTUAL_SERVICES_RESTARTED=NO")
    print("ACTUAL_DATABASE_TOUCHED=NO")


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--environment", required=True)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--evidence-file")
    parser.add_argument("--fixture-site-env")
    parser.add_argument("--fixture-redis-config")
    parser.add_argument("--incident-id")
    parser.add_argument("--backup-root")
    parser.add_argument("--fault-after")
    args = parser.parse_args(argv)
    if args.environment == "production":
        print("PRODUCTION_EXECUTION=BLOCKED")
        print("EXECUTION_BLOCKED=YES")
        print("ROTATION_PLAN=BLOCKED")
        return 1
    if args.environment != "staging" or not args.dry_run:
        print("EXECUTION_BLOCKED=YES")
        print("ROTATION_PLAN=BLOCKED")
        return 1
    if not all((args.evidence_file, args.fixture_site_env, args.fixture_redis_config,
                args.incident_id, args.backup_root)):
        print("ROTATION_PLAN=BLOCKED")
        return 1
    try:
        config = json.loads(REGISTRY.read_text(encoding="utf-8"))["staging"]
        evidence = load_evidence(args.evidence_file)
        plan = build_dry_run_plan(
            evidence, config, args.fixture_site_env, args.fixture_redis_config,
            args.incident_id, args.backup_root, args.fault_after)
    except (PlanBlocked, OSError, ValueError, KeyError, TypeError):
        # Deliberately omit exception text: a parser error may embed a secret.
        print("ROTATION_PLAN=BLOCKED")
        return 1
    print_plan(plan)
    return 1 if plan["fault"]["rollback_required"] == "YES" else 0


if __name__ == "__main__":
    raise SystemExit(main())
