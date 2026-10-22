"""GSE-03B5B staging-only Redis rotation executor.

The command path is deliberately closed unless all CLI and live readiness
gates pass. Exceptions are reduced to fixed status codes at the CLI boundary.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote, urlsplit
from urllib.request import urlopen

try:
    import pwd
except ImportError:  # Local Windows tests never instantiate RealOps.
    pwd = None


HERE = Path(__file__).resolve().parent


def _module(name, path):
    spec = importlib.util.spec_from_file_location(name, HERE / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


plan = _module("gse_redis_plan", "redis-rotate-plan.py")
discovery = _module("gse_redis_discovery", "redis-discovery.py")
rollback = _module("gse_redis_rollback", "redis-rollback.py")
CONFIRMATION = "REDIS-STAGING-ROTATE"
BACKUP_ROOT = Path("/home/gsadmin/security/backups/redis")
LOCK_PATH = Path("/home/gsadmin/security/locks/redis-staging-rotation.lock")
FAULT_POINTS = frozenset({
    "AFTER_BACKUP_SITE_ENV", "AFTER_BACKUP_REDIS_CONFIG",
    "AFTER_REDIS_CONFIG_UPDATE", "AFTER_SITE_ENV_UPDATE",
    "AFTER_REDIS_RESTART", "AFTER_REDIS_PING",
    "AFTER_SITE_API_RESTART", "AFTER_SITE_WORKER_RESTART",
    "AFTER_HEALTH_CHECK",
})
REPORT_KEYS = (
    "EXECUTION_BLOCKED", "FILES_MODIFIED", "SERVICES_RESTARTED",
    "IDEMPOTENCY_GUARD", "reason",
    "REDIS_ROTATION_EXECUTION", "BACKUP", "REDIS_CONFIG_UPDATE",
    "SITE_ENV_UPDATE", "REDIS_RESTART", "NEW_REDIS_PING",
    "OLD_REDIS_CREDENTIAL_REJECTED", "SITE_API_RESTART",
    "SITE_WORKER_RESTART", "POST_ROTATION_PREFLIGHT", "ROLLBACK",
    "MANUAL_INTERVENTION_REQUIRED", "APPLICATION_HTTP_HEALTH",
)


class RotationBlocked(Exception):
    """A fixed reason code, never data from a secret-bearing file or command."""


def block(code):
    raise RotationBlocked(code)


def gate(environment, execute, incident_id, confirmation):
    if environment == "production":
        block("PRODUCTION_EXECUTION_BLOCKED")
    if (environment != "staging" or execute is not True
            or confirmation != CONFIRMATION
            or not isinstance(incident_id, str)
            or not plan.INCIDENT_RE.fullmatch(incident_id)):
        block("EXECUTION_GATE_FAILED")
    return Permit(environment, execute, incident_id, confirmation)


@dataclass
class Permit:
    environment: str
    execute: bool
    incident_id: str
    confirmation: str
    readiness: str = "UNKNOWN"
    backup_complete: bool = False


def require_permit(permit, *, mutation=False):
    if (not isinstance(permit, Permit) or permit.environment != "staging"
            or permit.execute is not True or permit.confirmation != CONFIRMATION
            or not plan.INCIDENT_RE.fullmatch(permit.incident_id)
            or permit.readiness != "READY"
            or (mutation and not permit.backup_complete)):
        block("MUTATION_GATE_FAILED" if mutation else "EXECUTION_GATE_FAILED")


def sha(data):
    return hashlib.sha256(data).digest()


def secure_subdirectories(path, permit):
    """Create only directories beneath the fixed staging security root."""
    require_permit(permit)
    anchor = Path("/home/gsadmin/security")
    if not path.is_relative_to(anchor):
        block("SECURITY_ROOT_MISMATCH")
    if anchor.is_symlink() or not anchor.is_dir():
        block("SECURITY_ROOT_UNAVAILABLE")
    current = anchor
    for part in path.relative_to(anchor).parts:
        current = current / part
        if current.is_symlink():
            block("SECURITY_DIRECTORY_SYMLINK")
        if not current.exists():
            os.mkdir(current, 0o700)
        if not current.is_dir():
            block("SECURITY_DIRECTORY_UNAVAILABLE")


@dataclass
class State:
    incident_id: str
    old_credential: str
    old_site_hash: bytes
    old_redis_hash: bytes
    redis_pid: int
    api_pid: int
    worker_pid: int
    redis_pm2_name: str
    backup_dir: Path | None = None
    new_credential: str | None = None
    mutation_started: bool = False
    rollback_active: bool = False
    statuses: dict = field(default_factory=dict)


def report_defaults():
    return {key: ("YES" if key == "EXECUTION_BLOCKED" else
                  "NO" if key in {"FILES_MODIFIED", "SERVICES_RESTARTED"} else
                  "BLOCKED" if key == "IDEMPOTENCY_GUARD" else
                  "UNKNOWN" if key == "reason" else
                  "NOT_REQUIRED" if key == "ROLLBACK" else
                  "NO" if key == "MANUAL_INTERVENTION_REQUIRED" else
                  "NOT_CONFIGURED" if key == "APPLICATION_HTTP_HEALTH" else
                  "FAIL") for key in REPORT_KEYS}


def _fault(name, fault_after, test_mode):
    if fault_after == name:
        if not test_mode or name not in FAULT_POINTS:
            block("FAULT_INJECTION_DISABLED")
        block("INJECTED_FAULT")


def execute_rotation(ops, permit, *, fault_after=None, test_mode=False,
                     credential_factory=None):
    """Coordinate the transaction. Injected ops are allowed only in local tests."""
    result = report_defaults()
    state = None
    locked = False
    try:
        if not isinstance(permit, Permit):
            block("EXECUTION_GATE_FAILED")
        gate(permit.environment, permit.execute, permit.incident_id, permit.confirmation)
        if fault_after and (not test_mode or fault_after not in FAULT_POINTS):
            block("FAULT_INJECTION_DISABLED")
        evidence = ops.preflight()
        plan.validate_evidence(evidence, ops.config)
        permit.readiness = "READY"
        require_permit(permit)
        state = ops.capture_before(permit, evidence)
        if not state.redis_pm2_name:
            block("REDIS_IDENTITY_UNPROVED")
        ops.acquire_lock(permit)
        locked = True
        ops.ensure_incident_available(permit)
        result["IDEMPOTENCY_GUARD"] = "PASS"
        ops.backup_site_env(permit, state)
        _fault("AFTER_BACKUP_SITE_ENV", fault_after, test_mode)
        ops.backup_redis_config(permit, state)
        _fault("AFTER_BACKUP_REDIS_CONFIG", fault_after, test_mode)
        ops.verify_backups(state)
        permit.backup_complete = True
        result["BACKUP"] = "PASS"
        require_permit(permit, mutation=True)
        factory = credential_factory or secrets.token_urlsafe
        state.new_credential = factory(48)
        if (not isinstance(state.new_credential, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{32,}", state.new_credential)):
            block("CREDENTIAL_GENERATION_FAILED")
        redis_old, site_old = ops.original_bytes(state)
        redis_new = plan.edit_redis_config(redis_old, state.new_credential,
                                            evidence["redis_process_cwd"])
        site_new = plan.edit_site_env(site_old, state.new_credential)
        values = plan.site_env_values(site_new)
        if (values["REDIS_PASSWORD"] != state.new_credential
                or unquote(urlsplit(values["REDIS_URL"]).password or "") != state.new_credential):
            block("PARITY_VALIDATION_FAILED")
        state.mutation_started = True
        result["FILES_MODIFIED"] = "YES"
        result["EXECUTION_BLOCKED"] = "NO"
        ops.write_redis_config(permit, state, redis_new)
        result["REDIS_CONFIG_UPDATE"] = "PASS"
        _fault("AFTER_REDIS_CONFIG_UPDATE", fault_after, test_mode)
        ops.write_site_env(permit, state, site_new)
        result["SITE_ENV_UPDATE"] = "PASS"
        _fault("AFTER_SITE_ENV_UPDATE", fault_after, test_mode)
        ops.verify_updated_files(state, redis_new, site_new)
        ops.restart_redis(permit, state)
        result["SERVICES_RESTARTED"] = "YES"
        result["REDIS_RESTART"] = "PASS"
        _fault("AFTER_REDIS_RESTART", fault_after, test_mode)
        if not ops.ping(state.new_credential):
            block("NEW_REDIS_PING_FAILED")
        result["NEW_REDIS_PING"] = "PASS"
        if ops.ping(state.old_credential):
            block("OLD_REDIS_CREDENTIAL_ACCEPTED")
        result["OLD_REDIS_CREDENTIAL_REJECTED"] = "PASS"
        _fault("AFTER_REDIS_PING", fault_after, test_mode)
        ops.restart_site(permit, state, "api")
        if not ops.process_online("api"):
            block("SITE_API_OFFLINE")
        result["SITE_API_RESTART"] = "PASS"
        _fault("AFTER_SITE_API_RESTART", fault_after, test_mode)
        ops.restart_site(permit, state, "worker")
        if not ops.process_online("worker"):
            block("SITE_WORKER_OFFLINE")
        result["SITE_WORKER_RESTART"] = "PASS"
        _fault("AFTER_SITE_WORKER_RESTART", fault_after, test_mode)
        result["APPLICATION_HTTP_HEALTH"] = ops.application_health()
        if result["APPLICATION_HTTP_HEALTH"] not in {"PASS", "NOT_CONFIGURED"}:
            block("APPLICATION_HEALTH_FAILED")
        _fault("AFTER_HEALTH_CHECK", fault_after, test_mode)
        if not ops.post_rotation_preflight(state):
            block("POST_ROTATION_PREFLIGHT_FAILED")
        result["POST_ROTATION_PREFLIGHT"] = "PASS"
        ops.finalize(permit, state)
        result["REDIS_ROTATION_EXECUTION"] = "PASS"
    except Exception as error:
        if isinstance(error, RotationBlocked) and str(error) in {
                "ROTATION_LOCK_ACTIVE", "BACKUP_COLLISION", "REDIS_IDENTITY_UNPROVED"}:
            result["reason"] = str(error)
        if state is not None and state.mutation_started:
            try:
                result["ROLLBACK"] = "PASS" if rollback.restore(ops, permit, state) else "FAIL"
            except Exception:
                result["ROLLBACK"] = "FAIL"
            if result["ROLLBACK"] == "FAIL":
                result["MANUAL_INTERVENTION_REQUIRED"] = "YES"
    finally:
        if locked and result["MANUAL_INTERVENTION_REQUIRED"] != "YES":
            try:
                ops.release_lock(permit)
            except Exception:
                result["MANUAL_INTERVENTION_REQUIRED"] = "YES"
    state = None
    return result


def atomic_write(path, content, permit):
    """Replace one existing staging file with fsynced bytes and preserved metadata."""
    require_permit(permit, mutation=True)
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        block("UNSAFE_WRITE_TARGET")
    previous = path.stat()
    fd, temp = tempfile.mkstemp(prefix=".gse-redis-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temp, stat.S_IMODE(previous.st_mode))
        if hasattr(os, "chown") and (os.stat(temp).st_uid, os.stat(temp).st_gid) != (previous.st_uid, previous.st_gid):
            os.chown(temp, previous.st_uid, previous.st_gid)
        elif (os.stat(temp).st_uid, os.stat(temp).st_gid) != (previous.st_uid, previous.st_gid):
            block("OWNER_PRESERVATION_FAILED")
        if (path.is_symlink() or os.stat(path).st_ino != previous.st_ino
                or path.stat().st_mtime_ns != previous.st_mtime_ns):
            block("WRITE_TARGET_CHANGED")
        os.replace(temp, path)
        if hasattr(os, "O_DIRECTORY"):
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


NODE_RESTART = r'''const fs=require("fs"), cp=require("child_process");
const dotenv=require("dotenv");
const values=dotenv.parse(fs.readFileSync(process.argv[1]));
const name=process.argv[2];
if (!/^(gourmet-novo-staging|gourmet-worker-staging)$/.test(name)) process.exit(2);
const child=cp.spawnSync("pm2",["restart",name,"--update-env"],
  {cwd:process.cwd(),env:{...process.env,...values},stdio:"ignore",timeout:30000});
process.exit(child.status===0?0:1);'''


class RealOps:
    def __init__(self, config):
        self.config = config
        self.site_env = Path(config["site_env"])
        self.redis_conf = Path(config["expected_config_candidates"][0])
        self.lock_inode = None
        self.backup_dir = None
        if (str(self.site_env) != "/home/gsadmin/secure-env/.env.staging"
                or str(self.redis_conf) != "/home/gsadmin/secure-env/p1rk/redis-staging.conf"
                or config["site_dir"] != "/var/www/gourmet-staging"):
            block("REGISTRY_TARGET_MISMATCH")

    def _run(self, argv, *, cwd=None, env=None, timeout=30):
        try:
            return subprocess.run(argv, cwd=cwd, env=env, capture_output=True,
                                  text=True, timeout=timeout, check=False, shell=False)
        except (OSError, subprocess.TimeoutExpired):
            block("COMMAND_FAILED")

    def preflight(self):
        result = self._run([sys.executable, str(HERE / "redis-discovery.py"),
                            "--runtime", "staging"], timeout=45)
        if result.returncode:
            block("PREFLIGHT_FAILED")
        return plan.parse_evidence_text(result.stdout)

    def _pm2_pid(self, name):
        result = self._run(["pm2", "pid", name])
        value = result.stdout.strip()
        return int(value) if result.returncode == 0 and value.isdecimal() else 0

    def _redis_pm2_identity(self, redis_pid):
        listing = self._run(["pm2", "ls", "--no-color"])
        if listing.returncode or len(listing.stdout) > 65536:
            block("PM2_LIST_UNAVAILABLE")
        names = set()
        for line in listing.stdout.splitlines():
            for field in line.split("│"):
                name = field.strip()
                if re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", name) and "redis" in name.lower() and "staging" in name.lower():
                    names.add(name)
        matches = [name for name in names if self._pm2_pid(name) == redis_pid]
        if len(matches) != 1:
            block("REDIS_PM2_IDENTITY_UNPROVED")
        return matches[0]

    def _file(self, path, *, redis=False):
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
            block("TARGET_FILE_UNSAFE")
        meta = path.stat()
        if redis and (stat.S_IMODE(meta.st_mode) != 0o600
                      or meta.st_uid != pwd.getpwnam("gsadmin").pw_uid):
            block("REDIS_CONFIG_METADATA_MISMATCH")
        return path.read_bytes()

    def capture_before(self, permit, evidence):
        require_permit(permit)
        redis_pid = int(evidence.get("redis_listener_pid", "0"))
        listener = discovery.discover_listener(6380)
        if (redis_pid <= 0 or listener.get("pid") != str(redis_pid)
                or listener.get("process") != "redis-server"
                or listener.get("address_match") != "YES"):
            block("REDIS_LISTENER_CHANGED")
        process = discovery.local_redis_metadata(redis_pid)
        if (process.get("executable") != "/usr/bin/redis-server"
                or process.get("user") != "gsadmin"
                or process.get("cwd") != evidence["redis_process_cwd"]
                or process.get("managed_by_pm2") != "YES"):
            block("REDIS_PROCESS_CHANGED")
        identity = self._redis_pm2_identity(redis_pid)
        pm2_source = discovery.pm2_explicit_config(redis_pid, self.config["expected_pm2_process"])
        if (identity != self.config["expected_pm2_process"]
                or pm2_source["authority"] != "PM2_SCRIPT_ARGUMENT"
                or pm2_source["path"] != str(self.redis_conf)):
            block("PM2_CONFIG_AUTHORITY_MISMATCH")
        api_pid = self._pm2_pid(self.config["site_process"])
        worker_pid = self._pm2_pid(self.config["worker_process"])
        if min(api_pid, worker_pid) <= 0:
            block("CONSUMER_OFFLINE")
        site = self._file(self.site_env)
        redis = self._file(self.redis_conf, redis=True)
        for legacy in self.config.get("legacy_config_candidates", []):
            if Path(legacy).exists() and os.path.samefile(self.redis_conf, legacy):
                block("ACTIVE_LEGACY_FILE_ALIAS")
        values = plan.site_env_values(site)
        url = urlsplit(values["REDIS_URL"])
        if (url.scheme != "redis" or url.hostname != "127.0.0.1"
                or url.port != 6380 or url.path not in {"", "/0"}
                or not url.password):
            block("SITE_ENV_ENDPOINT_MISMATCH")
        old_credential = unquote(url.password)
        active_credential = discovery.requirepass_value_in_memory(str(self.redis_conf))
        if (active_credential is None or active_credential != old_credential
                or values["REDIS_PASSWORD"] == old_credential):
            block("ACTIVE_CREDENTIAL_RELATIONSHIP_CHANGED")
        return State(permit.incident_id, old_credential, sha(site), sha(redis),
                     redis_pid, api_pid, worker_pid, identity)

    def acquire_lock(self, permit):
        require_permit(permit)
        secure_subdirectories(LOCK_PATH.parent, permit)
        if LOCK_PATH.parent.is_symlink() or not LOCK_PATH.parent.is_dir():
            block("LOCK_PARENT_UNAVAILABLE")
        try:
            fd = os.open(LOCK_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            block("ROTATION_LOCK_ACTIVE")
        with os.fdopen(fd, "w", encoding="ascii") as stream:
            stream.write(f"{permit.incident_id}\n{os.getpid()}\n{int(time.time())}\n")
            stream.flush()
            os.fsync(stream.fileno())
        self.lock_inode = LOCK_PATH.stat().st_ino

    def release_lock(self, permit):
        require_permit(permit)
        if self.lock_inode is not None and LOCK_PATH.is_file() and not LOCK_PATH.is_symlink():
            metadata = LOCK_PATH.read_text(encoding="ascii", errors="replace").splitlines()
            if (LOCK_PATH.stat().st_ino == self.lock_inode
                    and metadata[:2] == [permit.incident_id, str(os.getpid())]):
                LOCK_PATH.unlink()

    def ensure_incident_available(self, permit):
        require_permit(permit)
        secure_subdirectories(BACKUP_ROOT, permit)
        if BACKUP_ROOT.is_symlink() or not BACKUP_ROOT.is_dir():
            block("BACKUP_ROOT_UNAVAILABLE")
        target = BACKUP_ROOT / permit.incident_id
        if target.exists() or target.is_symlink():
            block("BACKUP_COLLISION")
        os.mkdir(target, 0o700)
        if stat.S_IMODE(target.stat().st_mode) != 0o700:
            block("BACKUP_DIRECTORY_MODE_FAILED")
        self.backup_dir = target

    def _backup(self, permit, state, source, name, digest):
        require_permit(permit)
        if self.backup_dir is None or self.backup_dir != BACKUP_ROOT / permit.incident_id:
            block("BACKUP_DIRECTORY_MISSING")
        source_data = self._file(source, redis=source == self.redis_conf)
        if sha(source_data) != digest:
            block("SOURCE_CHANGED_BEFORE_BACKUP")
        destination = self.backup_dir / name
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(source_data)
            stream.flush()
            os.fsync(stream.fileno())
        if (sha(destination.read_bytes()) != digest
                or stat.S_IMODE(destination.stat().st_mode) != 0o600):
            block("BACKUP_PARITY_FAILED")
        state.backup_dir = self.backup_dir

    def backup_site_env(self, permit, state):
        self._backup(permit, state, self.site_env, "site-env.before", state.old_site_hash)

    def backup_redis_config(self, permit, state):
        self._backup(permit, state, self.redis_conf, "redis-staging.conf.before", state.old_redis_hash)

    def verify_backups(self, state):
        if (state.backup_dir is None
                or sha((state.backup_dir / "site-env.before").read_bytes()) != state.old_site_hash
                or sha((state.backup_dir / "redis-staging.conf.before").read_bytes()) != state.old_redis_hash):
            block("BACKUP_PARITY_FAILED")

    def original_bytes(self, state):
        self.verify_backups(state)
        return ((state.backup_dir / "redis-staging.conf.before").read_bytes(),
                (state.backup_dir / "site-env.before").read_bytes())

    def write_redis_config(self, permit, state, data):
        require_permit(permit, mutation=True)
        if sha(self._file(self.redis_conf, redis=True)) != state.old_redis_hash:
            block("REDIS_CONFIG_CHANGED")
        atomic_write(self.redis_conf, data, permit)

    def write_site_env(self, permit, state, data):
        require_permit(permit, mutation=True)
        if sha(self._file(self.site_env)) != state.old_site_hash:
            block("SITE_ENV_CHANGED")
        atomic_write(self.site_env, data, permit)

    def verify_updated_files(self, state, redis_data, site_data):
        if (self._file(self.redis_conf, redis=True) != redis_data
                or self._file(self.site_env) != site_data):
            block("UPDATED_FILE_MISMATCH")
        values = plan.site_env_values(site_data)
        if values["REDIS_PASSWORD"] != unquote(urlsplit(values["REDIS_URL"]).password or ""):
            block("POST_UPDATE_PARITY_FAILED")

    def restart_redis(self, permit, state):
        require_permit(permit, mutation=True)
        if (not state.redis_pm2_name or not state.backup_dir
                or self.backup_dir != state.backup_dir):
            block("REDIS_RESTART_GUARD_FAILED")
        current_pid = self._pm2_pid(state.redis_pm2_name)
        current_source = (discovery.pm2_explicit_config(current_pid, state.redis_pm2_name)
                          if current_pid > 0 else
                          discovery.pm2_described_config(state.redis_pm2_name, allow_offline=True)
                          if state.rollback_active else {"path": "UNKNOWN"})
        if current_source["path"] != str(self.redis_conf):
            block("REDIS_RESTART_AUTHORITY_CHANGED")
        result = self._run(["pm2", "restart", state.redis_pm2_name, "--update-env"])
        if result.returncode:
            block("REDIS_RESTART_FAILED")
        listener = discovery.discover_listener(6380)
        if (listener.get("found") != "YES"
                or listener.get("address_match") != "YES"
                or listener.get("process") != "redis-server"):
            block("REDIS_RESTART_IDENTITY_FAILED")
        pid = int(listener.get("pid", "0"))
        if pid <= 0 or self._pm2_pid(state.redis_pm2_name) != pid:
            block("REDIS_RESTART_PM2_MISMATCH")
        renewed_source = discovery.pm2_explicit_config(pid, state.redis_pm2_name)
        if renewed_source["path"] != str(self.redis_conf):
            block("REDIS_RESTART_AUTHORITY_CHANGED")
        process = discovery.local_redis_metadata(pid)
        active = discovery.discover_active_config(
            "127.0.0.1", 6380, listener, process,
            registry_candidates=[str(self.redis_conf)], glob_fn=lambda _directory: [],
            expected_user="gsadmin")
        if (process.get("executable") != "/usr/bin/redis-server"
                or process.get("managed_by_pm2") != "YES"
                or active.get("active_match") != "YES"
                or active.get("path") != str(self.redis_conf)):
            block("REDIS_RESTART_CONFIG_MISMATCH")

    def ping(self, credential):
        return discovery.connectivity_ping("127.0.0.1", 6380, credential) == "PASS"

    def restart_site(self, permit, state, kind):
        require_permit(permit, mutation=True)
        if kind not in {"api", "worker"}:
            block("SITE_RESTART_TARGET_INVALID")
        name = self.config["site_process" if kind == "api" else "worker_process"]
        if name not in {"gourmet-novo-staging", "gourmet-worker-staging"}:
            block("SITE_RESTART_TARGET_INVALID")
        result = self._run(["node", "-e", NODE_RESTART, str(self.site_env), name],
                           cwd=self.config["site_dir"], timeout=45)
        if result.returncode:
            block("SITE_RESTART_FAILED")

    def process_online(self, kind):
        name = self.config["site_process" if kind == "api" else "worker_process"]
        return self._pm2_pid(name) > 0

    def application_health(self):
        address = self.config.get("application_health_url")
        if not address:
            return "NOT_CONFIGURED"
        try:
            with urlopen(address, timeout=5) as response:
                return "PASS" if 200 <= response.status < 300 else "FAIL"
        except Exception:
            return "FAIL"

    def post_rotation_preflight(self, state):
        evidence = self.preflight()
        return all(evidence.get(key) == value for key, value in {
            "redis_discovery_contract_version": "2",
            "redis_config_authority": "PM2_SCRIPT_ARGUMENT",
            "redis_config_path": self.config["expected_config_candidates"][0],
            "active_requirepass_vs_redis_url": "SAME",
            "active_requirepass_vs_redis_password": "SAME",
            "redis_url_vs_redis_password": "SAME",
            "REDIS_CONNECTIVITY": "PASS", "redis_password_url_parity": "PASS",
            "REDIS_CREDENTIAL_RELATIONSHIP": "PASSWORD_AND_URL_SAME_CREDENTIAL",
            "CONNECTIVITY_WITH_REDIS_URL_CREDENTIAL": "PASS",
            "CONNECTIVITY_WITH_REDIS_PASSWORD": "PASS",
            "SITE_REDIS_SERVER_IDENTIFIED": "YES", "redis_active_config_match": "YES",
            "redis_credential_source": "REDIS_CONF",
        }.items()) and self.ping(state.new_credential) and not self.ping(state.old_credential)

    def preflight_restored(self, state):
        evidence = self.preflight()
        try:
            plan.validate_evidence(evidence, self.config)
            return True
        except plan.PlanBlocked:
            return False

    def restore_files(self, permit, state):
        require_permit(permit, mutation=True)
        self.verify_backups(state)
        redis_old, site_old = self.original_bytes(state)
        atomic_write(self.redis_conf, redis_old, permit)
        atomic_write(self.site_env, site_old, permit)
        if (sha(self.redis_conf.read_bytes()) != state.old_redis_hash
                or sha(self.site_env.read_bytes()) != state.old_site_hash):
            block("ROLLBACK_HASH_MISMATCH")

    def finalize(self, permit, state):
        require_permit(permit, mutation=True)
        # Backups remain available for audit and any later manual recovery.
        self.verify_backups(state)


def print_report(report):
    for key in REPORT_KEYS:
        print(f"{key}={report[key]}")


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--environment", required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--incident-id")
    parser.add_argument("--confirm")
    args = parser.parse_args(argv)
    try:
        permit = gate(args.environment, args.execute, args.incident_id, args.confirm)
    except RotationBlocked as exc:
        if str(exc) == "PRODUCTION_EXECUTION_BLOCKED":
            print("PRODUCTION_EXECUTION=BLOCKED")
        print("EXECUTION_BLOCKED=YES")
        print("FILES_MODIFIED=NO")
        print("SERVICES_RESTARTED=NO")
        return 1
    try:
        config = json.loads((HERE / "redis-registry.json").read_text(encoding="utf-8"))["staging"]
        result = execute_rotation(RealOps(config), permit)
    except Exception:
        result = report_defaults()
    print_report(result)
    return 0 if result["REDIS_ROTATION_EXECUTION"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
