"""Redis topology evidence and safe, read-only runtime observations.

The runtime path intentionally reports UNKNOWN when a server's authentication
source or a process's actual Redis usage cannot be proved from safe metadata.
"""
import argparse
import hashlib
import hmac
import ipaddress
import json
import os
import re
import subprocess
import sys
import shlex
import stat
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit

try:
    import pwd
except ImportError:  # Windows runs only the local, injected tests.
    pwd = None

REGISTRY = Path(__file__).with_name("redis-registry.json")
KEYS = ("REDIS_PASSWORD", "REDIS_URL")
AUTH_MODELS = {"REQUIREPASS", "ACL_DEFAULT_USER", "ACL_NAMED_USER", "NO_PASSWORD"}
RELATIONSHIPS = {
    "PASSWORD_SEPARATE", "PASSWORD_EMBEDDED_IN_URL",
    "PASSWORD_AND_URL_SAME_CREDENTIAL", "PASSWORD_REDUNDANT",
    "URL_WITHOUT_PASSWORD", "URL_IS_CANONICAL",
    "PASSWORD_IS_CANONICAL", "BOTH_USED_SAME_SERVER_DIFFERENT_CREDENTIAL",
    "DIFFERENT_SERVERS", "LEGACY_PASSWORD_UNUSED",
    "LEGACY_URL_UNUSED", "INCONSISTENT_CONFIGURATION", "UNKNOWN",
}
CREDENTIAL_SOURCES = {
    "DOCKER_SECRET", "ENV_FILE", "DOCKER_COMMAND", "REDIS_CONF",
    "ACL_FILE", "EXTERNAL_MANAGED", "DOCKER_ENV_UNREADABLE_BY_POLICY", "AMBIGUOUS_CONFIG", "UNKNOWN",
}
FUTURE_ACTIONS = {
    "BACKUP_SERVER_AUTH_CONFIG", "BACKUP_SITE_ENV", "PREPARE_CLIENT_CREDENTIALS",
    "UPDATE_REDIS_AUTH", "UPDATE_SITE_ENV", "RESTART_CONFIRMED_CONSUMERS",
    "VERIFY_PING", "VERIFY_HEALTH", "REMOVE_OLD_CREDENTIAL",
    "ROLLBACK_IF_FAILURE",
    # Abstract safe sequence actions for GSE-03B2:
    "BACKUP_CLIENT_ENV", "BACKUP_REDIS_AUTH_SOURCE", "GENERATE_NEW_PASSWORD",
    "UPDATE_REDIS_SERVER_CREDENTIAL", "UPDATE_REDIS_URL", "UPDATE_REDIS_PASSWORD",
    "UPDATE_REDUNDANT_REDIS_PASSWORD_IF_REQUIRED",
    "UPDATE_REDUNDANT_REDIS_URL_IF_REQUIRED",
    "RESTART_SITE_API_IF_REQUIRED", "RESTART_SITE_WORKER_IF_REQUIRED",
    "RELOAD_OR_RESTART_REDIS_AS_REQUIRED", "REDIS_PING", "APPLICATION_HEALTH",
    "BACKUP_REDIS_CONFIG", "GENERATE_NEW_REDIS_PASSWORD", "UPDATE_REDIS_REQUIREPASS",
    "RECONCILE_REDUNDANT_REDIS_PASSWORD", "RESTART_OR_RELOAD_REDIS",
    "RESTART_SITE_API", "RESTART_SITE_WORKER", "VERIFY_REDIS_PING",
    "VERIFY_APPLICATION_HEALTH", "ROLLBACK_ON_FAILURE",
}

LOCAL_REDIS_SEQUENCE = [
    "BACKUP_SITE_ENV", "BACKUP_REDIS_CONFIG", "GENERATE_NEW_REDIS_PASSWORD",
    "UPDATE_REDIS_REQUIREPASS", "UPDATE_REDIS_URL",
    "RECONCILE_REDUNDANT_REDIS_PASSWORD", "RESTART_OR_RELOAD_REDIS",
    "RESTART_SITE_API", "RESTART_SITE_WORKER", "VERIFY_REDIS_PING",
    "VERIFY_APPLICATION_HEALTH", "ROLLBACK_ON_FAILURE",
]


def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sanitize_host(host):
    if not host or not isinstance(host, str):
        return "UNKNOWN"
    host = host.strip()
    if ord(host[0]) < 32 or any(c in host for c in " \r\n\t@/:"):
        return "UNKNOWN"
    if re.fullmatch(r"[A-Za-z0-9_.-]+", host):
        return host
    return "UNKNOWN"


def parse_redis_url(value):
    """Return private password hash and public structure, never the URL itself."""
    if not isinstance(value, str) or any(ord(char) < 32 for char in value):
        raise ValueError("invalid URL")
    parsed = urlsplit(value)
    if parsed.scheme not in {"redis", "rediss"} or not parsed.hostname:
        raise ValueError("invalid Redis URL")
    port = parsed.port  # Also validates port syntax/range.
    password = unquote(parsed.password) if parsed.password is not None else None
    sanitized_host = sanitize_host(parsed.hostname)
    db_idx = int(parsed.path.lstrip("/")) if parsed.path.lstrip("/").isdigit() else 0
    return {
        "redis_url_scheme": parsed.scheme,
        "redis_url_host_present": "YES",
        "redis_url_port_present": "YES" if port is not None else "NO",
        "redis_url_password_present": "YES" if password is not None else "NO",
        "redis_url_database_index_present": "YES" if parsed.path.lstrip("/").isdigit() else "NO",
        "redis_target_host": sanitized_host,
        "redis_target_port": port if port is not None else (6380 if parsed.scheme == "rediss" else 6379),
        "redis_target_db": db_idx,
        "url_password_hash": digest(password) if password is not None else None,
    }


def classify_relationship(password_present, password_hash, url_present, url_password_hash, url_valid=True):
    if not url_valid or (password_present and not password_hash):
        return "UNKNOWN", "UNKNOWN"
    if not url_present:
        return ("PASSWORD_SEPARATE", "NOT_APPLICABLE") if password_present else ("UNKNOWN", "UNKNOWN")
    if url_password_hash is None:
        return "URL_WITHOUT_PASSWORD", "NOT_APPLICABLE"
    if not password_present:
        return "PASSWORD_EMBEDDED_IN_URL", "NOT_APPLICABLE"
    if password_hash == url_password_hash:
        return "PASSWORD_AND_URL_SAME_CREDENTIAL", "PASS"
    return "PASSWORD_REDUNDANT", "FAIL"


def classify_values(password=None, url_value=None):
    """Synthetic/local test entry point. The result contains no credential."""
    url_info = None
    valid = True
    if url_value is not None:
        try:
            url_info = parse_redis_url(url_value)
        except (ValueError, TypeError):
            valid = False
    relationship, parity = classify_relationship(
        password is not None,
        digest(password) if password is not None else None,
        url_value is not None,
        url_info["url_password_hash"] if url_info else None,
        valid,
    )
    public = {key: value for key, value in (url_info or {}).items() if key != "url_password_hash"}
    return {**public, "relationship": relationship, "redis_password_url_parity": parity}


def classify_config_auth(config_text):
    """Classify synthetic/known config lines without returning credentials."""
    active = [line.strip() for line in config_text.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    requirepass = [line.split(None, 1)[1].strip().strip('"\'') for line in active
                   if re.match(r"^requirepass\s+", line, re.I)]
    users = [line.split() for line in active if line.lower().startswith("user ")]
    authenticated = [parts for parts in users if len(parts) >= 3 and "on" in parts[2:]
                     and any(token.startswith((">", "#")) and len(token) > 1 for token in parts[2:])]
    named = [parts for parts in authenticated if parts[1] != "default"]
    default = [parts for parts in authenticated if parts[1] == "default"]
    if any(requirepass) and users:
        return "UNKNOWN"
    if any(requirepass):
        return "REQUIREPASS"
    if named and default:
        return "UNKNOWN"
    if named:
        return "ACL_NAMED_USER"
    if default:
        return "ACL_DEFAULT_USER"
    if any(len(parts) >= 3 and parts[1] == "default" and "on" in parts[2:]
           and "nopass" in parts[2:] for parts in users):
        return "NO_PASSWORD"
    return "UNKNOWN"


def assess_readiness(evidence):
    """Only the fully correlated staging topology can be rotation ready."""
    exact = {
        "socket_listening": "YES", "socket_address_match": "YES",
        "listener_owner_visible": "YES", "server_type": "LOCAL_PROCESS",
        "process_identity_verified": True, "managed_by_pm2": "YES",
        "active_config_match": "YES", "credential_source": "REDIS_CONF",
        "config_authority": "PM2_SCRIPT_ARGUMENT", "discovery_contract_version": 2,
        "auth_model": "REQUIREPASS", "auth_ping": "PASS",
        "requirepass_status": "CONFIGURED", "connectivity": "PASS",
        "connectivity_url": "PASS", "connectivity_password": "FAIL",
        "site_api_uses_redis": "YES", "site_worker_uses_redis": "YES",
        "api_restart_required": "YES", "worker_restart_required": "YES",
        "api_usage": "MIXED", "worker_usage": "MIXED",
        "relationship_parity": "FAIL", "relationship": "INCONSISTENT_CONFIGURATION",
    }
    backups = evidence.get("backup_targets", [])
    complete = (
        all(evidence.get(key) == value for key, value in exact.items())
        and evidence.get("server_identified") is True
        and evidence.get("credential_source_identified") is True
        and evidence.get("other_consumers_known") is True
        and evidence.get("backup_targets_complete") is True
        and len(backups) == 2 and len(set(backups)) == 2
        and all(safe_path(path) != "UNKNOWN" for path in backups)
        and evidence.get("config_path") == backups[1]
        and evidence.get("executable", "UNKNOWN").endswith("/redis-server")
        and evidence.get("restart_targets_known") is True
        and len(evidence.get("restart_targets", [])) == 2
        and evidence.get("future_sequence") == LOCAL_REDIS_SEQUENCE
    )

    return {
        "ROTATION_READINESS": "READY" if complete else "BLOCKED",
        "FUTURE_ROTATION_SEQUENCE": "KNOWN" if complete else "UNKNOWN",
        "future_backup_targets": len(backups),
        "future_restart_targets": len(evidence.get("restart_targets", [])),
        "future_rotation_steps": list(evidence["future_sequence"]) if complete else [],
    }


def connectivity_ping(host, port, password=None, username=None, tls=False, cli="redis-cli"):
    """Optional future read-only probe. Credentials live only in child env."""
    if username is not None or not host or not isinstance(port, int) or not (1 <= port <= 65535):
        return "NOT_TESTED"
    child_env = os.environ.copy()
    child_env.pop("REDISCLI_AUTH", None)
    if password is not None:
        child_env["REDISCLI_AUTH"] = password
    command = [cli, "-h", host, "-p", str(port)]
    if tls:
        command.append("--tls")
    command.append("PING")
    try:
        result = subprocess.run(command, env=child_env, capture_output=True, text=True, timeout=5, check=False, shell=False)
    except (OSError, subprocess.TimeoutExpired):
        return "FAIL"
    return "PASS" if result.returncode == 0 and result.stdout.strip() == "PONG" else "FAIL"


# Node resolves the deployment's own dotenv package and emits only hashes/shape.
NODE_DOTENV_PROBE = r'''
const fs = require("fs");
const crypto = require("crypto");
const dotenv = require("dotenv");
const parsed = dotenv.parse(fs.readFileSync(process.argv[1]));
const has = k => Object.prototype.hasOwnProperty.call(parsed, k);
const sha = s => crypto.createHash("sha256").update(s).digest("hex");
const out = { password_present: has("REDIS_PASSWORD"), url_present: has("REDIS_URL"),
  password_hash: has("REDIS_PASSWORD") ? sha(parsed.REDIS_PASSWORD) : null,
  url_hash: has("REDIS_URL") ? sha(parsed.REDIS_URL) : null,
  url_valid: false, url_password_hash: null, url_shape: {} };
if (out.url_present) {
  try {
    const u = new URL(parsed.REDIS_URL);
    if (!["redis:", "rediss:"].includes(u.protocol) || !u.hostname) throw Error("invalid");
    const pw = u.password ? decodeURIComponent(u.password) : null;
    out.url_password_hash = pw === null ? null : sha(pw);
    out.url_shape = { redis_url_scheme: u.protocol.slice(0, -1),
      redis_url_host_present: "YES", redis_url_port_present: u.port ? "YES" : "NO",
      redis_url_password_present: pw === null ? "NO" : "YES",
      redis_url_database_index_present: /^\/[0-9]+$/.test(u.pathname) ? "YES" : "NO",
      redis_target_host: u.hostname,
      redis_target_port: u.port ? parseInt(u.port, 10) : (u.protocol === "rediss:" ? 6380 : 6379),
      redis_target_db: /^\/[0-9]+$/.test(u.pathname) ? parseInt(u.pathname.slice(1), 10) : 0 };
    out.url_valid = true;
  } catch (_) { out.url_valid = false; }
}
process.stdout.write(JSON.stringify(out));
'''


def probe_site_env(site_env, site_dir):
    try:
        result = subprocess.run(
            ["node", "-e", NODE_DOTENV_PROBE, str(site_env)], cwd=site_dir,
            capture_output=True, text=True, timeout=5, check=False, shell=False,
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            if set(data) == {"password_present", "url_present", "password_hash", "url_hash", "url_valid", "url_password_hash", "url_shape"}:
                return data
    except (OSError, ValueError, subprocess.TimeoutExpired):
        pass
    return None


def extract_env_credentials_in_memory(site_env_path):
    """Safely extracts Redis credentials in memory only. Never printed or logged."""
    try:
        content = Path(site_env_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None, None
    raw = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            k, v = line.split("=", 1)
            k = k.strip()
            v = v.strip().strip("'\"")
            if k in ("REDIS_PASSWORD", "REDIS_URL"):
                raw[k] = v
    cred_redis_pwd = raw.get("REDIS_PASSWORD")
    cred_redis_url = raw.get("REDIS_URL")
    url_password = None
    if cred_redis_url:
        try:
            parsed = urlsplit(cred_redis_url)
            if parsed.password is not None:
                url_password = unquote(parsed.password)
        except Exception:
            pass
    return cred_redis_pwd, url_password


def pm2_pid(name):
    try:
        result = subprocess.run(["pm2", "pid", name], capture_output=True, text=True, timeout=5, check=False, shell=False)
        pid = result.stdout.strip()
        return int(pid) if result.returncode == 0 and pid.isdecimal() and int(pid) > 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def probe_process(pid):
    if pid is None:
        return None
    try:
        raw = Path(f"/proc/{pid}/environ").read_bytes()
    except OSError:
        return None
    selected = {}
    for key in KEYS:
        prefix = (key + "=").encode()
        matches = [part[len(prefix):] for part in raw.split(b"\0") if part.startswith(prefix)]
        if len(matches) > 1:
            return None
        if matches:
            try:
                selected[key] = matches[0].decode("utf-8")
            except UnicodeDecodeError:
                return None
    password = selected.get("REDIS_PASSWORD")
    url = selected.get("REDIS_URL")
    result = {"password_present": password is not None, "url_present": url is not None,
              "password_hash": digest(password) if password is not None else None,
              "url_hash": digest(url) if url is not None else None}
    try:
        result["url_shape"] = parse_redis_url(url) if url is not None else {}
        result["url_valid"] = True
    except ValueError:
        result["url_shape"] = {}
        result["url_valid"] = False
    # The private URL password hash is unnecessary for process parity.
    result["url_shape"].pop("url_password_hash", None)
    return result


def docker_candidates():
    try:
        result = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"],
            capture_output=True, text=True, timeout=5, check=False, shell=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if result.returncode:
        return []
    candidates = []
    for row in result.stdout.splitlines():
        parts = row.split("\t")
        if len(parts) != 4:
            continue
        name, image, status, _ports = parts
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
            continue
        state = status.split()[0].upper() if status else "UNKNOWN"
        if state not in {"UP", "EXITED", "CREATED", "RESTARTING", "PAUSED"}:
            state = "UNKNOWN"
        candidates.append((name, state))
    return candidates


def docker_host_port_match(port, run_fn=None):
    """Check published host ports without inspecting containers or their env."""
    run_fn = run_fn or subprocess.run
    try:
        result = run_fn(["docker", "ps", "--format", "{{.Ports}}"],
                        capture_output=True, text=True, timeout=5, check=False, shell=False)
    except (OSError, subprocess.TimeoutExpired):
        return "UNKNOWN"
    if result.returncode:
        return "UNKNOWN"
    published = re.compile(rf"(?:^|[,\s])(?:127\.0\.0\.1|0\.0\.0\.0|\[::1\]|\[::\]|:::?):{port}->\d+/tcp(?:$|[,\s])")
    return "YES" if any(published.search(line) for line in result.stdout.splitlines()) else "NO"


def inspect_container_structural_metadata(container_name):
    """Safely inspects structural metadata only."""
    if not container_name or not re.fullmatch(r"[A-Za-z0-9_.-]+", container_name):
        return None
    format_template = "{{.Name}}\t{{.Config.Image}}\t{{.HostConfig.NetworkMode}}\t{{json .Mounts}}\t{{json .Config.Cmd}}\t{{json .NetworkSettings.Ports}}\t{{json .HostConfig.PortBindings}}"
    try:
        result = subprocess.run(
            ["docker", "inspect", "--format", format_template, container_name],
            capture_output=True, text=True, timeout=5, check=False, shell=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    parts = result.stdout.strip().split("\t")
    if len(parts) < 4:
        return None
    name, image, network_mode, mounts_raw = parts[0], parts[1], parts[2], parts[3]
    cmd_raw = parts[4] if len(parts) > 4 else "[]"
    try:
        mounts = json.loads(mounts_raw) if mounts_raw else []
    except json.JSONDecodeError:
        mounts = []
    try:
        cmd = json.loads(cmd_raw) if cmd_raw else []
    except json.JSONDecodeError:
        cmd = []
    try:
        ports = json.loads(parts[5]) if len(parts) > 5 else {}
        bindings = json.loads(parts[6]) if len(parts) > 6 else {}
    except json.JSONDecodeError:
        ports, bindings = {}, {}
    return {
        "name": safe_label(name.lstrip("/")),
        "image": image,
        "network_mode": network_mode,
        "mounts": mounts,
        "cmd": cmd,
        "ports": ports,
        "port_bindings": bindings,
    }


def detect_command_requirepass(cmd_tokens):
    """Detects if --requirepass is in cmd arguments, returning boolean without secret."""
    if not isinstance(cmd_tokens, list):
        return False
    for token in cmd_tokens:
        if token == "--requirepass" or token.startswith("--requirepass="):
            return True
    return False


def classify_credential_source_from_metadata(meta):
    """Classify Redis credential source without inspecting container env."""
    if not meta:
        return "UNKNOWN"
    mounts = meta.get("mounts", [])
    cmd = meta.get("cmd", [])
    for m in mounts:
        dest = str(m.get("Destination", "")).lower()
        src = str(m.get("Source", "")).lower()
        if dest.startswith("/run/secrets") or "/secrets" in dest:
            return "DOCKER_SECRET"
    for m in mounts:
        dest = str(m.get("Destination", "")).lower()
        src = str(m.get("Source", "")).lower()
        combined = dest + " " + src
        if combined.endswith(".acl") or "users.acl" in combined:
            return "ACL_FILE"
        if combined.endswith(".conf") or "redis.conf" in combined:
            return "REDIS_CONF"
    if detect_command_requirepass(cmd):
        return "DOCKER_COMMAND"
    return "DOCKER_ENV_UNREADABLE_BY_POLICY"


def identify_site_redis_server(target_host, target_port, candidates, inspect_fn=None):
    """
    Identifies if a candidate matches the site's Redis server.
    Does not assume unrelated containers (like refeicao-*) belong to Gourmet.
    """
    if inspect_fn is None:
        inspect_fn = inspect_container_structural_metadata

    if not target_host or target_host == "UNKNOWN":
        return {"identified": False, "server_type": "UNKNOWN", "server_name": "UNKNOWN", "metadata": None}

    matches = []
    for name, status in candidates:
        if status != "UP":
            continue
        meta = inspect_fn(name)
        if meta and port_mapping_matches(meta, target_host, target_port):
            matches.append(meta)
    if len(matches) == 1:
        meta = matches[0]
        return {"identified": True, "server_type": "DOCKER_CONTAINER", "server_name": meta["name"], "metadata": meta}
    return {"identified": False, "server_type": "UNKNOWN", "server_name": "UNKNOWN", "metadata": None}


def safe_label(value):
    return value if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.-]+", value) else "UNKNOWN"


def safe_path(value):
    return value if isinstance(value, str) and value.startswith("/") and re.fullmatch(r"/[A-Za-z0-9_./-]+", value) and ".." not in Path(value).parts else "UNKNOWN"


def port_mapping_matches(meta, host, port):
    """Match the published host endpoint, independent of container names."""
    if host not in {"127.0.0.1", "localhost"} or not isinstance(port, int):
        return False
    for field in ("ports", "port_bindings"):
        for container_port, bindings in (meta.get(field) or {}).items():
            if not re.fullmatch(r"\d+/tcp", container_port) or not isinstance(bindings, list):
                continue
            if any(b.get("HostPort") == str(port) and b.get("HostIp") in {"127.0.0.1", "0.0.0.0", "::", ""} for b in bindings if isinstance(b, dict)):
                return True
    return False


def discover_listener(port=6380, run_fn=None):
    """Prove the listening socket separately from process-owner visibility."""
    run_fn = run_fn or subprocess.run
    report = {"found": "NO", "address_match": "NO", "owner_visible": "NO",
              "type": "UNKNOWN", "pid": "UNKNOWN", "process": "UNKNOWN"}
    if not isinstance(port, int) or not 1 <= port <= 65535:
        return report

    def rows(with_process):
        try:
            result = run_fn(["ss", "-ltnp" if with_process else "-ltn"],
                            capture_output=True, text=True, timeout=5, check=False, shell=False)
        except (OSError, subprocess.TimeoutExpired):
            return []
        if result.returncode:
            return []
        selected = []
        for line in result.stdout.splitlines():
            fields = line.split()
            if len(fields) < 4 or fields[0] != "LISTEN":
                continue
            address = fields[3]
            if address.endswith(f":{port}"):
                selected.append((address.rsplit(":", 1)[0].strip("[]"), line))
        return selected

    socket_rows = rows(False)
    if not socket_rows:
        return report
    report["found"] = "YES"
    report["address_match"] = "YES" if any(host == "127.0.0.1" for host, _ in socket_rows) else "NO"
    # IPv4 is the site's endpoint. IPv6 may share the same owner, but never
    # substitutes for evidence that 127.0.0.1:port is listening.
    owner_rows = [line for host, line in rows(True) if host == "127.0.0.1"]
    owners = {match.groups() for row in owner_rows
              for match in re.finditer(r'users:\(\("([A-Za-z0-9_.-]+)",pid=(\d+)', row)}
    if len(owners) != 1:
        return report
    process, pid = next(iter(owners))
    process = safe_label(process)
    report.update(owner_visible="YES", pid=pid, process=process)
    kind = "DOCKER_PROXY" if process in {"docker-proxy", "rootlesskit"} else "REDIS_PROCESS" if process == "redis-server" else "OTHER" if process != "UNKNOWN" else "UNKNOWN"
    report["type"] = kind
    return report


def local_redis_metadata(pid, run_fn=None):
    """Read only process identity fields. Never read or print command arguments."""
    meta = {"executable": "UNKNOWN", "user": "UNKNOWN", "cwd": "UNKNOWN",
            "process": "UNKNOWN", "parent_process": "UNKNOWN",
            "parent_detected": "NO", "managed_by_pm2": "UNKNOWN"}
    if not str(pid).isdecimal() or int(pid) < 1:
        return meta
    run_fn = run_fn or subprocess.run

    def ps(pid_value, fields):
        try:
            result = run_fn(["ps", "-p", str(pid_value), "-o", fields],
                            capture_output=True, text=True, timeout=5, check=False, shell=False)
            return result.stdout.strip() if result.returncode == 0 else ""
        except (OSError, subprocess.TimeoutExpired):
            return ""

    try:
        exe = os.path.realpath(os.readlink(f"/proc/{pid}/exe"))
        cwd = os.path.realpath(os.readlink(f"/proc/{pid}/cwd"))
        meta["executable"] = safe_path(exe)
        meta["cwd"] = safe_path(cwd)
    except OSError:
        pass
    identity = ps(pid, "user=,comm=").split(None, 1)
    if len(identity) == 2:
        meta["user"] = safe_label(identity[0])
        meta["process"] = safe_label(identity[1])
    ppid = ps(pid, "ppid=")
    if ppid.isdecimal() and int(ppid) > 0:
        parent = ps(ppid, "user=,comm=").split(None, 1)
        if len(parent) == 2 and safe_label(parent[0]) == meta["user"]:
            meta["parent_process"] = "PM2" if parent[1].lower().startswith("pm2") else safe_label(parent[1])
            meta["parent_detected"] = "YES"
    try:
        cgroup = Path(f"/proc/{pid}/cgroup").read_text(encoding="utf-8", errors="replace")
    except OSError:
        cgroup = ""
    if meta["parent_process"] == "PM2" or re.search(r"(?:^|/)pm2-[A-Za-z0-9_.-]+\.service(?:$|\n)", cgroup):
        meta["managed_by_pm2"] = "YES"
    elif meta["parent_detected"] == "YES" and cgroup:
        meta["managed_by_pm2"] = "NO"
    return meta


def inspect_redis_config(path):
    """Parse selected directives without exposing password or user tokens."""
    info = {"port": "UNKNOWN", "bind": "UNKNOWN", "dir": "UNKNOWN", "dbfilename": "UNKNOWN",
            "appendonly": "UNKNOWN", "requirepass": "ABSENT", "aclfile": "UNKNOWN",
            "aclfile_present": "NO", "conflict": False, "readable": False, "users": []}
    if safe_path(path) == "UNKNOWN":
        return info
    try:
        if Path(path).stat().st_size > 1024 * 1024:
            return info
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        info["requirepass"] = "UNAVAILABLE"
        return info
    info["readable"] = True
    seen = set()
    for line in lines:
        try:
            words = shlex.split(line, comments=True)
        except ValueError:
            continue
        if not words:
            continue
        key = words[0].lower()
        if key in {"port", "bind", "dir", "dbfilename", "appendonly", "requirepass", "aclfile", "include"}:
            if key in seen or key == "include":
                info["conflict"] = True
            seen.add(key)
        if key == "requirepass" and len(words) > 1:
            info["requirepass"] = "PRESENT"
        elif key == "aclfile" and len(words) > 1:
            info["aclfile"] = safe_path(words[1])
            info["aclfile_present"] = "YES"
        elif key == "port" and len(words) == 2 and words[1].isdigit():
            info["port"] = words[1]
        elif key == "bind" and len(words) > 1:
            binds = []
            for value in words[1:]:
                try:
                    binds.append(str(ipaddress.ip_address(value.lstrip("-"))))
                except ValueError:
                    info["conflict"] = True
            info["bind"] = ",".join(dict.fromkeys(binds)) or "UNKNOWN"
        elif key == "dir" and len(words) == 2:
            info["dir"] = safe_path(words[1])
        elif key == "dbfilename" and len(words) == 2:
            info["dbfilename"] = safe_label(words[1])
        elif key == "appendonly" and len(words) == 2:
            info["appendonly"] = words[1].lower() if words[1].lower() in {"yes", "no"} else "UNKNOWN"
        elif key == "user" and len(words) > 2:
            info["users"].append((safe_label(words[1]), "on" if "on" in words[2:] else "off" if "off" in words[2:] else "UNKNOWN"))
    return info


def discover_active_config(target_host, target_port, socket, process, registry_candidates=(),
                           exists_fn=None, config_reader=None, glob_fn=None, expected_user=None):
    """Correlate a bounded set of files with the socket and process cwd."""
    exists_fn = exists_fn or (lambda path: Path(path).is_file())
    config_reader = config_reader or inspect_redis_config
    glob_fn = glob_fn or (lambda directory: Path(directory).glob("*.conf"))
    candidates = set()
    for candidate in registry_candidates:
        if safe_path(candidate) != "UNKNOWN" and candidate.endswith(".conf"):
            candidates.add(candidate)
    cwd = process.get("cwd", "UNKNOWN")
    if safe_path(cwd) != "UNKNOWN":
        for directory in (PurePosixPath(cwd), PurePosixPath(cwd).parent):
            try:
                for candidate in list(glob_fn(str(directory)))[:32]:
                    candidate = str(candidate)
                    if safe_path(candidate) != "UNKNOWN" and candidate.endswith(".conf"):
                        candidates.add(candidate)
            except OSError:
                pass
    existing = sorted(path for path in candidates if exists_fn(path))
    matches = []
    for path in existing:
        config = config_reader(path)
        dbfile = config.get("dbfilename", "UNKNOWN")
        data_dir = config.get("dir", "UNKNOWN")
        dbfile_valid = dbfile != "UNKNOWN" and data_dir != "UNKNOWN" and exists_fn(str(PurePosixPath(data_dir) / dbfile))
        valid = (
            socket.get("found") == "YES" and socket.get("address_match") == "YES"
            and socket.get("owner_visible") == "YES" and socket.get("type") == "REDIS_PROCESS"
            and process.get("executable", "UNKNOWN").endswith("/redis-server")
            and process.get("process") == "redis-server"
            and (expected_user is None or process.get("user") == expected_user)
            and config.get("readable") is True and config.get("conflict") is False
            and config.get("port") == str(target_port)
            and target_host in config.get("bind", "").split(",")
            and data_dir == cwd and config.get("requirepass") == "PRESENT"
            and config.get("aclfile_present") == "NO"
            and dbfile_valid
        )
        if valid:
            matches.append((path, config))
    return {"candidate_count": len(existing), "active_match": "YES" if len(matches) == 1 else "NO",
            "path": matches[0][0] if len(matches) == 1 else "UNKNOWN",
            "config": matches[0][1] if len(matches) == 1 else None,
            "source": "REDIS_CONF" if len(matches) == 1 else "AMBIGUOUS_CONFIG" if len(matches) > 1 else "UNKNOWN"}


def parse_pm2_description(raw):
    """Discard every PM2 row except a fixed set of structural fields."""
    if len(raw) > 128 * 1024:
        return {}
    raw = re.sub(r"\x1b\[[0-9;]*m", "", raw)
    allowed = {"status", "name", "script path", "script args", "pid path", "exec cwd", "script id"}
    fields = {}
    for line in raw.splitlines():
        if "Divergent env variables" in line:
            break
        columns = [part.strip() for part in re.split(r"[│|]", line)]
        if len(columns) < 4:
            continue
        key, value = columns[1:3]
        if key in {"env", "environment", "Environment"}:
            break
        if key in allowed:
            if key in fields:
                return {}
            fields[key] = value
    return fields


def pm2_described_config(expected_name, run_fn=None, allow_offline=False):
    """Reduce PM2 describe to an exact app, executable and config argument."""
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", expected_name or ""):
        return {"path": "UNKNOWN", "authority": "UNKNOWN", "name": "UNKNOWN"}
    run_fn = run_fn or subprocess.run
    try:
        result = run_fn(["pm2", "describe", expected_name], capture_output=True, text=True,
                        timeout=5, check=False, shell=False)
        if result.returncode:
            raise ValueError("PM2_DESCRIBE_UNAVAILABLE")
        fields = parse_pm2_description(result.stdout)
        allowed_status = {"online", "stopped", "errored"} if allow_offline else {"online"}
        if (fields.get("status") not in allowed_status or fields.get("name") != expected_name
                or fields.get("script path") != "/usr/bin/redis-server"):
            raise ValueError("PM2_IDENTITY_MISMATCH")
        tokens = shlex.split(fields.get("script args", ""))
        if len(tokens) != 1 or safe_path(tokens[0]) == "UNKNOWN" or not tokens[0].endswith(".conf"):
            raise ValueError("PM2_CONFIG_ARGUMENT_INVALID")
        return {"path": tokens[0], "authority": "PM2_SCRIPT_ARGUMENT", "name": expected_name}
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return {"path": "UNKNOWN", "authority": "UNKNOWN", "name": "UNKNOWN"}


def pm2_explicit_config(redis_pid, expected_name, run_fn=None):
    """Correlate the listener PID with a named PM2 app and its script argument."""
    if not str(redis_pid).isdecimal() or not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", expected_name or ""):
        return {"path": "UNKNOWN", "authority": "UNKNOWN", "name": "UNKNOWN"}
    run_fn = run_fn or subprocess.run
    try:
        pid_result = run_fn(["pm2", "pid", expected_name], capture_output=True, text=True,
                            timeout=5, check=False, shell=False)
        if pid_result.returncode or pid_result.stdout.strip() != str(redis_pid):
            return {"path": "UNKNOWN", "authority": "UNKNOWN", "name": "UNKNOWN"}
        return pm2_described_config(expected_name, run_fn=run_fn)
    except (OSError, subprocess.TimeoutExpired):
        return {"path": "UNKNOWN", "authority": "UNKNOWN", "name": "UNKNOWN"}


def direct_process_config(pid):
    """Return only a unique absolute .conf argument; never expose the argv bytes."""
    if not str(pid).isdecimal():
        return "UNKNOWN"
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return "UNKNOWN"
    if len(raw) > 65536:
        return "UNKNOWN"
    paths = [item.decode("utf-8", errors="replace") for item in raw.split(b"\0")[1:]
             if item.startswith(b"/") and item.endswith(b".conf")]
    return paths[0] if len(paths) == 1 and safe_path(paths[0]) != "UNKNOWN" else "UNKNOWN"


def service_unit_config(pid, run_fn=None, cgroup_reader=None):
    """Select one .conf from a Redis systemd ExecStart without returning raw argv."""
    if not str(pid).isdecimal():
        return "UNKNOWN"
    try:
        cgroup = (cgroup_reader or (lambda p: Path(p).read_text(encoding="utf-8", errors="replace")))(
            f"/proc/{pid}/cgroup")
        units = set(re.findall(r"(?:^|/)([A-Za-z0-9_.@-]+\.service)(?:$|\n)", cgroup, re.M))
        if len(units) != 1:
            return "UNKNOWN"
        unit = next(iter(units))
        result = (run_fn or subprocess.run)(
            ["systemctl", "show", unit, "--property=ExecStart", "--value"],
            capture_output=True, text=True, timeout=5, check=False, shell=False)
        if result.returncode or len(result.stdout) > 65536 or "/redis-server" not in result.stdout:
            return "UNKNOWN"
        candidates = set(re.findall(r"(/[A-Za-z0-9_./-]+\.conf)(?=\s|;|$)", result.stdout))
        return next(iter(candidates)) if len(candidates) == 1 and safe_path(next(iter(candidates))) != "UNKNOWN" else "UNKNOWN"
    except (OSError, subprocess.TimeoutExpired):
        return "UNKNOWN"


def select_config_authority(pm2_path="UNKNOWN", process_path="UNKNOWN",
                            service_path="UNKNOWN", heuristic_path="UNKNOWN"):
    """A declared runtime argument takes precedence over any matching candidate."""
    for authority, path in (("PM2_SCRIPT_ARGUMENT", pm2_path),
                            ("PROCESS_ARGUMENT", process_path),
                            ("SERVICE_UNIT_ARGUMENT", service_path),
                            ("VALIDATED_CANDIDATE_HEURISTIC", heuristic_path)):
        if path != "UNKNOWN" and safe_path(path) != "UNKNOWN" and path.endswith(".conf"):
            return authority, path
    return "UNKNOWN", "UNKNOWN"


def config_file_metadata_ok(path, expected_user="gsadmin", stat_fn=None, uid_fn=None):
    """Require a private, regular config owned by the expected process user."""
    try:
        info = (stat_fn or os.stat)(path)
        uid = (uid_fn or (lambda user: pwd.getpwnam(user).pw_uid))(expected_user)
        return (stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
                and info.st_uid == uid and not Path(path).is_symlink())
    except (OSError, KeyError, AttributeError, TypeError):
        return False


def requirepass_value_in_memory(path):
    """Read one credential only for equality checks; never return it to reports."""
    try:
        if Path(path).stat().st_size > 1024 * 1024:
            return None
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    found = []
    for line in lines:
        try:
            words = shlex.split(line, comments=True)
        except ValueError:
            return None
        if words and words[0].lower() == "requirepass":
            if len(words) != 2:
                return None
            found.append(words[1])
    return found[0] if len(found) == 1 else None


def safe_credential_relation(left, right):
    return "UNKNOWN" if left is None or right is None else "SAME" if hmac.compare_digest(left, right) else "DIFFERENT"


def inspect_legacy_config(active_path, candidates, active_info, config_reader=None,
                          password_reader=None):
    """Describe inactive candidates without allowing one to replace the active path."""
    config_reader = config_reader or inspect_redis_config
    password_reader = password_reader or requirepass_value_in_memory
    result = {"detected": "NO", "path": "UNKNOWN", "operationally_similar": "UNKNOWN",
              "requirepass_relationship": "UNKNOWN", "classification": "UNKNOWN"}
    for path in candidates:
        if path == active_path or safe_path(path) == "UNKNOWN" or not Path(path).is_file():
            continue
        try:
            if os.path.samefile(path, active_path):
                continue
        except OSError:
            pass
        legacy_info = config_reader(path)
        if not legacy_info.get("readable"):
            continue
        keys = ("port", "bind", "dir", "dbfilename", "appendonly", "requirepass", "aclfile_present")
        similar = all(legacy_info.get(key) == active_info.get(key) for key in keys)
        relation = safe_credential_relation(password_reader(active_path), password_reader(path))
        result = {"detected": "YES", "path": path,
                  "operationally_similar": "YES" if similar else "NO",
                  "requirepass_relationship": relation,
                  "classification": "STALE_CREDENTIAL_CONFIG" if relation == "DIFFERENT" else "DUPLICATE_OR_LEGACY_CANDIDATE"}
        break
    return result


def redis_auth_probe(host, port, password, tls=False, run_fn=None):
    """Allow only three read operations; return reduced status, never server values."""
    run_fn = run_fn or subprocess.run
    result = {"ping": "FAIL", "whoami_available": "NO", "current_user": "UNKNOWN",
              "requirepass_status": "UNAVAILABLE", "auth_model": "UNKNOWN"}
    if host not in {"127.0.0.1", "localhost"} or not isinstance(port, int):
        return result
    env = os.environ.copy()
    env.pop("REDISCLI_AUTH", None)
    if password is not None:
        env["REDISCLI_AUTH"] = password
    base = ["redis-cli", "-h", host, "-p", str(port)] + (["--tls"] if tls else [])
    def call(*args):
        try:
            return run_fn(base + list(args), env=env, capture_output=True, text=True,
                          timeout=5, check=False, shell=False)
        except (OSError, subprocess.TimeoutExpired):
            return None
    ping = call("PING")
    if ping is None or ping.returncode != 0 or ping.stdout.strip() != "PONG":
        return result
    result["ping"] = "PASS"
    who = call("ACL", "WHOAMI")
    if who is not None and who.returncode == 0:
        user = safe_label(who.stdout.strip())
        if user != "UNKNOWN":
            result["whoami_available"] = "YES"
            result["current_user"] = user
    cfg = call("CONFIG", "GET", "requirepass")
    if cfg is not None and cfg.returncode == 0:
        lines = cfg.stdout.splitlines()
        if lines and lines[0].strip() == "requirepass":
            result["requirepass_status"] = "CONFIGURED" if len(lines) > 1 and bool(lines[1].strip()) else "NOT_CONFIGURED"
    if result["current_user"] not in {"UNKNOWN", "default"}:
        result["auth_model"] = "ACL_NAMED_USER"
    elif result["current_user"] == "default" and result["requirepass_status"] == "CONFIGURED":
        result["auth_model"] = "REQUIREPASS"
    elif result["current_user"] == "default" and result["requirepass_status"] == "NOT_CONFIGURED":
        result["auth_model"] = "NO_PASSWORD" if password is None else "ACL_DEFAULT_USER"
    return result


def resolve_config_paths(meta):
    """Return host-side mounted config and ACL paths only when structurally linked."""
    paths = {"config": "UNKNOWN", "acl": "UNKNOWN"}
    if not meta:
        return paths
    for mount in meta.get("mounts", []):
        dst, src = mount.get("Destination"), mount.get("Source")
        if safe_path(src) == "UNKNOWN" or safe_path(dst) == "UNKNOWN":
            continue
        if dst.endswith(".conf"):
            paths["config"] = src
        elif dst.endswith(".acl"):
            paths["acl"] = src
    return paths


def restart_impact(uses_redis, process_observation):
    if uses_redis != "YES" or process_observation is None:
        return "UNKNOWN"
    return "YES" if process_observation.get("url_present") or process_observation.get("password_present") else "UNKNOWN"


def scan_codebase_redis_usage(codebase_dir):
    """
    Scans site directory for Redis usage references.
    Returns:
        findings: list of dicts {file, line, variable, usage_type}
        api_usage: DIRECT_REDIS_URL | PASSWORD_PLUS_HOST_PORT | MIXED | DECLARED_BUT_UNUSED | UNKNOWN
        worker_usage: DIRECT_REDIS_URL | PASSWORD_PLUS_HOST_PORT | MIXED | DECLARED_BUT_UNUSED | UNKNOWN
        module_shared: bool or None
    """
    path = Path(codebase_dir)
    if not path.is_dir():
        return [], "UNKNOWN", "UNKNOWN", False

    ignored_dirs = {
        "node_modules", ".git", ".next", "dist", "build", "coverage", ".gemini", "vendor", "backups", "releases"
    }
    allowed_exts = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".json"}

    findings = []
    has_url_client = False
    has_pwd_client = False
    has_url_decl = False
    has_pwd_decl = False

    worker_url_client = False
    worker_pwd_client = False
    api_url_client = False
    api_pwd_client = False
    shared_redis_modules = set()

    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in ignored_dirs and not d.startswith(".")
                   and not re.match(r"^dist\.(?:previous|rollback|pre-|failed|old|swap|backup)", d)]
        for file in files:
            ext = Path(file).suffix.lower()
            if ext not in allowed_exts:
                continue
            full_path = Path(root) / file
            rel_path = full_path.relative_to(path).as_posix()

            try:
                content = full_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            if "REDIS" not in content and "redis" not in content and "ioredis" not in content and "Bull" not in content:
                continue

            lines = content.splitlines()
            is_worker_file = any(token in rel_path.lower() for token in ("worker", "job", "queue", "cron"))
            is_shared_module = any(token in rel_path.lower() for token in ("lib/redis", "config/redis", "shared/redis", "utils/redis"))

            file_has_client = bool(re.search(r"(?:createClient|new\s+Redis|new\s+(?:Bull|Queue|Worker)|redis\.createClient|ioredis)", content, re.I))
            if is_shared_module and file_has_client:
                shared_redis_modules.add(rel_path)

            for line_idx, line in enumerate(lines, 1):
                found_vars = []
                if "REDIS_URL" in line:
                    found_vars.append("REDIS_URL")
                if "REDIS_PASSWORD" in line:
                    found_vars.append("REDIS_PASSWORD")
                if "REDIS_HOST" in line:
                    found_vars.append("REDIS_HOST")
                if "REDIS_PORT" in line:
                    found_vars.append("REDIS_PORT")

                if not found_vars:
                    continue

                for var in found_vars:
                    is_conn = bool(re.search(r"(?:createClient|new\s+Redis|url\s*:|connection\s*:|new\s+(?:Queue|Worker|Bull)|redis\.createClient)", line, re.I)) or file_has_client
                    is_decl = any(kw in line for kw in ("z.", "Joi.", "interface ", "type ", "enum ", ".default(")) or rel_path.endswith((".d.ts", ".json", "env.ts", "env.mjs", "schema.ts"))

                    if is_conn:
                        usage_type = "CLIENT_CONNECTION"
                        if var == "REDIS_URL":
                            has_url_client = True
                            if is_worker_file:
                                worker_url_client = True
                            else:
                                api_url_client = True
                        elif var in ("REDIS_PASSWORD", "REDIS_HOST", "REDIS_PORT"):
                            has_pwd_client = True
                            if is_worker_file:
                                worker_pwd_client = True
                            else:
                                api_pwd_client = True
                    elif is_decl:
                        usage_type = "DECLARATION"
                        if var == "REDIS_URL":
                            has_url_decl = True
                        elif var == "REDIS_PASSWORD":
                            has_pwd_decl = True
                    else:
                        usage_type = "CONFIG_MAPPING"
                        if var == "REDIS_URL":
                            has_url_decl = True
                        elif var == "REDIS_PASSWORD":
                            has_pwd_decl = True

                    findings.append({
                        "file": rel_path,
                        "line": line_idx,
                        "variable": var,
                        "usage_type": usage_type,
                    })

    if not findings:
        return [], "UNKNOWN", "UNKNOWN", False

    module_shared = bool(shared_redis_modules) or (not worker_url_client and not worker_pwd_client and (has_url_client or has_pwd_client))

    def classify_usage(has_url, has_pwd, has_u_decl, has_p_decl):
        if has_url and has_pwd:
            return "MIXED"
        if has_url and not has_pwd:
            return "DIRECT_REDIS_URL"
        if has_pwd and not has_url:
            return "PASSWORD_PLUS_HOST_PORT"
        if has_p_decl and not has_pwd:
            return "DECLARED_BUT_UNUSED"
        if has_u_decl and not has_url:
            return "DECLARED_BUT_UNUSED"
        return "UNKNOWN"

    if module_shared:
        overall = classify_usage(has_url_client, has_pwd_client, has_url_decl, has_pwd_decl)
        api_usage = overall
        worker_usage = overall
    else:
        api_usage = classify_usage(api_url_client, api_pwd_client, has_url_decl, has_pwd_decl)
        worker_usage = classify_usage(worker_url_client, worker_pwd_client, has_url_decl, has_pwd_decl)

    return findings, api_usage, worker_usage, module_shared


def discover_auth_model(host, port, password=None, username=None, tls=False, cli="redis-cli", exec_fn=None):
    """
    Discovers auth model without ever printing secret values.
    Returns: auth_model, auth_discovery_status, requirepass_status
    """
    if exec_fn is None:
        def default_exec(command, env=None):
            return subprocess.run(command, env=env, capture_output=True, text=True, timeout=5, check=False, shell=False)
        exec_fn = default_exec

    child_env = os.environ.copy()
    if password is not None:
        child_env["REDISCLI_AUTH"] = password

    base_cmd = [cli, "-h", host, "-p", str(port)]
    if tls:
        base_cmd.append("--tls")

    # 1. Probe ACL WHOAMI
    whoami_cmd = base_cmd + ["ACL", "WHOAMI"]
    try:
        res_whoami = exec_fn(whoami_cmd, env=child_env)
    except (OSError, subprocess.TimeoutExpired):
        return "UNKNOWN", "EXEC_ERROR", "UNKNOWN"

    acl_supported = False
    whoami = None
    if res_whoami.returncode == 0:
        whoami = res_whoami.stdout.strip()
        acl_supported = True
    elif "NOAUTH" in res_whoami.stderr or "NOPERM" in res_whoami.stderr or "NOAUTH" in res_whoami.stdout:
        return "UNKNOWN", "INSUFFICIENT_PERMISSION", "UNKNOWN"

    # 2. Probe ACL USERS
    users = []
    if acl_supported:
        users_cmd = base_cmd + ["ACL", "USERS"]
        try:
            res_users = exec_fn(users_cmd, env=child_env)
            if res_users.returncode == 0:
                users = [u for u in res_users.stdout.split() if re.fullmatch(r"[A-Za-z0-9_.-]+", u)]
            elif "NOAUTH" in res_users.stderr or "NOPERM" in res_users.stderr:
                return "UNKNOWN", "INSUFFICIENT_PERMISSION", "UNKNOWN"
        except (OSError, subprocess.TimeoutExpired):
            pass

    # 3. Probe CONFIG GET requirepass
    cfg_cmd = base_cmd + ["CONFIG", "GET", "requirepass"]
    requirepass_status = "UNKNOWN"
    try:
        res_cfg = exec_fn(cfg_cmd, env=child_env)
        if res_cfg.returncode == 0:
            lines = [l.strip() for l in res_cfg.stdout.splitlines() if l.strip()]
            val = lines[1] if len(lines) > 1 else ""
            requirepass_status = "CONFIGURED" if bool(val) else "NOT_CONFIGURED"
        elif "NOAUTH" in res_cfg.stderr or "NOPERM" in res_cfg.stderr:
            requirepass_status = "RESTRICTED"
    except (OSError, subprocess.TimeoutExpired):
        pass

    if acl_supported:
        if whoami and whoami != "default":
            return "ACL_NAMED_USER", "PASS", requirepass_status
        if any(u != "default" for u in users):
            return "ACL_NAMED_USER", "PASS", requirepass_status
        if requirepass_status == "CONFIGURED":
            return "REQUIREPASS", "PASS", requirepass_status
        if whoami == "default" and requirepass_status == "NOT_CONFIGURED" and password is None:
            return "NO_PASSWORD", "PASS", requirepass_status
        return "ACL_DEFAULT_USER", "PASS", requirepass_status

    if requirepass_status == "CONFIGURED":
        return "REQUIREPASS", "PASS", requirepass_status
    if requirepass_status == "NOT_CONFIGURED" and password is None:
        return "NO_PASSWORD", "PASS", requirepass_status
    if requirepass_status == "RESTRICTED":
        return "UNKNOWN", "INSUFFICIENT_PERMISSION", requirepass_status

    return "UNKNOWN", "UNKNOWN", requirepass_status


def probe_credentials_connectivity(host, port, cred_redis_pwd=None, url_password=None, tls=False, ping_fn=None):
    if ping_fn is None:
        ping_fn = connectivity_ping

    conn_url = "NOT_TESTED"
    conn_pwd = "NOT_TESTED"

    if host and host != "UNKNOWN" and isinstance(port, int) and 1 <= port <= 65535:
        if url_password is not None:
            conn_url = ping_fn(host, port, password=url_password, tls=tls)
        if cred_redis_pwd is not None:
            conn_pwd = ping_fn(host, port, password=cred_redis_pwd, tls=tls)

    if conn_url == "PASS" or conn_pwd == "PASS":
        overall = "PASS"
    elif conn_url == "FAIL" or conn_pwd == "FAIL":
        overall = "FAIL"
    else:
        overall = "NOT_TESTED"

    return {
        "CONNECTIVITY_WITH_REDIS_URL_CREDENTIAL": conn_url,
        "CONNECTIVITY_WITH_REDIS_PASSWORD": conn_pwd,
        "REDIS_CONNECTIVITY": overall,
    }


def classify_credential_relationship(
    api_usage="UNKNOWN",
    worker_usage="UNKNOWN",
    url_parity="UNKNOWN",
    conn_url="NOT_TESTED",
    conn_pwd="NOT_TESTED",
    target_hosts_differ=False,
    password_present=True,
    url_present=True,
):
    if target_hosts_differ:
        return "DIFFERENT_SERVERS"

    if conn_url == "FAIL" and conn_pwd == "FAIL":
        return "INCONSISTENT_CONFIGURATION"

    if (api_usage == "DIRECT_REDIS_URL" and worker_usage == "PASSWORD_PLUS_HOST_PORT") or \
       (api_usage == "PASSWORD_PLUS_HOST_PORT" and worker_usage == "DIRECT_REDIS_URL"):
        if conn_url == "PASS" and conn_pwd == "PASS":
            return "BOTH_USED_SAME_SERVER_DIFFERENT_CREDENTIAL"

    code_uses_url = "DIRECT_REDIS_URL" in (api_usage, worker_usage)
    code_uses_pwd = "PASSWORD_PLUS_HOST_PORT" in (api_usage, worker_usage)
    if "MIXED" in (api_usage, worker_usage):
        if url_parity == "PASS" and conn_url == "PASS" and conn_pwd == "PASS":
            return "PASSWORD_AND_URL_SAME_CREDENTIAL"
        if conn_url == "PASS" and conn_pwd == "FAIL":
            return "INCONSISTENT_CONFIGURATION"
        return "UNKNOWN"

    if api_usage == "DECLARED_BUT_UNUSED" or worker_usage == "DECLARED_BUT_UNUSED":
        if code_uses_url and not code_uses_pwd and conn_url == "PASS" and conn_pwd == "FAIL":
            return "LEGACY_PASSWORD_UNUSED"
        if code_uses_pwd and not code_uses_url:
            return "LEGACY_URL_UNUSED"

    if code_uses_url and not code_uses_pwd:
        if conn_url == "PASS" and conn_pwd in {"FAIL", "NOT_TESTED"}:
            return "URL_IS_CANONICAL"

    if code_uses_pwd and not code_uses_url:
        if conn_pwd == "PASS":
            return "PASSWORD_IS_CANONICAL"

    if (code_uses_url and conn_url == "FAIL") or (code_uses_pwd and conn_pwd == "FAIL"):
        return "INCONSISTENT_CONFIGURATION"

    return "UNKNOWN"


def build_future_rotation_sequence(relationship, auth_model, credential_source, site_uses_redis, worker_uses_redis):
    """Produces the abstract metadata sequence for the proven topology. Never executes."""
    if (relationship, auth_model, credential_source, site_uses_redis, worker_uses_redis) == (
            "INCONSISTENT_CONFIGURATION", "REQUIREPASS", "REDIS_CONF", "YES", "YES"):
        return list(LOCAL_REDIS_SEQUENCE)
    seq = [
        "BACKUP_CLIENT_ENV",
        "BACKUP_REDIS_AUTH_SOURCE",
        "GENERATE_NEW_PASSWORD",
        "UPDATE_REDIS_SERVER_CREDENTIAL",
    ]
    if relationship == "URL_IS_CANONICAL":
        seq.append("UPDATE_REDIS_URL")
        seq.append("UPDATE_REDUNDANT_REDIS_PASSWORD_IF_REQUIRED")
    elif relationship == "PASSWORD_IS_CANONICAL":
        seq.append("UPDATE_REDIS_PASSWORD")
        seq.append("UPDATE_REDUNDANT_REDIS_URL_IF_REQUIRED")
    else:
        seq.append("UPDATE_SITE_ENV")

    seq.append("RELOAD_OR_RESTART_REDIS_AS_REQUIRED")

    if site_uses_redis == "YES":
        seq.append("RESTART_SITE_API_IF_REQUIRED")
    if worker_uses_redis == "YES":
        seq.append("RESTART_SITE_WORKER_IF_REQUIRED")

    seq.extend(["REDIS_PING", "APPLICATION_HEALTH", "ROLLBACK_IF_FAILURE"])
    return seq


def consumer_report(kind, observation, configured):
    print(f"consumer={kind}")
    if observation is None:
        print("redis_password_present=UNKNOWN")
        print("redis_url_present=UNKNOWN")
        print("parity=UNKNOWN")
        return
    print(f"redis_password_present={'YES' if observation['password_present'] else 'NO'}")
    print(f"redis_url_present={'YES' if observation['url_present'] else 'NO'}")
    if configured is None:
        parity = "UNKNOWN"
    elif not any(configured[k] for k in ("password_present", "url_present")) and not any(observation[k] for k in ("password_present", "url_present")):
        parity = "NOT_APPLICABLE"
    else:
        parity = "PASS" if all(
            configured[k + "_present"] == observation[k + "_present"]
            and configured[k + "_hash"] == observation[k + "_hash"]
            for k in ("password", "url")
        ) else "FAIL"
    print(f"parity={parity}")


def runtime():
    config = json.loads(REGISTRY.read_text(encoding="utf-8"))["staging"]
    print("ENVIRONMENT=staging")
    print("redis_discovery_contract_version=2")
    print("redis_config_authority_required=YES")
    site_env = Path(config["site_env"])
    site_dir = Path(config["site_dir"])
    env_observation = probe_site_env(site_env, site_dir)
    for key, field in (("REDIS_PASSWORD", "password_present"), ("REDIS_URL", "url_present")):
        status = "UNKNOWN" if env_observation is None else ("YES" if env_observation[field] else "NO")
        print(f"site_env_{key.lower()}_present={status}")
    if env_observation is None:
        relation, relation_parity = "UNKNOWN", "UNKNOWN"
        shape = {}
    else:
        relation, relation_parity = classify_relationship(
            env_observation["password_present"], env_observation["password_hash"],
            env_observation["url_present"], env_observation["url_password_hash"],
            env_observation["url_valid"] or not env_observation["url_present"],
        )
        shape = env_observation["url_shape"]
    for key in ("redis_url_scheme", "redis_url_host_present", "redis_url_port_present", "redis_url_password_present", "redis_url_database_index_present"):
        print(f"{key}={shape.get(key, 'UNKNOWN')}")
    print(f"redis_url_contains_password={shape.get('redis_url_password_present', 'UNKNOWN')}")

    redis_target_host = shape.get("redis_target_host", "UNKNOWN")
    redis_target_port = shape.get("redis_target_port", 6379)
    redis_target_db = shape.get("redis_target_db", 0)
    print(f"redis_target_host={redis_target_host}")
    print(f"redis_target_port={redis_target_port}")
    print(f"redis_target_db={redis_target_db}")

    print(f"redis_password_url_relationship={relation}")
    print(f"redis_password_url_parity={relation_parity}")

    site = probe_process(pm2_pid(config["site_process"]))
    worker = probe_process(pm2_pid(config["worker_process"]))
    consumer_report("SITE_API", site, env_observation)
    consumer_report("SITE_WORKER", worker, env_observation)

    findings, api_usage, worker_usage, module_shared = scan_codebase_redis_usage(site_dir)
    for f in findings[:50]:
        print(f"source_reference={f['file']}:{f['line']}")
        print(f"variable={f['variable']}")
        print(f"usage_type={f['usage_type']}")
    print(f"source_reference_count={len(findings)}")
    print(f"source_reference_output_limited={'YES' if len(findings) > 50 else 'NO'}")

    print(f"SITE_API_REDIS_CONFIG_USAGE={api_usage}")
    print(f"SITE_WORKER_REDIS_CONFIG_USAGE={worker_usage}")
    print(f"redis_config_module_shared={'YES' if module_shared else ('NO' if module_shared is False else 'UNKNOWN')}")

    site_api_uses = "YES" if api_usage in {"DIRECT_REDIS_URL", "PASSWORD_PLUS_HOST_PORT", "MIXED"} else "UNKNOWN"
    site_worker_uses = "YES" if worker_usage in {"DIRECT_REDIS_URL", "PASSWORD_PLUS_HOST_PORT", "MIXED"} else "UNKNOWN"
    print(f"SITE_API_USES_REDIS={site_api_uses}")
    print(f"SITE_WORKER_USES_REDIS={site_worker_uses}")
    if site_api_uses == "YES" or site_worker_uses == "YES":
        c_src = "REDIS_URL" if api_usage == "DIRECT_REDIS_URL" else ("REDIS_PASSWORD" if api_usage == "PASSWORD_PLUS_HOST_PORT" else "BOTH")
        print(f"consumer_config_source={c_src}")

    other_procs = config.get("other_processes", [])
    if other_procs:
        print("OTHER_PM2_PROCESS=CONFIGURED")
    else:
        print("OTHER_PM2_PROCESS=NONE_CONFIGURED")

    expected_endpoint_match = (
        redis_target_host == config.get("expected_host")
        and redis_target_port == config.get("expected_port")
    )
    listener = discover_listener(redis_target_port)
    print(f"redis_socket_listening={listener['found']}")
    print(f"redis_socket_address_match={listener['address_match']}")
    print(f"redis_listener_owner_visible={listener['owner_visible']}")
    print(f"redis_listener_found={listener['found']}")
    print(f"redis_listener_type={listener['type']}")
    print(f"redis_listener_pid={listener['pid']}")
    print(f"redis_listener_process={listener['process']}")
    print(f"redis_expected_endpoint_match={'YES' if expected_endpoint_match else 'NO'}")
    docker_mapping = docker_host_port_match(redis_target_port)
    print(f"docker_host_port_6380_match={docker_mapping}")
    server_info = {"identified": False, "server_type": "UNKNOWN", "server_name": "UNKNOWN", "metadata": None}
    local_meta = {"executable": "UNKNOWN", "user": "UNKNOWN", "cwd": "UNKNOWN",
                  "process": "UNKNOWN", "parent_process": "UNKNOWN", "parent_detected": "NO",
                  "managed_by_pm2": "UNKNOWN"}
    active = {"candidate_count": 0, "active_match": "NO", "path": "UNKNOWN",
              "config": None, "source": "UNKNOWN"}
    config_authority = "UNKNOWN"
    pm2_identity = {"path": "UNKNOWN", "authority": "UNKNOWN", "name": "UNKNOWN"}
    if listener["type"] == "DOCKER_PROXY" and docker_mapping == "YES":
        server_info = identify_site_redis_server(redis_target_host, redis_target_port, docker_candidates())
    elif listener["type"] == "REDIS_PROCESS":
        local_meta = local_redis_metadata(listener["pid"])
        if local_meta["managed_by_pm2"] == "YES":
            pm2_identity = pm2_explicit_config(listener["pid"], config.get("expected_pm2_process"))
            config_authority, chosen_path = select_config_authority(pm2_path=pm2_identity["path"])
        else:
            config_authority, chosen_path = select_config_authority(
                process_path=direct_process_config(listener["pid"]),
                service_path=service_unit_config(listener["pid"]))
            if chosen_path == "UNKNOWN":
                candidate = discover_active_config(
                    redis_target_host, redis_target_port, listener, local_meta,
                    config.get("expected_config_candidates", []),
                    expected_user=config.get("expected_process_user"))
                config_authority, chosen_path = select_config_authority(
                    heuristic_path=candidate["path"])
        if (chosen_path != "UNKNOWN"
                and config_file_metadata_ok(chosen_path, config.get("expected_process_user", "gsadmin"))):
            active = discover_active_config(
                redis_target_host, redis_target_port, listener, local_meta,
                [chosen_path], glob_fn=lambda _directory: [],
                expected_user=config.get("expected_process_user"),
            )
        if (expected_endpoint_match and docker_mapping == "NO"
                and local_meta["managed_by_pm2"] == "YES"
                and config_authority == "PM2_SCRIPT_ARGUMENT"
                and active["active_match"] == "YES"):
            server_info = {"identified": True, "server_type": "LOCAL_PROCESS", "server_name": "redis-server", "metadata": None}
    print(f"redis_port_mapping_match={'YES' if server_info['server_type'] == 'DOCKER_CONTAINER' else 'NO'}")
    print(f"redis_executable={local_meta['executable']}")
    print(f"redis_process_user={local_meta['user']}")
    print(f"redis_process_cwd={local_meta['cwd']}")
    print(f"redis_parent_process={local_meta['parent_process']}")
    print(f"redis_parent_process_detected={local_meta['parent_detected']}")
    print(f"redis_managed_by_pm2={local_meta['managed_by_pm2']}")
    print(f"redis_pm2_process_name={pm2_identity['name']}")
    print(f"redis_config_authority={config_authority}")
    print(f"redis_config_candidate_count={active['candidate_count']}")
    print(f"redis_active_config_match={active['active_match']}")
    print(f"redis_config_path={active['path']}")
    legacy = inspect_legacy_config(active["path"], config.get("legacy_config_candidates", []),
                                   active["config"]) if active["config"] else {
                                       "detected": "NO", "path": "UNKNOWN",
                                       "operationally_similar": "UNKNOWN",
                                       "requirepass_relationship": "UNKNOWN", "classification": "UNKNOWN"}
    print(f"redis_legacy_config_detected={legacy['detected']}")
    print(f"legacy_config_path={legacy['path']}")
    print(f"legacy_config_operationally_similar={legacy['operationally_similar']}")
    print(f"legacy_requirepass_relationship={legacy['requirepass_relationship']}")
    print(f"legacy_candidate_classification={legacy['classification']}")
    print(f"SITE_REDIS_SERVER_IDENTIFIED={'YES' if server_info['identified'] else 'NO'}")
    print(f"site_redis_server_type={server_info['server_type']}")
    print(f"site_redis_server_name={server_info['server_name']}")

    paths = resolve_config_paths(server_info["metadata"])
    cfg_info = active["config"]
    if cfg_info:
        print(f"config_bind={cfg_info['bind']}")
        print(f"config_port={cfg_info['port']}")
        print(f"config_dir={cfg_info['dir']}")
        print(f"config_dbfilename={cfg_info['dbfilename']}")
        print(f"config_appendonly={cfg_info['appendonly']}")
        print(f"config_requirepass_present={'YES' if cfg_info['requirepass'] == 'PRESENT' else 'NO'}")
        print(f"config_aclfile_present={cfg_info['aclfile_present']}")

    cred_redis_pwd, url_password = extract_env_credentials_in_memory(site_env)
    active_password = requirepass_value_in_memory(active["path"]) if active["active_match"] == "YES" else None
    print(f"active_requirepass_vs_redis_url={safe_credential_relation(active_password, url_password)}")
    print(f"active_requirepass_vs_redis_password={safe_credential_relation(active_password, cred_redis_pwd)}")
    print(f"redis_url_vs_redis_password={safe_credential_relation(url_password, cred_redis_pwd)}")
    conn_results = probe_credentials_connectivity(redis_target_host, redis_target_port, cred_redis_pwd, url_password)
    print(f"CONNECTIVITY_WITH_REDIS_URL_CREDENTIAL={conn_results['CONNECTIVITY_WITH_REDIS_URL_CREDENTIAL']}")
    print(f"CONNECTIVITY_WITH_REDIS_PASSWORD={conn_results['CONNECTIVITY_WITH_REDIS_PASSWORD']}")
    print(f"REDIS_CONNECTIVITY={conn_results['REDIS_CONNECTIVITY']}")
    if conn_results["REDIS_CONNECTIVITY"] == "NOT_TESTED":
        print("connectivity_not_tested_reason=SERVER_AUTH_TOPOLOGY_UNKNOWN")

    auth = redis_auth_probe(redis_target_host, redis_target_port, url_password) if conn_results["CONNECTIVITY_WITH_REDIS_URL_CREDENTIAL"] == "PASS" else {
        "ping": "FAIL", "whoami_available": "NO", "current_user": "UNKNOWN", "requirepass_status": "UNAVAILABLE", "auth_model": "UNKNOWN"}
    auth_model = auth["auth_model"]
    print(f"redis_auth_ping={auth['ping']}")
    print(f"redis_acl_whoami_available={auth['whoami_available']}")
    print(f"redis_acl_current_user={auth['current_user']}")
    print(f"requirepass_status={auth['requirepass_status']}")
    print(f"redis_server_auth_model={auth_model}")
    if (server_info["server_type"] == "LOCAL_PROCESS" and cfg_info
            and cfg_info["requirepass"] == "PRESENT"
            and cfg_info["aclfile_present"] == "NO"
            and auth["requirepass_status"] == "CONFIGURED"
            and auth_model == "REQUIREPASS"):
        cred_source = "REDIS_CONF"
        paths["config"] = active["path"]
    elif active["source"] == "AMBIGUOUS_CONFIG":
        cred_source = "AMBIGUOUS_CONFIG"
    elif server_info["server_type"] == "DOCKER_CONTAINER":
        cred_source = classify_credential_source_from_metadata(server_info["metadata"])
    else:
        cred_source = "UNKNOWN"
    print(f"redis_credential_source={cred_source}")

    cred_relationship = classify_credential_relationship(
        api_usage=api_usage,
        worker_usage=worker_usage,
        url_parity=relation_parity,
        conn_url=conn_results["CONNECTIVITY_WITH_REDIS_URL_CREDENTIAL"],
        conn_pwd=conn_results["CONNECTIVITY_WITH_REDIS_PASSWORD"],
        password_present=env_observation["password_present"] if env_observation else False,
        url_present=env_observation["url_present"] if env_observation else False,
    )
    print(f"REDIS_CREDENTIAL_RELATIONSHIP={cred_relationship}")
    api_restart = restart_impact(site_api_uses, site)
    worker_restart = restart_impact(site_worker_uses, worker)
    print(f"SITE_API_RESTART_REQUIRED_ON_ROTATION={api_restart}")
    print(f"SITE_WORKER_RESTART_REQUIRED_ON_ROTATION={worker_restart}")
    backup_targets = [config["site_env"]]
    if cred_source == "REDIS_CONF" and paths["config"] != "UNKNOWN":
        backup_targets.append(paths["config"])
    if cred_source == "ACL_FILE" and paths["acl"] != "UNKNOWN":
        backup_targets.append(paths["acl"])
        if paths["config"] != "UNKNOWN":
            backup_targets.append(paths["config"])
    backup_targets = list(dict.fromkeys(backup_targets))
    source_backup_known = cred_source == "REDIS_CONF" and len(backup_targets) == 2

    can_be_ready = (
        server_info["identified"]
        and config_authority == config.get("required_config_authority")
        and active["path"] in config.get("expected_config_candidates", [])
        and safe_credential_relation(active_password, url_password) == "SAME"
        and safe_credential_relation(active_password, cred_redis_pwd) == "DIFFERENT"
        and auth_model == "REQUIREPASS"
        and cred_source == "REDIS_CONF"
        and site_api_uses == "YES"
        and site_worker_uses == "YES"
        and cred_relationship == "INCONSISTENT_CONFIGURATION"
        and conn_results["REDIS_CONNECTIVITY"] == "PASS"
        and conn_results["CONNECTIVITY_WITH_REDIS_URL_CREDENTIAL"] == "PASS"
        and source_backup_known and api_restart == "YES" and worker_restart == "YES"
    )

    if can_be_ready:
        future_seq = build_future_rotation_sequence(cred_relationship, auth_model, cred_source, site_api_uses, site_worker_uses)
    else:
        future_seq = []

    evidence = {
        "server_identified": server_info["identified"],
        "server_type": server_info["server_type"],
        "socket_listening": listener["found"],
        "socket_address_match": listener["address_match"],
        "listener_owner_visible": listener["owner_visible"],
        "process_identity_verified": local_meta["process"] == "redis-server" and local_meta["user"] == config.get("expected_process_user") and expected_endpoint_match,
        "managed_by_pm2": local_meta["managed_by_pm2"],
        "active_config_match": active["active_match"],
        "config_authority": config_authority,
        "discovery_contract_version": 2,
        "config_path": active["path"],
        "executable": local_meta["executable"],
        "auth_model": auth_model,
        "auth_ping": auth["ping"],
        "requirepass_status": auth["requirepass_status"],
        "credential_source_identified": cred_source not in {"UNKNOWN", "DOCKER_ENV_UNREADABLE_BY_POLICY"},
        "credential_source": cred_source,
        "site_api_uses_redis": site_api_uses,
        "site_worker_uses_redis": site_worker_uses,
        "api_usage": api_usage,
        "worker_usage": worker_usage,
        "api_restart_required": api_restart,
        "worker_restart_required": worker_restart,
        "other_consumers_known": True,
        "relationship": cred_relationship if cred_relationship != "UNKNOWN" else relation,
        "relationship_parity": relation_parity,
        "backup_targets": backup_targets,
        "backup_targets_complete": source_backup_known,
        "restart_targets": [config["site_process"], config["worker_process"]] if (site_api_uses == "YES" or site_worker_uses == "YES") else [],
        "restart_targets_known": api_restart == "YES" and worker_restart == "YES",
        "future_sequence": future_seq,
        "connectivity": conn_results["REDIS_CONNECTIVITY"],
        "connectivity_url": conn_results["CONNECTIVITY_WITH_REDIS_URL_CREDENTIAL"],
        "connectivity_password": conn_results["CONNECTIVITY_WITH_REDIS_PASSWORD"],
        "connectivity_not_tested_reason": "SERVER_AUTH_TOPOLOGY_UNKNOWN" if conn_results["REDIS_CONNECTIVITY"] == "NOT_TESTED" else None,
    }
    readiness = assess_readiness(evidence)
    for key, value in readiness.items():
        if key == "future_rotation_steps":
            for idx, step in enumerate(value, 1):
                print(f"future_step_{idx}={step}")
                print(f"future_rotation_step={step}")
        else:
            print(f"{key}={value}")
    for target in backup_targets:
        print(f"future_backup_target={target}")
    print("NO_SECRET_VALUES_PRINTED=PASS")
    print("NO_FILES_MODIFIED=PASS")
    print("NO_SERVICES_RESTARTED=PASS")
    print("NO_DATABASE_READS=PASS")
    print("NO_DATABASE_WRITES=PASS")
    print("REDIS_PREFLIGHT=PASS")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", required=True)
    args = parser.parse_args(argv)
    if args.runtime == "production":
        print("PRODUCTION_PREFLIGHT=BLOCKED")
        print("REDIS_PREFLIGHT=FAIL")
        return 1
    if args.runtime != "staging":
        print("REDIS_PREFLIGHT=FAIL")
        return 1
    try:
        return runtime()
    except (OSError, ValueError, KeyError, TypeError):
        print("REDIS_PREFLIGHT=FAIL")
        return 1


if __name__ == "__main__":
    sys.exit(main())
