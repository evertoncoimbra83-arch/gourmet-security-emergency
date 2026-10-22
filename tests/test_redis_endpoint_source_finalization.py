"""GSE-03B4: endpoint, process, active config, and readiness models."""
import importlib.util
import io
import json
import subprocess
import tempfile
import unittest
from contextlib import ExitStack, redirect_stdout
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "rotations" / "redis" / "redis-discovery.py"
spec = importlib.util.spec_from_file_location("redis_b4", SCRIPT)
redis = importlib.util.module_from_spec(spec)
spec.loader.exec_module(redis)


class RedisEndpointSourceFinalization(unittest.TestCase):
    HOST = "127.0.0.1"
    PORT = 6380
    CONFIG = "/home/gsadmin/secure-env/p1rk/redis-staging.conf"
    CWD = "/home/gsadmin/redis-staging/data"
    RDB = CWD + "/staging.rdb"
    ENV = "/home/gsadmin/secure-env/.env.staging"

    @staticmethod
    def ss_line(address, process="", pid=927):
        owner = f' users:(("{process}",pid={pid},fd=6))' if process else ""
        return f"LISTEN 0 511 {address} 0.0.0.0:*{owner}\n"

    def ss_run(self, command, **kwargs):
        owner = command[1] == "-ltnp"
        rows = self.ss_line("127.0.0.1:6380", "redis-server" if owner else "")
        rows += self.ss_line("[::1]:6380", "redis-server" if owner else "")
        return subprocess.CompletedProcess(command, 0, "State Recv-Q Send-Q Local Address:Port Peer Address:Port\n" + rows, "")

    @staticmethod
    def process():
        return {"executable": "/usr/bin/redis-server", "user": "gsadmin", "cwd": RedisEndpointSourceFinalization.CWD,
                "process": "redis-server", "parent_process": "PM2", "parent_detected": "YES", "managed_by_pm2": "YES"}

    @staticmethod
    def config():
        return {"port": "6380", "bind": "127.0.0.1,::1", "dir": RedisEndpointSourceFinalization.CWD,
                "dbfilename": "staging.rdb", "appendonly": "yes", "requirepass": "PRESENT",
                "aclfile": "UNKNOWN", "aclfile_present": "NO", "conflict": False, "readable": True, "users": []}

    def active(self, config=None, extra=()):
        cfg = config or self.config()
        existing = {self.CONFIG, self.RDB, *extra}
        return redis.discover_active_config(
            self.HOST, self.PORT, redis.discover_listener(run_fn=self.ss_run), self.process(),
            [self.CONFIG, *extra], exists_fn=lambda p: p in existing,
            config_reader=lambda p: cfg, glob_fn=lambda d: [], expected_user="gsadmin")

    @staticmethod
    def evidence():
        return {"socket_listening": "YES", "socket_address_match": "YES", "listener_owner_visible": "YES",
                "server_identified": True, "server_type": "LOCAL_PROCESS", "process_identity_verified": True,
                "managed_by_pm2": "YES", "active_config_match": "YES",
                "config_authority": "PM2_SCRIPT_ARGUMENT", "discovery_contract_version": 2,
                "config_path": RedisEndpointSourceFinalization.CONFIG, "executable": "/usr/bin/redis-server",
                "credential_source_identified": True, "credential_source": "REDIS_CONF",
                "auth_model": "REQUIREPASS", "auth_ping": "PASS", "requirepass_status": "CONFIGURED",
                "connectivity": "PASS", "connectivity_url": "PASS", "connectivity_password": "FAIL",
                "site_api_uses_redis": "YES", "site_worker_uses_redis": "YES",
                "api_restart_required": "YES", "worker_restart_required": "YES",
                "api_usage": "MIXED", "worker_usage": "MIXED", "relationship_parity": "FAIL",
                "relationship": "INCONSISTENT_CONFIGURATION", "other_consumers_known": True,
                "backup_targets": [RedisEndpointSourceFinalization.ENV, RedisEndpointSourceFinalization.CONFIG],
                "backup_targets_complete": True, "restart_targets": ["site", "worker"],
                "restart_targets_known": True, "future_sequence": list(redis.LOCAL_REDIS_SEQUENCE)}

    def test_ss_socket_ipv4_and_ipv6_without_pid(self):
        listener = redis.discover_listener(run_fn=self.ss_run)
        self.assertEqual(listener["found"], "YES")
        self.assertEqual(listener["address_match"], "YES")
        calls = []
        def no_owner(command, **kwargs):
            calls.append(command)
            return subprocess.CompletedProcess(command, 0, self.ss_line("127.0.0.1:6380") + self.ss_line("[::1]:6380"), "")
        listener = redis.discover_listener(run_fn=no_owner)
        self.assertEqual(listener["found"], "YES")
        self.assertEqual(listener["owner_visible"], "NO")
        self.assertEqual([x[1] for x in calls], ["-ltn", "-ltnp"])

    def test_ipv6_only_does_not_match_ipv4_endpoint(self):
        def ipv6_only(command, **kwargs):
            return subprocess.CompletedProcess(command, 0, self.ss_line("[::1]:6380", "redis-server"), "")
        listener = redis.discover_listener(run_fn=ipv6_only)
        self.assertEqual(listener["found"], "YES")
        self.assertEqual(listener["address_match"], "NO")

    def test_ss_process_owner_and_dynamic_pid(self):
        listener = redis.discover_listener(run_fn=self.ss_run)
        self.assertEqual((listener["type"], listener["pid"], listener["process"]), ("REDIS_PROCESS", "927", "redis-server"))
        def dynamic(command, **kwargs):
            row = self.ss_line("127.0.0.1:6380", "redis-server" if command[1] == "-ltnp" else "", 12345)
            return subprocess.CompletedProcess(command, 0, row, "")
        self.assertEqual(redis.discover_listener(run_fn=dynamic)["pid"], "12345")

    def test_process_exe_cwd_parent_and_cgroup(self):
        def run(command, **kwargs):
            pid, field = command[2], command[4]
            value = {("927", "user=,comm="): "gsadmin redis-server\n",
                     ("927", "ppid="): "846\n",
                     ("846", "user=,comm="): "gsadmin PM2 v6.0.14: God Daemon\n"}.get((pid, field), "")
            return subprocess.CompletedProcess(command, 0 if value else 1, value, "")
        def link(path):
            return "/usr/bin/redis-server" if path.endswith("/exe") else self.CWD
        with patch.object(redis.os, "readlink", side_effect=link), \
             patch.object(redis.os.path, "realpath", side_effect=lambda p: p), \
             patch.object(redis.Path, "read_text", return_value="0::/system.slice/pm2-gsadmin.service\n"):
            meta = redis.local_redis_metadata(927, run_fn=run)
        self.assertEqual(meta["executable"], "/usr/bin/redis-server")
        self.assertEqual(meta["cwd"], self.CWD)
        self.assertEqual(meta["parent_process"], "PM2")
        self.assertEqual(meta["managed_by_pm2"], "YES")
        self.assertEqual(meta["user"], "gsadmin")

    def test_cgroup_detects_pm2_without_visible_parent(self):
        def run(command, **kwargs):
            value = "gsadmin redis-server\n" if command[-1] == "user=,comm=" and command[2] == "927" else ""
            return subprocess.CompletedProcess(command, 0 if value else 1, value, "")
        with patch.object(redis.os, "readlink", side_effect=lambda p: "/usr/bin/redis-server" if p.endswith("/exe") else self.CWD), \
             patch.object(redis.os.path, "realpath", side_effect=lambda p: p), \
             patch.object(redis.Path, "read_text", return_value="0::/system.slice/pm2-gsadmin.service\n"):
            meta = redis.local_redis_metadata(927, run_fn=run)
        self.assertEqual(meta["managed_by_pm2"], "YES")
        self.assertEqual(meta["parent_detected"], "NO")

    def test_docker_without_6380_mapping(self):
        run = lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, "0.0.0.0:6379->6379/tcp\n", "")
        self.assertEqual(redis.docker_host_port_match(6380, run_fn=run), "NO")

    def test_docker_6380_mapping_detected(self):
        run = lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, "127.0.0.1:6380->6379/tcp\n", "")
        self.assertEqual(redis.docker_host_port_match(6380, run_fn=run), "YES")

    def test_candidate_exists_and_unique_active_match(self):
        result = self.active()
        self.assertEqual(result["candidate_count"], 1)
        self.assertEqual(result["active_match"], "YES")
        self.assertEqual(result["path"], self.CONFIG)
        self.assertEqual(result["source"], "REDIS_CONF")

    def test_config_port_bind_dir_dbfile_and_requirepass(self):
        cfg = self.config()
        for field, wrong in (("port", "6379"), ("bind", "::1"), ("dir", "/tmp"),
                             ("dbfilename", "other.rdb"), ("requirepass", "ABSENT"),
                             ("aclfile_present", "YES")):
            with self.subTest(field=field):
                changed = dict(cfg, **{field: wrong})
                self.assertEqual(self.active(config=changed)["active_match"], "NO")

    def test_config_dbfile_must_exist(self):
        result = redis.discover_active_config(self.HOST, self.PORT, redis.discover_listener(run_fn=self.ss_run),
                                              self.process(), [self.CONFIG], exists_fn=lambda p: p == self.CONFIG,
                                              config_reader=lambda p: self.config(), glob_fn=lambda d: [])
        self.assertEqual(result["active_match"], "NO")

    def test_ambiguous_configs_block(self):
        other = "/home/gsadmin/redis-staging/second.conf"
        result = self.active(extra=(other,))
        self.assertEqual(result["candidate_count"], 2)
        self.assertEqual(result["source"], "AMBIGUOUS_CONFIG")
        self.assertEqual(result["path"], "UNKNOWN")

    def test_candidate_search_is_bounded(self):
        visited = []
        def glob(directory):
            visited.append(directory)
            return []
        redis.discover_active_config(self.HOST, self.PORT, redis.discover_listener(run_fn=self.ss_run),
                                     self.process(), [self.CONFIG], exists_fn=lambda p: p in {self.CONFIG, self.RDB},
                                     config_reader=lambda p: self.config(), glob_fn=glob)
        self.assertEqual(visited, [self.CWD, "/home/gsadmin/redis-staging"])

    def test_config_can_be_discovered_from_cwd_parent_without_registry_path(self):
        result = redis.discover_active_config(
            self.HOST, self.PORT, redis.discover_listener(run_fn=self.ss_run), self.process(), [],
            exists_fn=lambda p: p in {self.CONFIG, self.RDB},
            config_reader=lambda p: self.config(),
            glob_fn=lambda directory: [self.CONFIG] if directory == "/home/gsadmin/redis-staging" else [])
        self.assertEqual(result["path"], self.CONFIG)

    def test_wrong_process_user_or_owner_blocks_config_match(self):
        process = dict(self.process(), user="other")
        result = redis.discover_active_config(
            self.HOST, self.PORT, redis.discover_listener(run_fn=self.ss_run), process, [self.CONFIG],
            exists_fn=lambda p: p in {self.CONFIG, self.RDB}, config_reader=lambda p: self.config(),
            glob_fn=lambda d: [], expected_user="gsadmin")
        self.assertEqual(result["active_match"], "NO")
        listener = dict(redis.discover_listener(run_fn=self.ss_run), owner_visible="NO")
        result = redis.discover_active_config(
            self.HOST, self.PORT, listener, self.process(), [self.CONFIG],
            exists_fn=lambda p: p in {self.CONFIG, self.RDB}, config_reader=lambda p: self.config(),
            glob_fn=lambda d: [])
        self.assertEqual(result["active_match"], "NO")

    def test_config_parser_sanitized_directives(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "redis-staging.conf"
            path.write_text("port 6380\nbind 127.0.0.1 ::1\ndir /home/gsadmin/redis-staging/data\n"
                            "appendonly yes\ndbfilename staging.rdb\nrequirepass SECRET_VALUE_X\n")
            with patch.object(redis, "safe_path", side_effect=lambda p: str(p)):
                cfg = redis.inspect_redis_config(str(path))
        self.assertEqual(cfg["port"], "6380")
        self.assertEqual(cfg["bind"], "127.0.0.1,::1")
        self.assertEqual(cfg["appendonly"], "yes")
        self.assertEqual(cfg["requirepass"], "PRESENT")
        self.assertEqual(cfg["aclfile_present"], "NO")
        self.assertNotIn("SECRET_VALUE_X", str(cfg))

    def test_include_and_duplicate_directives_are_conflicts(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "redis.conf"
            path.write_text("port 6380\nport 6381\ninclude /other.conf\n")
            with patch.object(redis, "safe_path", side_effect=lambda p: str(p)):
                self.assertTrue(redis.inspect_redis_config(str(path))["conflict"])

    def test_auth_requirepass_model(self):
        def run(command, **kwargs):
            if command[-1] == "PING":
                value = "PONG\n"
            elif command[-2:] == ["ACL", "WHOAMI"]:
                value = "default\n"
            else:
                value = "requirepass\nSERVER_SECRET_VALUE\n"
            return subprocess.CompletedProcess(command, 0, value, "")
        auth = redis.redis_auth_probe(self.HOST, self.PORT, "URL_SECRET_VALUE", run_fn=run)
        self.assertEqual(auth["auth_model"], "REQUIREPASS")
        self.assertEqual(auth["requirepass_status"], "CONFIGURED")
        self.assertNotIn("SERVER_SECRET_VALUE", str(auth))

    def test_relationship_remains_inconsistent(self):
        relation = redis.classify_credential_relationship("MIXED", "MIXED", "FAIL", "PASS", "FAIL")
        self.assertEqual(relation, "INCONSISTENT_CONFIGURATION")

    def test_restart_impact_api_and_worker(self):
        obs = {"url_present": True, "password_present": True}
        self.assertEqual(redis.restart_impact("YES", obs), "YES")
        self.assertEqual(redis.restart_impact("YES", obs), "YES")

    def test_future_backup_targets_and_sequence(self):
        evidence = self.evidence()
        self.assertEqual(len(evidence["backup_targets"]), 2)
        self.assertEqual(redis.build_future_rotation_sequence("INCONSISTENT_CONFIGURATION", "REQUIREPASS", "REDIS_CONF", "YES", "YES"), redis.LOCAL_REDIS_SEQUENCE)
        self.assertEqual(len(redis.LOCAL_REDIS_SEQUENCE), 12)

    def test_ready_only_complete_topology(self):
        result = redis.assess_readiness(self.evidence())
        self.assertEqual(result["ROTATION_READINESS"], "READY")
        self.assertEqual(result["FUTURE_ROTATION_SEQUENCE"], "KNOWN")
        self.assertEqual(result["future_backup_targets"], 2)

    def test_missing_evidence_blocks_readiness(self):
        values = {"socket_listening": "NO", "socket_address_match": "NO", "server_identified": False,
                  "server_type": "UNKNOWN", "process_identity_verified": False, "managed_by_pm2": "UNKNOWN",
                  "active_config_match": "NO", "config_path": "UNKNOWN", "credential_source": "UNKNOWN",
                  "auth_model": "UNKNOWN", "connectivity": "FAIL", "connectivity_url": "FAIL",
                  "api_restart_required": "UNKNOWN", "worker_restart_required": "UNKNOWN",
                  "relationship": "URL_IS_CANONICAL", "future_sequence": []}
        for field, value in values.items():
            with self.subTest(field=field):
                evidence = self.evidence()
                evidence[field] = value
                self.assertEqual(redis.assess_readiness(evidence)["ROTATION_READINESS"], "BLOCKED")

    def test_historical_dist_swap_and_backups_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ("dist.swap-old-iac-h1-123", "dist.swap", "dist.backup", "backups", "releases", "node_modules", ".git"):
                folder = root / name
                folder.mkdir()
                (folder / "redis.js").write_text("new Redis(process.env.REDIS_PASSWORD)")
            server = root / "server"
            server.mkdir()
            (server / "redis.js").write_text("new Redis(process.env.REDIS_URL)")
            findings, usage, _, _ = redis.scan_codebase_redis_usage(root)
        self.assertEqual(len(findings), 1)
        self.assertEqual(usage, "DIRECT_REDIS_URL")

    def test_runtime_reports_proven_staging_topology_without_execution(self):
        shape = redis.parse_redis_url("redis://:URL_SECRET_VALUE@127.0.0.1:6380/0")
        shape.pop("url_password_hash")
        env = {"password_present": True, "url_present": True,
               "password_hash": redis.digest("WRONG_SECRET_VALUE"),
               "url_hash": redis.digest("redis://:URL_SECRET_VALUE@127.0.0.1:6380/0"),
               "url_password_hash": redis.digest("URL_SECRET_VALUE"),
               "url_valid": True, "url_shape": shape}
        process_env = {"password_present": True, "url_present": True,
                       "password_hash": env["password_hash"], "url_hash": env["url_hash"]}
        active = {"candidate_count": 1, "active_match": "YES", "path": self.CONFIG,
                  "config": self.config(), "source": "REDIS_CONF"}
        connectivity = {"CONNECTIVITY_WITH_REDIS_URL_CREDENTIAL": "PASS",
                        "CONNECTIVITY_WITH_REDIS_PASSWORD": "FAIL", "REDIS_CONNECTIVITY": "PASS"}
        auth = {"ping": "PASS", "whoami_available": "YES", "current_user": "default",
                "requirepass_status": "CONFIGURED", "auth_model": "REQUIREPASS"}
        listener = redis.discover_listener(run_fn=self.ss_run)
        registry = {"staging": {"site_env": self.ENV, "site_dir": "/var/www/gourmet-staging",
                                "site_process": "site", "worker_process": "worker",
                                "expected_host": self.HOST, "expected_port": self.PORT,
                                "expected_process_user": "gsadmin",
                                "expected_pm2_process": "redis-staging",
                                "required_config_authority": "PM2_SCRIPT_ARGUMENT",
                                "redis_discovery_contract_version": 2,
                                "expected_config_candidates": [self.CONFIG]}}
        with tempfile.TemporaryDirectory() as tmp:
            registry_path = Path(tmp) / "registry.json"
            registry_path.write_text(json.dumps(registry))
            output = io.StringIO()
            with ExitStack() as stack:
                for name, value in (("REGISTRY", registry_path),
                                    ("probe_site_env", lambda *a: env),
                                    ("pm2_pid", lambda *a: 1),
                                    ("probe_process", lambda *a: process_env),
                                    ("scan_codebase_redis_usage", lambda *a: ([], "MIXED", "MIXED", True)),
                                    ("discover_listener", lambda *a: listener),
                                    ("docker_host_port_match", lambda *a: "NO"),
                                    ("local_redis_metadata", lambda *a: self.process()),
                                    ("pm2_explicit_config", lambda *a: {"path": self.CONFIG, "authority": "PM2_SCRIPT_ARGUMENT", "name": "redis-staging"}),
                                    ("config_file_metadata_ok", lambda *a: True),
                                    ("discover_active_config", lambda *a, **k: active),
                                    ("inspect_legacy_config", lambda *a, **k: {
                                        "detected": "YES", "path": "/home/gsadmin/redis-staging/redis-staging.conf",
                                        "operationally_similar": "YES", "requirepass_relationship": "DIFFERENT",
                                        "classification": "STALE_CREDENTIAL_CONFIG"}),
                                    ("requirepass_value_in_memory", lambda *a: "URL_SECRET_VALUE"),
                                    ("extract_env_credentials_in_memory", lambda *a: ("WRONG_SECRET_VALUE", "URL_SECRET_VALUE")),
                                    ("probe_credentials_connectivity", lambda *a: connectivity),
                                    ("redis_auth_probe", lambda *a: auth)):
                    stack.enter_context(patch.object(redis, name, value))
                stack.enter_context(redirect_stdout(output))
                self.assertEqual(redis.runtime(), 0)
        report = output.getvalue()
        for marker in ("SITE_REDIS_SERVER_IDENTIFIED=YES", "site_redis_server_type=LOCAL_PROCESS",
                       "redis_executable=/usr/bin/redis-server", "redis_config_path=" + self.CONFIG,
                       "redis_discovery_contract_version=2", "redis_config_authority=PM2_SCRIPT_ARGUMENT",
                       "redis_legacy_config_detected=YES",
                       "legacy_requirepass_relationship=DIFFERENT",
                       "active_requirepass_vs_redis_url=SAME",
                       "active_requirepass_vs_redis_password=DIFFERENT",
                       "redis_credential_source=REDIS_CONF", "redis_server_auth_model=REQUIREPASS",
                       "REDIS_CREDENTIAL_RELATIONSHIP=INCONSISTENT_CONFIGURATION",
                       "future_backup_targets=2", "future_step_12=ROLLBACK_ON_FAILURE",
                       "ROTATION_READINESS=READY", "FUTURE_ROTATION_SEQUENCE=KNOWN"):
            self.assertIn(marker, report)
        self.assertEqual(report.count("source_reference="), 0)
        self.assertNotIn("URL_SECRET_VALUE", report)
        self.assertNotIn("WRONG_SECRET_VALUE", report)

    def test_static_read_only_policy(self):
        source = SCRIPT.read_text(encoding="utf-8")
        for forbidden in ("pm2 env", "pm2 jlist", "printenv", "cat .env", "source .env",
                          "Config.Env", "redis-cli -a", "redis-cli --pass", "CONFIG SET",
                          "CONFIG REWRITE", "ACL SETUSER", "FLUSHDB", "FLUSHALL",
                          "pm2 restart", "docker restart", "systemctl restart", "pm2 save",
                          "mysql", "mariadb", "shell=True"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)

    def test_production_execution_blocked(self):
        output = io.StringIO()
        with redirect_stdout(output):
            code = redis.main(["--runtime", "production"])
        self.assertEqual(code, 1)
        self.assertIn("PRODUCTION_PREFLIGHT=BLOCKED", output.getvalue())


if __name__ == "__main__":
    unittest.main()
