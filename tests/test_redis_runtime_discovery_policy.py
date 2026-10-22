"""Policy and functionality tests for GSE-03B2: Redis Runtime Usage & Server Auth Discovery."""
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
DISCOVERY_PATH = ROOT / "rotations" / "redis" / "redis-discovery.py"
spec = importlib.util.spec_from_file_location("redis_discovery_runtime", DISCOVERY_PATH)
redis = importlib.util.module_from_spec(spec)
spec.loader.exec_module(redis)


class RedisRuntimeDiscoveryPolicy(unittest.TestCase):
    # 1. detectar process.env.REDIS_URL
    def test_01_detect_process_env_redis_url(self):
        with tempfile.TemporaryDirectory() as temp:
            src = Path(temp) / "src"
            src.mkdir()
            (src / "client.js").write_text(
                'const { createClient } = require("redis");\n'
                'const client = createClient({ url: process.env.REDIS_URL });\n'
            )
            findings, api_usage, worker_usage, shared = redis.scan_codebase_redis_usage(temp)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["variable"], "REDIS_URL")
            self.assertEqual(findings[0]["usage_type"], "CLIENT_CONNECTION")
            self.assertEqual(api_usage, "DIRECT_REDIS_URL")
            self.assertEqual(worker_usage, "DIRECT_REDIS_URL")
            self.assertTrue(shared)

    # 2. detectar process.env.REDIS_PASSWORD
    def test_02_detect_process_env_redis_password(self):
        with tempfile.TemporaryDirectory() as temp:
            src = Path(temp) / "src"
            src.mkdir()
            (src / "redis.ts").write_text(
                'import Redis from "ioredis";\n'
                'const r = new Redis({ host: process.env.REDIS_HOST, port: Number(process.env.REDIS_PORT), password: process.env.REDIS_PASSWORD });\n'
            )
            findings, api_usage, worker_usage, shared = redis.scan_codebase_redis_usage(temp)
            vars_found = [f["variable"] for f in findings]
            self.assertIn("REDIS_PASSWORD", vars_found)
            self.assertIn("REDIS_HOST", vars_found)
            self.assertEqual(api_usage, "PASSWORD_PLUS_HOST_PORT")

    # 3. detectar uso misto
    def test_03_detect_mixed_usage(self):
        with tempfile.TemporaryDirectory() as temp:
            src = Path(temp) / "src"
            src.mkdir()
            (src / "cache.js").write_text('const r1 = new Redis(process.env.REDIS_URL);\n')
            (src / "store.js").write_text('const r2 = new Redis({ password: process.env.REDIS_PASSWORD });\n')
            findings, api_usage, worker_usage, shared = redis.scan_codebase_redis_usage(temp)
            self.assertEqual(api_usage, "MIXED")

    # 4. distinguir declaração de uso real
    def test_04_distinguish_declaration_from_real_usage(self):
        with tempfile.TemporaryDirectory() as temp:
            src = Path(temp) / "src"
            src.mkdir()
            (src / "env.ts").write_text(
                'export const envSchema = {\n'
                '  REDIS_PASSWORD: z.string().optional(),\n'
                '  REDIS_URL: z.string().url(),\n'
                '};\n'
            )
            (src / "lib.ts").write_text(
                'import { createClient } from "redis";\n'
                'export const client = createClient({ url: process.env.REDIS_URL });\n'
            )
            findings, api_usage, worker_usage, shared = redis.scan_codebase_redis_usage(temp)
            self.assertEqual(api_usage, "DIRECT_REDIS_URL")
            decl_vars = [f["variable"] for f in findings if f["usage_type"] == "DECLARATION"]
            conn_vars = [f["variable"] for f in findings if f["usage_type"] == "CLIENT_CONNECTION"]
            self.assertIn("REDIS_PASSWORD", decl_vars)
            self.assertIn("REDIS_URL", conn_vars)

    # 5. host da URL pode ser mostrado
    def test_05_url_host_can_be_shown(self):
        shape = redis.parse_redis_url("redis://:secret@127.0.0.1:6379/1")
        self.assertEqual(shape["redis_target_host"], "127.0.0.1")
        self.assertEqual(shape["redis_target_port"], 6379)
        self.assertEqual(shape["redis_target_db"], 1)

    # 6. password da URL nunca mostrado
    def test_06_url_password_never_shown(self):
        sensitive = "CRITICAL_SECRET_PASSWORD_998877"
        shape = redis.parse_redis_url(f"redis://:{sensitive}@127.0.0.1:6379/0")
        serialized = json.dumps(shape)
        self.assertNotIn(sensitive, serialized)
        self.assertNotIn(sensitive, str(shape))

    # 7. redis target container matching
    def test_07_redis_target_container_matching(self):
        candidates = [("gourmet-redis-staging", "UP"), ("other-service", "UP")]
        server = redis.identify_site_redis_server("127.0.0.1", 6379, candidates, inspect_fn=lambda name: {"name": name, "mounts": [], "ports": {"6379/tcp": [{"HostIp": "127.0.0.1", "HostPort": "6379"}]} if name == "gourmet-redis-staging" else {}})
        self.assertTrue(server["identified"])
        self.assertEqual(server["server_name"], "gourmet-redis-staging")
        self.assertEqual(server["server_type"], "DOCKER_CONTAINER")

    # 8. container não correspondente não é assumido
    def test_08_container_not_matching_not_assumed(self):
        candidates = [("refeicao-redis-staging", "UP"), ("refeicao-redis", "UP")]
        server = redis.identify_site_redis_server("127.0.0.1", 6379, candidates, inspect_fn=lambda name: {"name": name, "mounts": []})
        self.assertFalse(server["identified"])
        self.assertEqual(server["server_name"], "UNKNOWN")
        self.assertEqual(server["server_type"], "UNKNOWN")

    # 9. auth REQUIREPASS
    def test_09_auth_requirepass(self):
        def fake_exec(cmd, env=None):
            if "WHOAMI" in cmd:
                return subprocess.CompletedProcess(cmd, 0, "default\n", "")
            if "USERS" in cmd:
                return subprocess.CompletedProcess(cmd, 0, "default\n", "")
            if "requirepass" in cmd:
                return subprocess.CompletedProcess(cmd, 0, "requirepass\nmy_secret_pw\n", "")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        model, status, reqpass = redis.discover_auth_model("127.0.0.1", 6379, password="pw", exec_fn=fake_exec)
        self.assertEqual(model, "REQUIREPASS")
        self.assertEqual(reqpass, "CONFIGURED")

    # 10. auth ACL default
    def test_10_auth_acl_default(self):
        def fake_exec(cmd, env=None):
            if "WHOAMI" in cmd:
                return subprocess.CompletedProcess(cmd, 0, "default\n", "")
            if "USERS" in cmd:
                return subprocess.CompletedProcess(cmd, 0, "default\n", "")
            if "requirepass" in cmd:
                return subprocess.CompletedProcess(cmd, 0, "requirepass\n\n", "")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        model, status, reqpass = redis.discover_auth_model("127.0.0.1", 6379, password="pw", exec_fn=fake_exec)
        self.assertEqual(model, "ACL_DEFAULT_USER")
        self.assertEqual(reqpass, "NOT_CONFIGURED")

    # 11. auth named user
    def test_11_auth_named_user(self):
        def fake_exec(cmd, env=None):
            if "WHOAMI" in cmd:
                return subprocess.CompletedProcess(cmd, 0, "gourmet_api\n", "")
            if "USERS" in cmd:
                return subprocess.CompletedProcess(cmd, 0, "default gourmet_api\n", "")
            if "requirepass" in cmd:
                return subprocess.CompletedProcess(cmd, 0, "requirepass\n\n", "")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        model, status, reqpass = redis.discover_auth_model("127.0.0.1", 6379, password="pw", exec_fn=fake_exec)
        self.assertEqual(model, "ACL_NAMED_USER")

    # 12. no password
    def test_12_no_password(self):
        def fake_exec(cmd, env=None):
            if "WHOAMI" in cmd:
                return subprocess.CompletedProcess(cmd, 0, "default\n", "")
            if "USERS" in cmd:
                return subprocess.CompletedProcess(cmd, 0, "default\n", "")
            if "requirepass" in cmd:
                return subprocess.CompletedProcess(cmd, 0, "requirepass\n\n", "")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        model, status, reqpass = redis.discover_auth_model("127.0.0.1", 6379, password=None, exec_fn=fake_exec)
        self.assertEqual(model, "NO_PASSWORD")

    # 13. unknown auth
    def test_13_unknown_auth(self):
        def fake_exec(cmd, env=None):
            return subprocess.CompletedProcess(cmd, 1, "", "NOAUTH Authentication required.\n")

        model, status, _ = redis.discover_auth_model("127.0.0.1", 6379, password="bad", exec_fn=fake_exec)
        self.assertEqual(model, "UNKNOWN")
        self.assertEqual(status, "INSUFFICIENT_PERMISSION")

    # 14. credential source redis.conf
    def test_14_credential_source_redis_conf(self):
        meta = {"mounts": [{"Destination": "/etc/redis/redis.conf", "Source": "/var/redis/redis.conf"}], "cmd": ["redis-server"]}
        self.assertEqual(redis.classify_credential_source_from_metadata(meta), "REDIS_CONF")

    # 15. credential source ACL file
    def test_15_credential_source_acl_file(self):
        meta = {"mounts": [{"Destination": "/etc/redis/users.acl", "Source": "/var/redis/users.acl"}], "cmd": ["redis-server"]}
        self.assertEqual(redis.classify_credential_source_from_metadata(meta), "ACL_FILE")

    # 16. credential source docker command
    def test_16_credential_source_docker_command(self):
        meta = {"mounts": [], "cmd": ["redis-server", "--requirepass", "FAKE_secret_value"]}
        self.assertEqual(redis.classify_credential_source_from_metadata(meta), "DOCKER_COMMAND")

    # 17. Docker env source bloqueado pela policy
    def test_17_docker_env_source_blocked_by_policy(self):
        meta = {"mounts": [], "cmd": ["redis-server"]}
        self.assertEqual(redis.classify_credential_source_from_metadata(meta), "DOCKER_ENV_UNREADABLE_BY_POLICY")

    # 18. connectivity usando URL credential
    def test_18_connectivity_using_url_credential(self):
        def fake_ping(host, port, password=None, tls=False):
            return "PASS" if password == "URL_SECRET" else "FAIL"

        res = redis.probe_credentials_connectivity("localhost", 6379, cred_redis_pwd="PW_SECRET", url_password="URL_SECRET", ping_fn=fake_ping)
        self.assertEqual(res["CONNECTIVITY_WITH_REDIS_URL_CREDENTIAL"], "PASS")
        self.assertEqual(res["CONNECTIVITY_WITH_REDIS_PASSWORD"], "FAIL")
        self.assertEqual(res["REDIS_CONNECTIVITY"], "PASS")

    # 19. connectivity usando REDIS_PASSWORD
    def test_19_connectivity_using_redis_password(self):
        def fake_ping(host, port, password=None, tls=False):
            return "PASS" if password == "PW_SECRET" else "FAIL"

        res = redis.probe_credentials_connectivity("localhost", 6379, cred_redis_pwd="PW_SECRET", url_password="URL_SECRET", ping_fn=fake_ping)
        self.assertEqual(res["CONNECTIVITY_WITH_REDIS_URL_CREDENTIAL"], "FAIL")
        self.assertEqual(res["CONNECTIVITY_WITH_REDIS_PASSWORD"], "PASS")
        self.assertEqual(res["REDIS_CONNECTIVITY"], "PASS")

    # 20. nenhum password em argv
    def test_20_no_password_in_argv(self):
        secret = "SENSITIVE_ARGV_TOKEN_XYZ"
        calls = []

        def fake_run(command, env=None, **kwargs):
            calls.append((command, env))
            return subprocess.CompletedProcess(command, 0, "PONG\n", "")

        with patch.object(redis.subprocess, "run", side_effect=fake_run):
            redis.connectivity_ping("127.0.0.1", 6379, password=secret)

        command, env = calls[0]
        self.assertNotIn(secret, " ".join(command))
        self.assertEqual(env["REDISCLI_AUTH"], secret)

    # 21. apenas PING permitido
    def test_21_only_ping_allowed(self):
        calls = []

        def fake_run(command, env=None, **kwargs):
            calls.append(command)
            return subprocess.CompletedProcess(command, 0, "PONG\n", "")

        with patch.object(redis.subprocess, "run", side_effect=fake_run):
            redis.connectivity_ping("127.0.0.1", 6379, password="pw")

        cmd = calls[0]
        self.assertEqual(cmd[-1], "PING")
        for forbidden in ("SET", "DEL", "CONFIG SET", "CONFIG REWRITE", "ACL SETUSER", "FLUSHDB", "FLUSHALL"):
            self.assertNotIn(forbidden, cmd)

    # 22. connectivity diferente entre duas credentials
    def test_22_connectivity_different_between_credentials(self):
        def fake_ping(host, port, password=None, tls=False):
            return "PASS" if password == "MATCHING" else "FAIL"

        res = redis.probe_credentials_connectivity("localhost", 6379, cred_redis_pwd="NON_MATCHING", url_password="MATCHING", ping_fn=fake_ping)
        self.assertEqual(res["CONNECTIVITY_WITH_REDIS_URL_CREDENTIAL"], "PASS")
        self.assertEqual(res["CONNECTIVITY_WITH_REDIS_PASSWORD"], "FAIL")

    # 23. canonical URL classification
    def test_23_canonical_url_classification(self):
        rel = redis.classify_credential_relationship(
            api_usage="DIRECT_REDIS_URL", worker_usage="DIRECT_REDIS_URL",
            conn_url="PASS", conn_pwd="FAIL"
        )
        self.assertEqual(rel, "URL_IS_CANONICAL")

    # 24. canonical password classification
    def test_24_canonical_password_classification(self):
        rel = redis.classify_credential_relationship(
            api_usage="PASSWORD_PLUS_HOST_PORT", worker_usage="PASSWORD_PLUS_HOST_PORT",
            conn_url="FAIL", conn_pwd="PASS"
        )
        self.assertEqual(rel, "PASSWORD_IS_CANONICAL")

    # 25. inconsistent config
    def test_25_inconsistent_config(self):
        rel = redis.classify_credential_relationship(
            api_usage="DIRECT_REDIS_URL", worker_usage="DIRECT_REDIS_URL",
            conn_url="FAIL", conn_pwd="FAIL"
        )
        self.assertEqual(rel, "INCONSISTENT_CONFIGURATION")

    # 26. different servers
    def test_26_different_servers(self):
        rel = redis.classify_credential_relationship(target_hosts_differ=True)
        self.assertEqual(rel, "DIFFERENT_SERVERS")

    # 27. legacy variable unused
    def test_27_legacy_variable_unused(self):
        rel = redis.classify_credential_relationship(
            api_usage="DECLARED_BUT_UNUSED", worker_usage="DIRECT_REDIS_URL",
            conn_url="PASS", conn_pwd="FAIL"
        )
        self.assertEqual(rel, "LEGACY_PASSWORD_UNUSED")

    # 28. readiness bloqueada com qualquer UNKNOWN
    def test_28_readiness_blocked_with_any_unknown(self):
        for key in ("server_identified", "auth_model", "credential_source_identified", "site_api_uses_redis", "site_worker_uses_redis", "relationship"):
            evidence = self.complete_evidence()
            if "identified" in key:
                evidence[key] = False
            else:
                evidence[key] = "UNKNOWN"
            res = redis.assess_readiness(evidence)
            self.assertEqual(res["ROTATION_READINESS"], "BLOCKED")
            self.assertEqual(res["FUTURE_ROTATION_SEQUENCE"], "UNKNOWN")

    # 29. readiness READY somente topologia completa
    def test_29_readiness_ready_only_complete_topology(self):
        evidence = self.complete_evidence()
        evidence["connectivity"] = "PASS"
        evidence["relationship"] = "URL_IS_CANONICAL"
        evidence["credential_source"] = "REDIS_CONF"
        evidence["future_sequence"] = redis.build_future_rotation_sequence("URL_IS_CANONICAL", "REQUIREPASS", "REDIS_CONF", "YES", "YES")
        res = redis.assess_readiness(evidence)
        self.assertEqual(res["ROTATION_READINESS"], "BLOCKED")
        self.assertEqual(res["FUTURE_ROTATION_SEQUENCE"], "UNKNOWN")

    # 30. future sequence somente metadata
    def test_30_future_sequence_metadata_only(self):
        seq = redis.build_future_rotation_sequence("URL_IS_CANONICAL", "REQUIREPASS", "REDIS_CONF", "YES", "YES")
        self.assertIn("UPDATE_REDIS_URL", seq)
        self.assertIn("BACKUP_CLIENT_ENV", seq)
        self.assertIn("UPDATE_REDIS_SERVER_CREDENTIAL", seq)
        self.assertTrue(all(isinstance(step, str) for step in seq))

    # Invariant policy tests
    def test_no_secret_dump_paths(self):
        raw = DISCOVERY_PATH.read_text(encoding="utf-8")
        for token in ("cat .env", "source .env", "pm2 env", "pm2 jlist", "printenv", "redis-cli -a", "redis-cli --pass"):
            self.assertNotIn(token, raw)

    def test_no_mutation_paths(self):
        raw = DISCOVERY_PATH.read_text(encoding="utf-8")
        for token in ("pm2 restart", "docker restart", "pm2 save", "mysql", "mariadb", "CONFIG SET", "ACL SETUSER", "FLUSHALL"):
            self.assertNotIn(token, raw)

    @staticmethod
    def complete_evidence():
        return {
            "server_identified": True,
            "auth_model": "ACL_DEFAULT_USER",
            "credential_source_identified": True,
            "credential_source": "ACL_FILE",
            "site_api_uses_redis": "YES",
            "site_worker_uses_redis": "YES",
            "other_consumers_known": True,
            "relationship": "PASSWORD_AND_URL_SAME_CREDENTIAL",
            "relationship_parity": "PASS",
            "backup_targets": ["FAKE_server_config", "FAKE_site_env"],
            "backup_targets_complete": True,
            "restart_targets": ["FAKE_site", "FAKE_worker"],
            "restart_targets_known": True,
            "future_sequence": [
                "BACKUP_SERVER_AUTH_CONFIG", "BACKUP_SITE_ENV", "PREPARE_CLIENT_CREDENTIALS",
                "UPDATE_REDIS_AUTH", "UPDATE_SITE_ENV", "RESTART_CONFIRMED_CONSUMERS",
                "VERIFY_PING", "VERIFY_HEALTH", "ROLLBACK_IF_FAILURE"
            ],
            "connectivity": "PASS",
        }


if __name__ == "__main__":
    unittest.main()
