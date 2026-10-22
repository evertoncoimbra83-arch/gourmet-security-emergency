"""Local-only transaction tests for the staging Redis executor."""
import importlib.util
import io
import os
import secrets
import stat
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "rotations" / "redis" / "redis-rotate-execute.py"
spec = importlib.util.spec_from_file_location("gse_redis_execute_test", SOURCE)
execute = importlib.util.module_from_spec(spec)
import sys
sys.modules[spec.name] = execute
spec.loader.exec_module(execute)
INCIDENT = "GSE-20261022T120000Z"
URL_KEY = "REDIS_" + "URL"
PASSWORD_KEY = "REDIS_" + "PASSWORD"


def evidence():
    config = execute.json.loads(execute.plan.REGISTRY.read_text())["staging"]
    result = dict(execute.plan.EVIDENCE_EXPECTED)
    result.update({
        "redis_config_path": config["expected_config_candidates"][0],
        "redis_executable": "/usr/bin/redis-server",
        "redis_process_cwd": "/home/gsadmin/redis-staging/data",
        "site_redis_server_name": "redis-server",
        "redis_socket_listening": "YES", "redis_socket_address_match": "YES",
        "redis_listener_owner_visible": "YES", "redis_listener_pid": "927",
        "redis_auth_ping": "PASS", "requirepass_status": "CONFIGURED",
        "config_port": "6380", "config_bind": "127.0.0.1,::1",
        "config_dir": "/home/gsadmin/redis-staging/data",
        "future_backup_target": [config["site_env"], config["expected_config_candidates"][0]],
    })
    return result, config


class FakeOps:
    def __init__(self, root):
        self.root = Path(root)
        self.site_env = self.root / "site.env"
        self.redis_conf = self.root / "redis.conf"
        self.legacy_conf = self.root / "legacy.conf"
        self.backup_root = self.root / "backups"
        self.backup_root.mkdir()
        self.locked = False
        self.events = []
        self.fail_at = None
        self.old = secrets.token_urlsafe(48)
        self.other = secrets.token_urlsafe(48)
        self.site_env.write_text(
            f"# fixture\nOTHER=keep\n{URL_KEY}=redis://:{self.old}@127.0.0.1:6380/0\n"
            f"{PASSWORD_KEY}={self.other}\n", encoding="utf-8")
        self.redis_conf.write_text(
            "# fixture\nport 6380\nbind 127.0.0.1 ::1\n"
            "dir /home/gsadmin/redis-staging/data\n"
            f"requirepass {self.old}\n", encoding="utf-8")
        self.legacy_conf.write_text(
            "# historical config\nport 6380\nbind 127.0.0.1 -::1\n"
            "dir /home/gsadmin/redis-staging/data\n"
            f"requirepass {self.other}\n", encoding="utf-8")
        os.chmod(self.site_env, 0o600)
        os.chmod(self.redis_conf, 0o600)
        self.site_original = self.site_env.read_bytes()
        self.redis_original = self.redis_conf.read_bytes()
        self.legacy_original = self.legacy_conf.read_bytes()
        self.metadata, self.config = evidence()
        self.current = self.old

    def _event(self, name):
        self.events.append(name)
        if self.fail_at == name:
            if name != "restore_files":
                self.fail_at = None
            raise execute.RotationBlocked("SIMULATED_FAILURE")

    def preflight(self):
        self._event("preflight")
        return dict(self.metadata)

    def capture_before(self, permit, metadata):
        execute.require_permit(permit)
        self._event("capture")
        return execute.State(permit.incident_id, self.old,
                             execute.sha(self.site_original), execute.sha(self.redis_original),
                             927, 1001, 1002, "redis-staging")

    def acquire_lock(self, permit):
        execute.require_permit(permit)
        if self.locked or (self.root / "rotation.lock").exists():
            execute.block("ROTATION_LOCK_ACTIVE")
        (self.root / "rotation.lock").write_text(permit.incident_id)
        self.locked = True
        self._event("lock")

    def release_lock(self, permit):
        self._event("unlock")
        (self.root / "rotation.lock").unlink()
        self.locked = False

    def ensure_incident_available(self, permit):
        self._event("incident")
        target = self.backup_root / permit.incident_id
        if target.exists():
            execute.block("BACKUP_COLLISION")
        target.mkdir(mode=0o700)
        self.backup_dir = target

    def _backup(self, permit, state, name, original):
        execute.require_permit(permit)
        target = self.backup_dir / name
        with open(target, "xb") as stream:
            stream.write(original)
        os.chmod(target, 0o600)
        state.backup_dir = self.backup_dir

    def backup_site_env(self, permit, state):
        self._backup(permit, state, "site-env.before", self.site_env.read_bytes())
        self._event("backup_site")

    def backup_redis_config(self, permit, state):
        self._backup(permit, state, "redis-staging.conf.before", self.redis_conf.read_bytes())
        self._event("backup_redis")

    def verify_backups(self, state):
        self._event("verify_backups")
        if (execute.sha((state.backup_dir / "site-env.before").read_bytes()) != state.old_site_hash
                or execute.sha((state.backup_dir / "redis-staging.conf.before").read_bytes()) != state.old_redis_hash):
            execute.block("BACKUP_HASH_FAIL")

    def original_bytes(self, state):
        self.verify_backups(state)
        return self.redis_original, self.site_original

    def write_redis_config(self, permit, state, data):
        execute.require_permit(permit, mutation=True)
        execute.atomic_write(self.redis_conf, data, permit)
        self._event("write_redis")

    def write_site_env(self, permit, state, data):
        execute.require_permit(permit, mutation=True)
        execute.atomic_write(self.site_env, data, permit)
        self._event("write_site")

    def verify_updated_files(self, state, redis_data, site_data):
        self._event("verify_updated")
        if self.redis_conf.read_bytes() != redis_data or self.site_env.read_bytes() != site_data:
            execute.block("FILE_MISMATCH")

    def restart_redis(self, permit, state):
        execute.require_permit(permit, mutation=True)
        self.current = self.old if self.redis_conf.read_bytes() == self.redis_original else state.new_credential
        self._event("restart_redis")

    def ping(self, credential):
        self._event("ping")
        return credential == self.current

    def restart_site(self, permit, state, kind):
        execute.require_permit(permit, mutation=True)
        self._event("restart_" + kind)

    def process_online(self, kind):
        self._event("online_" + kind)
        return True

    def application_health(self):
        self._event("health")
        return "NOT_CONFIGURED"

    def post_rotation_preflight(self, state):
        self._event("postflight")
        return True

    def preflight_restored(self, state):
        self._event("restored_preflight")
        return self.site_env.read_bytes() == self.site_original and self.redis_conf.read_bytes() == self.redis_original

    def restore_files(self, permit, state):
        execute.require_permit(permit, mutation=True)
        self._event("restore_files")
        execute.atomic_write(self.redis_conf, (state.backup_dir / "redis-staging.conf.before").read_bytes(), permit)
        execute.atomic_write(self.site_env, (state.backup_dir / "site-env.before").read_bytes(), permit)
        if (execute.sha(self.redis_conf.read_bytes()) != state.old_redis_hash
                or execute.sha(self.site_env.read_bytes()) != state.old_site_hash):
            execute.block("RESTORE_HASH_FAIL")

    def finalize(self, permit, state):
        self._event("finalize")


def run(ops, fault=None):
    permit = execute.gate("staging", True, INCIDENT, execute.CONFIRMATION)
    return execute.execute_rotation(ops, permit, fault_after=fault, test_mode=True)


class RedisRealExecutorPolicy(unittest.TestCase):
    def test_cli_gates_and_production(self):
        for args in (["--environment", "staging"],
                     ["--environment", "staging", "--execute", "--incident-id", INCIDENT],
                     ["--environment", "production", "--execute", "--incident-id", INCIDENT,
                      "--confirm", execute.CONFIRMATION]):
            with self.subTest(args=args), redirect_stdout(io.StringIO()) as out:
                self.assertEqual(execute.main(args), 1)
                self.assertTrue("BLOCKED" in out.getvalue())

    def test_readiness_gate_before_lock_or_backup(self):
        with tempfile.TemporaryDirectory() as root:
            ops = FakeOps(root)
            ops.metadata["ROTATION_READINESS"] = "BLOCKED"
            result = run(ops)
            self.assertEqual(result["REDIS_ROTATION_EXECUTION"], "FAIL")
            self.assertFalse((Path(root) / "rotation.lock").exists())
            self.assertEqual(list(ops.backup_root.iterdir()), [])

    def test_success_order_backup_modes_parity_and_report(self):
        with tempfile.TemporaryDirectory() as root:
            ops = FakeOps(root)
            out = io.StringIO()
            with redirect_stdout(out):
                result = run(ops)
                execute.print_report(result)
            self.assertEqual(result["REDIS_ROTATION_EXECUTION"], "PASS")
            self.assertEqual(result["ROLLBACK"], "NOT_REQUIRED")
            self.assertEqual(result["APPLICATION_HTTP_HEALTH"], "NOT_CONFIGURED")
            self.assertLess(ops.events.index("backup_redis"), ops.events.index("write_redis"))
            self.assertLess(ops.events.index("write_site"), ops.events.index("restart_redis"))
            self.assertLess(ops.events.index("restart_redis"), ops.events.index("restart_api"))
            self.assertLess(ops.events.index("restart_api"), ops.events.index("restart_worker"))
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE((ops.backup_root / INCIDENT).stat().st_mode), 0o700)
            for name in ("site-env.before", "redis-staging.conf.before"):
                if os.name != "nt":
                    self.assertEqual(stat.S_IMODE((ops.backup_root / INCIDENT / name).stat().st_mode), 0o600)
            values = execute.plan.site_env_values(ops.site_env.read_bytes())
            self.assertTrue(values[PASSWORD_KEY] == unquote(urlsplit(values[URL_KEY]).password))
            self.assertFalse(ops.old in out.getvalue())
            self.assertFalse(values[PASSWORD_KEY] in out.getvalue())
            self.assertTrue(ops.legacy_conf.read_bytes() == ops.legacy_original)
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(ops.site_env.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(ops.redis_conf.stat().st_mode), 0o600)

    def test_fault_points_rollback_after_first_write(self):
        for point in sorted(execute.FAULT_POINTS):
            with self.subTest(point=point), tempfile.TemporaryDirectory() as root:
                ops = FakeOps(root)
                result = run(ops, point)
                self.assertEqual(result["REDIS_ROTATION_EXECUTION"], "FAIL")
                if point in {"AFTER_BACKUP_SITE_ENV", "AFTER_BACKUP_REDIS_CONFIG"}:
                    self.assertEqual(result["ROLLBACK"], "NOT_REQUIRED")
                else:
                    self.assertEqual(result["ROLLBACK"], "PASS")
                    self.assertTrue(ops.site_env.read_bytes() == ops.site_original)
                    self.assertTrue(ops.redis_conf.read_bytes() == ops.redis_original)
                    self.assertTrue(ops.legacy_conf.read_bytes() == ops.legacy_original)
                    self.assertIn("restored_preflight", ops.events)
                    tail = ops.events[ops.events.index("restore_files"):]
                    self.assertLess(tail.index("restore_files"), tail.index("restart_redis"))
                    self.assertLess(tail.index("restart_redis"), tail.index("restart_api"))
                    self.assertLess(tail.index("restart_api"), tail.index("restart_worker"))
                    self.assertLess(tail.index("restart_worker"), tail.index("restored_preflight"))

    def test_service_and_verify_failures_rollback(self):
        for event in ("restart_redis", "restart_api", "restart_worker", "postflight", "health"):
            with self.subTest(event=event), tempfile.TemporaryDirectory() as root:
                ops = FakeOps(root)
                ops.fail_at = event
                result = run(ops)
                self.assertEqual(result["ROLLBACK"], "PASS")
                self.assertTrue(ops.site_env.read_bytes() == ops.site_original)

    def test_rollback_failure_requires_manual_intervention_and_retains_lock(self):
        with tempfile.TemporaryDirectory() as root:
            ops = FakeOps(root)
            ops.fail_at = "restore_files"
            result = run(ops, "AFTER_REDIS_CONFIG_UPDATE")
            self.assertEqual(result["ROLLBACK"], "FAIL")
            self.assertEqual(result["MANUAL_INTERVENTION_REQUIRED"], "YES")
            self.assertTrue((Path(root) / "rotation.lock").exists())

    def test_duplicate_incident_and_lock_block(self):
        with tempfile.TemporaryDirectory() as root:
            ops = FakeOps(root)
            self.assertEqual(run(ops)["REDIS_ROTATION_EXECUTION"], "PASS")
            self.assertEqual(run(ops)["REDIS_ROTATION_EXECUTION"], "FAIL")
        with tempfile.TemporaryDirectory() as root:
            ops = FakeOps(root)
            (Path(root) / "rotation.lock").write_text("stale or active")
            self.assertEqual(run(ops)["REDIS_ROTATION_EXECUTION"], "FAIL")
            self.assertTrue((Path(root) / "rotation.lock").exists())

    def test_identity_and_old_credential_guards(self):
        with tempfile.TemporaryDirectory() as root:
            ops = FakeOps(root)
            with patch.object(ops, "capture_before", side_effect=execute.RotationBlocked("UNPROVED")):
                self.assertEqual(run(ops)["REDIS_ROTATION_EXECUTION"], "FAIL")
            self.assertEqual(list(ops.backup_root.iterdir()), [])
        with tempfile.TemporaryDirectory() as root:
            ops = FakeOps(root)
            ops.current = ops.old
            with patch.object(ops, "ping", return_value=True):
                result = run(ops)
            self.assertEqual(result["ROLLBACK"], "PASS")

    def test_fault_injection_not_available_in_real_mode(self):
        with tempfile.TemporaryDirectory() as root:
            ops = FakeOps(root)
            permit = execute.gate("staging", True, INCIDENT, execute.CONFIRMATION)
            result = execute.execute_rotation(ops, permit, fault_after="AFTER_REDIS_RESTART")
            self.assertEqual(result["REDIS_ROTATION_EXECUTION"], "FAIL")
            self.assertEqual(ops.events, [])

    def test_generated_once_and_never_reported(self):
        with tempfile.TemporaryDirectory() as root:
            ops = FakeOps(root)
            generated = secrets.token_urlsafe(48)
            calls = []
            def factory(length):
                calls.append(length)
                return generated
            permit = execute.gate("staging", True, INCIDENT, execute.CONFIRMATION)
            out = io.StringIO()
            with redirect_stdout(out):
                result = execute.execute_rotation(ops, permit, credential_factory=factory)
                execute.print_report(result)
            self.assertEqual(calls, [48])
            self.assertEqual(result["REDIS_ROTATION_EXECUTION"], "PASS")
            self.assertFalse(generated in out.getvalue())
            self.assertTrue(generated.encode() in ops.redis_conf.read_bytes())

    def test_backup_hash_failure_blocks_before_mutation(self):
        with tempfile.TemporaryDirectory() as root:
            ops = FakeOps(root)
            with patch.object(ops, "verify_backups", side_effect=execute.RotationBlocked("HASH_FAIL")):
                result = run(ops)
            self.assertEqual(result["REDIS_ROTATION_EXECUTION"], "FAIL")
            self.assertEqual(result["ROLLBACK"], "NOT_REQUIRED")
            self.assertTrue(ops.site_env.read_bytes() == ops.site_original)
            self.assertTrue(ops.redis_conf.read_bytes() == ops.redis_original)

    def test_new_ping_failure_rolls_back(self):
        with tempfile.TemporaryDirectory() as root:
            ops = FakeOps(root)
            original_ping = ops.ping
            calls = []
            def fail_new_once(credential):
                calls.append(credential)
                if len(calls) == 1:
                    return False
                return original_ping(credential)
            with patch.object(ops, "ping", side_effect=fail_new_once):
                result = run(ops)
            self.assertEqual(result["ROLLBACK"], "PASS")
            self.assertTrue(ops.redis_conf.read_bytes() == ops.redis_original)

    def test_pm2_identity_requires_unique_pid_match(self):
        config = evidence()[1]
        ops = object.__new__(execute.RealOps)
        ops.config = config
        table = "│ id │ name │ mode │ pid │ status │\n│ 1 │ redis-staging │ fork │ 927 │ online │\n│ 2 │ redis-production │ fork │ 411 │ online │"
        with patch.object(ops, "_run", return_value=SimpleNamespace(returncode=0, stdout=table)):
            with patch.object(ops, "_pm2_pid", return_value=927):
                self.assertEqual(ops._redis_pm2_identity(927), "redis-staging")
            with patch.object(ops, "_pm2_pid", return_value=411):
                with self.assertRaises(execute.RotationBlocked):
                    ops._redis_pm2_identity(927)

    def test_postflight_requires_new_parity_and_coherent_relationship(self):
        config = evidence()[1]
        ops = object.__new__(execute.RealOps)
        ops.config = config
        ops.redis_conf = Path(config["expected_config_candidates"][0])
        state = SimpleNamespace(new_credential=secrets.token_urlsafe(48), old_credential=secrets.token_urlsafe(48))
        baseline = {
            "redis_discovery_contract_version": "2",
            "redis_config_authority": "PM2_SCRIPT_ARGUMENT",
            "redis_config_path": config["expected_config_candidates"][0],
            "active_requirepass_vs_redis_url": "SAME",
            "active_requirepass_vs_redis_password": "SAME",
            "redis_url_vs_redis_password": "SAME",
            "REDIS_CONNECTIVITY": "PASS", "redis_password_url_parity": "PASS",
            "CONNECTIVITY_WITH_REDIS_URL_CREDENTIAL": "PASS",
            "CONNECTIVITY_WITH_REDIS_PASSWORD": "PASS",
            "REDIS_CREDENTIAL_RELATIONSHIP": "PASSWORD_AND_URL_SAME_CREDENTIAL",
            "SITE_REDIS_SERVER_IDENTIFIED": "YES", "redis_active_config_match": "YES",
            "redis_credential_source": "REDIS_CONF",
        }
        with patch.object(ops, "preflight", return_value=baseline), patch.object(ops, "ping", side_effect=[True, False]):
            self.assertTrue(ops.post_rotation_preflight(state))
        baseline["redis_password_url_parity"] = "FAIL"
        with patch.object(ops, "preflight", return_value=baseline):
            self.assertFalse(ops.post_rotation_preflight(state))

    def test_safe_source_audit(self):
        source = SOURCE.read_text(encoding="utf-8")
        forbidden = ("pm2 jlist", "pm2 env", "pm2 save", "docker inspect Config.Env",
                     "shell=True", "--pass", "redis-cli -a", "FLUSHALL", "ACL SETUSER")
        for phrase in forbidden:
            self.assertFalse(phrase in source)
        self.assertFalse(".env.production" in source)
        self.assertFalse("gourmet-worker\"" in source)
        self.assertTrue("require_permit(permit, mutation=True)" in source)

    def test_relationship_after_parity(self):
        relation = execute.discovery.classify_credential_relationship(
            "MIXED", "MIXED", "PASS", "PASS", "PASS")
        self.assertEqual(relation, "PASSWORD_AND_URL_SAME_CREDENTIAL")


if __name__ == "__main__":
    unittest.main()
