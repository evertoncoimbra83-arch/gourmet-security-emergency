"""GSE-03B5A staging-only dry-run planner and pure editor tests."""
import importlib.util
import io
import json
import os
import secrets
import shutil
import stat
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "rotations" / "redis" / "redis-rotate-plan.py"
spec = importlib.util.spec_from_file_location("redis_rotate_plan", SOURCE)
plan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plan)
REGISTRY = json.loads((ROOT / "rotations" / "redis" / "redis-registry.json").read_text())["staging"]
INCIDENT = "GSE-20261022T120000Z"
URL_KEY = "REDIS_" + "URL"
PASSWORD_KEY = "REDIS_" + "PASSWORD"


def evidence():
    result = dict(plan.EVIDENCE_EXPECTED)
    result.update({
        "redis_config_path": REGISTRY["expected_config_candidates"][0],
        "redis_executable": "/usr/bin/redis-server",
        "redis_process_cwd": "/home/gsadmin/redis-staging/data",
        "site_redis_server_name": "redis-server",
        "redis_socket_listening": "YES", "redis_socket_address_match": "YES",
        "redis_listener_owner_visible": "YES", "redis_auth_ping": "PASS",
        "requirepass_status": "CONFIGURED", "config_port": "6380",
        "config_bind": "127.0.0.1,::1",
        "config_dir": "/home/gsadmin/redis-staging/data",
        "future_backup_target": [REGISTRY["site_env"], REGISTRY["expected_config_candidates"][0]],
    })
    return result


def fixtures(directory, newline="\n"):
    old_url_password = secrets.token_urlsafe(48)
    old_other_password = secrets.token_urlsafe(48)
    site = Path(directory) / "site-env.fixture"
    redis = Path(directory) / "redis-config.fixture"
    site_text = newline.join((
        "# GSE_SYNTHETIC_FIXTURE", "OTHER_KEY=preserve",
        f'{URL_KEY}="redis://:{old_url_password}@127.0.0.1:6380/0?client=site" # url note',
        f"{PASSWORD_KEY}='{old_other_password}'", "LAST_KEY=preserve", ""))
    redis_text = newline.join((
        "# GSE_SYNTHETIC_FIXTURE", "# requirepass commented",
        "port 6380", "bind 127.0.0.1 ::1",
        "dir /home/gsadmin/redis-staging/data", "dbfilename staging.rdb",
        f'requirepass "{old_url_password}" # auth note', "appendonly yes", ""))
    site.write_bytes(site_text.encode())
    redis.write_bytes(redis_text.encode())
    return site, redis, old_url_password, old_other_password


class RedisRotationPlanPolicy(unittest.TestCase):
    def build(self, site, redis, root, **kwargs):
        return plan.build_dry_run_plan(evidence(), REGISTRY, site, redis, INCIDENT,
                                      Path(root) / "future-backups", **kwargs)

    def test_staging_dry_run_allowed_and_plan_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            site, redis, _, _ = fixtures(tmp)
            before = (site.read_bytes(), redis.read_bytes())
            result = self.build(site, redis, tmp)
            self.assertEqual(result["post_rotation_parity_model"], "PASS")
            self.assertEqual(result["fault"]["rotation_success"], "NOT_EXECUTED")
            self.assertTrue((site.read_bytes(), redis.read_bytes()) == before)

    def test_staging_execute_without_dry_run_blocked(self):
        output = io.StringIO()
        with redirect_stdout(output):
            code = plan.main(["--environment", "staging"])
        self.assertEqual(code, 1)
        self.assertTrue("EXECUTION_BLOCKED=YES" in output.getvalue())

    def test_production_blocked_even_with_dry_run(self):
        output = io.StringIO()
        with redirect_stdout(output):
            code = plan.main(["--environment", "production", "--dry-run"])
        self.assertEqual(code, 1)
        self.assertTrue("PRODUCTION_EXECUTION=BLOCKED" in output.getvalue())

    def test_readiness_and_auth_source_preconditions(self):
        for key, wrong in (("ROTATION_READINESS", "BLOCKED"),
                           ("redis_credential_source", "UNKNOWN"),
                           ("redis_server_auth_model", "ACL_DEFAULT_USER"),
                           ("SITE_API_USES_REDIS", "NO"),
                           ("SITE_WORKER_RESTART_REQUIRED_ON_ROTATION", "UNKNOWN"),
                           ("REDIS_CREDENTIAL_RELATIONSHIP", "URL_IS_CANONICAL"),
                           ("future_backup_targets", "1")):
            with self.subTest(key=key):
                metadata = evidence()
                metadata[key] = wrong
                with self.assertRaises(plan.PlanBlocked):
                    plan.validate_evidence(metadata, REGISTRY)

    def test_evidence_loader_drops_unrecognized_sensitive_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "evidence.txt"
            sensitive = secrets.token_urlsafe(48)
            path.write_text("ROTATION_READINESS=READY\n" + PASSWORD_KEY + "=" + sensitive + "\nrequirepass=" + sensitive + "\n")
            loaded = plan.load_evidence(path)
            self.assertEqual(loaded["ROTATION_READINESS"], "READY")
            self.assertFalse(sensitive in repr(loaded))
            path.write_text("ROTATION_READINESS=READY\nROTATION_READINESS=READY\n")
            with self.assertRaises(plan.PlanBlocked):
                plan.load_evidence(path)

    def test_backup_targets_and_collision(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = plan.backup_plan(tmp, INCIDENT)
            self.assertEqual(len(paths), 2)
            self.assertTrue(paths["site"].endswith("site-env.before"))
            self.assertTrue(paths["redis"].endswith("redis-staging.conf.before"))
            (Path(tmp) / INCIDENT).mkdir()
            with self.assertRaises(plan.PlanBlocked):
                plan.backup_plan(tmp, INCIDENT)

    def test_duplicate_execution_blocked_in_session(self):
        with tempfile.TemporaryDirectory() as tmp:
            seen = set()
            plan.backup_plan(tmp, INCIDENT, seen)
            with self.assertRaises(plan.PlanBlocked):
                plan.backup_plan(tmp, INCIDENT, seen)

    def test_requirepass_single_editor_preserves_remainder_and_newlines(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, redis, _, _ = fixtures(tmp, "\r\n")
            original = redis.read_bytes()
            new = secrets.token_urlsafe(48)
            edited = plan.edit_redis_config(original, new, "/home/gsadmin/redis-staging/data")
            self.assertTrue((f'requirepass "{new}" # auth note\r\n').encode() in edited)
            self.assertTrue(b"# requirepass commented\r\n" in edited)
            self.assertTrue(b"port 6380\r\n" in edited)
            self.assertTrue(redis.read_bytes() == original)

    def test_missing_or_duplicate_requirepass_blocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, redis, _, _ = fixtures(tmp)
            raw = redis.read_bytes()
            new = secrets.token_urlsafe(48)
            line = next(line for line in raw.splitlines(keepends=True) if line.startswith(b"requirepass "))
            for changed in (raw.replace(line, b""), raw + line):
                with self.assertRaises(plan.PlanBlocked):
                    plan.edit_redis_config(changed, new, "/home/gsadmin/redis-staging/data")

    def test_config_endpoint_and_directory_mismatch_block(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, redis, _, _ = fixtures(tmp)
            raw = redis.read_bytes()
            new = secrets.token_urlsafe(48)
            for old, replacement in ((b"port 6380", b"port 6379"),
                                     (b"bind 127.0.0.1 ::1", b"bind ::1"),
                                     (b"dir /home/gsadmin/redis-staging/data", b"dir /tmp")):
                with self.subTest(old=old):
                    with self.assertRaises(plan.PlanBlocked):
                        plan.edit_redis_config(raw.replace(old, replacement), new,
                                               "/home/gsadmin/redis-staging/data")

    def test_config_mode_and_owner_mismatch_block(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, redis, _, _ = fixtures(tmp)
            raw, new = redis.read_bytes(), secrets.token_urlsafe(48)
            with self.assertRaises(plan.PlanBlocked):
                plan.edit_redis_config(raw, new, "/home/gsadmin/redis-staging/data",
                                       expected_mode=0o600, actual_mode=0o644)
            with self.assertRaises(plan.PlanBlocked):
                plan.edit_redis_config(raw, new, "/home/gsadmin/redis-staging/data",
                                       expected_owner=1000, actual_owner=1001)

    def test_site_env_url_and_password_receive_same_credential(self):
        with tempfile.TemporaryDirectory() as tmp:
            site, _, _, _ = fixtures(tmp)
            original = site.read_bytes()
            new = secrets.token_urlsafe(48)
            edited = plan.edit_site_env(original, new)
            values = plan.site_env_values(edited)
            parsed = urlsplit(values["REDIS_URL"])
            self.assertTrue(unquote(parsed.password) == new)
            self.assertTrue(values["REDIS_PASSWORD"] == new)
            self.assertEqual((parsed.hostname, parsed.port, parsed.path, parsed.query),
                             ("127.0.0.1", 6380, "/0", "client=site"))
            self.assertTrue(b"OTHER_KEY=preserve" in edited)
            self.assertTrue(b"LAST_KEY=preserve" in edited)
            self.assertTrue(b"# url note" in edited)
            self.assertTrue(site.read_bytes() == original)

    def test_three_way_credential_parity_in_edited_model(self):
        with tempfile.TemporaryDirectory() as tmp:
            site, redis, _, _ = fixtures(tmp)
            new = secrets.token_urlsafe(48)
            site_after = plan.edit_site_env(site.read_bytes(), new)
            redis_after = plan.edit_redis_config(redis.read_bytes(), new,
                                                 "/home/gsadmin/redis-staging/data")
            values = plan.site_env_values(site_after)
            self.assertTrue(values["REDIS_PASSWORD"] == new)
            self.assertTrue(unquote(urlsplit(values["REDIS_URL"]).password) == new)
            self.assertTrue((f'requirepass "{new}"').encode() in redis_after)

    def test_env_missing_or_duplicate_keys_block(self):
        with tempfile.TemporaryDirectory() as tmp:
            site, _, _, _ = fixtures(tmp)
            raw = site.read_bytes()
            new = secrets.token_urlsafe(48)
            for key in ((URL_KEY + "=").encode(), (PASSWORD_KEY + "=").encode()):
                line = next(line for line in raw.splitlines(keepends=True) if line.startswith(key))
                for changed in (raw.replace(line, b""), raw + line):
                    with self.subTest(key=key, changed=len(changed)):
                        with self.assertRaises(plan.PlanBlocked):
                            plan.edit_site_env(changed, new)

    def test_wrong_url_host_port_db_and_scheme_block(self):
        with tempfile.TemporaryDirectory() as tmp:
            site, _, _, _ = fixtures(tmp)
            raw = site.read_bytes()
            new = secrets.token_urlsafe(48)
            for old, replacement in ((b"127.0.0.1", b"localhost"),
                                     (b":6380", b":6379"),
                                     (b"/0?client", b"/1?client"),
                                     (b"redis://", b"rediss://")):
                with self.subTest(old=old):
                    with self.assertRaises(plan.PlanBlocked):
                        plan.edit_site_env(raw.replace(old, replacement), new)

    def test_credential_generation_is_cs_rng_and_metadata_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            site, redis, _, _ = fixtures(tmp)
            calls = []
            def factory(n):
                calls.append(n)
                return secrets.token_urlsafe(n)
            result = self.build(site, redis, tmp, credential_factory=factory)
            self.assertEqual(calls, [48])
            self.assertGreaterEqual(result["new_credential_length"], 32)
            self.assertNotIn("credential", result)

    def test_credential_never_appears_in_output_or_exception(self):
        with tempfile.TemporaryDirectory() as tmp:
            site, redis, _, _ = fixtures(tmp)
            new = secrets.token_urlsafe(48)
            result = self.build(site, redis, tmp, credential_factory=lambda n: new)
            output = io.StringIO()
            with redirect_stdout(output):
                plan.print_plan(result)
            self.assertFalse(new in output.getvalue())
            self.assertFalse(new in repr(result))
            with self.assertRaises(plan.PlanBlocked) as raised:
                plan.edit_site_env(site.read_bytes().replace(b"127.0.0.1", b"localhost"), new)
            self.assertFalse(new in str(raised.exception))

    def test_already_updated_config_or_env_blocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            site, redis, old_url, _ = fixtures(tmp)
            with self.assertRaises(plan.PlanBlocked):
                plan.edit_redis_config(redis.read_bytes(), old_url,
                                       "/home/gsadmin/redis-staging/data")
            old_password = plan.site_env_values(site.read_bytes())["REDIS_PASSWORD"]
            with self.assertRaises(plan.PlanBlocked):
                plan.edit_site_env(site.read_bytes(), old_password)

    def test_atomic_write_preserves_mode_and_original_fixture(self):
        with tempfile.TemporaryDirectory(prefix="gse-redis-dry-run-") as tmp:
            source, _, _, _ = fixtures(tmp)
            destination = Path(tmp) / "redis-config.fixture"
            destination.unlink()
            shutil.copy2(source, destination)
            os.chmod(destination, 0o600)
            previous_mode = stat.S_IMODE(destination.stat().st_mode)
            original = source.read_bytes()
            replacement = b"# GSE_SYNTHETIC_FIXTURE\nSIMULATED=YES\n"
            plan.atomic_replace_fixture_copy(destination, replacement, tmp)
            self.assertEqual(destination.read_bytes(), replacement)
            self.assertTrue(source.read_bytes() == original)
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), previous_mode)

    def test_atomic_write_rejects_outside_sandbox(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(plan.PlanBlocked):
                plan.atomic_replace_fixture_copy(Path(tmp).parent / "outside.fixture", b"x", tmp)

    def test_fixture_marker_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ordinary"
            path.write_bytes(b"ordinary data")
            with self.assertRaises(plan.PlanBlocked):
                plan.validate_fixture(path)

    def test_cli_success_and_explicit_http_not_configured(self):
        with tempfile.TemporaryDirectory() as tmp:
            site, redis, _, _ = fixtures(tmp)
            evidence_path = Path(tmp) / "evidence.txt"
            metadata = evidence()
            evidence_path.write_text("\n".join(
                f"{key}={item}" for key, value in metadata.items()
                for item in (value if isinstance(value, list) else [value])) + "\n")
            output = io.StringIO()
            with redirect_stdout(output):
                code = plan.main(["--environment", "staging", "--dry-run",
                                  "--evidence-file", str(evidence_path),
                                  "--fixture-site-env", str(site),
                                  "--fixture-redis-config", str(redis),
                                  "--incident-id", INCIDENT,
                                  "--backup-root", str(Path(tmp) / "future-backups")])
            self.assertEqual(code, 0)
            self.assertTrue("APPLICATION_HTTP_HEALTH=NOT_CONFIGURED" in output.getvalue())
            self.assertTrue("step_14=CLEANUP_TEMP_FILES" in output.getvalue())
            self.assertTrue("rollback_7=VERIFY_APPLICATION_HEALTH" in output.getvalue())
            self.assertTrue("ACTUAL_FILES_CHANGED=NO" in output.getvalue())

    def test_fault_injection_all_nine_checkpoints_requires_full_rollback(self):
        with tempfile.TemporaryDirectory() as tmp:
            site, redis, _, _ = fixtures(tmp)
            originals = (site.read_bytes(), redis.read_bytes())
            for checkpoint in plan.FAULT_CHECKPOINTS:
                with self.subTest(checkpoint=checkpoint):
                    result = self.build(site, redis, tmp, fault_after=checkpoint)
                    self.assertEqual(result["fault"]["rollback_required"], "YES")
                    self.assertEqual(result["fault"]["rotation_success"], "NO")
                    self.assertEqual(result["fault"]["simulated_execution"], "FAIL")
                    self.assertTrue((site.read_bytes(), redis.read_bytes()) == originals)
            self.assertEqual(len(plan.FAULT_CHECKPOINTS), 9)
            self.assertEqual(plan.ROLLBACK_STEPS, (
                "RESTORE_REDIS_CONFIG", "RESTORE_SITE_ENV",
                "RESTART_REDIS_WITH_OLD_CONFIG", "RESTART_SITE_API",
                "RESTART_SITE_WORKER", "VERIFY_OLD_REDIS_PING",
                "VERIFY_APPLICATION_HEALTH"))

    def test_fault_plan_never_reports_partial_success(self):
        result = {"backup_site": "/tmp/incident/site-env.before",
                  "backup_redis": "/tmp/incident/redis-staging.conf.before",
                  "new_credential_length": 64, "application_http_health": "NOT_CONFIGURED",
                  "post_rotation_parity_model": "PASS",
                  "fault": plan.simulate_fault("RESTART_SITE_WORKER")}
        output = io.StringIO()
        with redirect_stdout(output):
            plan.print_plan(result)
        self.assertTrue("ROLLBACK_REQUIRED=YES" in output.getvalue())
        self.assertTrue("ROTATION_SUCCESS=NO" in output.getvalue())
        self.assertFalse("ROTATION_SUCCESS=YES" in output.getvalue())

    def test_unknown_fault_checkpoint_blocks(self):
        with self.assertRaises(plan.PlanBlocked):
            plan.simulate_fault("NOT_A_CHECKPOINT")

    def test_static_no_execution_paths(self):
        source = SOURCE.read_text(encoding="utf-8")
        for forbidden in ("pm2 env", "pm2 jlist", "printenv", "cat .env", "source .env",
                          "Config.Env", "redis-cli -a", "redis-cli --pass", "CONFIG SET",
                          "CONFIG REWRITE", "ACL SETUSER", "FLUSHDB", "FLUSHALL",
                          "pm2 save", "mysql", "mariadb", "shell=True",
                          '"ssh"', '"redis-cli"', '"pm2"', '"systemctl"'):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
