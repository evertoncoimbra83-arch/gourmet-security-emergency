import importlib.util
import io
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
REDIS = ROOT / "rotations" / "redis"
DEPLOY = ROOT / "deploy"
SHELL = (REDIS / "redis-preflight.sh").read_text()
COMMON = (REDIS / "redis-common.sh").read_text()
DISCOVERY_SOURCE = (REDIS / "redis-discovery.py").read_text()
RUNNER_SOURCE = (DEPLOY / "redis_runner_common.py").read_text()
spec = importlib.util.spec_from_file_location("redis_discovery_preflight", REDIS / "redis-discovery.py")
redis = importlib.util.module_from_spec(spec)
spec.loader.exec_module(redis)
runner_spec = importlib.util.spec_from_file_location("redis_runner", DEPLOY / "redis_runner_common.py")
runner = importlib.util.module_from_spec(runner_spec)
runner_spec.loader.exec_module(runner)


class RedisPreflightPolicy(unittest.TestCase):
    def test_site_env_uses_dotenv_and_hashes(self):
        self.assertIn('dotenv.parse(fs.readFileSync', DISCOVERY_SOURCE)
        self.assertIn('password_hash:', DISCOVERY_SOURCE)
        self.assertIn('url_hash:', DISCOVERY_SOURCE)
        self.assertNotIn('process.stdout.write(parsed.REDIS_URL)', DISCOVERY_SOURCE)

    def test_site_and_worker_selective_process_probe(self):
        self.assertIn('site = probe_process(pm2_pid(config["site_process"]))', DISCOVERY_SOURCE)
        self.assertIn('worker = probe_process(pm2_pid(config["worker_process"]))', DISCOVERY_SOURCE)
        self.assertIn('prefix = (key + "=").encode()', DISCOVERY_SOURCE)
        self.assertIn('part.startswith(prefix)', DISCOVERY_SOURCE)
        self.assertNotIn('print(raw)', DISCOVERY_SOURCE)

    def test_no_insecure_environment_dump(self):
        for forbidden in ("pm2 env", "pm2 jlist", "printenv", "cat .env", "source .env", "docker inspect", "Config.Env"):
            self.assertNotIn(forbidden, SHELL + COMMON + DISCOVERY_SOURCE)

    def test_docker_structural_listing_only(self):
        self.assertIn('"docker", "ps", "--format"', DISCOVERY_SOURCE)
        self.assertIn('{{.Names}}\\t{{.Image}}\\t{{.Status}}\\t{{.Ports}}', DISCOVERY_SOURCE)
        self.assertIn('redis_port_mapping_match=', DISCOVERY_SOURCE)
        self.assertNotIn('"docker", "restart"', DISCOVERY_SOURCE)

    def test_auth_and_consumer_unknown_blocked_at_runtime(self):
        output = io.StringIO()
        with patch.object(redis, "probe_site_env", return_value=None), patch.object(redis, "pm2_pid", return_value=None), patch.object(redis, "docker_candidates", return_value=[]), redirect_stdout(output):
            self.assertEqual(redis.runtime(), 0)
        result = output.getvalue()
        for marker in ("redis_server_auth_model=UNKNOWN", "redis_credential_source=UNKNOWN", "SITE_API_USES_REDIS=UNKNOWN", "SITE_WORKER_USES_REDIS=UNKNOWN", "REDIS_CONNECTIVITY=NOT_TESTED", "ROTATION_READINESS=BLOCKED", "FUTURE_ROTATION_SEQUENCE=UNKNOWN", "REDIS_PREFLIGHT=PASS"):
            self.assertIn(marker, result)

    def test_consumer_parity_without_values(self):
        configured = {"password_present": True, "url_present": True, "password_hash": "a" * 64, "url_hash": "b" * 64}
        output = io.StringIO()
        with redirect_stdout(output):
            redis.consumer_report("SITE_API", dict(configured), configured)
        self.assertIn("parity=PASS", output.getvalue())
        self.assertNotIn("a" * 64, output.getvalue())
        self.assertNotIn("b" * 64, output.getvalue())

    def test_connectivity_only_ping_no_password_argv(self):
        for forbidden in ('"-a"', '"--pass"', '"SET"', '"DEL"', '"FLUSHDB"', '"FLUSHALL"', '"CONFIG SET"', '"ACL SETUSER"'):
            self.assertNotIn(forbidden, DISCOVERY_SOURCE)
        self.assertIn('command.append("PING")', DISCOVERY_SOURCE)
        self.assertIn('child_env["REDISCLI_AUTH"] = password', DISCOVERY_SOURCE)

    def test_no_mutation_commands(self):
        for forbidden in ("pm2 restart", "docker restart", "pm2 save", "mysql", "mariadb"):
            self.assertNotIn(forbidden, SHELL + COMMON + DISCOVERY_SOURCE + RUNNER_SOURCE)
        self.assertNotIn("redis-rotate-execute.sh", SHELL + COMMON + DISCOVERY_SOURCE + RUNNER_SOURCE)

    def test_shell_production_blocked(self):
        self.assertIn('PRODUCTION_PREFLIGHT=BLOCKED', SHELL)
        self.assertLess(SHELL.index('PRODUCTION_PREFLIGHT=BLOCKED'), SHELL.index('redis_run_readonly'))

    def test_runner_production_before_ssh(self):
        result = subprocess.run([sys.executable, str(DEPLOY / "run-redis-preflight.py"), "--environment", "production"], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("PRODUCTION_PREFLIGHT=BLOCKED", result.stdout)
        self.assertLess(RUNNER_SOURCE.index('if args.environment == "production"'), RUNNER_SOURCE.index('["ssh", host, "test"'))

    def test_runner_invalid_incident(self):
        with tempfile.TemporaryDirectory() as temp:
            current = Path(temp) / "current-incident.txt"
            current.write_text("INVALID")
            with patch.object(runner, "CURRENT_INCIDENT", current), patch.object(runner.subprocess, "run") as run, redirect_stdout(io.StringIO()):
                self.assertEqual(runner.main(["--environment", "staging"]), 1)
                run.assert_not_called()

    def test_runner_absent_sandbox(self):
        with tempfile.TemporaryDirectory() as temp:
            current = Path(temp) / "current-incident.txt"
            config = Path(temp) / "transport.json"
            current.write_text("GSE-20261021T000000Z")
            config.write_text('{"ssh_host":"FAKE_host","remote_base":"/FAKE_base"}')
            with patch.object(runner, "CURRENT_INCIDENT", current), patch.object(runner, "CONFIG_PATH", config), patch.object(runner.subprocess, "run", return_value=subprocess.CompletedProcess([], 1)) as run, redirect_stdout(io.StringIO()):
                self.assertEqual(runner.main(["--environment", "staging"]), 1)
                self.assertEqual(run.call_count, 1)
                self.assertEqual(run.call_args.args[0][2:5], ["test", "-f", "/FAKE_base/GSE-20261021T000000Z/package/rotations/redis/redis-preflight.sh"])

    def test_runner_staging_uses_existing_sandbox(self):
        with tempfile.TemporaryDirectory() as temp:
            current = Path(temp) / "current-incident.txt"
            config = Path(temp) / "transport.json"
            current.write_text("GSE-20261021T000000Z")
            config.write_text('{"ssh_host":"FAKE_host","remote_base":"/FAKE_base"}')
            with patch.object(runner, "CURRENT_INCIDENT", current), patch.object(runner, "CONFIG_PATH", config), patch.object(runner.subprocess, "run", side_effect=[subprocess.CompletedProcess([], 0), subprocess.CompletedProcess([], 0)]) as run, redirect_stdout(io.StringIO()):
                self.assertEqual(runner.main(["--environment", "staging"]), 0)
                self.assertEqual(run.call_count, 2)
                self.assertEqual(run.call_args.args[0][-2:], ["/FAKE_base/GSE-20261021T000000Z/package/rotations/redis/redis-preflight.sh", "staging"])
                self.assertIs(run.call_args.kwargs["shell"], False)


if __name__ == "__main__":
    unittest.main()
