import importlib.util
import io
import os
import re
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AUTH = ROOT / "rotations" / "auth"
EXEC = (AUTH / "auth-rotate-execute.sh").read_text()
COMMON = (AUTH / "auth-common.sh").read_text()
RUNNER = ROOT / "deploy" / "auth_runner_common.py"
spec = importlib.util.spec_from_file_location("auth_env", AUTH / "auth-env.py")
env_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(env_module)


class AuthExecutePolicy(unittest.TestCase):
    def test_production_block_local_before_ssh(self):
        result = subprocess.run([sys.executable, str(ROOT / "deploy" / "run-auth-rotation-execute.py"), "--environment", "production", "--secret", "JWT_SECRET", "--execute"], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("PRODUCTION_EXECUTION=BLOCKED", result.stdout)
        source = RUNNER.read_text()
        self.assertLess(source.index('if args.environment == "production"'), source.index('subprocess.run(["ssh"'))

    def test_shell_production_block_before_mutation(self):
        self.assertLess(EXEC.index('PRODUCTION_EXECUTION=BLOCKED'), EXEC.index('mkdir -p -m 700'))
        self.assertLess(EXEC.index('PRODUCTION_EXECUTION=BLOCKED'), EXEC.index('MUTATION_STARTED=1'))

    def test_incident_id_and_whitelist(self):
        self.assertIn('^GSE-[0-9]{8}T[0-9]{6}Z$', EXEC)
        self.assertIn('SESSION_SECRET|JWT_SECRET|NEXTAUTH_SECRET', EXEC)
        self.assertIn('SECRET_INVALID=FAIL', EXEC)

    def test_execute_required(self):
        self.assertIn('EXECUTE_FLAG_REQUIRED=FAIL', EXEC)
        result = subprocess.run([sys.executable, str(ROOT / "deploy" / "run-auth-rotation-execute.py"), "--environment", "staging", "--secret", "JWT_SECRET"], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("EXECUTE_FLAG_REQUIRED=FAIL", result.stdout)

    def test_backup_and_collision(self):
        self.assertIn('/home/gsadmin/backups/gse/${INCIDENT_ID}/auth/${TARGET_SECRET}', EXEC)
        self.assertIn('backup_already_exists=FAIL', EXEC)
        self.assertLess(EXEC.index('backup_already_exists=FAIL'), EXEC.index('mkdir -p -m 700'))
        self.assertIn('chmod 600 "$BACKUP_SITE_ENV"', EXEC)
        self.assertIn('original_file_hash', EXEC)

    def test_dependency_before_mutation(self):
        self.assertLess(EXEC.index("require.resolve('dotenv')"), EXEC.index('MUTATION_STARTED=1'))
        self.assertLess(EXEC.index('auth-preflight.sh'), EXEC.index('MUTATION_STARTED=1'))

    def test_csprng_and_no_value_argv_or_output(self):
        source = (AUTH / "auth-env.py").read_text()
        self.assertIn('secrets.token_urlsafe(48)', source)
        self.assertIn('print(new_hash)', source)
        self.assertNotIn('print(new_secret)', source)
        self.assertNotIn('sys.argv.append(new_secret)', source)
        self.assertNotRegex(EXEC, r'echo\s+.*\$new_secret')

    def test_atomic_write_contract(self):
        source = (AUTH / "auth-env.py").read_text()
        for fragment in ('tempfile.mkstemp(dir=path.parent', 'os.chmod(tmp, original_mode)', 'os.fsync(stream.fileno())', 'os.replace(tmp, path)'):
            self.assertIn(fragment, source)

    def test_missing_and_duplicate_key_fail(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / ".env.staging"
            key = b"JWT_" + b"SECRET"
            for data in (b"OTHER=x\n", key + b"=a\n" + key + b"=b\n"):
                path.write_bytes(data)
                with self.assertRaises(ValueError):
                    env_module.require_single(path, "JWT_SECRET")

    def test_preserve_lines_comments_newlines_and_mode(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / ".env.staging"
            key = b"JWT_" + b"SECRET"
            before = b"# comment\r\nOTHER=a=b#c  \r\n" + key + b"='old value'\r\nLAST=x\r\n"
            path.write_bytes(before)
            os.chmod(path, 0o640)
            output = io.StringIO()
            with redirect_stdout(output), redirect_stderr(io.StringIO()):
                env_module.update(path, "JWT_SECRET")
            after = path.read_bytes()
            self.assertTrue(after.startswith(b"# comment\r\nOTHER=a=b#c  \r\n"))
            self.assertTrue(after.endswith(b"LAST=x\r\n"))
            self.assertEqual(after.count(key + b"="), 1)
            self.assertRegex(output.getvalue().strip(), r"^[0-9a-f]{64}$")
            if os.name != "nt":
                self.assertEqual(path.stat().st_mode & 0o777, 0o640)

    def test_restart_and_worker_invariant(self):
        self.assertIn('env -C "$SITE_DIR" node', COMMON)
        self.assertIn('spawnSync("pm2", ["restart", process.argv[2], "--update-env"]', COMMON)
        self.assertIn('SITE_PROCESS=gourmet-novo-staging', COMMON)
        self.assertIn('worker_pid_after" = "$worker_pid_before', EXEC)
        self.assertNotIn('restart "$WORKER_PROCESS"', EXEC + COMMON)

    def test_no_persistence_or_database(self):
        for forbidden in ("pm2 save", "mysql", "mariadb", "shell=True"):
            self.assertNotIn(forbidden, EXEC + COMMON + RUNNER.read_text())

    def test_rollback_contract(self):
        for marker in ('trap rollback_mutation EXIT', 'ROLLBACK_STARTED=YES', 'ROLLBACK_SITE_ENV=PASS', 'ROLLBACK_SITE_PROCESS=PASS', 'ROLLBACK_WORKER_UNTOUCHED=PASS', 'ROLLBACK_OLD_HASH_RESTORED=PASS', 'ROLLBACK_FINISHED=PASS'):
            self.assertIn(marker, EXEC)
        self.assertIn('if [ "$MUTATION_STARTED" -eq 1 ]; then', EXEC)
        self.assertIn('trap - EXIT', EXEC)
        self.assertIn('restart_site_api', EXEC)


if __name__ == "__main__":
    unittest.main()
