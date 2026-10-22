"""Isolated file mutation faults plus shell rollback gate assertions."""
import importlib.util
import io
import os
import shlex
import shutil
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
AUTH = ROOT / "rotations" / "auth"
spec = importlib.util.spec_from_file_location("auth_env_faults", AUTH / "auth-env.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
SHELL = (AUTH / "auth-rotate-execute.sh").read_text()
ROLLBACK_FUNCTION = "rollback_mutation() {" + SHELL.split("rollback_mutation() {", 1)[1].split("\n}\ntrap rollback_mutation EXIT", 1)[0] + "\n}"


def shell_path(path):
    value = str(path).replace("\\", "/")
    if len(value) > 1 and value[1] == ":":
        return "/" + value[0].lower() + value[2:]
    return value


def bash_executable():
    if os.name == "nt":
        candidate = Path(r"C:\Program Files\Git\bin\bash.exe")
        return str(candidate) if candidate.exists() else None
    return shutil.which("bash")


class AuthFaultInjection(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / ".env.staging"
        self.original = b"# keep\nSESSION_SECRET=old\nOTHER=a=b#c  \n"
        self.path.write_bytes(self.original)

    def test_failure_after_generation_before_replace_keeps_env(self):
        with patch.object(module.os, "replace", side_effect=OSError("injected")):
            with self.assertRaises(OSError):
                module.update(self.path, "SESSION_SECRET")
        self.assertEqual(self.path.read_bytes(), self.original)
        self.assertEqual(list(self.path.parent.glob(".tmp_auth_env_*")), [])

    def test_generation_failure_keeps_env(self):
        with patch.object(module.secrets, "token_urlsafe", side_effect=RuntimeError("injected")):
            with self.assertRaises(RuntimeError):
                module.update(self.path, "SESSION_SECRET")
        self.assertEqual(self.path.read_bytes(), self.original)

    def test_after_write_rollback_gate(self):
        self.assertLess(SHELL.index('MUTATION_STARTED=1'), SHELL.index('auth-env.py" update'))
        self.assertIn('cp -p "$BACKUP_SITE_ENV" "$SITE_ENV"', SHELL)

    def test_during_restart_rollback_gate(self):
        self.assertIn('restart_site_api || exit 1', SHELL)
        self.assertIn('if [ "$MUTATION_STARTED" -eq 1 ]; then', SHELL)

    def test_after_restart_before_parity_rollback_gate(self):
        self.assertLess(SHELL.index('restart_site_api || exit 1'), SHELL.index('site_pid_after='))
        self.assertIn('site_pid_after" != "$site_pid_before', SHELL)

    def test_final_parity_failure_rollback_gate(self):
        self.assertIn('process_env_key_hash "$site_pid_after" "$TARGET_SECRET"', SHELL)
        self.assertIn('ROLLBACK_OLD_HASH_RESTORED=PASS', SHELL)
        self.assertIn('ROLLBACK_WORKER_UNTOUCHED=PASS', SHELL)

    def test_failed_update_emits_no_secret(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(module.os, "replace", side_effect=OSError("injected")):
            with redirect_stdout(stdout), redirect_stderr(stderr), self.assertRaises(OSError):
                module.update(self.path, "SESSION_SECRET")
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "")

    def test_rollback_shell_with_injected_phase_failures(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("local Bash unavailable")
        for phase in ("after_generation", "after_env_write", "during_restart", "after_restart_before_parity", "final_parity"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as temp:
                base = Path(temp)
                site_env = base / ".env.staging"
                backup = base / "backup.env"
                marker = base / "restart.called"
                backup.write_bytes(self.original)
                simulated_key = b"SESSION_" + b"SECRET"
                site_env.write_bytes(self.original if phase == "after_generation" else simulated_key + b"=new\n")
                body = f"""set -euo pipefail
SITE_ENV={shlex.quote(shell_path(site_env))}
BACKUP_SITE_ENV={shlex.quote(shell_path(backup))}
marker={shlex.quote(shell_path(marker))}
TARGET_SECRET=SESSION_SECRET
SITE_PROCESS=gourmet-novo-staging
WORKER_PROCESS=gourmet-worker-staging
worker_pid_before=123
old_hash=oldhash
original_mode=600
MUTATION_STARTED=1
finished=0
restart_site_api() {{ touch "$marker"; }}
dotenv_key_hash() {{ if cmp -s "$SITE_ENV" "$BACKUP_SITE_ENV"; then printf oldhash; else printf newhash; fi; }}
process_env_key_hash() {{ printf oldhash; }}
pm2_pid() {{ printf 123; }}
{ROLLBACK_FUNCTION}
trap rollback_mutation EXIT
exit 9
"""
                result = subprocess.run([bash, "-c", body], capture_output=True, text=True)
                self.assertEqual(result.returncode, 9, result.stderr)
                self.assertEqual(site_env.read_bytes(), self.original)
                self.assertTrue(marker.exists())
                for expected in ("ROLLBACK_STARTED=YES", "ROLLBACK_SITE_ENV=PASS", "ROLLBACK_SITE_PROCESS=PASS", "ROLLBACK_WORKER_UNTOUCHED=PASS", "ROLLBACK_OLD_HASH_RESTORED=PASS", "ROLLBACK_FINISHED=PASS", "AUTH_ROTATION_EXECUTE=FAIL"):
                    self.assertIn(expected, result.stdout)
                self.assertNotIn((simulated_key + b"=new").decode(), result.stdout + result.stderr)

    def test_pre_mutation_failure_does_not_restart_or_restore(self):
        bash = bash_executable()
        if bash is None:
            self.skipTest("local Bash unavailable")
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            site_env = base / ".env.staging"
            site_env.write_bytes(b"before")
            body = f"""set -euo pipefail
SITE_ENV={shlex.quote(shell_path(site_env))}
MUTATION_STARTED=0
finished=0
{ROLLBACK_FUNCTION}
trap rollback_mutation EXIT
exit 7
"""
            result = subprocess.run([bash, "-c", body], capture_output=True, text=True)
            self.assertEqual(result.returncode, 7, result.stderr)
            self.assertEqual(site_env.read_bytes(), b"before")
            self.assertNotIn("ROLLBACK_STARTED=YES", result.stdout)
            self.assertIn("AUTH_ROTATION_EXECUTE=FAIL", result.stdout)


if __name__ == "__main__":
    unittest.main()
