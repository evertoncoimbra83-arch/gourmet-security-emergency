import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PLAN = ROOT / "rotations" / "auth" / "auth-rotate-plan.py"


def run(*args):
    return subprocess.run([sys.executable, str(PLAN), *args], capture_output=True, text=True, cwd=ROOT)


class AuthPlanPolicy(unittest.TestCase):
    def test_staging_each_secret(self):
        for secret in ("SESSION_SECRET", "JWT_SECRET", "NEXTAUTH_SECRET"):
            with self.subTest(secret=secret):
                result = run("--environment", "staging", "--secret", secret, "--dry-run")
                self.assertEqual(result.returncode, 0)
                self.assertIn("AUTH_ROTATION_PLAN=PASS", result.stdout)

    def test_production_rejected(self):
        self.assertNotEqual(run("--environment", "production", "--secret", "JWT_SECRET", "--dry-run").returncode, 0)

    def test_invalid_secret_rejected(self):
        self.assertNotEqual(run("--environment", "staging", "--secret", "INVALID", "--dry-run").returncode, 0)

    def test_dry_run_required(self):
        result = run("--environment", "staging", "--secret", "JWT_SECRET")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("DRY_RUN_REQUIRED=FAIL", result.stdout)

    def test_impacts(self):
        impacts = {
            "SESSION_SECRET": "ACTIVE_SESSIONS_MAY_BE_INVALIDATED",
            "JWT_SECRET": "ACTIVE_JWTS_MAY_BE_INVALIDATED",
            "NEXTAUTH_SECRET": "NEXTAUTH_SESSIONS_OR_TOKENS_MAY_BE_INVALIDATED",
        }
        for secret, impact in impacts.items():
            self.assertIn("EXPECTED_IMPACT=" + impact, run("--environment", "staging", "--secret", secret, "--dry-run").stdout)

    def test_no_worker_or_database(self):
        output = run("--environment", "staging", "--secret", "JWT_SECRET", "--dry-run").stdout
        for marker in ("WOULD_RESTART_WORKER=NO", "ACTUAL_DATABASE_TOUCHED=NO", "ACTUAL_SECRET_GENERATED=NO", "ACTUAL_FILES_CHANGED=NO", "ACTUAL_SERVICES_RESTARTED=NO"):
            self.assertIn(marker, output)


if __name__ == "__main__":
    unittest.main()
