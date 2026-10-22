import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AUTH = ROOT / "rotations" / "auth"


class AuthPreflightPolicy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.registry = json.loads((AUTH / "auth-registry.json").read_text())
        cls.preflight = (AUTH / "auth-preflight.sh").read_text()
        cls.common = (AUTH / "auth-common.sh").read_text()

    def test_registry_staging(self):
        staging = self.registry["staging"]
        self.assertEqual(staging["site_env"], "/home/gsadmin/secure-env/.env.staging")
        self.assertEqual(staging["site_dir"], "/var/www/gourmet-staging")
        self.assertEqual(staging["site_process"], "gourmet-novo-staging")
        self.assertEqual(staging["worker_process"], "gourmet-worker-staging")

    def test_three_secrets_and_metadata(self):
        secrets = self.registry["staging"]["secrets"]
        self.assertEqual(set(secrets), {"SESSION_SECRET", "JWT_SECRET", "NEXTAUTH_SECRET"})
        for meta in secrets.values():
            self.assertEqual(meta, {
                "required_in_site_env": True, "restart_site_api": True,
                "restart_worker": False, "database_touch": False,
                "expected_effect": "session_or_token_invalidation",
            })

    def test_registry_has_no_values(self):
        for meta in self.registry["staging"]["secrets"].values():
            self.assertFalse(any("value" in key or "token" in key for key in meta))

    def test_disallowed_dumps(self):
        for forbidden in ("pm2 env", "pm2 jlist", "printenv", "cat .env", "source .env"):
            self.assertNotIn(forbidden, self.preflight + self.common)

    def test_selective_process_hash(self):
        self.assertIn('"/proc/" + sys.argv[1] + "/environ"', self.common)
        self.assertIn('part.startswith(prefix)', self.common)
        self.assertIn('hashlib.sha256(matches[0]).hexdigest()', self.common)
        self.assertNotIn('print(data)', self.common)

    def test_dotenv_semantics(self):
        self.assertIn('dotenv.parse(fs.readFileSync', self.common)
        self.assertIn('crypto.createHash("sha256").update(value)', self.common)

    def test_process_lookup(self):
        self.assertIn('pm2 pid "$1"', self.common)
        self.assertIn('pm2_pid "$WORKER_PROCESS"', self.preflight)

    def test_required_outputs(self):
        for marker in ("SITE_ENV=PASS", "PROCESS_PARITY=PASS", "SITE_PROCESS=ONLINE", "WORKER_PROCESS=ONLINE", "SITE_HTTP_HEALTH=NOT_CONFIGURED", "AUTH_PREFLIGHT=PASS"):
            self.assertIn(marker, self.preflight)

    def test_read_only_assertions(self):
        for marker in ("NO_SECRET_VALUES_PRINTED=PASS", "NO_FILES_MODIFIED=PASS", "NO_SERVICES_RESTARTED=PASS", "NO_DATABASE_READS=PASS", "NO_DATABASE_WRITES=PASS"):
            self.assertIn(marker, self.preflight)


if __name__ == "__main__":
    unittest.main()
