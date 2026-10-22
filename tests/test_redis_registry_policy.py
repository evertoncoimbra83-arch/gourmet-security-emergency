import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REGISTRY = ROOT / "rotations" / "redis" / "redis-registry.json"


class RedisRegistryPolicy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = REGISTRY.read_text(encoding="utf-8")
        cls.data = json.loads(cls.raw)

    def test_staging_paths(self):
        staging = self.data["staging"]
        self.assertEqual(staging["site_env"], "/home/gsadmin/secure-env/.env.staging")
        self.assertEqual(staging["site_dir"], "/var/www/gourmet-staging")

    def test_staging_processes(self):
        staging = self.data["staging"]
        self.assertEqual(staging["site_process"], "gourmet-novo-staging")
        self.assertEqual(staging["worker_process"], "gourmet-worker-staging")

    def test_both_secrets_registered(self):
        self.assertEqual(set(self.data["staging"]["secrets"]), {"REDIS_PASSWORD", "REDIS_URL"})

    def test_coordinated_classification(self):
        for metadata in self.data["staging"]["secrets"].values():
            self.assertEqual(metadata["rotation_class"], "COORDINATED_ROTATE")

    def test_no_values_stored(self):
        for metadata in self.data["staging"]["secrets"].values():
            self.assertEqual(set(metadata), {"rotation_class"})

    def test_only_staging_configured(self):
        self.assertNotIn("production", self.data)


if __name__ == "__main__":
    unittest.main()
