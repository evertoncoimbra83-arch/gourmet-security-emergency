import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
DISCOVERY = ROOT / "rotations" / "redis" / "redis-discovery.py"
FIXTURES = ROOT / "tests" / "fixtures" / "redis"
spec = importlib.util.spec_from_file_location("redis_discovery", DISCOVERY)
redis = importlib.util.module_from_spec(spec)
spec.loader.exec_module(redis)


class RedisDiscoveryPolicy(unittest.TestCase):
    def test_plain_url(self):
        shape = redis.parse_redis_url("redis://localhost:6379")
        self.assertEqual(shape["redis_url_scheme"], "redis")
        self.assertEqual(shape["redis_url_host_present"], "YES")
        self.assertEqual(shape["redis_url_port_present"], "YES")
        self.assertEqual(shape["redis_url_password_present"], "NO")

    def test_password_url(self):
        shape = redis.parse_redis_url("redis://:FAKE_value@localhost:6379/0")
        self.assertEqual(shape["redis_url_password_present"], "YES")
        self.assertEqual(shape["redis_url_database_index_present"], "YES")

    def test_named_user_url(self):
        shape = redis.parse_redis_url("redis://FAKE_user:FAKE_value@localhost:6379")
        self.assertNotIn("username", shape)
        self.assertEqual(shape["redis_url_password_present"], "YES")

    def test_tls_url(self):
        self.assertEqual(redis.parse_redis_url("rediss://localhost:6380")["redis_url_scheme"], "rediss")

    def test_percent_encoded_special_characters(self):
        password = "FAKE_a@b:c#d"
        url = "redis://:FAKE_a%40b%3Ac%23d@localhost:6379"
        self.assertEqual(redis.parse_redis_url(url)["url_password_hash"], redis.digest(password))

    def test_raw_at_and_colon_in_password(self):
        url = "redis://:FAKE_a@b:c@localhost:6379"
        self.assertEqual(redis.parse_redis_url(url)["url_password_hash"], redis.digest("FAKE_a@b:c"))

    def test_invalid_url_rejected(self):
        for url in ("http://localhost:6379", "redis://", "redis://localhost:bad", "redis://localhost\n:6379"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                redis.parse_redis_url(url)

    def test_no_credential_in_public_result(self):
        value = "FAKE_sensitive_value"
        url = "redis://FAKE_user:" + value + "@localhost:6379?token=FAKE_query"
        report = redis.classify_values(value, url)
        serialized = json.dumps(report)
        for forbidden in (value, "FAKE_user", "FAKE_query", url):
            self.assertNotIn(forbidden, serialized)

    def test_relationship_same(self):
        fixture = json.loads((FIXTURES / "env-password-and-url.txt").read_text())
        result = redis.classify_values(fixture["REDIS_PASSWORD"], fixture["REDIS_URL"])
        self.assertEqual(result["relationship"], "PASSWORD_AND_URL_SAME_CREDENTIAL")
        self.assertEqual(result["redis_password_url_parity"], "PASS")

    def test_relationship_different(self):
        result = redis.classify_values("FAKE_other", "redis://:FAKE_value@localhost:6379")
        self.assertEqual(result["relationship"], "PASSWORD_REDUNDANT")
        self.assertEqual(result["redis_password_url_parity"], "FAIL")

    def test_url_without_password(self):
        result = redis.classify_values("FAKE_value", "redis://localhost:6379")
        self.assertEqual(result["relationship"], "URL_WITHOUT_PASSWORD")
        self.assertEqual(result["redis_password_url_parity"], "NOT_APPLICABLE")

    def test_separate_password(self):
        fixture = json.loads((FIXTURES / "env-password-only.txt").read_text())
        self.assertEqual(redis.classify_values(fixture["REDIS_PASSWORD"])["relationship"], "PASSWORD_SEPARATE")

    def test_url_only(self):
        fixture = json.loads((FIXTURES / "env-url-only.txt").read_text())
        self.assertEqual(redis.classify_values(url_value=fixture["REDIS_URL"])["relationship"], "PASSWORD_EMBEDDED_IN_URL")

    def test_unknown_without_values(self):
        self.assertEqual(redis.classify_values()["relationship"], "UNKNOWN")

    def test_config_fixtures(self):
        self.assertEqual(redis.classify_config_auth((FIXTURES / "redis-config-requirepass.txt").read_text()), "REQUIREPASS")
        self.assertEqual(redis.classify_config_auth((FIXTURES / "redis-config-acl.txt").read_text()), "ACL_NAMED_USER")
        self.assertEqual(redis.classify_config_auth("# nothing\n"), "UNKNOWN")

    def test_connectivity_child_env_only(self):
        calls = []
        def fake_run(command, **kwargs):
            calls.append((command, kwargs))
            return subprocess.CompletedProcess(command, 0, "PONG\n", "")
        with patch.object(redis.subprocess, "run", side_effect=fake_run):
            result = redis.connectivity_ping("localhost", 6379, "FAKE_password")
        self.assertEqual(result, "PASS")
        command, kwargs = calls[0]
        self.assertEqual(command[-1], "PING")
        self.assertNotIn("FAKE_password", " ".join(command))
        self.assertEqual(kwargs["env"]["REDISCLI_AUTH"], "FAKE_password")
        self.assertIs(kwargs["shell"], False)

    def test_connectivity_named_user_deferred(self):
        with patch.object(redis.subprocess, "run") as run:
            self.assertEqual(redis.connectivity_ping("localhost", 6379, "FAKE_password", username="FAKE_user"), "NOT_TESTED")
            run.assert_not_called()

    def test_readiness_unknown_auth_blocked(self):
        evidence = self.complete_evidence()
        evidence["auth_model"] = "UNKNOWN"
        self.assertEqual(redis.assess_readiness(evidence)["ROTATION_READINESS"], "BLOCKED")

    def test_readiness_unknown_consumer_blocked(self):
        evidence = self.complete_evidence()
        evidence["site_worker_uses_redis"] = "UNKNOWN"
        self.assertEqual(redis.assess_readiness(evidence)["ROTATION_READINESS"], "BLOCKED")

    def test_readiness_unknown_relationship_blocked(self):
        evidence = self.complete_evidence()
        evidence["relationship"] = "UNKNOWN"
        self.assertEqual(redis.assess_readiness(evidence)["ROTATION_READINESS"], "BLOCKED")

    def test_readiness_sequence_required(self):
        evidence = self.complete_evidence()
        evidence["future_sequence"] = []
        self.assertEqual(redis.assess_readiness(evidence)["FUTURE_ROTATION_SEQUENCE"], "UNKNOWN")

    def test_unverified_sequence_blocked(self):
        evidence = self.complete_evidence()
        evidence["future_sequence"] = ["FAKE_unverified_action"]
        self.assertEqual(redis.assess_readiness(evidence)["ROTATION_READINESS"], "BLOCKED")

    def test_readiness_complete(self):
        result = redis.assess_readiness(self.complete_evidence())
        self.assertEqual(result["ROTATION_READINESS"], "BLOCKED")
        self.assertEqual(result["FUTURE_ROTATION_SEQUENCE"], "UNKNOWN")
        self.assertEqual(result["future_backup_targets"], 2)
        self.assertEqual(result["future_restart_targets"], 2)
        self.assertEqual(result["future_rotation_steps"], [])

    @staticmethod
    def complete_evidence():
        return {
            "server_identified": True, "auth_model": "ACL_DEFAULT_USER",
            "credential_source_identified": True, "site_api_uses_redis": "YES",
            "site_worker_uses_redis": "YES", "other_consumers_known": True,
            "relationship": "PASSWORD_AND_URL_SAME_CREDENTIAL", "relationship_parity": "PASS",
            "backup_targets": ["FAKE_server_config", "FAKE_site_env"], "backup_targets_complete": True,
            "restart_targets": ["FAKE_site", "FAKE_worker"], "restart_targets_known": True,
            "future_sequence": ["BACKUP_SERVER_AUTH_CONFIG", "BACKUP_SITE_ENV", "PREPARE_CLIENT_CREDENTIALS", "UPDATE_REDIS_AUTH", "UPDATE_SITE_ENV", "RESTART_CONFIRMED_CONSUMERS", "VERIFY_PING", "VERIFY_HEALTH", "ROLLBACK_IF_FAILURE"], "connectivity": "NOT_TESTED",
            "connectivity_not_tested_reason": "FAKE_isolated_fixture",
        }


if __name__ == "__main__":
    unittest.main()
