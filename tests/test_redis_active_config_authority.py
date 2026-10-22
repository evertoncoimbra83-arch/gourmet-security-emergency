"""GSE-03B4C: the PM2 script argument outranks matching Redis candidates."""
import importlib.util
import io
import json
import os
import secrets
import stat
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
DISCOVERY = ROOT / "rotations" / "redis" / "redis-discovery.py"
PLAN = ROOT / "rotations" / "redis" / "redis-rotate-plan.py"


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


redis = module("redis_authority_test", DISCOVERY)
plan = module("redis_plan_authority_test", PLAN)
CONFIG = json.loads((ROOT / "rotations" / "redis" / "redis-registry.json").read_text())["staging"]
ACTIVE = CONFIG["expected_config_candidates"][0]
LEGACY = CONFIG["legacy_config_candidates"][0]


def full_evidence():
    result = dict(plan.EVIDENCE_EXPECTED)
    result.update({
        "redis_config_path": ACTIVE,
        "redis_executable": "/usr/bin/redis-server",
        "redis_process_cwd": "/home/gsadmin/redis-staging/data",
        "site_redis_server_name": "redis-server",
        "redis_socket_listening": "YES", "redis_socket_address_match": "YES",
        "redis_listener_owner_visible": "YES", "redis_auth_ping": "PASS",
        "requirepass_status": "CONFIGURED", "config_port": "6380",
        "config_bind": "127.0.0.1,::1",
        "config_dir": "/home/gsadmin/redis-staging/data",
        "future_backup_target": [CONFIG["site_env"], ACTIVE],
    })
    return result


class RedisConfigAuthority(unittest.TestCase):
    def test_pm2_description_only_structural_fields(self):
        secret = secrets.token_urlsafe(48)
        raw = ("│ status │ \x1b[32monline\x1b[39m │\n│ name │ redis-staging │\n"
               "│ script path │ /usr/bin/redis-server │\n"
               f"│ script args │ {ACTIVE} │\n"
               f"│ Divergent env variables │ {secret} │\n"
               f"│ REDIS_PASSWORD │ {secret} │\n"
               "│ script args │ /untrusted/env.conf │\n")
        fields = redis.parse_pm2_description(raw)
        self.assertEqual(fields["script args"], ACTIVE)
        self.assertFalse(secret in repr(fields))
        self.assertFalse("Divergent env variables" in repr(fields))

    def test_pm2_pid_dynamic_and_config_argument(self):
        seen = []
        def run(command, **kwargs):
            seen.append(command)
            if command[:2] == ["pm2", "pid"]:
                return subprocess.CompletedProcess(command, 0, "5017\n", "")
            raw = ("│ status │ online │\n│ name │ redis-staging │\n"
                   "│ script path │ /usr/bin/redis-server │\n"
                   f"│ script args │ {ACTIVE} │\n")
            return subprocess.CompletedProcess(command, 0, raw, "")
        self.assertEqual(redis.pm2_explicit_config("5017", "redis-staging", run)["path"], ACTIVE)
        self.assertEqual(redis.pm2_explicit_config("927", "redis-staging", run)["path"], "UNKNOWN")
        self.assertTrue(all(item[2] == "redis-staging" for item in seen))

    def test_pm2_argument_absolute_and_single(self):
        for arg in ("relative.conf", f"{ACTIVE} --secret material", "N/A", ""):
            with self.subTest(arg=arg):
                def run(command, **kwargs):
                    if command[1] == "pid":
                        return subprocess.CompletedProcess(command, 0, "927\n", "")
                    raw = ("│ status │ online │\n│ name │ redis-staging │\n"
                           "│ script path │ /usr/bin/redis-server │\n"
                           f"│ script args │ {arg} │\n")
                    return subprocess.CompletedProcess(command, 0, raw, "")
                self.assertEqual(redis.pm2_explicit_config("927", "redis-staging", run)["authority"], "UNKNOWN")

    def test_offline_pm2_description_only_for_verified_rollback(self):
        def run(command, **kwargs):
            raw = ("│ status │ errored │\n│ name │ redis-staging │\n"
                   "│ script path │ /usr/bin/redis-server │\n"
                   f"│ script args │ {ACTIVE} │\n")
            return subprocess.CompletedProcess(command, 0, raw, "")
        self.assertEqual(redis.pm2_described_config("redis-staging", run_fn=run)["path"], "UNKNOWN")
        self.assertEqual(redis.pm2_described_config("redis-staging", run_fn=run,
                                                     allow_offline=True)["path"], ACTIVE)

    def test_authority_precedence(self):
        self.assertEqual(redis.select_config_authority(ACTIVE, LEGACY, LEGACY, LEGACY),
                         ("PM2_SCRIPT_ARGUMENT", ACTIVE))
        self.assertEqual(redis.select_config_authority(process_path=ACTIVE, service_path=LEGACY,
                                                       heuristic_path=LEGACY), ("PROCESS_ARGUMENT", ACTIVE))
        self.assertEqual(redis.select_config_authority(service_path=ACTIVE, heuristic_path=LEGACY),
                         ("SERVICE_UNIT_ARGUMENT", ACTIVE))
        self.assertEqual(redis.select_config_authority(heuristic_path=LEGACY),
                         ("VALIDATED_CANDIDATE_HEURISTIC", LEGACY))

    def test_direct_and_service_arguments_are_reduced_to_paths(self):
        secret = secrets.token_urlsafe(48)
        argv = b"/usr/bin/redis-server\0" + ACTIVE.encode() + b"\0--requirepass\0" + secret.encode() + b"\0"
        with patch.object(redis.Path, "read_bytes", return_value=argv):
            self.assertEqual(redis.direct_process_config("927"), ACTIVE)
        def run(command, **kwargs):
            output = f"{{ path=/usr/bin/redis-server ; argv[]=/usr/bin/redis-server {ACTIVE} --requirepass {secret} ; }}"
            return subprocess.CompletedProcess(command, 0, output, "")
        self.assertEqual(redis.service_unit_config(
            "927", run_fn=run,
            cgroup_reader=lambda _: "0::/system.slice/redis-staging.service\n"), ACTIVE)

    def test_active_config_private_regular_file_required(self):
        good = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=1001)
        bad_mode = SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=1001)
        bad_owner = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=1002)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "active.conf"
            path.write_text("fixture")
            self.assertTrue(redis.config_file_metadata_ok(str(path), stat_fn=lambda _: good, uid_fn=lambda _: 1001))
            self.assertFalse(redis.config_file_metadata_ok(str(path), stat_fn=lambda _: bad_mode, uid_fn=lambda _: 1001))
            self.assertFalse(redis.config_file_metadata_ok(str(path), stat_fn=lambda _: bad_owner, uid_fn=lambda _: 1001))
            self.assertFalse(redis.config_file_metadata_ok(str(path) + ".missing", uid_fn=lambda _: 1001))

    def test_authoritative_config_endpoint_cwd_and_requirepass(self):
        socket = {"found": "YES", "address_match": "YES", "owner_visible": "YES", "type": "REDIS_PROCESS"}
        process = {"executable": "/usr/bin/redis-server", "process": "redis-server",
                   "user": "gsadmin", "cwd": "/home/gsadmin/redis-staging/data"}
        def info(port="6380", directory="/home/gsadmin/redis-staging/data", password="PRESENT"):
            return {"readable": True, "conflict": False, "port": port,
                    "bind": "127.0.0.1,::1", "dir": directory,
                    "dbfilename": "staging.rdb", "requirepass": password,
                    "aclfile_present": "NO"}
        existing = {ACTIVE, LEGACY, "/home/gsadmin/redis-staging/data/staging.rdb"}
        for config_info, expected in ((info(), "YES"), (info(port="6379"), "NO"),
                                      (info(directory="/tmp"), "NO"),
                                      (info(password="ABSENT"), "NO")):
            with self.subTest(config_info=config_info):
                found = redis.discover_active_config(
                    "127.0.0.1", 6380, socket, process, [ACTIVE],
                    exists_fn=lambda p: p in existing, config_reader=lambda _: config_info,
                    glob_fn=lambda _: [], expected_user="gsadmin")
                # The PM2-selected call excludes the operationally similar legacy file.
                self.assertEqual(found["active_match"], expected)
                self.assertEqual(found["path"], ACTIVE if expected == "YES" else "UNKNOWN")

    def test_legacy_similar_with_different_credential_is_stale(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(redis, "safe_path", side_effect=lambda p: str(p)):
            active = Path(tmp) / "active.conf"
            legacy = Path(tmp) / "legacy.conf"
            first, second = secrets.token_urlsafe(48), secrets.token_urlsafe(48)
            common = "bind 127.0.0.1 -::1\nport 6380\ndir /home/gsadmin/redis-staging/data\ndbfilename staging.rdb\nappendonly yes\n"
            active.write_text(common + "requirepass " + first + "\n")
            legacy.write_text(common + "requirepass " + second + "\n")
            before = legacy.read_bytes()
            result = redis.inspect_legacy_config(str(active), [str(legacy)], redis.inspect_redis_config(str(active)))
            self.assertEqual(result["detected"], "YES")
            self.assertEqual(result["operationally_similar"], "YES")
            self.assertEqual(result["requirepass_relationship"], "DIFFERENT")
            self.assertEqual(result["classification"], "STALE_CREDENTIAL_CONFIG")
            self.assertFalse(first in repr(result) or second in repr(result))
            self.assertTrue(legacy.read_bytes() == before)

    def test_credential_comparison_metadata_only(self):
        active, redundant = secrets.token_urlsafe(48), secrets.token_urlsafe(48)
        out = io.StringIO()
        with redirect_stdout(out):
            print("active_requirepass_vs_redis_url=" + redis.safe_credential_relation(active, active))
            print("active_requirepass_vs_redis_password=" + redis.safe_credential_relation(active, redundant))
            print("redis_url_vs_redis_password=" + redis.safe_credential_relation(active, redundant))
        report = out.getvalue()
        self.assertIn("active_requirepass_vs_redis_url=SAME", report)
        self.assertIn("active_requirepass_vs_redis_password=DIFFERENT", report)
        self.assertFalse(active in report or redundant in report)
        self.assertEqual(redis.classify_credential_relationship("MIXED", "MIXED", "FAIL", "PASS", "FAIL"),
                         "INCONSISTENT_CONFIGURATION")

    def test_old_ready_evidence_invalidated_new_accepted(self):
        current = full_evidence()
        plan.validate_evidence(current, CONFIG)
        old = dict(current)
        old.pop("redis_discovery_contract_version")
        old.pop("redis_config_authority")
        old["redis_config_path"] = LEGACY
        old["future_backup_target"] = [CONFIG["site_env"], LEGACY]
        with self.assertRaises(plan.PlanBlocked):
            plan.validate_evidence(old, CONFIG)
        self.assertEqual(CONFIG["expected_config_candidates"], [ACTIVE])
        self.assertEqual(CONFIG["legacy_config_candidates"], [LEGACY])

    def test_readiness_requires_pm2_authority_and_new_contract(self):
        previous = {
            "socket_listening": "YES", "socket_address_match": "YES", "listener_owner_visible": "YES",
            "server_identified": True, "server_type": "LOCAL_PROCESS", "process_identity_verified": True,
            "managed_by_pm2": "YES", "active_config_match": "YES", "config_path": ACTIVE,
            "executable": "/usr/bin/redis-server", "credential_source_identified": True,
            "credential_source": "REDIS_CONF", "auth_model": "REQUIREPASS",
            "auth_ping": "PASS", "requirepass_status": "CONFIGURED",
            "connectivity": "PASS", "connectivity_url": "PASS", "connectivity_password": "FAIL",
            "site_api_uses_redis": "YES", "site_worker_uses_redis": "YES",
            "api_restart_required": "YES", "worker_restart_required": "YES",
            "api_usage": "MIXED", "worker_usage": "MIXED", "relationship_parity": "FAIL",
            "relationship": "INCONSISTENT_CONFIGURATION", "other_consumers_known": True,
            "backup_targets": [CONFIG["site_env"], ACTIVE], "backup_targets_complete": True,
            "restart_targets": [CONFIG["site_process"], CONFIG["worker_process"]],
            "restart_targets_known": True, "future_sequence": list(redis.LOCAL_REDIS_SEQUENCE),
        }
        self.assertEqual(redis.assess_readiness(previous)["ROTATION_READINESS"], "BLOCKED")
        previous.update(config_authority="PM2_SCRIPT_ARGUMENT", discovery_contract_version=2)
        self.assertEqual(redis.assess_readiness(previous)["ROTATION_READINESS"], "READY")

    def test_source_prohibitions(self):
        source = DISCOVERY.read_text(encoding="utf-8")
        executor_source = (ROOT / "rotations" / "redis" / "redis-rotate-execute.py").read_text(encoding="utf-8")
        self.assertTrue(ACTIVE in executor_source)
        self.assertFalse(LEGACY in executor_source)
        for forbidden in ("pm2 env", "pm2 jlist", "pm2 save", "shell=True"):
            self.assertFalse(forbidden in source)
            self.assertFalse(forbidden in executor_source)


if __name__ == "__main__":
    unittest.main()
