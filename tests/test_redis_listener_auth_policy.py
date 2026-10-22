"""GSE-03B3 read-only listener and authentication discovery."""
import importlib.util
import io
import json
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "rotations" / "redis" / "redis-discovery.py"
spec = importlib.util.spec_from_file_location("redis_b3", SCRIPT)
redis = importlib.util.module_from_spec(spec)
spec.loader.exec_module(redis)


class RedisListenerAuthPolicy(unittest.TestCase):
    def test_listener_6380_identified(self):
        row = 'State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\nLISTEN 0 511 127.0.0.1:6380 0.0.0.0:* users:(("docker-proxy",pid=42,fd=4))\n'
        out = redis.discover_listener(run_fn=lambda *a, **k: subprocess.CompletedProcess(a, 0, row, ''))
        self.assertEqual((out['found'], out['type'], out['pid']), ('YES', 'DOCKER_PROXY', '42'))

    def test_docker_port_mapping_identified(self):
        meta = {'name': 'opaque', 'ports': {'6379/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '6380'}]}}
        out = redis.identify_site_redis_server('127.0.0.1', 6380, [('opaque', 'UP')], lambda _: meta)
        self.assertTrue(out['identified'])
        self.assertEqual(out['server_name'], 'opaque')

    def test_local_redis_process_identified(self):
        row = 'LISTEN 0 511 127.0.0.1:6380 0.0.0.0:* users:(("redis-server",pid=51,fd=4))\n'
        self.assertEqual(redis.discover_listener(run_fn=lambda *a, **k: subprocess.CompletedProcess(a, 0, row, ''))['type'], 'REDIS_PROCESS')

    def test_wrong_container_not_matched(self):
        meta = {'name': 'gourmet-redis', 'ports': {'6379/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '6379'}]}}
        self.assertFalse(redis.identify_site_redis_server('127.0.0.1', 6380, [('gourmet-redis', 'UP')], lambda _: meta)['identified'])

    def test_docker_env_never_read(self):
        calls = []
        def run(cmd, **kw):
            calls.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, '/redis\tredis:7\tbridge\t[]\t[]\t{}\t{}\n', '')
        with patch.object(redis.subprocess, 'run', side_effect=run):
            redis.inspect_container_structural_metadata('redis')
        self.assertNotIn('Config.Env', json.dumps(calls))

    def test_requirepass_presence_and_value_sanitized(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'redis.conf'
            path.write_text('port 6379\nrequirepass TOP_SECRET_987\nuser default on >ANOTHER_SECRET\n')
            with patch.object(redis, 'safe_path', lambda p: str(p)):
                out = redis.inspect_redis_config(str(path))
            self.assertEqual(out['requirepass'], 'PRESENT')
            self.assertNotIn('TOP_SECRET_987', str(out))
            self.assertNotIn('ANOTHER_SECRET', str(out))

    def test_auth_probe_sanitizes_whoami_and_requirepass(self):
        calls = []
        def run(cmd, **kw):
            calls.append((cmd, kw['env']['REDISCLI_AUTH']))
            if cmd[-1] == 'PING':
                return subprocess.CompletedProcess(cmd, 0, 'PONG\n', '')
            if cmd[-2:] == ['ACL', 'WHOAMI']:
                return subprocess.CompletedProcess(cmd, 0, 'user\nSECRET_BAD\n', '')
            return subprocess.CompletedProcess(cmd, 0, 'requirepass\nSERVER_SECRET\n', '')
        out = redis.redis_auth_probe('127.0.0.1', 6380, 'URL_SECRET', run_fn=run)
        self.assertEqual(out['ping'], 'PASS')
        self.assertEqual(out['requirepass_status'], 'CONFIGURED')
        self.assertEqual(out['current_user'], 'UNKNOWN')
        self.assertNotIn('SERVER_SECRET', str(out))
        self.assertTrue(all('URL_SECRET' not in str(cmd) for cmd, _ in calls))

    def test_url_pass_password_fail(self):
        out = redis.probe_credentials_connectivity('127.0.0.1', 6380, 'WRONG', 'RIGHT', ping_fn=lambda h, p, password, tls: 'PASS' if password == 'RIGHT' else 'FAIL')
        self.assertEqual((out['CONNECTIVITY_WITH_REDIS_URL_CREDENTIAL'], out['CONNECTIVITY_WITH_REDIS_PASSWORD']), ('PASS', 'FAIL'))

    def test_canonical_and_inconsistent(self):
        self.assertEqual(redis.classify_credential_relationship('DIRECT_REDIS_URL', 'DIRECT_REDIS_URL', conn_url='PASS', conn_pwd='FAIL'), 'URL_IS_CANONICAL')
        self.assertEqual(redis.classify_credential_relationship('MIXED', 'MIXED', conn_url='PASS', conn_pwd='FAIL'), 'INCONSISTENT_CONFIGURATION')

    def test_config_source_and_docker_env_block(self):
        meta = {'mounts': [{'Source': '/etc/redis/redis.conf', 'Destination': '/redis.conf'}], 'cmd': ['redis-server', '/redis.conf']}
        self.assertEqual(redis.resolve_config_paths(meta)['config'], '/etc/redis/redis.conf')
        self.assertEqual(redis.classify_credential_source_from_metadata(meta), 'REDIS_CONF')
        self.assertEqual(redis.classify_credential_source_from_metadata({'mounts': [], 'cmd': ['redis-server']}), 'DOCKER_ENV_UNREADABLE_BY_POLICY')

    def test_api_worker_restart_impact(self):
        self.assertEqual(redis.restart_impact('YES', {'url_present': True, 'password_present': False}), 'YES')
        self.assertEqual(redis.restart_impact('YES', {'url_present': False, 'password_present': True}), 'YES')
        self.assertEqual(redis.restart_impact('YES', None), 'UNKNOWN')

    def test_historical_dist_and_backups_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ('dist.previous1', 'dist.rollback2', 'dist.pre-3', 'dist.failed4', 'dist.old5', 'backups', 'releases', 'node_modules', '.git'):
                folder = root / name
                folder.mkdir()
                (folder / 'redis.js').write_text('new Redis(process.env.REDIS_PASSWORD)')
            active = root / 'server'
            active.mkdir()
            (active / 'redis.js').write_text('new Redis(process.env.REDIS_URL)')
            findings, usage, _, _ = redis.scan_codebase_redis_usage(root)
            self.assertEqual(len(findings), 1)
            self.assertEqual(usage, 'DIRECT_REDIS_URL')

    def test_future_sequence_only_when_complete(self):
        evidence = {'server_identified': True, 'auth_model': 'REQUIREPASS', 'credential_source_identified': True,
                    'credential_source': 'REDIS_CONF', 'site_api_uses_redis': 'YES', 'site_worker_uses_redis': 'YES',
                    'relationship': 'URL_IS_CANONICAL', 'connectivity': 'PASS', 'other_consumers_known': True,
                    'backup_targets': ['/env', '/redis.conf'], 'backup_targets_complete': True,
                    'restart_targets': ['api', 'worker'], 'restart_targets_known': True,
                    'future_sequence': redis.build_future_rotation_sequence('URL_IS_CANONICAL', 'REQUIREPASS', 'REDIS_CONF', 'YES', 'YES')}
        self.assertEqual(redis.assess_readiness(evidence)['ROTATION_READINESS'], 'BLOCKED')
        evidence['credential_source'] = 'DOCKER_ENV_UNREADABLE_BY_POLICY'
        self.assertEqual(redis.assess_readiness(evidence)['FUTURE_ROTATION_SEQUENCE'], 'UNKNOWN')


if __name__ == '__main__':
    unittest.main()
