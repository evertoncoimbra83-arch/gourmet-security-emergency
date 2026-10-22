from pathlib import Path
import hashlib
import os
import secrets
import tempfile
import unittest


def normalize_secret_bytes(data: bytes) -> bytes:
    return data.rstrip(b"\r\n")


def sha256_val(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


class MockGIRotationExecutor:
    """
    Mock engine faithfully simulating the exact state machine, atomic writes,
    container mounts, process environments, backups, and automatic rollback of
    rotations/gi/gi-rotate-execute.sh without touching any real daemon or credentials.
    """

    def __init__(self, base_dir: Path, token_name: str, required_in_site: bool):
        self.base_dir = base_dir
        self.token_name = token_name
        self.required_in_site = required_in_site

        # Setup initial fake files
        self.secret_file = self.base_dir / "secret.txt"
        self.initial_token_bytes = b"MOCK_ORIGINAL_TOKEN_VALUE_000"
        self.secret_file.write_bytes(self.initial_token_bytes + b"\n")
        self.old_hash = sha256_val(self.initial_token_bytes)

        self.site_env = self.base_dir / "site.env"
        self.site_env_content_original = (
            f"APP_ENV=staging\n{self.token_name}={self.initial_token_bytes.decode('utf-8')}\nPORT=3000\n"
        )
        self.site_env.write_text(self.site_env_content_original, encoding="utf-8")

        # Containers setup
        if self.token_name == "GI_SITE_PRE_PREPARE_TOKEN":
            self.containers = ["gi_staging_http_03c_f3b3b2_shadow"]
        else:
            self.containers = [
                "gi_staging_http",
                "gi_staging_http_03c_shadow",
                "gi_staging_http_03c_f3b3b2_shadow",
            ]

        self.container_mounts = {}
        for c in self.containers:
            m_path = self.base_dir / f"mount_{c}.txt"
            m_path.write_bytes(self.initial_token_bytes + b"\n")
            self.container_mounts[c] = m_path

        # Process IDs
        self.site_pid_before = 1001
        self.site_pid = self.site_pid_before
        self.site_proc_env = {self.token_name: self.initial_token_bytes.decode("utf-8")}

        self.worker_pid_before = 2002
        self.worker_pid = self.worker_pid_before

        # Tracking state
        self.backup_dir = self.base_dir / "backup"
        self.backup_secret_file = self.backup_dir / "secret_file.bak"
        self.backup_site_env = self.backup_dir / "site_env.bak"

        self.mutation_started = False
        self.rotation_succeeded = False
        self.rollback_called = False
        self.rollback_actions_performed = False
        self.site_api_restarted = False
        self.containers_restarted = []
        self.new_hash = None

    def execute(self, fail_at_step: int = None):
        """
        Executes rotation steps with optional fault injection at step 1..12:
        1: backup secret
        2: backup env
        3: token generation
        4: update secret file
        5: update site env
        6: restart container 1
        7: restart container 2
        8: restart container 3
        9: container health check
        10: site api restart
        11: site process parity check
        12: final health check
        """
        try:
            # Step 1: Backup secret
            self.backup_dir.mkdir(parents=True, exist_ok=True)
            self.backup_secret_file.write_bytes(self.secret_file.read_bytes())
            if fail_at_step == 1:
                raise RuntimeError("Fault injected at step 1: backup secret")

            # Step 2: Backup env
            if self.required_in_site:
                self.backup_site_env.write_bytes(self.site_env.read_bytes())
            if fail_at_step == 2:
                raise RuntimeError("Fault injected at step 2: backup env")

            # MUTATION STARTS HERE
            self.mutation_started = True

            # Step 3: Token generation
            new_token = secrets.token_urlsafe(48)
            self.new_hash = sha256_val(new_token.encode("utf-8"))
            if fail_at_step == 3:
                raise RuntimeError("Fault injected at step 3: token generation")

            # Step 4: Atomic update secret file
            tmp_sec = self.base_dir / "tmp_sec.tmp"
            tmp_sec.write_bytes(new_token.encode("utf-8") + b"\n")
            os.replace(tmp_sec, self.secret_file)
            if fail_at_step == 4:
                raise RuntimeError("Fault injected at step 4: update secret file")

            # Step 5: Atomic update site env if required
            if self.required_in_site:
                lines = self.site_env.read_text(encoding="utf-8").splitlines(keepends=True)
                new_lines = []
                for line in lines:
                    if line.startswith(f"{self.token_name}="):
                        new_lines.append(f"{self.token_name}={new_token}\n")
                    else:
                        new_lines.append(line)
                tmp_env = self.base_dir / "tmp_env.tmp"
                tmp_env.write_text("".join(new_lines), encoding="utf-8")
                os.replace(tmp_env, self.site_env)

            if fail_at_step == 5:
                raise RuntimeError("Fault injected at step 5: update site env")

            # Steps 6, 7, 8: Restart containers & update mounts
            for idx, c in enumerate(self.containers, start=6):
                self.containers_restarted.append(c)
                # mount updated on restart
                self.container_mounts[c].write_bytes(new_token.encode("utf-8") + b"\n")
                if fail_at_step == idx:
                    raise RuntimeError(f"Fault injected at step {idx}: restart container {c}")

            # Step 9: Container health check
            if fail_at_step == 9:
                raise RuntimeError("Fault injected at step 9: container health check")

            # Step 10: Site API restart
            if self.required_in_site:
                self.site_api_restarted = True
                self.site_pid = 1002  # New PID after PM2 restart
                self.site_proc_env[self.token_name] = new_token
            if fail_at_step == 10:
                raise RuntimeError("Fault injected at step 10: site api restart")

            # Step 11: Site process parity check
            if fail_at_step == 11:
                raise RuntimeError("Fault injected at step 11: site process parity check")

            # Step 12: Final health check
            if fail_at_step == 12:
                raise RuntimeError("Fault injected at step 12: final health check")

            self.rotation_succeeded = True
            return True

        except Exception as exc:
            self._trigger_rollback()
            return False

    def _trigger_rollback(self):
        self.rollback_called = True
        if not self.mutation_started:
            # No destructive action if mutation hadn't started
            self.rollback_actions_performed = False
            return

        self.rollback_actions_performed = True

        # 1. Restore secret file
        if self.backup_secret_file.exists():
            os.replace(self.backup_secret_file, self.secret_file)

        # 2. Restore site env
        if self.required_in_site and self.backup_site_env.exists():
            os.replace(self.backup_site_env, self.site_env)

        # 3. Restore containers
        for c in self.containers:
            self.container_mounts[c].write_bytes(self.initial_token_bytes + b"\n")

        # 4. Restore site API
        if self.required_in_site:
            self.site_pid = 1003  # PM2 restart back to original env
            self.site_proc_env[self.token_name] = self.initial_token_bytes.decode("utf-8")

        # Worker is never touched
        # worker_pid remains unchanged


class TestGIRotationFaultInjection(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_01_pre_mutation_failure_step_1(self):
        """Failure before mutation (step 1: backup secret) does NOT perform destructive rollback."""
        engine = MockGIRotationExecutor(self.tmp_path, "GI_ATTENTION_READ_TOKEN", required_in_site=True)
        success = engine.execute(fail_at_step=1)

        self.assertFalse(success)
        self.assertTrue(engine.rollback_called)
        self.assertFalse(engine.rollback_actions_performed)
        self.assertEqual(sha256_val(normalize_secret_bytes(engine.secret_file.read_bytes())), engine.old_hash)

    def test_02_pre_mutation_failure_step_2(self):
        """Failure before mutation (step 2: backup env) does NOT perform destructive rollback."""
        engine = MockGIRotationExecutor(self.tmp_path, "GI_ATTENTION_READ_TOKEN", required_in_site=True)
        success = engine.execute(fail_at_step=2)

        self.assertFalse(success)
        self.assertTrue(engine.rollback_called)
        self.assertFalse(engine.rollback_actions_performed)

    def test_03_post_mutation_failure_step_3_token_gen(self):
        """Failure at step 3 (token generation) triggers full rollback and restores old_hash."""
        engine = MockGIRotationExecutor(self.tmp_path, "GI_ATTENTION_READ_TOKEN", required_in_site=True)
        success = engine.execute(fail_at_step=3)

        self.assertFalse(success)
        self.assertTrue(engine.rollback_called)
        self.assertTrue(engine.rollback_actions_performed)
        self.assertEqual(sha256_val(normalize_secret_bytes(engine.secret_file.read_bytes())), engine.old_hash)
        self.assertEqual(engine.worker_pid, engine.worker_pid_before)

    def test_04_post_mutation_failure_step_4_update_secret(self):
        """Failure at step 4 (update secret file) triggers rollback and restores secret file."""
        engine = MockGIRotationExecutor(self.tmp_path, "GI_ATTENTION_READ_TOKEN", required_in_site=True)
        success = engine.execute(fail_at_step=4)

        self.assertFalse(success)
        self.assertTrue(engine.rollback_actions_performed)
        self.assertEqual(sha256_val(normalize_secret_bytes(engine.secret_file.read_bytes())), engine.old_hash)

    def test_05_post_mutation_failure_step_5_update_site_env(self):
        """Failure at step 5 (update site env) triggers rollback and restores both secret and site env."""
        engine = MockGIRotationExecutor(self.tmp_path, "GI_ATTENTION_READ_TOKEN", required_in_site=True)
        success = engine.execute(fail_at_step=5)

        self.assertFalse(success)
        self.assertTrue(engine.rollback_actions_performed)
        self.assertEqual(sha256_val(normalize_secret_bytes(engine.secret_file.read_bytes())), engine.old_hash)
        self.assertIn(engine.initial_token_bytes.decode("utf-8"), engine.site_env.read_text(encoding="utf-8"))

    def test_06_post_mutation_failure_step_6_container_1(self):
        """Failure at step 6 (first container restart) restores secret, env and container mounts."""
        engine = MockGIRotationExecutor(self.tmp_path, "GI_ATTENTION_READ_TOKEN", required_in_site=True)
        success = engine.execute(fail_at_step=6)

        self.assertFalse(success)
        self.assertTrue(engine.rollback_actions_performed)
        self.assertEqual(sha256_val(normalize_secret_bytes(engine.secret_file.read_bytes())), engine.old_hash)
        for c, m in engine.container_mounts.items():
            self.assertEqual(sha256_val(normalize_secret_bytes(m.read_bytes())), engine.old_hash)

    def test_07_post_mutation_failure_step_7_container_2(self):
        """Failure at step 7 (second container restart) restores all mounts to old_hash."""
        engine = MockGIRotationExecutor(self.tmp_path, "GI_ATTENTION_READ_TOKEN", required_in_site=True)
        success = engine.execute(fail_at_step=7)

        self.assertFalse(success)
        self.assertTrue(engine.rollback_actions_performed)
        self.assertEqual(sha256_val(normalize_secret_bytes(engine.secret_file.read_bytes())), engine.old_hash)
        for c, m in engine.container_mounts.items():
            self.assertEqual(sha256_val(normalize_secret_bytes(m.read_bytes())), engine.old_hash)

    def test_08_post_mutation_failure_step_8_container_3(self):
        """Failure at step 8 (third container restart) restores all mounts to old_hash."""
        engine = MockGIRotationExecutor(self.tmp_path, "GI_ATTENTION_READ_TOKEN", required_in_site=True)
        success = engine.execute(fail_at_step=8)

        self.assertFalse(success)
        self.assertTrue(engine.rollback_actions_performed)
        self.assertEqual(sha256_val(normalize_secret_bytes(engine.secret_file.read_bytes())), engine.old_hash)

    def test_09_post_mutation_failure_step_9_container_health(self):
        """Failure at step 9 (container health check) triggers rollback."""
        engine = MockGIRotationExecutor(self.tmp_path, "GI_ATTENTION_READ_TOKEN", required_in_site=True)
        success = engine.execute(fail_at_step=9)

        self.assertFalse(success)
        self.assertTrue(engine.rollback_actions_performed)
        self.assertEqual(sha256_val(normalize_secret_bytes(engine.secret_file.read_bytes())), engine.old_hash)

    def test_10_post_mutation_failure_step_10_site_api_restart(self):
        """Failure at step 10 (Site API restart) triggers rollback and revalidates site proc env."""
        engine = MockGIRotationExecutor(self.tmp_path, "GI_ATTENTION_READ_TOKEN", required_in_site=True)
        success = engine.execute(fail_at_step=10)

        self.assertFalse(success)
        self.assertTrue(engine.rollback_actions_performed)
        self.assertEqual(engine.site_proc_env["GI_ATTENTION_READ_TOKEN"], engine.initial_token_bytes.decode("utf-8"))
        self.assertEqual(engine.worker_pid, engine.worker_pid_before)

    def test_11_post_mutation_failure_step_11_site_process_parity(self):
        """Failure at step 11 (Site process parity check) triggers rollback."""
        engine = MockGIRotationExecutor(self.tmp_path, "GI_ATTENTION_READ_TOKEN", required_in_site=True)
        success = engine.execute(fail_at_step=11)

        self.assertFalse(success)
        self.assertTrue(engine.rollback_actions_performed)
        self.assertEqual(sha256_val(normalize_secret_bytes(engine.secret_file.read_bytes())), engine.old_hash)

    def test_12_post_mutation_failure_step_12_final_health(self):
        """Failure at step 12 (final health check) triggers rollback."""
        engine = MockGIRotationExecutor(self.tmp_path, "GI_ATTENTION_READ_TOKEN", required_in_site=True)
        success = engine.execute(fail_at_step=12)

        self.assertFalse(success)
        self.assertTrue(engine.rollback_actions_performed)
        self.assertEqual(sha256_val(normalize_secret_bytes(engine.secret_file.read_bytes())), engine.old_hash)
        self.assertEqual(engine.worker_pid, engine.worker_pid_before)

    def test_13_site_pre_prepare_fault_injection(self):
        """Section I: GI_SITE_PRE_PREPARE_TOKEN never modifies Site env and never restarts Site API."""
        engine = MockGIRotationExecutor(self.tmp_path, "GI_SITE_PRE_PREPARE_TOKEN", required_in_site=False)

        # Successful execution
        success = engine.execute(fail_at_step=None)
        self.assertTrue(success)
        self.assertFalse(engine.site_api_restarted)
        self.assertEqual(engine.worker_pid, engine.worker_pid_before)
        self.assertEqual(len(engine.containers), 1)
        self.assertEqual(engine.containers[0], "gi_staging_http_03c_f3b3b2_shadow")
        self.assertEqual(engine.site_env.read_text(encoding="utf-8"), engine.site_env_content_original)

        # Injected failure
        engine_fail = MockGIRotationExecutor(self.tmp_path, "GI_SITE_PRE_PREPARE_TOKEN", required_in_site=False)
        fail_res = engine_fail.execute(fail_at_step=6)
        self.assertFalse(fail_res)
        self.assertTrue(engine_fail.rollback_actions_performed)
        self.assertFalse(engine_fail.site_api_restarted)
        self.assertEqual(engine_fail.worker_pid, engine_fail.worker_pid_before)
        self.assertEqual(sha256_val(normalize_secret_bytes(engine_fail.secret_file.read_bytes())), engine_fail.old_hash)

    def test_14_production_block_before_mutation(self):
        """Section J: PRODUCTION_BLOCK_BEFORE_MUTATION verification."""
        shell_content = (Path(__file__).resolve().parent.parent / "rotations" / "gi" / "gi-rotate-execute.sh").read_text(encoding="utf-8")
        runner_content = (Path(__file__).resolve().parent.parent / "deploy" / "run-gi-rotation-execute.py").read_text(encoding="utf-8")

        # In runner: production check must happen before any SSH
        prod_check_idx = runner_content.find('PRODUCTION_EXECUTION=BLOCKED')
        ssh_call_idx = runner_content.find('"ssh",')
        self.assertNotEqual(prod_check_idx, -1)
        self.assertNotEqual(ssh_call_idx, -1)
        self.assertLess(prod_check_idx, ssh_call_idx)

        # In shell: production check must happen before mkdir, backup, or mutation
        shell_prod_idx = shell_content.find('PRODUCTION_EXECUTION=BLOCKED')
        shell_mkdir_idx = shell_content.find('mkdir -p')
        shell_mut_idx = shell_content.find('MUTATION_STARTED=1')
        self.assertNotEqual(shell_prod_idx, -1)
        self.assertNotEqual(shell_mkdir_idx, -1)
        self.assertNotEqual(shell_mut_idx, -1)
        self.assertLess(shell_prod_idx, shell_mkdir_idx)
        self.assertLess(shell_prod_idx, shell_mut_idx)


if __name__ == "__main__":
    unittest.main()
