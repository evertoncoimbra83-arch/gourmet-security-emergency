from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parent.parent
SHELL_SCRIPT = ROOT / "rotations" / "gi" / "gi-rotate-execute.sh"
RUNNER_SCRIPT = ROOT / "deploy" / "run-gi-rotation-execute.py"


class TestGISiteRestartDependency(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.shell_content = SHELL_SCRIPT.read_text(encoding="utf-8")
        cls.runner_content = RUNNER_SCRIPT.read_text(encoding="utf-8")

    def test_01_restart_helper_enforces_cwd(self):
        """1. restart helper força cwd /var/www/gourmet-staging"""
        self.assertIn('SITE_DIR="/var/www/gourmet-staging"', self.shell_content)
        self.assertIn('env -C "$target_site_dir" node -e', self.shell_content)
        self.assertIn('restart_site_api "$SITE_DIR" "$SITE_ENV" "$SITE_PROCESS"', self.shell_content)

    def test_02_dotenv_dependency_precheck_before_mutation(self):
        """2. dotenv dependency precheck ocorre antes de MUTATION_STARTED"""
        dotenv_check_idx = self.shell_content.find("site_restart_dotenv_dependency=PASS")
        mutation_started_idx = self.shell_content.find("MUTATION_STARTED=1")
        backup_creation_idx = self.shell_content.find("=== BACKUP CREATION ===")

        self.assertNotEqual(dotenv_check_idx, -1)
        self.assertNotEqual(mutation_started_idx, -1)
        self.assertNotEqual(backup_creation_idx, -1)

        # Precheck must happen before backup creation and before mutation start
        self.assertLess(dotenv_check_idx, backup_creation_idx)
        self.assertLess(dotenv_check_idx, mutation_started_idx)

    def test_03_dependency_failure_does_not_mutate(self):
        """3. dependency failure não causa mutation"""
        pattern = (
            r"if env -C \"\$SITE_DIR\" node -e \"require\.resolve\('dotenv'\)\"[^;]*; then[\s\S]*?"
            r"else[\s\S]*?"
            r"echo \"SITE_RESTART_DEPENDENCY=FAIL\"[\s\S]*?"
            r"exit 1"
        )
        self.assertTrue(re.search(pattern, self.shell_content))

    def test_04_production_remains_blocked(self):
        """4. production continua bloqueado"""
        self.assertIn('echo "PRODUCTION_EXECUTION=BLOCKED"', self.shell_content)
        self.assertIn('ALLOWED_ENVIRONMENTS = {\n    "staging",\n}', self.runner_content)

    def test_05_worker_never_restarted(self):
        """5. worker continua nunca reiniciado"""
        self.assertNotIn("pm2 restart gourmet-worker", self.shell_content)
        self.assertNotIn("pm2 restart gourmet-worker-staging", self.shell_content)
        self.assertIn('echo "worker_untouched=PASS"', self.shell_content)

    def test_06_pm2_save_nonexistent(self):
        """6. pm2 save continua inexistente"""
        self.assertNotIn("pm2 save", self.shell_content)
        self.assertIn('echo "PM2_SAVE_RUN=NO"', self.shell_content)

    def test_07_restart_uses_gourmet_novo_staging(self):
        """7. restart usa gourmet-novo-staging"""
        self.assertIn('SITE_PROCESS="gourmet-novo-staging"', self.shell_content)
        self.assertIn('pm2", ["restart", procName, "--update-env"]', self.shell_content)

    def test_08_restart_uses_site_env_staging(self):
        """8. restart usa .env.staging"""
        self.assertIn('SITE_ENV="/home/gsadmin/secure-env/.env.staging"', self.shell_content)
        self.assertIn('dotenv.parse(fs.readFileSync(envFile))', self.shell_content)

    def test_09_rollback_reuses_same_restart_helper(self):
        """9. rollback reutiliza o mesmo restart helper"""
        # Count occurrences of restart_site_api function call
        matches = re.findall(r'restart_site_api\s+"\$SITE_DIR"\s+"\$SITE_ENV"\s+"\$SITE_PROCESS"', self.shell_content)
        self.assertEqual(len(matches), 2, "Expected restart_site_api to be called in normal flow and in rollback")

    def test_10_subprocess_node_does_not_print_env(self):
        """10. subprocess Node não imprime env"""
        self.assertNotIn("console.log(env", self.shell_content)
        self.assertNotIn("console.log(process.env", self.shell_content)
        self.assertNotIn("console.log(envConfig", self.shell_content)

    def test_11_token_never_in_argv(self):
        """11. token não aparece em argv"""
        self.assertNotIn('sys.argv', self.shell_content.replace('sys.argv[1]', '').replace('sys.argv[2]', '').replace('sys.argv[3]', '').replace('sys.argv[4]', ''))
        # Only paths and keys passed to python, never token values
        self.assertIn('"$SECRET_FILE" "$SITE_ENV" "$REQUIRED_IN_SITE_ENV" "$TARGET_TOKEN"', self.shell_content)

    def test_12_secret_output_paths_remain_zero(self):
        """12. secret output paths continuam 0"""
        for pattern in ['echo "$new_token"', 'echo $new_token', 'print(new_token)']:
            self.assertNotIn(pattern, self.shell_content)


if __name__ == "__main__":
    unittest.main()
