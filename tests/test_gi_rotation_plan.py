from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = ROOT / "rotations" / "gi" / "gi-rotate-plan.py"


def run_plan_cli(args_list):
    cmd = [sys.executable, str(SCRIPT_PATH)] + args_list
    result = subprocess.run(
        cmd,
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    return result


class TestGIRotationPlan(unittest.TestCase):

    def test_01_staging_attention_read_token(self):
        """1. staging + GI_ATTENTION_READ_TOKEN => PASS"""
        res = run_plan_cli(["--environment", "staging", "--token", "GI_ATTENTION_READ_TOKEN", "--dry-run"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("GI_ROTATION_PLAN=PASS", res.stdout)
        self.assertIn("token=GI_ATTENTION_READ_TOKEN", res.stdout)
        self.assertIn("environment=staging", res.stdout)

    def test_02_staging_recommendation_read_token(self):
        """2. staging + GI_RECOMMENDATION_READ_TOKEN => PASS"""
        res = run_plan_cli(["--environment", "staging", "--token", "GI_RECOMMENDATION_READ_TOKEN", "--dry-run"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("GI_ROTATION_PLAN=PASS", res.stdout)
        self.assertIn("token=GI_RECOMMENDATION_READ_TOKEN", res.stdout)

    def test_03_staging_proposal_read_token(self):
        """3. staging + GI_PROPOSAL_READ_TOKEN => PASS"""
        res = run_plan_cli(["--environment", "staging", "--token", "GI_PROPOSAL_READ_TOKEN", "--dry-run"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("GI_ROTATION_PLAN=PASS", res.stdout)
        self.assertIn("token=GI_PROPOSAL_READ_TOKEN", res.stdout)

    def test_04_staging_site_pre_prepare_token(self):
        """4. staging + GI_SITE_PRE_PREPARE_TOKEN => PASS"""
        res = run_plan_cli(["--environment", "staging", "--token", "GI_SITE_PRE_PREPARE_TOKEN", "--dry-run"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("GI_ROTATION_PLAN=PASS", res.stdout)
        self.assertIn("token=GI_SITE_PRE_PREPARE_TOKEN", res.stdout)
        self.assertIn("containers_count=1", res.stdout)
        self.assertIn("container=gi_staging_http_03c_f3b3b2_shadow", res.stdout)

    def test_05_production_attention_read_token(self):
        """5. production + GI_ATTENTION_READ_TOKEN => PASS"""
        res = run_plan_cli(["--environment", "production", "--token", "GI_ATTENTION_READ_TOKEN", "--dry-run"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("GI_ROTATION_PLAN=PASS", res.stdout)
        self.assertIn("environment=production", res.stdout)
        self.assertIn("containers_count=1", res.stdout)
        self.assertIn("container=gi_production_http", res.stdout)

    def test_06_production_recommendation_read_token(self):
        """6. production + GI_RECOMMENDATION_READ_TOKEN => PASS"""
        res = run_plan_cli(["--environment", "production", "--token", "GI_RECOMMENDATION_READ_TOKEN", "--dry-run"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("GI_ROTATION_PLAN=PASS", res.stdout)
        self.assertIn("token=GI_RECOMMENDATION_READ_TOKEN", res.stdout)

    def test_07_production_proposal_read_token(self):
        """7. production + GI_PROPOSAL_READ_TOKEN => PASS"""
        res = run_plan_cli(["--environment", "production", "--token", "GI_PROPOSAL_READ_TOKEN", "--dry-run"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("GI_ROTATION_PLAN=PASS", res.stdout)
        self.assertIn("token=GI_PROPOSAL_READ_TOKEN", res.stdout)

    def test_08_production_site_pre_prepare_token(self):
        """8. production + GI_SITE_PRE_PREPARE_TOKEN => FAIL"""
        res = run_plan_cli(["--environment", "production", "--token", "GI_SITE_PRE_PREPARE_TOKEN", "--dry-run"])
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("TOKEN_NOT_AVAILABLE_IN_ENVIRONMENT", res.stdout)

    def test_09_invalid_environment(self):
        """9. environment inválido => FAIL"""
        res = run_plan_cli(["--environment", "invalid_env", "--token", "GI_ATTENTION_READ_TOKEN", "--dry-run"])
        self.assertNotEqual(res.returncode, 0)

    def test_10_invalid_token(self):
        """10. token inválido => FAIL"""
        res = run_plan_cli(["--environment", "staging", "--token", "INVALID_TOKEN", "--dry-run"])
        self.assertNotEqual(res.returncode, 0)

    def test_11_missing_dry_run(self):
        """11. ausência de --dry-run => FAIL"""
        res = run_plan_cli(["--environment", "staging", "--token", "GI_ATTENTION_READ_TOKEN"])
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("DRY_RUN_REQUIRED", res.stdout)

    def test_12_staging_site_pre_prepare_no_update_site_env(self):
        """12. staging site-pre-prepare: WOULD_UPDATE_SITE_ENV=NO"""
        res = run_plan_cli(["--environment", "staging", "--token", "GI_SITE_PRE_PREPARE_TOKEN", "--dry-run"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("WOULD_UPDATE_SITE_ENV=NO", res.stdout)

    def test_13_staging_site_pre_prepare_no_restart_site_api(self):
        """13. staging site-pre-prepare: WOULD_RESTART_SITE_API=NO"""
        res = run_plan_cli(["--environment", "staging", "--token", "GI_SITE_PRE_PREPARE_TOKEN", "--dry-run"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("WOULD_RESTART_SITE_API=NO", res.stdout)

    def test_14_read_token_staging_update_site_env_yes(self):
        """14. read token staging: WOULD_UPDATE_SITE_ENV=YES"""
        res = run_plan_cli(["--environment", "staging", "--token", "GI_ATTENTION_READ_TOKEN", "--dry-run"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("WOULD_UPDATE_SITE_ENV=YES", res.stdout)

    def test_15_read_token_production_restart_site_api_yes(self):
        """15. read token production: WOULD_RESTART_SITE_API=YES"""
        res = run_plan_cli(["--environment", "production", "--token", "GI_ATTENTION_READ_TOKEN", "--dry-run"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("WOULD_RESTART_SITE_API=YES", res.stdout)

    def test_16_actual_secret_generated_no(self):
        """16. qualquer plano: ACTUAL_SECRET_GENERATED=NO"""
        res = run_plan_cli(["--environment", "staging", "--token", "GI_ATTENTION_READ_TOKEN", "--dry-run"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("ACTUAL_SECRET_GENERATED=NO", res.stdout)

    def test_17_actual_files_changed_no(self):
        """17. qualquer plano: ACTUAL_FILES_CHANGED=NO"""
        res = run_plan_cli(["--environment", "staging", "--token", "GI_ATTENTION_READ_TOKEN", "--dry-run"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("ACTUAL_FILES_CHANGED=NO", res.stdout)

    def test_18_actual_services_restarted_no(self):
        """18. qualquer plano: ACTUAL_SERVICES_RESTARTED=NO"""
        res = run_plan_cli(["--environment", "staging", "--token", "GI_ATTENTION_READ_TOKEN", "--dry-run"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("ACTUAL_SERVICES_RESTARTED=NO", res.stdout)

    def test_19_actual_database_touched_no(self):
        """19. qualquer plano: ACTUAL_DATABASE_TOUCHED=NO"""
        res = run_plan_cli(["--environment", "staging", "--token", "GI_ATTENTION_READ_TOKEN", "--dry-run"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("ACTUAL_DATABASE_TOUCHED=NO", res.stdout)

    def test_20_worker_restart_no(self):
        """20. worker: WOULD_RESTART_WORKER=NO"""
        res = run_plan_cli(["--environment", "staging", "--token", "GI_ATTENTION_READ_TOKEN", "--dry-run"])
        self.assertEqual(res.returncode, 0)
        self.assertIn("WOULD_RESTART_WORKER=NO", res.stdout)


if __name__ == "__main__":
    unittest.main()
