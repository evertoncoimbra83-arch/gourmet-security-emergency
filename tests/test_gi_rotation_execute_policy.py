from pathlib import Path
import re
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent
SHELL_SCRIPT = ROOT / "rotations" / "gi" / "gi-rotate-execute.sh"
RUNNER_SCRIPT = ROOT / "deploy" / "run-gi-rotation-execute.py"


def run_runner_cli(args_list):
    cmd = [sys.executable, str(RUNNER_SCRIPT)] + args_list
    result = subprocess.run(
        cmd,
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    return result


class TestGIRotationExecutePolicy(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.shell_content = SHELL_SCRIPT.read_text(encoding="utf-8")
        cls.runner_content = RUNNER_SCRIPT.read_text(encoding="utf-8")

    def test_01_production_blocked_in_runner(self):
        """1. production bloqueado no runner"""
        res = run_runner_cli(["--environment", "production", "--token", "GI_ATTENTION_READ_TOKEN", "--execute"])
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("PRODUCTION_EXECUTION=BLOCKED", res.stdout)
        self.assertIn("GI_ROTATION_REMOTE_EXECUTE=FAIL", res.stdout)

    def test_02_production_blocked_in_shell(self):
        """2. production bloqueado no shell"""
        self.assertIn('if [ "$ENVIRONMENT" = "production" ]; then', self.shell_content)
        self.assertIn('echo "PRODUCTION_EXECUTION=BLOCKED"', self.shell_content)

    def test_03_invalid_token_blocked(self):
        """3. token inválido bloqueado"""
        res = run_runner_cli(["--environment", "staging", "--token", "INVALID_TOKEN", "--execute"])
        self.assertNotEqual(res.returncode, 0)

        # In shell script
        self.assertIn('TOKEN_INVALID=FAIL', self.shell_content)

    def test_04_missing_execute_flag_blocked(self):
        """4. ausência --execute bloqueada"""
        res = run_runner_cli(["--environment", "staging", "--token", "GI_ATTENTION_READ_TOKEN"])
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("EXECUTE_FLAG_REQUIRED", res.stdout)

        # In shell script
        self.assertIn('if [ "$EXECUTE_FLAG" != "--execute" ]; then', self.shell_content)
        self.assertIn('echo "EXECUTE_FLAG_REQUIRED=FAIL"', self.shell_content)

    def test_05_invalid_incident_id_blocked(self):
        """5. incident ID inválido bloqueado"""
        self.assertIn(r'if ! [[ "$INCIDENT_ID" =~ ^GSE-[0-9]{8}T[0-9]{6}Z$ ]]; then', self.shell_content)
        self.assertIn('echo "incident_id_validation=FAIL"', self.shell_content)

    def test_06_worker_restart_nonexistent(self):
        """6. worker restart inexistente"""
        self.assertNotIn("pm2 restart gourmet-worker", self.shell_content)
        self.assertNotIn("pm2 restart gourmet-worker-staging", self.shell_content)
        self.assertNotIn("pm2 reload gourmet-worker", self.shell_content)

    def test_07_pm2_save_nonexistent(self):
        """7. pm2 save inexistente"""
        self.assertNotIn("pm2 save", self.shell_content)
        self.assertNotIn("pm2 save", self.runner_content)
        self.assertIn('echo "PM2_SAVE_RUN=NO"', self.shell_content)

    def test_08_db_commands_nonexistent(self):
        """8. DB commands inexistentes"""
        for bad_cmd in ["mysql", "mariadb", "DROP TABLE", "DELETE FROM", "ALTER TABLE", "UPDATE users"]:
            self.assertNotIn(bad_cmd, self.shell_content)
        self.assertIn('echo "DATABASE_TOUCHED=NO"', self.shell_content)

    def test_09_site_pre_prepare_no_site_env_update(self):
        """9. Site-pre-prepare não atualiza Site env"""
        self.assertIn('"GI_SITE_PRE_PREPARE_TOKEN")', self.shell_content)
        self.assertIn('REQUIRED_IN_SITE_ENV="no"', self.shell_content)
        self.assertIn('if [ "$REQUIRED_IN_SITE_ENV" = "yes" ]; then', self.shell_content)

    def test_10_site_pre_prepare_no_site_api_restart(self):
        """10. Site-pre-prepare não reinicia Site API"""
        pattern = r'if \[ "\$REQUIRED_IN_SITE_ENV" = "yes" \]; then[\s\S]*?restarting_site_api=[\s\S]*?else[\s\S]*?site_process_restart=NOT_REQUIRED'
        self.assertTrue(re.search(pattern, self.shell_content))

    def test_11_read_token_updates_site_env(self):
        """11. read token atualiza Site env"""
        self.assertIn('"GI_ATTENTION_READ_TOKEN")', self.shell_content)
        self.assertIn('REQUIRED_IN_SITE_ENV="yes"', self.shell_content)

    def test_12_read_token_restarts_site_api(self):
        """12. read token reinicia Site API"""
        self.assertIn('SITE_PROCESS="gourmet-novo-staging"', self.shell_content)
        self.assertIn('pm2", ["restart", procName, "--update-env"]', self.shell_content)

    def test_13_backup_mandatory(self):
        """13. backup obrigatório"""
        self.assertIn('BACKUP_DIR="/home/gsadmin/backups/gse/${INCIDENT_ID}/gi/${TARGET_TOKEN}"', self.shell_content)
        self.assertIn('backup_directory=${BACKUP_DIR}', self.shell_content)
        self.assertIn('backup_secret_file=PASS', self.shell_content)

    def test_14_rollback_mandatory(self):
        """14. rollback obrigatório"""
        self.assertIn('trap rollback_mutation ERR EXIT', self.shell_content)
        self.assertIn('ROLLBACK_STARTED=YES', self.shell_content)
        self.assertIn('ROLLBACK_FINISHED=PASS', self.shell_content)

    def test_15_old_new_hash_never_values(self):
        """15. old_hash/new_hash nunca valores"""
        self.assertIn('echo "OLD_HASH=${old_hash}"', self.shell_content)
        self.assertIn('echo "NEW_HASH=${new_hash}"', self.shell_content)
        self.assertNotIn('echo "TOKEN=', self.shell_content)
        self.assertNotIn('echo "NEW_TOKEN=', self.shell_content)

    def test_16_token_generation_csprng(self):
        """16. token generation usa secrets CSPRNG"""
        self.assertIn('import hashlib, os, secrets, sys, tempfile', self.shell_content)
        self.assertIn('new_token = secrets.token_urlsafe(48)', self.shell_content)

    def test_17_secret_file_atomic_write(self):
        """17. secret file escrita atômica"""
        self.assertIn('tempfile.mkstemp(dir=sec_dir, prefix=".tmp_sec_")', self.shell_content)
        self.assertIn('os.fsync(f.fileno())', self.shell_content)
        self.assertIn('os.chmod(tmp_sec, 0o600)', self.shell_content)
        self.assertIn('os.replace(tmp_sec, secret_file)', self.shell_content)

    def test_18_site_env_atomic_write(self):
        """18. Site env escrita atômica"""
        self.assertIn('tempfile.mkstemp(dir=env_dir, prefix=".tmp_env_")', self.shell_content)
        self.assertIn('os.fsync(wf.fileno())', self.shell_content)
        self.assertIn('os.chmod(tmp_env, 0o600)', self.shell_content)
        self.assertIn('os.replace(tmp_env, site_env)', self.shell_content)

    def test_19_container_list_read_tokens(self):
        """19. container lista correta read tokens"""
        self.assertIn('"gi_staging_http"', self.shell_content)
        self.assertIn('"gi_staging_http_03c_shadow"', self.shell_content)
        self.assertIn('"gi_staging_http_03c_f3b3b2_shadow"', self.shell_content)

    def test_20_container_list_site_pre_prepare(self):
        """20. container lista correta site-pre-prepare"""
        pattern = r'"GI_SITE_PRE_PREPARE_TOKEN"\)[\s\S]*?CONTAINERS=\([\s\S]*?"gi_staging_http_03c_f3b3b2_shadow"[\s\S]*?\)'
        self.assertTrue(re.search(pattern, self.shell_content))

    def test_21_worker_pid_preserved(self):
        """21. worker PID deve ser preservado"""
        self.assertIn('if [ "$worker_pid_now" != "$worker_pid_before" ]; then', self.shell_content)
        self.assertIn('echo "worker_untouched=PASS"', self.shell_content)

    def test_22_production_not_in_allowed_environments(self):
        """22. produção não aparece em lista de environments executáveis"""
        self.assertIn('ALLOWED_ENVIRONMENTS = {\n    "staging",\n}', self.runner_content)
        self.assertNotIn('"production"', self.runner_content.split("ALLOWED_ENVIRONMENTS = {")[1].split("}")[0])

    def test_23_shell_no_pm2_save(self):
        """23. shell não contém pm2 save"""
        self.assertNotIn("pm2 save", self.shell_content)

    def test_24_shell_no_mysql_mariadb(self):
        """24. shell não contém mysql/mariadb"""
        self.assertNotIn("mysql", self.shell_content)
        self.assertNotIn("mariadb", self.shell_content)

    def test_25_shell_no_insecure_dumps(self):
        """25. shell não contém printenv/pm2 env/pm2 jlist"""
        self.assertNotIn("printenv", self.shell_content)
        self.assertNotIn("pm2 env", self.shell_content)
        self.assertNotIn("pm2 jlist", self.shell_content)

    def test_26_shell_never_prints_token(self):
        """26. shell não imprime NEW_TOKEN"""
        self.assertNotIn('echo "$new_token"', self.shell_content)
        self.assertNotIn('print(new_token)', self.shell_content)

    def test_27_rollback_restores_files(self):
        """27. rollback restaura arquivos"""
        self.assertIn('cp -p "$BACKUP_SECRET_FILE" "$SECRET_FILE"', self.shell_content)
        self.assertIn('cp -p "$BACKUP_SITE_ENV" "$SITE_ENV"', self.shell_content)

    def test_28_rollback_revalidates(self):
        """28. rollback revalida e reporta"""
        self.assertIn('echo "ROLLBACK_SECRET=PASS"', self.shell_content)
        self.assertIn('echo "ROLLBACK_CONTAINERS=PASS"', self.shell_content)
        self.assertIn('echo "ROLLBACK_WORKER_UNTOUCHED=PASS"', self.shell_content)
        self.assertIn('echo "ROLLBACK_FINISHED=PASS"', self.shell_content)

    def test_29_health_uses_internal_docker(self):
        """29. health usa Docker interno, não host port GI"""
        self.assertIn("docker exec \"$primary_container\" node -e \"fetch('http://127.0.0.1:3002/api/health')", self.shell_content)
        self.assertNotIn("curl http://127.0.0.1:3002", self.shell_content)

    def test_30_site_http_health_not_configured(self):
        """30. SITE_HTTP_HEALTH=NOT_CONFIGURED em staging"""
        self.assertIn('echo "SITE_HTTP_HEALTH=NOT_CONFIGURED"', self.shell_content)


if __name__ == "__main__":
    unittest.main()
