"""Deployment safety and backup regression tests (no Docker daemon required)."""
import json
import os
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

MODULE_PATH = Path(__file__).resolve().parents[1] / 'scripts' / 'deploy.py'

class DeploymentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('deployment', MODULE_PATH)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def test_validation_entrypoint_exists(self):
        self.assertTrue(callable(getattr(self.module, 'validate_env', None)))

    def env(self):
        return {
            'ACCOUNT_REGION': 'cn', 'SUPABASE_PUBLIC_URL': 'https://account.example.cn',
            'API_EXTERNAL_URL': 'https://account.example.cn/auth/v1',
            'SITE_URL': 'https://account.example.cn',
            'POSTGRES_PASSWORD': 'a'*40, 'JWT_SECRET': 'b'*48,
            'ANON_KEY': 'anon-test-key', 'SERVICE_ROLE_KEY': 'service-test-key',
            'DASHBOARD_PASSWORD': 'c'*40, 'SMTP_HOST': 'smtp.feishu.cn',
            'SMTP_USER': 'hello@example.cn', 'SMTP_PASS': 'smtp-test-private-value',
            'SMTP_ADMIN_EMAIL': 'hello@example.cn', 'SMTP_PORT': '587',
            'ENABLE_EMAIL_AUTOCONFIRM': 'false', 'ENABLE_PHONE_SIGNUP': 'false',
            'SUPABASE_PUBLISHABLE_KEY': 'sb_publishable_test',
            'SUPABASE_SECRET_KEY': 'sb_secret_test',
            'JWT_KEYS': '[{"kty":"EC","d":"test-private","alg":"ES256"}]',
            'JWT_JWKS': '{"keys":[{"kty":"EC","alg":"ES256"}]}',
        }

    def config(self):
        return {'services': {
            'api-gw': {'image': 'envoyproxy/envoy:v1.39.6', 'ports': [{'host_ip': '127.0.0.1', 'published': '18200', 'target': 8000}]},
            'db': {'image': 'supabase/postgres:17.6.1.136'},
            'supavisor': {'image': 'supabase/supavisor:2.9.13'},
            'auth': {'image': 'supabase/gotrue:v2.197.0', 'environment': {
                'GOTRUE_MAILER_AUTOCONFIRM': 'false', 'GOTRUE_EXTERNAL_PHONE_ENABLED': 'false',
                'GOTRUE_MAILER_OTP_EXP': '900', 'GOTRUE_SMTP_MAX_FREQUENCY': '60s',
                'GOTRUE_PASSWORD_MIN_LENGTH': '8',
                'GOTRUE_JWT_KEYS': self.env()['JWT_KEYS'],
                'GOTRUE_MAILER_TEMPLATES_CONFIRMATION': 'http://account-email-templates:8000/confirmation.html',
                'GOTRUE_MAILER_TEMPLATES_RECOVERY': 'http://account-email-templates:8000/recovery.html',
            }},
            'account-email-templates': {'image': 'python@sha256:abcdef', 'read_only': True},
            'realtime': {'image': 'supabase/realtime:v2.148.3', 'environment': {'API_JWT_JWKS': self.env()['JWT_JWKS']}},
            'storage': {'image': 'supabase/storage-api:v1.89.12', 'environment': {'JWT_JWKS': self.env()['JWT_JWKS']}},
            'functions': {'image': 'supabase/edge-runtime:v1.77.9', 'environment': {'SUPABASE_JWKS': self.env()['JWT_JWKS']}},
        }}

    def test_valid_private_deployment_is_accepted(self):
        self.module.validate_env(self.env(), 'cn')
        self.module.validate_compose(self.config())

    def test_rejects_wrong_region_and_non_https_urls(self):
        for changes in ({'ACCOUNT_REGION': 'global'}, {'SUPABASE_PUBLIC_URL': 'http://example.cn'}, {'API_EXTERNAL_URL': 'https://different.example/auth/v1'}):
            env = self.env(); env.update(changes)
            with self.assertRaises(ValueError): self.module.validate_env(env, 'cn')

    def test_rejects_defaults_without_leaking_secret(self):
        for key, value in [('POSTGRES_PASSWORD', 'your-super-secret-password'), ('JWT_SECRET', 'short'), ('SMTP_PASS', '')]:
            env = self.env(); env[key] = value
            with self.assertRaises(ValueError) as e: self.module.validate_env(env, 'cn')
            self.assertNotIn('smtp-test-private-value', str(e.exception))

    def test_rejects_auto_confirmation_and_phone_signups(self):
        for key in ('ENABLE_EMAIL_AUTOCONFIRM', 'ENABLE_PHONE_SIGNUP'):
            env = self.env(); env[key] = 'true'
            with self.assertRaises(ValueError): self.module.validate_env(env, 'cn')

    def test_rejects_public_ports_even_after_compose_merge(self):
        for service, host in [('api-gw', '0.0.0.0'), ('db', '127.0.0.1'), ('supavisor', '::')]:
            config = self.config(); config['services'][service]['ports'] = [{'published': '5432', 'target': 5432, 'host_ip': host}]
            with self.assertRaises(ValueError): self.module.validate_compose(config)

    def test_rejects_unpinned_images_and_template_publication(self):
        for change in ('image', 'template'):
            config = self.config()
            if change == 'image': config['services']['db']['image'] = 'supabase/postgres:latest'
            else: config['services']['account-email-templates']['ports'] = [{'host_ip':'127.0.0.1','target':8000,'published':'18500'}]
            with self.assertRaises(ValueError): self.module.validate_compose(config)

    def test_rejects_missing_email_policy(self):
        config = self.config(); del config['services']['auth']['environment']['GOTRUE_MAILER_OTP_EXP']
        with self.assertRaises(ValueError): self.module.validate_compose(config)

    def test_dotenv_preserves_quoted_hash_and_rejects_duplicates(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / '.env'; p.write_text("SMTP_PASS='private#value'\nREGION=cn\n", encoding='utf-8')
            self.assertEqual(self.module.read_env(p)['SMTP_PASS'], 'private#value')
            p.write_text('KEY=a\nKEY=b\n', encoding='utf-8')
            with self.assertRaises(ValueError): self.module.read_env(p)

    def test_compose_command_uses_explicit_files_and_no_shell(self):
        command = self.module.compose_command(Path('/repo'), Path('/private/cn.env'), 'cn')
        self.assertEqual(command[:2], ['docker', 'compose'])
        self.assertIn('watcherobot-cn', command)
        self.assertEqual(command.count('-f'), 2)
        self.assertIn(str(Path('/private/cn.env')), command)

    def test_private_env_overrides_inherited_shell_for_every_compose_call(self):
        with tempfile.TemporaryDirectory() as temp:
            env_path = Path(temp) / '.env'
            env_path.write_text('\n'.join(k+'='+v for k,v in self.env().items()), encoding='utf-8')
            env_path.chmod(0o600)
            results = [type('Result', (), {'returncode':0, 'stdout':json.dumps(self.config())})(), type('Result', (), {'returncode':0})()]
            with patch.dict(os.environ, {'SMTP_PASS':'wrong-shell-secret'}), patch.object(self.module.subprocess, 'run', side_effect=results) as run:
                code = self.module.main(['status','--env-file',str(env_path)])
            self.assertEqual(code, 0)
            for call in run.call_args_list:
                self.assertEqual(call.kwargs.get('env', {}).get('SMTP_PASS'), 'smtp-test-private-value')
    def test_certificate_renewal_removes_temporary_rules_after_failure(self):
        with patch.object(self.module.subprocess, 'run') as run:
            run.side_effect = [type('Result', (), {'returncode':0})(), RuntimeError('CA unreachable'), type('Result', (), {'returncode':0})()]
            with self.assertRaises(RuntimeError):
                self.module.renew_certificate(Path('/private/acme'), 'account.example.cn', ['172.65.32.248'])
        self.assertEqual(run.call_count, 3)
        self.assertIn('-I', run.call_args_list[0].args[0])
        self.assertIn('-D', run.call_args_list[-1].args[0])
        self.assertIn('172.65.32.248', run.call_args_list[-1].args[0])

    def test_certificate_renewal_rejects_non_public_ca_addresses(self):
        for ip in ('127.0.0.1', '10.0.0.1'):
            with patch.object(self.module.subprocess, 'run') as run:
                with self.assertRaises(ValueError):
                    self.module.renew_certificate(Path('/private/acme'), 'account.example.cn', [ip])
                run.assert_not_called()
    def test_rejects_opaque_keys_without_asymmetric_verifiers(self):
        for service, key in [('auth','GOTRUE_JWT_KEYS'),('realtime','API_JWT_JWKS'),('storage','JWT_JWKS'),('functions','SUPABASE_JWKS')]:
            config = self.config(); del config['services'][service]['environment'][key]
            with self.assertRaises(ValueError): self.module.validate_compose(config)

    def test_same_checkout_cannot_reuse_database_for_another_region(self):
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp)
            self.module.ensure_region(repo, 'cn')
            self.module.ensure_region(repo, 'cn')
            with self.assertRaises(ValueError): self.module.ensure_region(repo, 'global')

    def test_backup_refuses_to_write_before_file_is_private(self):
        with tempfile.TemporaryDirectory() as temp:
            destination = Path(temp) / 'backup.sql'
            with patch.object(self.module, 'protect_backup', side_effect=PermissionError('ACL unavailable')), patch.object(self.module.subprocess, 'run') as run:
                with self.assertRaises(PermissionError): self.module.backup_database(['docker','compose'], destination)
                run.assert_not_called()
            self.assertFalse(destination.exists())
            self.assertEqual(list(Path(temp).iterdir()), [])

    def test_certificate_cleanup_retries_a_busy_firewall_lock(self):
        with patch.object(self.module.subprocess, 'run') as run:
            run.side_effect = [type('Result', (), {'returncode':0})(), type('Result', (), {'returncode':0})(), type('Result', (), {'returncode':1})(), type('Result', (), {'returncode':0})()]
            self.module.renew_certificate(Path('/private/acme'), 'account.example.cn', ['172.65.32.248'])
        self.assertEqual(run.call_count, 4)
        self.assertTrue(all('--wait' in c.args[0] for c in run.call_args_list if c.args[0][0]=='iptables'))

    def test_failed_backup_is_not_published(self):
        with tempfile.TemporaryDirectory() as temp:
            destination = Path(temp) / 'backup.sql'
            with patch.object(self.module.subprocess, 'run') as run:
                run.return_value.returncode = 1
                with self.assertRaises(RuntimeError): self.module.backup_database(['docker','compose'], destination)
            self.assertFalse(destination.exists())
            self.assertEqual(list(Path(temp).iterdir()), [])

    def test_successful_backup_is_private_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as temp:
            destination = Path(temp) / 'backup.sql'
            def write_dump(*args, **kwargs):
                kwargs['stdout'].write(b'-- private dump\n')
                return type('Result', (), {'returncode':0})()
            with patch.object(self.module.subprocess, 'run', side_effect=write_dump):
                self.module.backup_database(['docker','compose'], destination)
            self.assertIn('private dump', destination.read_text())
            with self.assertRaises(FileExistsError): self.module.backup_database(['docker','compose'], destination)

if __name__ == '__main__': unittest.main()
