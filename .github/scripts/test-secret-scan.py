#!/usr/bin/env python3
"""Exercise the production scanner helper with clean and oversized inputs."""
import json
import os
from pathlib import Path
import secrets
import string
import subprocess
import tempfile
import unittest


HELPER = Path(__file__).with_name('scan-repository-secrets.sh')


class SecretScanTests(unittest.TestCase):
    def test_clean_tree_and_oversized_secret_through_production_helper(self):
        with tempfile.TemporaryDirectory(prefix='repository-secret-scan-') as temporary:
            directory = Path(temporary)
            repository = directory / 'repository'
            repository.mkdir()
            (repository / 'README.md').write_text('A clean repository fixture.\n', encoding='utf-8')
            report = directory / 'findings.json'
            environment = dict(os.environ)
            environment['GITLEAKS_REPORT_PATH'] = str(report)

            def scan():
                result = subprocess.run(
                    ['bash', str(HELPER), str(repository)],
                    env=environment, capture_output=True, text=True, check=False,
                )
                findings = json.loads(report.read_text(encoding='utf-8')) if report.is_file() else []
                metadata = [(item['RuleID'], item['File'], item['StartLine']) for item in findings]
                return result.returncode, metadata

            code, findings = scan()
            self.assertEqual(code, 0, 'The production helper must accept the clean tree.')
            self.assertEqual(findings, [])

            # Generate the nonfunctional canary at runtime; no complete token is committed.
            token = 'ghp_' + ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(36))
            payload = repository / 'oversized.json'
            with payload.open('w', encoding='utf-8') as stream:
                stream.write('{"padding":"')
                stream.write(' ' * (21 * 1024 * 1024))
                stream.write('",\n"token":' + json.dumps(token) + '}\n')
            self.assertGreater(payload.stat().st_size, 20 * 1024 * 1024)
            report.unlink(missing_ok=True)
            code, findings = scan()
            self.assertEqual(code, 1, 'The production helper must reject a secret in an oversized text file.')
            self.assertIn(('github-pat', 'oversized.json', 2), findings)


if __name__ == '__main__':
    unittest.main()
