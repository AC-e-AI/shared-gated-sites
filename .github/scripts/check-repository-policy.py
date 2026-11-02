#!/usr/bin/env python3
"""Validate repository stewardship and immutable workflow dependencies."""
import json
from pathlib import Path
import re
import sys
import unittest
import yaml

SHA = re.compile(r"[0-9a-fA-F]{40}\Z")


def workflow_errors(text, name):
    errors = []
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError:
        return [f'{name}: invalid workflow YAML']
    if not isinstance(document, dict):
        return [f'{name}: expected a workflow mapping']
    if 'permissions' not in document:
        errors.append(f"{name}: declare workflow permissions explicitly")
    jobs = document.get('jobs') or {}
    if not isinstance(jobs, dict):
        return errors + [f'{name}: expected a jobs mapping']
    uses = []
    for job in jobs.values():
        if not isinstance(job, dict):
            errors.append(f'{name}: expected a job mapping')
            continue
        if job.get('secrets') == 'inherit':
            errors.append(f'{name}: pass reusable-workflow secrets explicitly')
        if 'uses' in job:
            uses.append(job['uses'])
        for step in job.get('steps') or []:
            if isinstance(step, dict) and 'uses' in step:
                uses.append(step['uses'])
    for target in uses:
        if not isinstance(target, str):
            errors.append(f'{name}: action reference must be a string')
            continue
        if target.startswith('./'):
            continue
        if target.startswith('docker://'):
            valid = bool(re.search(r'@sha256:[a-fA-F0-9]{64}\Z', target))
        else:
            valid = '@' in target and bool(SHA.fullmatch(target.rsplit('@', 1)[1]))
        if not valid:
            errors.append(f"{name}: pin action/reusable workflow to a full commit SHA")
    return errors


def repository_errors(root):
    errors = []
    def require(path):
        if not (root / path).is_file() or not (root / path).read_text(encoding='utf-8').strip():
            errors.append(f"missing or empty {path}")
    require('.github/CODEOWNERS')
    require('SECURITY.md')
    require('.gitignore')
    if not any((root / n).is_file() for n in ['README.md', 'README.txt', 'README.rst', 'README']):
        errors.append('missing repository README')
    if not any((root / n).is_file() for n in ['LICENSE', 'LICENSE.md', 'LICENSE.txt', 'NOTICE.md', 'NOTICE']):
        errors.append('missing repository-wide license or proprietary notice')
    owners = root / '.github/CODEOWNERS'
    if owners.is_file():
        lines = [line.split('#', 1)[0].split() for line in owners.read_text(encoding='utf-8').splitlines()]
        if not any(len(parts) > 1 and parts[0] == '*' and any(owner.startswith('@') for owner in parts[1:]) for parts in lines):
            errors.append('CODEOWNERS must have a catch-all GitHub owner')
    manifest = root / '.github/repository-governance.json'
    try:
        metadata = json.loads(manifest.read_text(encoding='utf-8'))
        for key in ['repository', 'maintainer', 'lifecycle', 'policy_scope']:
            if not isinstance(metadata.get(key), str) or not metadata[key].strip():
                errors.append(f'governance metadata needs {key}')
    except (OSError, ValueError):
        errors.append('missing or invalid repository-governance.json')
    for path in sorted((root / '.github/workflows').glob('*')):
        if path.suffix in {'.yml', '.yaml'}:
            errors.extend(workflow_errors(path.read_text(encoding='utf-8'), path.name))
    return errors


class GuardTests(unittest.TestCase):
    @staticmethod
    def workflow(step):
        return 'permissions: read-all\njobs:\n  check:\n    runs-on: ubuntu-latest\n    steps:\n      '+step+'\n'

    def test_pinned_action_passes(self):
        self.assertEqual(workflow_errors(self.workflow('- uses: actions/checkout@' + 'a' * 40), 'ci.yml'), [])

    def test_mutable_action_is_denied(self):
        self.assertTrue(any('full commit SHA' in error for error in workflow_errors(self.workflow('- uses: actions/checkout@v4'), 'ci.yml')))

    def test_missing_permissions_is_denied(self):
        source = self.workflow('- run: true').removeprefix('permissions: read-all\n')
        self.assertTrue(any('permissions' in error for error in workflow_errors(source, 'ci.yml')))

    def test_implicit_secret_forwarding_is_denied(self):
        self.assertTrue(any('secrets explicitly' in error for error in workflow_errors('permissions: read-all\njobs:\n  ci:\n    secrets: inherit\n', 'ci.yml')))

    def test_local_action_is_allowed(self):
        self.assertEqual(workflow_errors(self.workflow('- uses: ./.github/actions/local'), 'ci.yml'), [])

    def test_flow_action_is_denied(self):
        self.assertTrue(workflow_errors('permissions: read-all\njobs:\n  check:\n    steps: [{uses: actions/checkout@v4}]\n', 'ci.yml'))

    def test_quoted_action_key_is_denied(self):
        self.assertTrue(workflow_errors(self.workflow('- "uses": actions/checkout@v4'), 'ci.yml'))

    def test_quoted_secrets_key_is_denied(self):
        self.assertTrue(workflow_errors('permissions: read-all\njobs:\n  ci:\n    "secrets": inherit\n', 'ci.yml'))

    def test_escaped_action_key_is_denied(self):
        self.assertTrue(workflow_errors(self.workflow(r'- "u\x73es": actions/checkout@v4'), 'ci.yml'))

    def test_explicit_mapping_action_key_is_denied(self):
        self.assertTrue(workflow_errors(self.workflow('- ? uses\n        : actions/checkout@v4'), 'ci.yml'))

    def test_quoted_pinned_action_is_allowed(self):
        self.assertEqual(workflow_errors(self.workflow('- "uses": actions/checkout@'+'a'*40), 'ci.yml'), [])


if __name__ == '__main__':
    if '--self-test' in sys.argv:
        unittest.main(argv=[sys.argv[0]])
    else:
        findings = repository_errors(Path.cwd())
        if findings:
            print('\n'.join(findings), file=sys.stderr)
            raise SystemExit(1)
        print('Repository policy checks passed')
