#!/usr/bin/env python3
"""Validate repository stewardship and immutable workflow dependencies."""
import json
from pathlib import Path
import re
import sys
import unittest
import yaml

SHA = re.compile(r"[0-9a-fA-F]{40}\Z")
IMAGE_REFERENCE = re.compile(r"[^@\s]+@sha256:[a-fA-F0-9]{64}")


# GitHub's workflow-syntax permission scopes, reviewed on 2026-11-02.
# https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#permissions
PERMISSION_LEVELS = {
    scope: {"read", "write", "none"}
    for scope in (
        "actions", "artifact-metadata", "attestations", "checks", "code-quality",
        "contents", "deployments", "discussions", "issues", "packages", "pages",
        "pull-requests", "security-events", "statuses",
    )
}
PERMISSION_LEVELS.update({
    "copilot-requests": {"write", "none"},
    "id-token": {"write", "none"},
    "models": {"read", "none"},
    "vulnerability-alerts": {"read", "none"},
})


def permission_errors(value: object, location: str) -> list[str]:
    if value == "read-all":
        return []
    if value == "write-all":
        return [f"{location}: replace write-all with named permissions"]
    if not isinstance(value, dict):
        return [f"{location}: declare explicit permissions as read-all or a mapping"]
    errors = []
    for scope, level in value.items():
        if not isinstance(scope, str) or scope not in PERMISSION_LEVELS:
            errors.append(f"{location}: invalid permission scope")
        elif not isinstance(level, str) or level not in PERMISSION_LEVELS[scope]:
            errors.append(f"{location}: invalid permission level")
    return errors


def container_errors(job: dict, location: str) -> list[str]:
    """Validate job and service images independently of action references."""
    errors = []

    def check_image(image: object, image_location: str) -> None:
        if not isinstance(image, str) or not IMAGE_REFERENCE.fullmatch(image):
            errors.append(f"{image_location}: pin container image to a full SHA-256 digest")

    if "container" in job:
        container = job["container"]
        if isinstance(container, dict):
            check_image(container.get("image"), f"{location}: container")
        elif isinstance(container, str):
            check_image(container, f"{location}: container")
        else:
            errors.append(f"{location}: container must be an image string or mapping")
    if "services" in job:
        services = job["services"]
        if not isinstance(services, dict):
            errors.append(f"{location}: services must be a mapping of image configurations")
        else:
            for service_name, service in services.items():
                service_location = f"{location}: service {service_name}"
                if not isinstance(service, dict):
                    errors.append(f"{service_location}: service must be an image configuration mapping")
                else:
                    check_image(service.get("image"), service_location)
    return errors



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
    else:
        errors.extend(permission_errors(document['permissions'], name))
    jobs = document.get('jobs') or {}
    if not isinstance(jobs, dict):
        return errors + [f'{name}: expected a jobs mapping']
    uses = []
    for job in jobs.values():
        if not isinstance(job, dict):
            errors.append(f'{name}: expected a job mapping')
            continue
        if 'permissions' in job:
            errors.extend(permission_errors(job['permissions'], name + ': job'))
        if 'secrets' in job and not isinstance(job['secrets'], dict):
            errors.append(f'{name}: pass reusable-workflow secrets explicitly')
        errors.extend(container_errors(job, name + ': job'))
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


    def test_folded_and_literal_secret_forwarding_is_denied(self):
        for style in ['>', '|', '>-', '|-']:
            with self.subTest(style=style):
                source = ('permissions: read-all\njobs:\n  ci:\n    uses: owner/repo/.github/workflows/ci.yml@'
                          + 'a' * 40 + '\n    secrets: ' + style + '\n      inherit\n')
                self.assertTrue(any('secrets explicitly' in error for error in workflow_errors(source, 'ci.yml')))

    def test_explicit_secret_mapping_is_allowed(self):
        source = ('permissions: read-all\njobs:\n  ci:\n    uses: owner/repo/.github/workflows/ci.yml@'
                  + 'a' * 40 + '\n    secrets: {token: "${{ secrets.TOKEN }}"}\n')
        self.assertEqual(workflow_errors(source, 'ci.yml'), [])

    @staticmethod
    def permission_workflow(value, job_level=False):
        document = {'permissions': 'read-all', 'jobs': {'check': {
            'runs-on': 'ubuntu-latest', 'steps': [{'uses': 'actions/checkout@' + 'a' * 40}]
        }}}
        if job_level:
            document['jobs']['check']['permissions'] = value
        else:
            document['permissions'] = value
        return yaml.safe_dump(document)

    def test_invalid_workflow_permissions_are_denied(self):
        for value in ['write-all', 'admin', None, True, 42, [],
                      {'contents': 'admin'}, {'contents': True}, {'unknown-scope': 'read'},
                      {'id-token': 'read'}, {'models': 'write'},
                      {'copilot-requests': 'read'}, {'vulnerability-alerts': 'write'}]:
            with self.subTest(value=value):
                errors = workflow_errors(self.permission_workflow(value), 'ci.yml')
                self.assertTrue(any('permission' in error for error in errors))

    def test_invalid_job_permissions_are_denied(self):
        for value in ['write-all', 'admin', None, True, 42, [],
                      {'contents': 'admin'}, {'contents': True}, {'unknown-scope': 'read'},
                      {'id-token': 'read'}, {'models': 'write'},
                      {'copilot-requests': 'read'}, {'vulnerability-alerts': 'write'}]:
            with self.subTest(value=value):
                errors = workflow_errors(self.permission_workflow(value, job_level=True), 'ci.yml')
                self.assertTrue(any('permission' in error for error in errors))

    def test_explicit_scoped_permissions_are_allowed_at_both_levels(self):
        for value in ['read-all', {}, {'contents': 'read'},
                      {'contents': 'write', 'id-token': 'write', 'pages': 'write'},
                      {'actions': 'none', 'models': 'read', 'vulnerability-alerts': 'read',
                       'copilot-requests': 'write', 'artifact-metadata': 'read', 'code-quality': 'write'}]:
            for job_level in [False, True]:
                with self.subTest(value=value, job_level=job_level):
                    self.assertEqual(workflow_errors(self.permission_workflow(value, job_level), 'ci.yml'), [])

    def test_job_permissions_may_inherit_explicit_workflow_permissions(self):
        self.assertEqual(workflow_errors(self.workflow('- run: echo safe'), 'ci.yml'), [])


    def test_job_and_service_images_require_immutable_digests(self):
        declarations = (
            'container: ubuntu:latest',
            'container: {image: ubuntu:latest}',
            '"container": {"image": ubuntu:latest}',
            '"conta\\x69ner": {image: ubuntu:latest}',
            'services: {cache: {image: redis:7}}',
            '"services": {"database": {"image": postgres:16}}',
            '"serv\\x69ces": {cache: {"im\\x61ge": redis:7}}',
        )
        for declaration in declarations:
            with self.subTest(declaration=declaration):
                source = self.workflow('- run: echo ok').replace('    steps:', '    ' + declaration + '\n    steps:')
                self.assertTrue(any('SHA-256 digest' in error for error in workflow_errors(source, 'ci.yml')))
                for mutable in ('ubuntu:latest', 'redis:7', 'postgres:16'):
                    source = source.replace(mutable, mutable.split(':')[0] + '@sha256:' + 'b' * 64)
                self.assertEqual(workflow_errors(source, 'ci.yml'), [])


    def test_invalid_container_and_service_shapes_fail_closed(self):
        declarations = (
            'container: null', 'container: []', 'container: {}',
            'container: {image: null}', 'container: {image: true}',
            'services: null', 'services: []', 'services: {cache: null}',
            'services: {cache: redis:7}', 'services: {cache: {}}',
            'services: {cache: {image: null}}',
        )
        for declaration in declarations:
            with self.subTest(declaration=declaration):
                source = self.workflow('- run: echo ok').replace('    steps:', '    ' + declaration + '\n    steps:')
                self.assertTrue(workflow_errors(source, 'ci.yml'))
        source = self.workflow('- run: echo ok').replace('    steps:', '    services: {}\n    steps:')
        self.assertEqual(workflow_errors(source, 'ci.yml'), [])


if __name__ == '__main__':
    if '--self-test' in sys.argv:
        unittest.main(argv=[sys.argv[0]])
    else:
        findings = repository_errors(Path.cwd())
        if findings:
            print('\n'.join(findings), file=sys.stderr)
            raise SystemExit(1)
        print('Repository policy checks passed')
