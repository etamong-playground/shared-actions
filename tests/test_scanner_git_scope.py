import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
HELPERS = ROOT / '.github/actions/source-secret-scan'
sys.path.insert(0, str(HELPERS))
import git_scope as SCOPE
import scan as SCAN
from process import IncompleteScan


class GitScopeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repository = self.root / 'source'
        self.repository.mkdir()
        self.scratch = self.root / 'scan'
        self.scratch.mkdir()
        self.env = SCOPE.environment(self.scratch)
        subprocess.run(['git', 'init', '-q', str(self.repository)], check=True, env=self.env)
        self.g('config', 'user.email', 'fixture@example.invalid')
        self.g('config', 'user.name', 'Fixture')
        self.first = self.add('first')
        self.second = self.add('second')

    def tearDown(self):
        self.temporary.cleanup()

    def g(self, *arguments):
        result = subprocess.run(['git', '-C', str(self.repository), *arguments],
                                capture_output=True, text=True, check=True, env=self.env)
        return result.stdout.strip()

    def add(self, text):
        (self.repository / 'file').write_text(text)
        self.g('add', 'file')
        self.g('commit', '-qm', text)
        return self.g('rev-parse', 'HEAD')

    def test_environment_drops_credentials_git_overrides_and_scanner_options(self):
        with patch.dict(os.environ, {'GH_TOKEN': 'controlled fixture', 'GITLEAKS_CONFIG': 'ignored',
                                     'GIT_DIR': '/unrelated', 'TRUFFLEHOG_NO_VERIFICATION': 'false'}):
            scratch = self.root / 'fresh'
            scratch.mkdir()
            env = SCOPE.environment(scratch)
        for key in ['GH_TOKEN', 'GITLEAKS_CONFIG', 'GIT_DIR', 'TRUFFLEHOG_NO_VERIFICATION']:
            self.assertNotIn(key, env)
        self.assertEqual(env['GIT_CONFIG_VALUE_0'], 'never')

    def test_mirror_preserves_custom_refs_and_drops_source_config(self):
        self.g('update-ref', 'refs/custom/retained', self.first)
        self.g('config', 'credential.helper', '!must-not-run')
        self.g('config', 'remote.origin.url', 'https://untrusted.invalid/source')
        destination, head = SCOPE.prepare(self.repository, self.scratch, self.env)
        self.assertEqual(head, self.second)
        self.assertEqual(SCOPE.git(destination, self.env, 'rev-parse', 'refs/custom/retained'), self.first)
        self.assertNotIn('credential', (destination / 'config').read_text())
        self.assertNotIn('untrusted', (destination / 'config').read_text())

    def test_shallow_checkout_is_rejected(self):
        clone = self.root / 'shallow'
        subprocess.run(['git', 'clone', '-q', '--depth=1', self.repository.as_uri(), str(clone)],
                       check=True, env=self.env)
        with self.assertRaises(IncompleteScan):
            SCOPE.prepare(clone, self.scratch, self.env)

    def test_push_range_is_bound_to_actual_head(self):
        event = {'before': self.first, 'after': self.second}
        self.assertEqual(SCOPE.range_base(self.repository, self.env, self.second, 'push', event), self.first)
        event['after'] = self.first
        with self.assertRaises(IncompleteScan):
            SCOPE.range_base(self.repository, self.env, self.second, 'push', event)

    def test_pr_range_resolves_observed_merge_base(self):
        self.assertEqual(SCOPE.range_base(self.repository, self.env, self.second, 'pull_request', {
            'pull_request': {'base': {'sha': self.first}}}), self.first)

    def test_missing_base_and_unsupported_events_never_fall_back_to_clean(self):
        for event_name, event in [('push', {'before': '0' * 40, 'after': self.second}),
                                  ('pull_request_target', {})]:
            with self.subTest(event=event_name), self.assertRaises(IncompleteScan):
                SCOPE.range_base(self.repository, self.env, self.second, event_name, event)
        self.assertIsNone(SCOPE.range_base(self.repository, self.env, self.second, 'workflow_dispatch', {}))

    def test_hidden_ref_cannot_be_silently_omitted_from_mirror(self):
        self.g('update-ref', 'refs/hidden/candidate', self.first)
        self.g('config', 'uploadpack.hideRefs', 'refs/hidden')
        with self.assertRaises(IncompleteScan):
            SCOPE.prepare(self.repository, self.scratch, self.env)

    def test_staged_snapshot_does_not_execute_fsmonitor_configuration(self):
        marker = self.root / 'executed'
        hook = self.root / 'fsmonitor'
        hook.write_text('#!/bin/sh\ntouch "' + str(marker) + '"\nprintf "token\\0"\n')
        hook.chmod(0o700)
        self.g('config', 'core.fsmonitor', str(hook))
        SCAN.staged_files(self.repository, self.root / 'snapshot', self.env)
        self.assertFalse(marker.exists(), 'Source-configured executable ran during staged snapshot')


if __name__ == '__main__':
    unittest.main()
