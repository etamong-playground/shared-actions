from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.github/actions/source-secret-scan'))
import exception_policy
import git_scope
import scan
from process import IncompleteScan


class ExceptionPolicyTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.repository = Path(self.scratch.name)
        self.env = git_scope.environment(self.repository)
        self.git('init', '-q')
        self.git('config', 'user.name', 'Fixture')
        self.git('config', 'user.email', 'fixture@example.invalid')
        (self.repository / 'fixture.txt').write_text('controlled synthetic fixture\n')
        self.commit()
        self.blob = self.git('rev-parse', 'HEAD:fixture.txt')
        self.entry = dict(repository='example/project', scanner='gitleaks', detector='FixtureDetector',
                          path='fixture.txt', blob_oid=self.blob, owner='Fixture maintainer',
                          reason='Controlled synthetic fixture', expires_at='2030-01-02T00:00:00Z',
                          removal_condition='Remove when supported history no longer contains the blob')
        self.policy_file = self.repository / exception_policy.PATH
        self.policy_file.parent.mkdir()
        self.write_policy([self.entry])
        self.base = self.commit()
        self.now = datetime(2030, 1, 1, tzinfo=timezone.utc)

    def git(self, *args):
        return subprocess.run(['git', '-C', str(self.repository), *args], env=self.env,
                              capture_output=True, text=True, check=True).stdout.strip()

    def commit(self):
        self.git('add', '.')
        self.git('commit', '-qm', 'fixture')
        return self.git('rev-parse', 'HEAD')

    def write_policy(self, entries):
        self.policy_file.write_text(json.dumps({'version': 1, 'exceptions': entries}))

    def load(self, head=None, event_name='pull_request', event=None, identity=None):
        head = head or self.git('rev-parse', 'HEAD')
        if event is None:
            event = {'repository': {'full_name': 'example/project', 'default_branch': 'main'},
                     'pull_request': {'base': {'sha': self.base, 'ref': 'main',
                                               'repo': {'full_name': 'example/project'}}}}
        identity = identity or {'repository': 'example/project', 'sha': head, 'ref': 'refs/pull/1/merge'}
        return exception_policy.load(self.repository, self.env, head, event_name, event, identity,
                                     scan.strict_json, clock=lambda: self.now)

    def test_exact_regular_blob_is_the_only_allowed_source(self):
        policy = self.load()
        self.assertTrue(policy.allows('gitleaks', 'FixtureDetector', 'fixture.txt', self.base))
        for arguments in [('trufflehog', 'FixtureDetector', 'fixture.txt', self.base),
                          ('gitleaks', 'OtherDetector', 'fixture.txt', self.base),
                          ('gitleaks', 'FixtureDetector', 'other.txt', self.base)]:
            self.assertFalse(policy.allows(*arguments))
        (self.repository / 'fixture.txt').write_text('changed source\n')
        changed = self.commit()
        self.assertFalse(policy.allows('gitleaks', 'FixtureDetector', 'fixture.txt', changed))

    def test_unapproved_blob_stays_incomplete_after_path_removal(self):
        (self.repository / 'fixture.txt').write_text('changed endpoint contents\n')
        head = self.commit()
        with self.assertRaises(IncompleteScan):
            self.load(head)
        (self.repository / 'fixture.txt').unlink()
        head = self.commit()
        with self.assertRaises(IncompleteScan):
            self.load(head)

    def test_proposed_policy_cannot_authorize_itself(self):
        changed = dict(self.entry, detector='ProposedDetector')
        self.write_policy([changed])
        head = self.commit()
        policy = self.load(head)
        self.assertTrue(policy.allows('gitleaks', 'FixtureDetector', 'fixture.txt', head))
        self.assertFalse(policy.allows('gitleaks', 'ProposedDetector', 'fixture.txt', head))

    def test_working_tree_policy_is_never_loaded(self):
        self.policy_file.write_text('malformed uncommitted policy')
        self.assertTrue(self.load().allows('gitleaks', 'FixtureDetector', 'fixture.txt', self.base))

    def test_policy_on_unprotected_pr_base_and_dispatch_is_not_used(self):
        metadata = {'repository': {'full_name': 'example/project', 'default_branch': 'main'}}
        event = deepcopy(metadata)
        event['pull_request'] = {'base': {'sha': self.base, 'ref': 'feature',
                                         'repo': {'full_name': 'example/project'}}}
        self.assertIsNone(self.load(event=event))
        event = dict(metadata, ref='refs/heads/feature')
        identity = {'repository': 'example/project', 'sha': self.base, 'ref': event['ref']}
        self.assertIsNone(self.load(event_name='workflow_dispatch', event=event, identity=identity))

    def test_default_push_and_dispatch_bind_observed_revision(self):
        event = {'repository': {'full_name': 'example/project', 'default_branch': 'main'},
                 'ref': 'refs/heads/main', 'after': self.base}
        identity = {'repository': 'example/project', 'sha': self.base, 'ref': event['ref']}
        for name in ['push', 'workflow_dispatch']:
            self.assertTrue(self.load(event_name=name, event=event, identity=identity).allows(
                'gitleaks', 'FixtureDetector', 'fixture.txt', self.base))
        with self.assertRaises(IncompleteScan):
            self.load(event_name='push', event=dict(event, after='a' * 40), identity=identity)
        with self.assertRaises(IncompleteScan):
            self.load(event_name='workflow_dispatch', event=event, identity=dict(identity, sha='a' * 40))

    def test_wrong_repository_expired_duplicate_and_unknown_policy_are_incomplete(self):
        cases = [[dict(self.entry, repository='other/project')],
                 [dict(self.entry, expires_at='2030-01-01T00:00:00Z')],
                 [self.entry, self.entry], [dict(self.entry, unexpected='value')],
                 [dict(self.entry, path='../fixture.txt')], [dict(self.entry, blob_oid='not-an-object')]]
        for entries in cases:
            with self.subTest(entries=entries):
                self.write_policy(entries)
                self.base = self.commit()
                with self.assertRaises(IncompleteScan):
                    self.load()

    def test_duplicate_json_unknown_version_and_limits_are_incomplete(self):
        for raw in ['{"version":1,"version":1,"exceptions":[]}',
                    '{"version":2,"exceptions":[]}',
                    json.dumps({'version': 1, 'exceptions': [self.entry] * 33}),
                    ' ' * 65537]:
            self.policy_file.write_text(raw)
            self.base = self.commit()
            with self.assertRaises(IncompleteScan):
                self.load()

    def test_expiry_during_execution_is_not_clean(self):
        policy = self.load()
        self.now = datetime(2030, 1, 2, tzinfo=timezone.utc)
        with self.assertRaises(IncompleteScan):
            policy.allows('gitleaks', 'FixtureDetector', 'fixture.txt', self.base)

    def test_deleted_or_symlinked_finding_does_not_search_ancestors(self):
        policy = self.load()
        (self.repository / 'fixture.txt').unlink()
        deleted = self.commit()
        with self.assertRaises(IncompleteScan):
            policy.allows('gitleaks', 'FixtureDetector', 'fixture.txt', deleted)
        (self.repository / 'fixture.txt').symlink_to('elsewhere')
        linked = self.commit()
        with self.assertRaises(IncompleteScan):
            policy.allows('gitleaks', 'FixtureDetector', 'fixture.txt', linked)

    def test_removing_only_the_approved_blob_preserves_historical_exception(self):
        (self.repository / 'fixture.txt').unlink()
        head = self.commit()
        self.assertTrue(self.load(head).allows('gitleaks', 'FixtureDetector', 'fixture.txt', self.base))

    def test_untrusted_local_context_and_absent_policy_apply_no_exceptions(self):
        self.assertIsNone(exception_policy.load(self.repository, self.env, self.base, None, None,
                                                None, scan.strict_json))
        self.policy_file.unlink()
        self.base = self.commit()
        self.assertIsNone(self.load())
