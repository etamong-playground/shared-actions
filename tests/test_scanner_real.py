from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import random
import string
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.github/actions/source-secret-scan'))
import git_scope
import scan


@unittest.skipUnless(os.environ.get('SCANNER_TEST_BIN_DIR'), 'Real-scanner qualification requires explicit binary directory')
class RealScannerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repository = self.root / 'source'
        self.repository.mkdir()
        self.scratch = self.root / 'scan'
        self.scratch.mkdir()
        env_root = self.root / 'fixture-env'
        env_root.mkdir()
        self.env = git_scope.environment(env_root)
        self.git('init', '-q')
        self.git('config', 'user.email', 'fixture@example.invalid')
        self.git('config', 'user.name', 'Fixture')
        (self.repository / 'text').write_text('clean fixture\n')
        self.first = self.commit()
        rng = random.Random(2112)
        self.candidate = 'ghp_' + ''.join(rng.choice(string.ascii_letters + string.digits) for _ in range(36))

    def tearDown(self):
        self.temporary.cleanup()

    def git(self, *arguments):
        return subprocess.run(['git', '-C', str(self.repository), *arguments],
                              capture_output=True, text=True, check=True, env=self.env).stdout.strip()

    def commit(self):
        self.git('add', '.')
        self.git('commit', '-qm', 'fixture')
        return self.git('rev-parse', 'HEAD')

    def check(self, tool, **kwargs):
        output = io.StringIO()
        binary = Path(os.environ['SCANNER_TEST_BIN_DIR']).resolve() / tool
        self.assertTrue(binary.is_file(), 'Qualification binary is absent')
        with redirect_stdout(output):
            code = scan.check(tool, binary, self.repository, self.scratch, **kwargs)
        text = output.getvalue()
        self.assertNotIn(self.candidate, text)
        self.assertEqual(list(self.scratch.iterdir()), [], 'Scratch directory was not cleaned')
        return code, text

    def test_full_history_clean_candidate_and_deleted_candidate(self):
        for tool in ['gitleaks', 'trufflehog']:
            with self.subTest(tool=tool):
                self.assertEqual(self.check(tool), (0, 'Source scan clean.\n'))
        (self.repository / 'text').write_text(self.candidate + '\n')
        self.commit()
        (self.repository / 'text').write_text('candidate removed\n')
        self.commit()
        for tool in ['gitleaks', 'trufflehog']:
            with self.subTest(tool=tool):
                self.assertEqual(self.check(tool)[0], 1)

    def fixture_policy(self):
        (self.repository / 'approved').write_text(self.candidate + '\n')
        self.commit()
        blob = self.git('rev-parse', 'HEAD:approved')
        entries = [dict(repository='example/project', scanner=tool, detector=detector,
                        path='approved', blob_oid=blob, owner='Fixture maintainer', reason='Synthetic qualification',
                        expires_at='2099-01-01T00:00:00Z', removal_condition='Remove fixture')
                   for tool, detector in [('gitleaks', 'github-pat'), ('trufflehog', 'Github')]]
        policy = self.repository / '.github/source-secret-exceptions.json'
        policy.parent.mkdir()
        policy.write_text(json.dumps({'version': 1, 'exceptions': entries}))
        return self.commit(), entries

    def dispatch_policy_check(self, tool):
        head = self.git('rev-parse', 'HEAD')
        event = {'repository': {'full_name': 'example/project', 'default_branch': 'main'},
                 'ref': 'refs/heads/main'}
        identity = {'repository': 'example/project', 'sha': head, 'ref': event['ref']}
        return self.check(tool, event_name='workflow_dispatch', event=event, identity=identity)

    def test_exact_reviewed_fixture_is_clean_but_copied_path_blocks(self):
        self.fixture_policy()
        for tool in ['gitleaks', 'trufflehog']:
            self.assertEqual(self.dispatch_policy_check(tool), (0, 'Source scan clean.\n'))
        (self.repository / 'copy').write_text(self.candidate + '\n')
        self.commit()
        for tool in ['gitleaks', 'trufflehog']:
            self.assertEqual(self.dispatch_policy_check(tool)[0], 2)

    def test_changed_fixture_endpoint_blocks_even_without_new_diff_finding(self):
        self.fixture_policy()
        (self.repository / 'approved').write_text(self.candidate + '\nchanged fixture blob\n')
        self.commit()
        for tool in ['gitleaks', 'trufflehog']:
            with self.subTest(tool=tool):
                self.assertEqual(self.dispatch_policy_check(tool)[0], 2)

    def test_changed_candidate_line_cannot_reuse_the_fixture_exception(self):
        self.fixture_policy()
        replacement = self.candidate[:-1] + ('A' if self.candidate[-1] != 'A' else 'B')
        (self.repository / 'approved').write_text(replacement + '\n')
        self.commit()
        for tool in ['gitleaks', 'trufflehog']:
            self.assertEqual(self.dispatch_policy_check(tool)[0], 2)

    def test_unapproved_intermediate_blob_is_not_hidden_by_restoration(self):
        self.fixture_policy()
        (self.repository / 'approved').write_text(self.candidate + '\nintermediate modification\n')
        self.commit()
        (self.repository / 'approved').write_text(self.candidate + '\n')
        self.commit()
        for tool in ['gitleaks', 'trufflehog']:
            self.assertEqual(self.dispatch_policy_check(tool)[0], 2)

    def test_approved_blob_renamed_to_another_path_is_incomplete(self):
        self.fixture_policy()
        self.git('mv', 'approved', 'renamed')
        self.commit()
        for tool in ['gitleaks', 'trufflehog']:
            self.assertEqual(self.dispatch_policy_check(tool)[0], 2)

    def test_deleted_approved_fixture_keeps_exact_historical_provenance(self):
        self.fixture_policy()
        (self.repository / 'approved').unlink()
        self.commit()
        for tool in ['gitleaks', 'trufflehog']:
            self.assertEqual(self.dispatch_policy_check(tool)[0], 0)

    def test_local_and_staged_scans_do_not_activate_committed_policy(self):
        self.fixture_policy()
        for tool in ['gitleaks', 'trufflehog']:
            self.assertEqual(self.check(tool)[0], 1)
            self.assertEqual(self.check(tool, staged=True)[0], 1)

    def test_other_candidate_is_not_filtered_with_approved_fixture(self):
        self.fixture_policy()
        replacement = self.candidate[:-1] + ('A' if self.candidate[-1] != 'A' else 'B')
        (self.repository / 'other').write_text(replacement + '\n')
        self.commit()
        for tool in ['gitleaks', 'trufflehog']:
            self.assertEqual(self.dispatch_policy_check(tool)[0], 1)

    def test_proposed_policy_does_not_replace_trusted_pr_base(self):
        base, entries = self.fixture_policy()
        for entry in entries:
            entry['blob_oid'] = 'a' * 40
        (self.repository / '.github/source-secret-exceptions.json').write_text(
            json.dumps({'version': 1, 'exceptions': entries}))
        head = self.commit()
        event = {'repository': {'full_name': 'example/project', 'default_branch': 'main'},
                 'pull_request': {'base': {'sha': base, 'ref': 'main',
                                           'repo': {'full_name': 'example/project'}}}}
        identity = {'repository': 'example/project', 'sha': head, 'ref': 'refs/pull/1/merge'}
        for tool in ['gitleaks', 'trufflehog']:
            self.assertEqual(self.check(tool, event_name='pull_request', event=event, identity=identity)[0], 0)
            self.assertEqual(self.dispatch_policy_check(tool)[0], 2)

    def test_repository_and_inline_suppression_cannot_hide_candidates(self):
        (self.repository / 'text').write_text(self.candidate + ' # gitleaks:allow trufflehog:ignore\n')
        (self.repository / '.gitleaks.toml').write_text('[allowlist]\nregexes = [".*"]\n')
        (self.repository / '.gitleaksignore').write_text('*\n')
        self.commit()
        for tool in ['gitleaks', 'trufflehog']:
            with self.subTest(tool=tool):
                self.assertEqual(self.check(tool)[0], 1)

    def test_staged_snapshot_uses_index_not_working_tree(self):
        (self.repository / 'text').write_text(self.candidate + '\n')
        self.git('add', 'text')
        (self.repository / 'text').write_text('clean working tree\n')
        for tool in ['gitleaks', 'trufflehog']:
            with self.subTest(tool=tool):
                self.assertEqual(self.check(tool, staged=True)[0], 1)

    def test_staged_snapshot_excludes_untracked_and_unstaged_content(self):
        (self.repository / 'text').write_text(self.candidate + '\n')
        (self.repository / 'untracked').write_text(self.candidate + '\n')
        for tool in ['gitleaks', 'trufflehog']:
            with self.subTest(tool=tool):
                self.assertEqual(self.check(tool, staged=True)[0], 0)

    def test_range_excludes_old_candidate_but_full_history_still_finds_it(self):
        (self.repository / 'text').write_text(self.candidate + '\n')
        self.commit()
        (self.repository / 'text').write_text('removed\n')
        base = self.commit()
        (self.repository / 'text').write_text('clean new commit\n')
        head = self.commit()
        self.assertEqual(self.check('trufflehog', event_name='push', event={'before': base, 'after': head})[0], 0)
        self.assertEqual(self.check('trufflehog')[0], 1)

    def test_range_candidate_and_unresolved_base_are_blocking(self):
        (self.repository / 'text').write_text(self.candidate + '\n')
        head = self.commit()
        self.assertEqual(self.check('trufflehog', event_name='pull_request', event={
            'pull_request': {'base': {'sha': self.first}}})[0], 1)
        self.assertEqual(self.check('trufflehog', event_name='push', event={
            'before': '0' * 40, 'after': head})[0], 2)

    def test_staged_symlink_is_rejected(self):
        (self.repository / 'linked').symlink_to(self.repository / 'text')
        self.git('add', 'linked')
        for tool in ['gitleaks', 'trufflehog']:
            with self.subTest(tool=tool):
                self.assertEqual(self.check(tool, staged=True)[0], 2)

    def test_full_history_includes_candidate_reachable_only_by_custom_ref(self):
        branch = self.git('branch', '--show-current')
        self.git('checkout', '-q', '--orphan', 'fixture-only')
        (self.repository / 'text').write_text(self.candidate + '\n')
        candidate_commit = self.commit()
        self.git('update-ref', 'refs/custom/candidate', candidate_commit)
        self.git('checkout', '-q', branch)
        self.git('branch', '-D', 'fixture-only')
        for tool in ['gitleaks', 'trufflehog']:
            with self.subTest(tool=tool):
                self.assertEqual(self.check(tool)[0], 1)
        self.git('config', 'uploadpack.hideRefs', 'refs/custom')
        for tool in ['gitleaks', 'trufflehog']:
            with self.subTest(tool=tool, hidden=True):
                self.assertEqual(self.check(tool)[0], 2)


if __name__ == '__main__':
    unittest.main()
