from contextlib import redirect_stdout
import io
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
