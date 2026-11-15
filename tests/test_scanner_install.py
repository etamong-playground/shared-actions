import hashlib
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('installer', ROOT / '.github/actions/source-secret-scan/install.py')
INSTALLER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSTALLER)


def archive(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w:gz') as target:
        for name, body, kind in entries:
            info = tarfile.TarInfo(name)
            info.type = kind
            info.size = len(body)
            target.addfile(info, io.BytesIO(body))
    return output.getvalue()


class ScannerInstallTests(unittest.TestCase):
    def test_supported_platform_pins_are_complete(self):
        for tool in INSTALLER.TOOLS:
            for system, arch in [('Darwin', 'arm64'), ('Darwin', 'x86_64'),
                                 ('Linux', 'aarch64'), ('Linux', 'x86_64')]:
                with self.subTest(tool=tool, system=system, arch=arch), \
                     patch.object(INSTALLER.platform, 'system', return_value=system), \
                     patch.object(INSTALLER.platform, 'machine', return_value=arch):
                    url, digest = INSTALLER.asset(tool)
                    self.assertTrue(url.startswith('https://github.com/'))
                    self.assertIn('/v' + INSTALLER.TOOLS[tool]['version'] + '/', url)
                    self.assertRegex(digest, r'^[0-9a-f]{64}$')

    def test_extracts_only_the_exact_regular_binary(self):
        raw = archive([('../escape', b'ignored', tarfile.REGTYPE),
                       ('gitleaks', b'controlled executable', tarfile.REGTYPE)])
        self.assertEqual(INSTALLER.archive_binary(raw, hashlib.sha256(raw).hexdigest(), 'gitleaks'),
                         b'controlled executable')

    def test_checksum_mismatch_rejects_before_archive_parsing(self):
        raw = archive([('gitleaks', b'changed binary', tarfile.REGTYPE)])
        with self.assertRaises(ValueError):
            INSTALLER.archive_binary(raw, '0' * 64, 'gitleaks')

    def test_link_duplicate_and_empty_binary_are_rejected(self):
        for entries in [[('gitleaks', b'', tarfile.SYMTYPE)],
                        [('gitleaks', b'a', tarfile.REGTYPE)] * 2,
                        [('gitleaks', b'', tarfile.REGTYPE)]]:
            with self.subTest(entries=entries):
                raw = archive(entries)
                with self.assertRaises(ValueError):
                    INSTALLER.archive_binary(raw, hashlib.sha256(raw).hexdigest(), 'gitleaks')

    def test_atomic_install_replaces_link_without_touching_target(self):
        raw = archive([('gitleaks', b'new binary', tarfile.REGTYPE)])
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            victim = directory / 'unchanged'
            victim.write_bytes(b'preserved')
            (directory / 'gitleaks').symlink_to(victim)
            with patch.object(INSTALLER, 'asset', return_value=('https://example.invalid/archive', hashlib.sha256(raw).hexdigest())), \
                 patch.object(INSTALLER.urllib.request, 'urlopen') as opened:
                opened.return_value.__enter__.return_value.read.return_value = raw
                result = INSTALLER.install('gitleaks', directory)
            self.assertEqual(result.read_bytes(), b'new binary')
            self.assertEqual(victim.read_bytes(), b'preserved')
            self.assertFalse(result.is_symlink())
            self.assertEqual(result.stat().st_mode & 0o777, 0o700)

    def test_install_failure_does_not_replace_existing_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'gitleaks'
            path.write_bytes(b'previous')
            with patch.object(INSTALLER.urllib.request, 'urlopen', side_effect=OSError('private diagnostic')):
                self.assertEqual(INSTALLER.main(['gitleaks', directory]), 2)
            self.assertEqual(path.read_bytes(), b'previous')

    def test_binary_and_entry_limits_reject_incomplete_archive(self):
        raw = archive([('gitleaks', b'too large', tarfile.REGTYPE)])
        with patch.object(INSTALLER, 'BINARY_BYTES', 2):
            with self.assertRaises(ValueError):
                INSTALLER.archive_binary(raw, hashlib.sha256(raw).hexdigest(), 'gitleaks')
        raw = archive([(str(n), b'a', tarfile.REGTYPE) for n in range(100)] +
                      [('gitleaks', b'a', tarfile.REGTYPE)])
        with self.assertRaises(ValueError):
            INSTALLER.archive_binary(raw, hashlib.sha256(raw).hexdigest(), 'gitleaks')


if __name__ == '__main__':
    unittest.main()
