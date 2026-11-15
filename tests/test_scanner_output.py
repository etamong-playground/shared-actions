from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.github/actions/source-secret-scan'))
import scan
from process import IncompleteScan


def truffle_record():
    return {
        'SourceMetadata': {'Data': {'Git': {'commit': 'a' * 40, 'file': 'fixture',
                                          'email': 'fixture@example.invalid', 'timestamp': 'fixture',
                                          'line': 1, 'repository_local_path': '/fixture'}}},
        'SourceID': 0, 'SourceType': 16, 'SourceName': 'fixture',
        'DetectorType': 1, 'DetectorName': 'GitHub', 'DetectorDescription': 'fixture',
        'DecoderName': 'PLAIN', 'Verified': False, 'VerificationFromCache': False,
        'Raw': 'synthetic candidate', 'RawV2': '', 'Redacted': 'synthetic',
        'ExtraData': {}, 'StructuredData': None, 'SecretParts': {},
    }


class ScannerOutputTests(unittest.TestCase):
    def count(self, record, code=0):
        return scan.trufflehog_count(json.dumps(record).encode() + b'\n', code)

    def test_qualified_offline_record_is_counted(self):
        self.assertEqual(self.count(truffle_record()), 1)
        self.assertEqual(scan.trufflehog_count(b'', 0), 0)

    def test_verified_cached_and_missing_raw_records_are_incomplete(self):
        for changes in [{'Verified': True}, {'VerificationFromCache': True}, {'Raw': '', 'RawV2': ''}]:
            item = truffle_record()
            item.update(changes)
            with self.subTest(changes=changes), self.assertRaises(IncompleteScan):
                self.count(item)

    def test_unknown_missing_and_wrongly_typed_fields_are_incomplete(self):
        for change in ['extra', 'missing', 'bool-integer', 'structured']:
            item = truffle_record()
            if change == 'extra':
                item['Unexpected'] = 'synthetic diagnostic'
            elif change == 'missing':
                del item['SourceMetadata']
            elif change == 'bool-integer':
                item['DetectorType'] = True
            else:
                item['StructuredData'] = {'unqualified': True}
            with self.subTest(change=change), self.assertRaises(IncompleteScan):
                self.count(item)

    def test_invalid_or_unqualified_source_metadata_is_incomplete(self):
        for metadata in [{}, {'Data': {'Git': {'file': 'fixture'}}},
                         {'Data': {'Filesystem': {'file': 'fixture', 'line': 1}}}]:
            item = truffle_record()
            item['SourceMetadata'] = metadata
            with self.subTest(metadata=metadata), self.assertRaises(IncompleteScan):
                self.count(item)

    def test_unexpected_exit_duplicate_keys_and_output_overflow_are_incomplete(self):
        with self.assertRaises(IncompleteScan):
            self.count(truffle_record(), 1)
        for raw in [b'{"key":1,"key":2}', b'{"number":NaN}']:
            with self.assertRaises(IncompleteScan):
                scan.strict_json(raw)
        with self.assertRaises(IncompleteScan):
            scan.trufflehog_count(b'x' * (256 * 1024 + 1), 0)

    def test_gitleaks_clean_and_error_exit_are_distinct(self):
        self.assertEqual(scan.gitleaks_count(b'[]', 0), 0)
        for raw, code in [(b'[]', 1), (b'[]', 2), (b'{}', 0), (b'[{"Secret":"synthetic"}]', 1)]:
            with self.subTest(code=code, raw=raw), self.assertRaises(IncompleteScan):
                scan.gitleaks_count(raw, code)

    def test_exception_filter_cannot_hide_invalid_or_oversized_raw_results(self):
        class AllowAll:
            def allows(self, *args):
                return True
        item = truffle_record()
        item['Verified'] = True
        with self.assertRaises(IncompleteScan):
            scan.trufflehog_count(json.dumps(item).encode(), 0, policy=AllowAll())
        raw = (json.dumps(truffle_record()).encode() + b'\n') * 1001
        with self.assertRaises(IncompleteScan):
            scan.trufflehog_count(raw, 0, policy=AllowAll())
        with self.assertRaises(IncompleteScan):
            scan.gitleaks_count(b'[]', 1, policy=AllowAll())

    def test_wrong_version_and_raw_diagnostics_never_leave_wrapper(self):
        for responses in [[(0, b'wrong version', b'')],
                          [(0, b'trufflehog 3.99.7', b''), (0, b'synthetic candidate', b'synthetic diagnostic')]]:
            with tempfile.TemporaryDirectory() as directory, \
                 patch.object(scan, 'run', side_effect=responses), \
                 patch.object(scan.git_scope, 'prepare', return_value=(Path('/fixture'), 'a' * 40)):
                output = io.StringIO()
                with redirect_stdout(output):
                    result = scan.check('trufflehog', Path('/fixture/scanner'), ROOT, Path(directory))
                self.assertEqual(result, 2)
                self.assertEqual(output.getvalue(), 'Source scan incomplete.\n')
                self.assertEqual(list(Path(directory).iterdir()), [])

    def test_unexpected_metadata_is_not_reclassified_as_clean(self):
        item = truffle_record()
        item['ExtraData'] = 'unqualified'
        with self.assertRaises(IncompleteScan):
            self.count(item)


if __name__ == '__main__':
    unittest.main()
