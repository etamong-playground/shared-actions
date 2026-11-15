#!/usr/bin/env python3
import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
import tempfile

import git_scope
from install import TOOLS
from process import IncompleteScan, budget, interruption, run

TRUFFLE_FLAGS = [
    '--no-verification', '--no-update', '--json', '--log-level=-1', '--concurrency=1',
    '--no-ignore-tag', '--force-skip-binaries', '--force-skip-archives',
    '--max-decode-depth=1', '--detector-timeout=2s', '--fail-on-scan-errors',
]
GITLEAKS_FIELDS = {
    'RuleID': str, 'Description': str, 'StartLine': int, 'EndLine': int,
    'StartColumn': int, 'EndColumn': int, 'Match': str, 'Secret': str,
    'File': str, 'SymlinkFile': str, 'Commit': str, 'Author': str, 'Email': str,
    'Date': str, 'Message': str, 'Tags': list, 'Fingerprint': str,
}
TRUFFLE_FIELDS = {
    'SourceMetadata': dict, 'SourceID': int, 'SourceType': int, 'SourceName': str,
    'DetectorType': int, 'DetectorName': str, 'DetectorDescription': str,
    'DecoderName': str, 'Verified': bool, 'VerificationFromCache': bool,
    'Raw': str, 'RawV2': str, 'Redacted': str, 'SecretParts': dict,
}


def strict_json(raw):
    def invalid_constant(_):
        raise IncompleteScan()
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise IncompleteScan()
            result[key] = value
        return result
    return json.loads(raw, parse_constant=invalid_constant, object_pairs_hook=unique_object)


def gitleaks_count(raw, code):
    items = strict_json(raw)
    if not isinstance(items, list) or code not in (0, 1) or len(items) > 1000:
        raise IncompleteScan()
    for item in items:
        if not isinstance(item, dict) or set(item) != set(GITLEAKS_FIELDS) | {'Entropy'}:
            raise IncompleteScan()
        if any(type(item[key]) is not kind for key, kind in GITLEAKS_FIELDS.items()):
            raise IncompleteScan()
        if type(item['Entropy']) not in (int, float) or any(type(tag) is not str for tag in item['Tags']):
            raise IncompleteScan()
        if item['Secret'] != 'REDACTED':
            raise IncompleteScan()
    if bool(items) != bool(code):
        raise IncompleteScan()
    return len(items)


def trufflehog_count(raw, code, staged=False):
    if code != 0:
        raise IncompleteScan()
    count = 0
    for line in raw.splitlines():
        if len(line) > 256 * 1024:
            raise IncompleteScan()
        item = strict_json(line)
        if not isinstance(item, dict) or set(item) != set(TRUFFLE_FIELDS) | {'ExtraData', 'StructuredData'}:
            raise IncompleteScan()
        if any(type(item[key]) is not kind for key, kind in TRUFFLE_FIELDS.items()):
            raise IncompleteScan()
        if (item['Verified'] or item['VerificationFromCache'] or not (item['Raw'] or item['RawV2'])
                or not re.fullmatch(r'[A-Za-z][A-Za-z0-9._-]{0,79}', item['DetectorName'])
                or item['ExtraData'] is not None and type(item['ExtraData']) is not dict
                or item['StructuredData'] is not None):
            raise IncompleteScan()
        source = item['SourceMetadata']
        kind = 'Filesystem' if staged else 'Git'
        if set(source) != {'Data'} or not isinstance(source['Data'], dict) or set(source['Data']) != {kind}:
            raise IncompleteScan()
        location = source['Data'][kind]
        fields = {'file': str, 'line': int} if staged else {
            'commit': str, 'file': str, 'email': str, 'timestamp': str,
            'line': int, 'repository_local_path': str,
        }
        if (not isinstance(location, dict) or set(location) != set(fields)
                or any(type(location[key]) is not value for key, value in fields.items())
                or location['line'] < 0):
            raise IncompleteScan()
        if not staged and not git_scope.COMMIT.fullmatch(location['commit']):
            raise IncompleteScan()
        count += 1
        if count > 1000:
            raise IncompleteScan()
    return count


def staged_files(repository, destination, env):
    code, output, _ = run(['git', '-C', str(repository), 'ls-files', '--stage', '-z'],
                          cwd=repository, env=env, timeout=30, output_bytes=1024 * 1024)
    if code:
        raise IncompleteScan()
    destination.mkdir()
    paths = set()
    total = 0
    for index, row in enumerate(output.split(b'\0')):
        if not row:
            continue
        if index >= 2000:
            raise IncompleteScan()
        metadata, name = row.split(b'\t', 1)
        mode, blob, stage = metadata.decode('ascii').split(' ')
        name = name.decode('utf-8')
        path = PurePosixPath(name)
        if (mode not in {'100644', '100755'} or stage != '0' or path.is_absolute()
                or '..' in path.parts or name != str(path) or name in paths
                or not git_scope.COMMIT.fullmatch(blob)):
            raise IncompleteScan()
        paths.add(name)
        code, contents, _ = run(['git', '-C', str(repository), 'cat-file', 'blob', blob],
                                cwd=repository, env=env, timeout=30, output_bytes=1024 * 1024)
        total += len(contents)
        if code or total > 16 * 1024 * 1024:
            raise IncompleteScan()
        if b'\0' not in contents:
            (destination / f'{index:08d}.txt').write_bytes(contents)


def check(tool, binary, repository, scratch_root, *, staged=False, event_name=None, event=None):
    try:
        scratch_root.mkdir(parents=True, exist_ok=True)
        with interruption(), budget(240), tempfile.TemporaryDirectory(prefix='source-scan-', dir=scratch_root) as directory:
            scratch = Path(directory).resolve()
            env = git_scope.environment(scratch)
            version_args = ['version'] if tool == 'gitleaks' else ['--version']
            code, version, diagnostics = run([str(binary), *version_args], cwd=scratch, env=env,
                                             timeout=10, output_bytes=4096)
            expected = TOOLS[tool]['version'] if tool == 'gitleaks' else 'trufflehog ' + TOOLS[tool]['version']
            if code or diagnostics or version.decode().strip().removeprefix('v') != expected:
                raise IncompleteScan()
            if staged:
                source = scratch / 'staged'
                staged_files(repository, source, env)
                head, base = None, None
            else:
                source, head = git_scope.prepare(repository, scratch, env)
                base = (git_scope.range_base(source, env, head, event_name, event)
                        if tool == 'trufflehog' and event_name is not None else None)
            if tool == 'gitleaks':
                config, ignore = scratch / 'rules.toml', scratch / 'ignore'
                config.write_text('[extend]\nuseDefault = true\n')
                ignore.write_text('')
                command = [str(binary), 'dir' if staged else 'git', str(source), '--config', str(config),
                           '--gitleaks-ignore-path', str(ignore), '--ignore-gitleaks-allow',
                           '--redact=100', '--no-banner', '--no-color', '--log-level=fatal',
                           '--max-decode-depth=0', '--max-archive-depth=0',
                           '--exit-code=1', '--report-format=json', '--report-path=-', '--timeout=180']
                if not staged:
                    command += ['--log-opts=--all --full-history']
            else:
                command = [str(binary), *TRUFFLE_FLAGS]
                if staged:
                    command += ['filesystem', '--max-symlink-depth=0', str(source)]
                else:
                    command += ['git', source.as_uri(), '--bare', '--trust-local-git-config']
                    if base:
                        command += ['--since-commit=' + base, '--branch=' + head]
            code, output, diagnostics = run(command, cwd=scratch, env=env)
            if diagnostics:
                raise IncompleteScan()
            count = gitleaks_count(output, code) if tool == 'gitleaks' else trufflehog_count(output, code, staged)
    except (IncompleteScan, OSError, ValueError, TypeError, KeyError, RecursionError):
        print('Source scan incomplete.')
        return 2
    if count:
        print(f'Source scan found {count} candidate(s).')
        return 1
    print('Source scan clean.')
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('tool', choices=TOOLS)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--repository', type=Path, default=Path('.'))
    parser.add_argument('--staged', action='store_true')
    args = parser.parse_args(argv)
    try:
        event_name, event = None, None
        if os.environ.get('GITHUB_ACTIONS') == 'true':
            if args.staged:
                raise IncompleteScan()
            event_name = os.environ['GITHUB_EVENT_NAME']
            if event_name not in {'pull_request', 'push', 'workflow_dispatch'}:
                raise IncompleteScan()
            with open(os.environ['GITHUB_EVENT_PATH'], 'rb') as source:
                raw = source.read(2 * 1024 * 1024 + 1)
            if len(raw) > 2 * 1024 * 1024:
                raise IncompleteScan()
            event = strict_json(raw)
        root = Path(os.environ.get('RUNNER_TEMP', '.tmp')) / 'source-scans'
        return check(args.tool, args.binary.resolve(), args.repository.resolve(), root,
                     staged=args.staged, event_name=event_name, event=event)
    except (IncompleteScan, OSError, ValueError, TypeError, KeyError, RecursionError):
        print('Source scan incomplete.')
        return 2


if __name__ == '__main__':
    sys.exit(main())
