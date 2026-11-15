import os
from pathlib import Path
import re

from process import IncompleteScan, run

COMMIT = re.compile(r'[0-9a-f]{40}')


def environment(scratch):
    home = scratch / 'home'
    home.mkdir()
    temporary = scratch / 'tmp'
    temporary.mkdir()
    return {
        'PATH': os.environ.get('PATH', os.defpath), 'HOME': str(home),
        'TMPDIR': str(temporary), 'LANG': 'C', 'LC_ALL': 'C',
        'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull,
        'GIT_TERMINAL_PROMPT': '0', 'GIT_NO_REPLACE_OBJECTS': '1',
        'GIT_CONFIG_COUNT': '4',
        'GIT_CONFIG_KEY_0': 'protocol.allow', 'GIT_CONFIG_VALUE_0': 'never',
        'GIT_CONFIG_KEY_1': 'protocol.file.allow', 'GIT_CONFIG_VALUE_1': 'always',
        'GIT_CONFIG_KEY_2': 'core.hooksPath', 'GIT_CONFIG_VALUE_2': os.devnull,
        'GIT_CONFIG_KEY_3': 'core.fsmonitor', 'GIT_CONFIG_VALUE_3': 'false',
    }


def git(repository, env, *arguments):
    code, output, _ = run(['git', '-C', str(repository), *arguments],
                          cwd=repository, env=env, timeout=60, output_bytes=1024 * 1024)
    if code:
        raise IncompleteScan()
    return output.decode('utf-8').strip()


def commit(repository, env, revision):
    if not COMMIT.fullmatch(revision):
        raise IncompleteScan()
    resolved = git(repository, env, 'rev-parse', '--verify', revision + '^{commit}')
    if not COMMIT.fullmatch(resolved):
        raise IncompleteScan()
    return resolved


def prepare(repository, scratch, env):
    repository = repository.resolve()
    if git(repository, env, 'rev-parse', '--is-shallow-repository') != 'false':
        raise IncompleteScan()
    head = git(repository, env, 'rev-parse', '--verify', 'HEAD^{commit}')
    if not COMMIT.fullmatch(head):
        raise IncompleteScan()
    refs = git(repository, env, 'for-each-ref', '--format=%(refname) %(objectname)')
    destination = scratch / 'source.git'
    code, _, _ = run(['git', 'clone', '--mirror', '--no-local', '--',
                       repository.as_uri(), str(destination)], cwd=scratch, env=env,
                      timeout=60, output_bytes=1024 * 1024)
    if code:
        raise IncompleteScan()
    (destination / 'config').write_text('[core]\nrepositoryformatversion = 0\nbare = true\n')
    if git(destination, env, 'rev-parse', '--is-shallow-repository') != 'false':
        raise IncompleteScan()
    if commit(destination, env, head) != head:
        raise IncompleteScan()
    if (git(destination, env, 'for-each-ref', '--format=%(refname) %(objectname)') != refs
            or git(repository, env, 'for-each-ref', '--format=%(refname) %(objectname)') != refs
            or git(repository, env, 'rev-parse', '--verify', 'HEAD^{commit}') != head):
        raise IncompleteScan()
    return destination, head


def range_base(repository, env, head, event_name, event):
    if event_name == 'pull_request':
        base = commit(repository, env, event['pull_request']['base']['sha'])
        base = git(repository, env, 'merge-base', base, head)
        return commit(repository, env, base)
    if event_name == 'push':
        before = commit(repository, env, event['before'])
        after = commit(repository, env, event['after'])
        if after != head:
            raise IncompleteScan()
        return before
    if event_name == 'workflow_dispatch':
        return None
    raise IncompleteScan()
