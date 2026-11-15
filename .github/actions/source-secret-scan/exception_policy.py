from datetime import datetime, timezone
from pathlib import PurePosixPath
import re

import git_scope
from process import IncompleteScan, run

PATH = '.github/source-secret-exceptions.json'
FIELDS = {'repository', 'scanner', 'detector', 'path', 'blob_oid', 'owner', 'reason',
          'expires_at', 'removal_condition'}


def tree_blob(repository, env, commit, path):
    if git_scope.commit(repository, env, commit) != commit:
        raise IncompleteScan()
    code, raw, diagnostics = run(
        ['git', '--literal-pathspecs', '-C', str(repository), 'ls-tree', '-z', commit, '--', path],
        cwd=repository, env=env, timeout=30, output_bytes=4096)
    if code or diagnostics:
        raise IncompleteScan()
    if not raw:
        return None
    rows = raw.split(b'\0')
    if len(rows) != 2 or rows[1]:
        raise IncompleteScan()
    metadata, name = rows[0].split(b'\t', 1)
    mode, kind, oid = metadata.decode('ascii').split(' ')
    if (mode not in {'100644', '100755'} or kind != 'blob' or name.decode('utf-8') != path
            or not git_scope.COMMIT.fullmatch(oid)):
        raise IncompleteScan()
    return oid


def policy_revision(repository, env, head, event_name, event, identity):
    if identity is None:
        return None
    repo = identity['repository']
    metadata = event['repository']
    if (not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repo)
            or metadata['full_name'] != repo or identity['sha'] != head):
        raise IncompleteScan()
    default_ref = 'refs/heads/' + metadata['default_branch']
    if event_name == 'pull_request':
        base = event['pull_request']['base']
        if base['repo']['full_name'] != repo:
            raise IncompleteScan()
        if 'refs/heads/' + base['ref'] != default_ref:
            return None
        return git_scope.commit(repository, env, base['sha'])
    if event_name == 'push':
        if event['after'] != head or event['ref'] != identity['ref']:
            raise IncompleteScan()
    elif event_name == 'workflow_dispatch':
        if event['ref'] != identity['ref']:
            raise IncompleteScan()
    else:
        raise IncompleteScan()
    if identity['ref'] != default_ref:
        return None
    return git_scope.commit(repository, env, head)


class Policy:
    def __init__(self, repository, env, entries, clock, head):
        self.repository, self.env, self.entries, self.clock = repository, env, entries, clock
        self.require_active()
        groups = {}
        for entry, _ in entries:
            binding = (entry['scanner'], entry['detector'])
            paths, blobs = groups.setdefault(binding, ({}, {}))
            paths.setdefault(entry['path'], set()).add(entry['blob_oid'])
            blobs.setdefault(entry['blob_oid'], set()).add(entry['path'])
        if groups:
            code, raw, diagnostics = run(
                ['git', '-C', str(repository), 'rev-list', '--all', '--max-count=1025', head],
                cwd=repository, env=env, timeout=30, output_bytes=65536)
            revisions = set(raw.decode('ascii').splitlines()) | {head}
            if code or diagnostics or len(revisions) > 1024:
                raise IncompleteScan()
            for revision in revisions:
                if not git_scope.COMMIT.fullmatch(revision):
                    raise IncompleteScan()
                code, raw, diagnostics = run(
                    ['git', '-C', str(repository), 'ls-tree', '-rz', '--full-tree', revision],
                    cwd=repository, env=env, timeout=30, output_bytes=1024 * 1024)
                if code or diagnostics:
                    raise IncompleteScan()
                for row in raw.split(b'\0'):
                    if not row:
                        continue
                    metadata, name = row.split(b'\t', 1)
                    mode, kind, oid = metadata.decode('ascii').split(' ')
                    name = name.decode('utf-8')
                    for paths, blobs in groups.values():
                        if name in paths or oid in blobs:
                            if (mode not in {'100644', '100755'} or kind != 'blob'
                                    or oid not in paths.get(name, set())
                                    or name not in blobs.get(oid, set())):
                                raise IncompleteScan()

    def require_active(self):
        if any(expiry <= self.clock() for _, expiry in self.entries):
            raise IncompleteScan()

    def allows(self, scanner, detector, path, commit):
        self.require_active()
        choices = [entry for entry, _ in self.entries
                   if (entry['scanner'], entry['detector'], entry['path']) == (scanner, detector, path)]
        if not choices:
            return False
        oid = tree_blob(self.repository, self.env, commit, path)
        if oid is None:
            raise IncompleteScan()
        return any(entry['blob_oid'] == oid for entry in choices)


def load(repository, env, head, event_name, event, identity, decode, clock=None):
    revision = policy_revision(repository, env, head, event_name, event, identity)
    if revision is None:
        return None
    oid = tree_blob(repository, env, revision, PATH)
    if oid is None:
        return None
    code, raw, diagnostics = run(['git', '-C', str(repository), 'cat-file', 'blob', oid],
                                 cwd=repository, env=env, timeout=30, output_bytes=65536)
    if code or diagnostics:
        raise IncompleteScan()
    payload = decode(raw)
    if (not isinstance(payload, dict) or set(payload) != {'version', 'exceptions'}
            or type(payload['version']) is not int or payload['version'] != 1
            or not isinstance(payload['exceptions'], list) or len(payload['exceptions']) > 32):
        raise IncompleteScan()
    seen, entries = set(), []
    for entry in payload['exceptions']:
        if (not isinstance(entry, dict) or set(entry) != FIELDS
                or any(type(value) is not str or not value.strip() or len(value) > 1024
                       for value in entry.values())):
            raise IncompleteScan()
        path = PurePosixPath(entry['path'])
        if (entry['repository'] != identity['repository'] or entry['scanner'] not in {'gitleaks', 'trufflehog'}
                or not re.fullmatch(r'[A-Za-z][A-Za-z0-9._-]{0,79}', entry['detector'])
                or path.is_absolute() or '..' in path.parts or entry['path'] != str(path)
                or not re.fullmatch(r'[A-Za-z0-9._/-]+', entry['path'])
                or not git_scope.COMMIT.fullmatch(entry['blob_oid'])):
            raise IncompleteScan()
        expiry = datetime.strptime(entry['expires_at'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
        if expiry.strftime('%Y-%m-%dT%H:%M:%SZ') != entry['expires_at']:
            raise IncompleteScan()
        key = tuple(entry[field] for field in ('repository', 'scanner', 'detector', 'path', 'blob_oid'))
        if key in seen:
            raise IncompleteScan()
        seen.add(key)
        entries.append((entry, expiry))
    return Policy(repository, env, entries, clock or (lambda: datetime.now(timezone.utc)), head)
