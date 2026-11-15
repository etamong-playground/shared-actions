#!/usr/bin/env python3
import argparse
import hashlib
import io
import os
from pathlib import Path
import platform
import sys
import tarfile
import tempfile
import urllib.request

TOOLS = {
    'gitleaks': {
        'version': '8.30.1', 'repository': 'gitleaks/gitleaks',
        'assets': {
            ('Darwin', 'arm64'): ('darwin_arm64', 'b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5'),
            ('Darwin', 'amd64'): ('darwin_x64', 'dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709'),
            ('Linux', 'arm64'): ('linux_arm64', 'e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080'),
            ('Linux', 'amd64'): ('linux_x64', '551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb'),
        },
    },
    'trufflehog': {
        'version': '3.99.7', 'repository': 'trufflesecurity/trufflehog',
        'assets': {
            ('Darwin', 'arm64'): ('darwin_arm64', '5540ef352fc88b1f580e91603689782c0107ca7d4a96c1aeb2714b3a98c766ce'),
            ('Darwin', 'amd64'): ('darwin_amd64', '6bdbc7b0aaeefcb50275036b49be1a3561b3c2e5902879300339abf9c64914c0'),
            ('Linux', 'arm64'): ('linux_arm64', '3060f7c9f18c70afdc432984cacabdd1e9103729b5d5fee7fb6755a90d1c59d4'),
            ('Linux', 'amd64'): ('linux_amd64', 'bdbea0508e439b144f49de14e775908de5f902f3d14ea7ae8354bae72b0b72ef'),
        },
    },
}
ARCHIVE_BYTES = 128 * 1024 * 1024
BINARY_BYTES = 384 * 1024 * 1024


def asset(tool):
    arch = {'aarch64': 'arm64', 'x86_64': 'amd64'}.get(platform.machine(), platform.machine())
    settings = TOOLS[tool]
    name, digest = settings['assets'][(platform.system(), arch)]
    version = settings['version']
    url = (f'https://github.com/{settings["repository"]}/releases/download/v{version}/'
           f'{tool}_{version}_{name}.tar.gz')
    return url, digest


def archive_binary(archive, expected_digest, tool):
    if len(archive) > ARCHIVE_BYTES or hashlib.sha256(archive).hexdigest() != expected_digest:
        raise ValueError('Archive verification failed')
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as source:
        binaries = []
        total = 0
        for index, member in enumerate(source):
            total += member.size
            if index >= 100 or member.size > BINARY_BYTES or total > 512 * 1024 * 1024:
                raise ValueError('Archive entry budget exceeded')
            if member.name == tool:
                binaries.append(member)
        if len(binaries) != 1 or not binaries[0].isfile() or not 0 < binaries[0].size <= BINARY_BYTES:
            raise ValueError('Invalid archive binary')
        with source.extractfile(binaries[0]) as binary:
            result = binary.read(BINARY_BYTES + 1)
        if len(result) != binaries[0].size:
            raise ValueError('Invalid archive binary size')
        return result


def install(tool, directory):
    url, digest = asset(tool)
    with urllib.request.urlopen(url, timeout=60) as response:
        archive = response.read(ARCHIVE_BYTES + 1)
    binary = archive_binary(archive, digest, tool)
    directory.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=tool + '-', dir=directory)
    try:
        with os.fdopen(descriptor, 'wb') as output:
            output.write(binary)
            output.flush()
            os.fchmod(output.fileno(), 0o700)
        os.replace(temporary, directory / tool)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return (directory / tool).resolve()


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('tool', choices=TOOLS)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args(argv)
    try:
        install(args.tool, args.directory)
    except (OSError, ValueError, KeyError, tarfile.TarError):
        print('Scanner installation incomplete.', file=sys.stderr)
        return 2
    print('Pinned scanner installed with verified archive checksum.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
