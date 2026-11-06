import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { readFile, realpath } from 'node:fs/promises';
import { dirname, join, sep } from 'node:path';
import { extractPackageFile } from './runtime/node_modules/renovate/dist/modules/manager/gomod/extract.js';
import { minimatch } from './runtime/node_modules/minimatch/dist/esm/index.js';

const exec = promisify(execFile);

export async function validateTools(workspace, policy, managers, inspect) {
  const root = await realpath(workspace);
  const readCommand = inspect ?? (async (command, args) => {
    try {
      const result = await exec(command, args, {
        cwd: root, timeout: 30000, maxBuffer: 2 * 1024 * 1024,
        env: { PATH: process.env.PATH, HOME: root, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GOTOOLCHAIN: 'local' },
      });
      return result.stdout;
    } catch { throw new Error('Cannot inspect caller files or installed tool versions'); }
  });
  const listed = (await readCommand('git', ['ls-files', '-z'])).split('\0').filter(Boolean);
  const ignored = ['**/node_modules/**', '**/bower_components/**', ...(policy.ignorePaths ?? [])];
  const paths = listed.filter(path => !ignored.some(pattern => minimatch(path, pattern, { dot: true })));
  if (paths.length > 20000) throw new Error('Caller file inspection exceeded its limit');
  const read = async path => {
    const selected = await realpath(join(root, path));
    if (!selected.startsWith(root + sep)) throw new Error('Caller manifest escapes the checkout');
    return readFile(selected, 'utf8');
  };
  const versions = new Map();
  if (managers.includes('npm')) {
    if (paths.some(path => /(^|\/)(yarn\.lock|bun\.lockb?|\.yarnrc\.yml)$/.test(path))) throw new Error('Only npm/pnpm projects are supported; exclude other projects explicitly');
    const manifests = new Map();
    for (const path of paths.filter(path => /(^|\/)package\.json$/.test(path))) {
      try { manifests.set(path, JSON.parse(await read(path))); } catch { throw new Error('Cannot read caller package manifest'); }
    }
    const contains = path => paths.includes(path);
    for (const [path, manifest] of manifests) {
      if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) throw new Error('Invalid caller package manifest');
      if (!manifest.packageManager && !['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'].some(key => manifest[key])) continue;
      let parent = path;
      let declaration;
      while (true) {
        declaration = manifests.get(parent)?.packageManager;
        if (declaration) break;
        const directory = dirname(dirname(parent));
        const next = join(directory, 'package.json');
        if (next === parent) break;
        parent = next;
      }
      const match = typeof declaration === 'string' && /^(npm|pnpm)@(\d+\.\d+\.\d+)(?:\+sha(?:224|256|384|512)\.[a-fA-F0-9]+)?$/.exec(declaration);
      if (!match) throw new Error('Caller packageManager must pin an exact npm or pnpm version');
      const [, name, version] = match;
      let directory = dirname(path);
      let locked = false;
      while (true) {
        for (const file of name === 'pnpm' ? ['pnpm-lock.yaml'] : ['package-lock.json', 'npm-shrinkwrap.json']) {
          const candidate = join(directory, file);
          if (contains(candidate)) {
            if (!(await read(candidate)).trim()) throw new Error('Managed dependency lockfiles must be nonempty');
            locked = true; break;
          }
        }
        if (locked) break;
        const parentDirectory = dirname(directory);
        if (parentDirectory === directory) break;
        directory = parentDirectory;
      }
      if (!locked) throw new Error('Managed npm/pnpm projects require a committed lockfile');
      if (versions.has(name) && versions.get(name) !== version) throw new Error('One worker run requires one installed version per package manager');
      versions.set(name, version);
    }
    for (const [name, version] of versions) if ((await readCommand(name, ['--version'])).trim() !== version) throw new Error('Installed package manager does not match caller packageManager');
  }
  if (managers.includes('gomod') && paths.some(path => /(^|\/)go\.mod$/.test(path))) {
    const version = /go version go(\d+)\.(\d+)(?:\.(\d+))?\b/.exec(await readCommand('go', ['version']));
    if (!version) throw new Error('Cannot establish the installed Go version');
    const current = version.slice(1).map(value => Number(value ?? 0));
    for (const path of paths.filter(path => /(^|\/)(go\.mod|go\.work)$/.test(path))) {
      const body = await read(path);
      if (path.endsWith('go.mod') && extractPackageFile(body)?.deps.some(dependency => dependency.datasource === 'go' && dependency.currentValue)) {
        const sum = path.slice(0, -3) + 'sum';
        if (!paths.includes(sum) || !(await read(sum)).trim()) throw new Error('Managed Go dependencies require a nonempty committed go.sum');
      }
      for (const directive of body.matchAll(/^(?:go|toolchain go)\s*(\d+)\.(\d+)(?:\.(\d+))?\s*$/gm)) {
        const required = directive.slice(1).map(value => Number(value ?? 0));
        const different = required.findIndex((value, index) => value !== current[index]);
        if (different !== -1 && required[different] > current[different]) throw new Error('Installed Go is older than the caller directive');
      }
    }
  }
}
