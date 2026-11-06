import assert from 'node:assert/strict';
import { test } from 'node:test';
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { configuration, inputs } from '../.github/actions/dependency-updates/policy.mjs';
import { childEnvironment } from '../.github/actions/dependency-updates/run.mjs';
import { validateTools } from '../.github/actions/dependency-updates/tools.mjs';
import { runCommand } from '../.github/actions/dependency-updates/process.mjs';

const action = resolve('.github/actions/dependency-updates');
const runtime = join(action, 'runtime/node_modules');
const native = name => import(pathToFileURL(join(runtime, 'renovate/dist', name)));
const input = { GITHUB_REPOSITORY: 'example/service', UPDATE_BOT: 'updater[bot]', UPDATE_DRY_RUN: 'true', UPDATE_WRITER_TOKEN: 'synthetic-caller', UPDATE_PR_LIMIT: '3' };

function command(file, args, options = {}) {
  const result = spawnSync(file, args, { encoding: 'utf8', ...options });
  assert.equal(result.status, 0, `${file} ${args.join(' ')}\n${result.stderr}`);
  return result.stdout.trim();
}
async function fixture(t) {
  await mkdir('.tmp', { recursive: true });
  const directory = await mkdtemp(resolve('.tmp', 'native-updater-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  return directory;
}

test('the actual pinned engine validates normal and maintenance configurations without warnings', () => {
  for (const maintenance of [false, true]) {
    const result = spawnSync(process.execPath, [join(runtime, 'renovate/dist/config-validator.js'), '--strict', join(action, 'config.cjs')], {
      encoding: 'utf8', env: { PATH: process.env.PATH, LOG_FORMAT: 'json', ...input, UPDATE_POLICY: '{}', UPDATE_PREFLIGHT: JSON.stringify({ managers: ['npm', 'gomod'], count: maintenance ? 3 : 0, maintenance }) },
    });
    assert.equal(result.status, 0, result.stdout + result.stderr);
    const records = result.stdout.split('\n').filter(Boolean).map(line => JSON.parse(line));
    assert.ok(records.some(record => record.msg === 'Config validated successfully against 1 file(s)'));
    assert.deepEqual(records.filter(record => record.level >= 40), [], 'Validator warnings are failures even when its exit status is zero');
  }
});

test('native HTTP credential selection retains the caller and bounds package/source readers', async () => {
  const rules = await native('util/host-rules.js');
  rules.clear();
  const config = inputs({ ...input, UPDATE_SOURCE_TOKEN: 'synthetic-source', UPDATE_SOURCE_REPOSITORIES: '["example/private"]', UPDATE_PACKAGE_TOKEN: 'synthetic-package', UPDATE_PACKAGE_SCOPE: '@private', UPDATE_REGISTRY_URL: 'https://packages.example/team/' });
  rules.add({ hostType: 'github', matchHost: 'https://api.github.com/', token: config.token });
  for (const rule of configuration(config, {}, { managers: ['npm', 'gomod'], count: 0 }).hostRules) rules.add(rule);
  assert.equal(rules.find({ hostType: 'github', url: 'https://api.github.com/repos/example/service/pulls' }).token, 'synthetic-caller');
  assert.equal(rules.find({ hostType: 'github-tags', url: 'https://api.github.com/repos/example/private/tags' }).token, 'synthetic-source');
  assert.notEqual(rules.find({ hostType: 'github-tags', url: 'https://api.github.com/repos/example/private-other/tags' }).token, 'synthetic-source');
  assert.equal(rules.find({ hostType: 'npm', url: 'https://packages.example/team/@private%2fmodule' }).token, 'synthetic-package');
  assert.equal(rules.find({ hostType: 'npm', url: 'https://packages.example/other/module' }).token, undefined);
  rules.clear();
});

test('real Git applies private reader headers only to the exact repository path', async t => {
  const root = await fixture(t);
  const selected = inputs({ ...input, UPDATE_SOURCE_TOKEN: 'synthetic-source', UPDATE_SOURCE_REPOSITORIES: '["example/private"]' });
  const runtimeEnv = childEnvironment(input, selected, {}, { managers: ['gomod'] }, root);
  const { GlobalConfig } = await native('config/global.js');
  const { getChildEnv } = await native('util/exec/utils.js');
  const { parseConfigs } = await native('workers/global/config/parse/index.js');
  const previous = Object.fromEntries(Object.keys(runtimeEnv).map(key => [key, process.env[key]]));
  Object.assign(process.env, runtimeEnv);
  try { await parseConfigs(runtimeEnv, []); } finally {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
  }
  GlobalConfig.set({ exposeAllEnv: false });
  const env = { ...getChildEnv(), PATH: process.env.PATH };
  for (const url of ['https://github.com/example/private', 'https://github.com/example/private.git', 'https://writer@github.com/example/private.git']) {
    assert.equal(command('git', ['config', '--get-urlmatch', 'http.extraHeader', url], { env }), `Authorization: Basic ${Buffer.from('x-access-token:synthetic-source').toString('base64')}`);
  }
  for (const url of ['https://github.com/example/private-other', 'https://github.com/example/private.git-other', 'https://github.com/example/service.git']) {
    assert.equal(spawnSync('git', ['config', '--get-urlmatch', 'http.extraHeader', url], { env }).status, 1);
  }
  const observed = [];
  const server = createServer((request, response) => { observed.push(request.headers.authorization); response.writeHead(404); response.end(); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;
  const local = { PATH: process.env.PATH, HOME: root, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_COUNT: '1', GIT_CONFIG_KEY_0: `http.${base}/private.git.extraHeader`, GIT_CONFIG_VALUE_0: 'Authorization: Basic synthetic-reader', GIT_TERMINAL_PROMPT: '0' };
  for (const name of ['private.git', 'private.git-other']) {
    await new Promise(resolve => {
      const child = spawn('git', ['ls-remote', `${base.replace('http://', 'http://writer@')}/${name}`], { env: local, stdio: 'ignore' });
      child.on('close', resolve);
    });
  }
  assert.equal(observed[0], 'Basic synthetic-reader');
  assert.notEqual(observed[1], 'Basic synthetic-reader');
});

for (const manager of ['npm', 'pnpm']) test(`native npm manifest update and ${manager} lock resolve the intended tarball`, async t => {
  const root = await fixture(t);
  const packages = [];
  for (const [version, value] of [['1.0.0', 1], ['1.1.0', 2]]) {
    const folder = join(root, version);
    await mkdir(folder);
    await writeFile(join(folder, 'package.json'), JSON.stringify({ name: 'fixture-dep', version, main: 'index.js' }));
    await writeFile(join(folder, 'index.js'), `module.exports = ${value};\n`);
    const filename = command('npm', ['pack', '--ignore-scripts', '--json'], { cwd: folder });
    packages.push(join(folder, JSON.parse(filename)[0].filename));
  }
  const consumer = join(root, 'consumer');
  await mkdir(consumer);
  const original = JSON.stringify({ name: 'fixture-consumer', private: true, version: '1.0.0', ...(manager === 'pnpm' ? { packageManager: 'pnpm@10.28.0' } : {}), dependencies: { 'fixture-dep': `file:${packages[0]}` } }, null, 2) + '\n';
  await writeFile(join(consumer, 'package.json'), original);
  const env = { ...process.env, npm_config_cache: join(root, 'npm-cache') };
  const pm = manager === 'npm' ? ['npm', ['install', '--package-lock-only', '--ignore-scripts', '--offline', '--no-audit']] : [process.execPath, [join(runtime, 'pnpm/bin/pnpm.cjs'), 'install', '--lockfile-only', '--ignore-scripts', '--offline', '--store-dir', join(root, 'pnpm-store')]];
  command(pm[0], pm[1], { cwd: consumer, env });
  const { updateDependency } = await native('modules/manager/npm/update/index.js');
  const changed = updateDependency({ fileContent: original, packageFile: 'package.json', upgrade: { depType: 'dependencies', depName: 'fixture-dep', currentValue: `file:${packages[0]}`, newValue: `file:${packages[1]}` } });
  assert.equal(JSON.parse(changed).dependencies['fixture-dep'], `file:${packages[1]}`);
  await writeFile(join(consumer, 'package.json'), changed);
  command(pm[0], pm[1], { cwd: consumer, env });
  const lock = join(consumer, manager === 'npm' ? 'package-lock.json' : 'pnpm-lock.yaml');
  const contents = await readFile(lock, 'utf8');
  const integrity = 'sha512-' + createHash('sha512').update(await readFile(packages[1])).digest('base64');
  assert.ok(contents.includes(integrity));
  command(pm[0], pm[1], { cwd: consumer, env });
  assert.equal(await readFile(lock, 'utf8'), contents, 'Repeated artifact generation is unchanged');
  if (manager === 'npm') command('npm', ['ci', '--ignore-scripts', '--offline', '--no-audit'], { cwd: consumer, env });
  else command(process.execPath, [join(runtime, 'pnpm/bin/pnpm.cjs'), 'install', '--frozen-lockfile', '--ignore-scripts', '--offline', '--store-dir', join(root, 'pnpm-store')], { cwd: consumer, env });
  assert.equal(command(process.execPath, ['-e', "console.log(require('fixture-dep'))"], { cwd: consumer }), '2');
});

test('native Go update and file-only proxy regenerate checksums and pass the consumer contract', async t => {
  const root = await fixture(t);
  const proxy = join(root, 'proxy');
  await mkdir(proxy);
  command('python3', ['-c', `import pathlib,zipfile,json
root=pathlib.Path(${JSON.stringify(proxy)})/'example.test/module/@v'
root.mkdir(parents=True)
for version,value in [('v1.0.0',1),('v1.1.0',2)]:
    mod='module example.test/module\\n\\ngo 1.25.0\\n'
    (root/(version+'.mod')).write_text(mod)
    (root/(version+'.info')).write_text(json.dumps({'Version':version,'Time':'2026-01-01T00:00:00Z'}))
    with zipfile.ZipFile(root/(version+'.zip'),'w') as z:
        for name,data in [('go.mod',mod),('value.go','package module\\nconst Value = '+str(value)+'\\n')]:
            z.writestr(zipfile.ZipInfo('example.test/module@'+version+'/'+name,date_time=(2026,1,1,0,0,0)),data)
(root/'list').write_text('v1.0.0\\nv1.1.0\\n')
`]);
  const consumer = join(root, 'consumer');
  await mkdir(consumer);
  const original = 'module example.test/consumer\n\ngo 1.25.0\n\nrequire example.test/module v1.0.0\n';
  await writeFile(join(consumer, 'go.mod'), original);
  await writeFile(join(consumer, 'value_test.go'), 'package consumer\nimport ("testing"; dep "example.test/module")\nfunc TestVersion(t *testing.T) { if dep.Value != 2 { t.Fatal(dep.Value) } }\n');
  const env = { ...process.env, GOPROXY: pathToFileURL(proxy).href, GOSUMDB: 'off', GOTOOLCHAIN: 'local', GOFLAGS: '-modcacherw', GOMODCACHE: join(root, 'modules') };
  const { GlobalConfig } = await native('config/global.js');
  GlobalConfig.set({ localDir: consumer });
  const { updateArtifacts } = await native('modules/manager/gomod/artifacts.js');
  assert.equal(await updateArtifacts({ packageFileName: 'go.mod', updatedDeps: [], newPackageFileContent: original, config: {} }), null, 'Native engine skips missing checksums');
  await assert.rejects(validateTools(consumer, {}, ['gomod'], async command => command === 'git' ? 'go.mod\0value_test.go\0' : 'go version go1.25.0 linux/amd64'), /committed go.sum/);
  command('go', ['mod', 'tidy'], { cwd: consumer, env });
  const { updateDependency } = await native('modules/manager/gomod/update.js');
  const changed = updateDependency({ fileContent: original, upgrade: { depType: 'require', depName: 'example.test/module', currentValue: 'v1.0.0', newValue: 'v1.1.0', managerData: { lineNumber: 4, multiLine: false } } });
  assert.ok(changed.includes('require example.test/module v1.1.0'));
  await writeFile(join(consumer, 'go.mod'), changed);
  command('go', ['mod', 'tidy'], { cwd: consumer, env });
  const checksums = await readFile(join(consumer, 'go.sum'), 'utf8');
  assert.match(checksums, /example\.test\/module v1\.1\.0 h1:/);
  command('go', ['test', './...'], { cwd: consumer, env });
  command('go', ['mod', 'tidy'], { cwd: consumer, env });
  assert.equal(await readFile(join(consumer, 'go.sum'), 'utf8'), checksums);
});

test('subprocess timeout rejects and does not print credential-bearing subprocess output', async t => {
  const root = await fixture(t);
  const signal = new AbortController().signal;
  await assert.rejects(runCommand(process.execPath, ['-e', "console.log('synthetic-secret');setInterval(()=>{},1000)"], { env: { PATH: process.env.PATH }, cwd: root, signal, timeout: 30 }), /timed out/);
});


test('native extraction and package rules leave package-manager declarations disabled', async () => {
  const { extractPackageJson } = await native('modules/manager/npm/extract/common/package-file.js');
  const { applyPackageRules } = await native('util/package-rules/index.js');
  const extracted = extractPackageJson({ packageManager: 'pnpm@10.28.0', devEngines: { packageManager: { name: 'pnpm', version: '10.28.0' } } }, 'package.json');
  assert.deepEqual(extracted.deps.map(dep => dep.depType).sort(), ['devEngines.packageManager', 'packageManager']);
  const rules = configuration(inputs(input), {}, { managers: ['npm'], count: 0 }).force.packageRules;
  for (const dep of extracted.deps) {
    const configured = await applyPackageRules({ ...dep, manager: 'npm', packageRules: rules });
    assert.equal(configured.enabled, false);
  }
});
