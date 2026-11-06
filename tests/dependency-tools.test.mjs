import assert from 'node:assert/strict';
import { test } from 'node:test';
import { spawnSync } from 'node:child_process';
import { chmod, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { validateTools } from '../.github/actions/dependency-updates/tools.mjs';

async function fixture(t) {
  await mkdir('.tmp', { recursive: true });
  const root = await mkdtemp(resolve('.tmp', 'updater-tools-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  return root;
}
function inspect(files, versions) {
  return async (command, args) => {
    if (command === 'git') { assert.deepEqual(args, ['ls-files', '-z']); return files.join('\0') + '\0'; }
    assert.ok(command in versions, `Unexpected tool ${command}`);
    return versions[command];
  };
}

test('workspace inheritance uses the declared exact package-manager version', async t => {
  const root = await fixture(t);
  await mkdir(join(root, 'web'));
  await writeFile(join(root, 'package.json'), JSON.stringify({ packageManager: 'pnpm@10.28.0' }));
  await writeFile(join(root, 'web/package.json'), JSON.stringify({ dependencies: { example: '1.0.0' } }));
  await writeFile(join(root, 'pnpm-lock.yaml'), 'lockfileVersion: 9.0\n');
  const files = ['package.json', 'web/package.json', 'pnpm-lock.yaml'];
  await validateTools(root, {}, ['npm'], inspect(files, { pnpm: '10.28.0\n' }));
  await assert.rejects(validateTools(root, {}, ['npm'], inspect(files, { pnpm: '11.0.0\n' })), /does not match/);
});

test('unsupported or undeclared managers and inconsistent workspace pins fail closed', async t => {
  const root = await fixture(t);
  await mkdir(join(root, 'web'));
  await writeFile(join(root, 'package.json'), JSON.stringify({ dependencies: { example: '1.0.0' } }));
  await assert.rejects(validateTools(root, {}, ['npm'], inspect(['package.json'], {})), /exact npm or pnpm/);
  await writeFile(join(root, 'package.json'), JSON.stringify({ packageManager: 'npm@11.17.0' }));
  await writeFile(join(root, 'web/package.json'), JSON.stringify({ packageManager: 'npm@10.0.0' }));
  await writeFile(join(root, 'package-lock.json'), '{}');
  await writeFile(join(root, 'web/package-lock.json'), '{}');
  await assert.rejects(validateTools(root, {}, ['npm'], inspect(['package.json', 'web/package.json', 'package-lock.json', 'web/package-lock.json'], {})), /one installed version/);
  await assert.rejects(validateTools(root, {}, ['npm'], inspect(['web/yarn.lock'], {})), /Only npm/);
  await validateTools(root, { ignorePaths: ['web/**'] }, ['npm'], inspect(['web/yarn.lock'], {}));
});

test('Go checks respect minimum Go and toolchain directives without downloading a compiler', async t => {
  const root = await fixture(t);
  await writeFile(join(root, 'go.mod'), 'module example.test/consumer\n\ngo 1.25.0\ntoolchain go1.25.4\n');
  await validateTools(root, {}, ['gomod'], inspect(['go.mod'], { go: 'go version go1.25.4 linux/amd64' }));
  await assert.rejects(validateTools(root, {}, ['gomod'], inspect(['go.mod'], { go: 'go version go1.25.0 linux/amd64' })), /older/);
});

test('failed bootstrap removes its private state without exposing ambient credentials', async t => {
  const root = await fixture(t);
  const fake = join(root, 'npm');
  const record = join(root, 'observed.json');
  await writeFile(fake, `#!${process.execPath}\nconst fs=require('node:fs');fs.writeFileSync(${JSON.stringify(record)},JSON.stringify({operator:process.env.OPERATOR_SECRET,registry:process.env.npm_config_registry}));process.exit(1);\n`);
  await chmod(fake, 0o700);
  const result = spawnSync(process.execPath, [resolve('.github/actions/dependency-updates/prepare.mjs')], {
    encoding: 'utf8', env: { PATH: root, RUNNER_TEMP: root, OPERATOR_SECRET: 'synthetic-operator-secret' },
  });
  assert.equal(result.status, 1);
  assert.ok(!result.stdout.includes('synthetic-operator-secret'));
  assert.ok(!result.stderr.includes('synthetic-operator-secret'));
  assert.deepEqual(JSON.parse(await readFile(record, 'utf8')), { registry: 'https://registry.npmjs.org/' });
  assert.ok(!(await readdir(root)).some(name => name.startsWith('dependency-engine-')));
});


test('managed modules cannot silently skip missing lockfiles or Go checksums', async t => {
  const root = await fixture(t);
  await writeFile(join(root, 'package.json'), JSON.stringify({ packageManager: 'npm@11.17.0', dependencies: { example: '1.0.0' } }));
  await assert.rejects(validateTools(root, {}, ['npm'], inspect(['package.json'], {})), /committed lockfile/);
  await writeFile(join(root, 'go.mod'), 'module example.test/consumer\n\ngo 1.25.0\nrequire example.test/module v1.0.0\n');
  await assert.rejects(validateTools(root, {}, ['gomod'], inspect(['go.mod'], { go: 'go version go1.25.0 linux/amd64' })), /committed go.sum/);
  await writeFile(join(root, 'go.mod'), 'module example.test/consumer\n\ngo 1.25.0\nreplace example.test/old => example.test/new v1.0.0\n');
  await assert.rejects(validateTools(root, {}, ['gomod'], inspect(['go.mod'], { go: 'go version go1.25.0 linux/amd64' })), /committed go.sum/);
  await writeFile(join(root, 'go.sum'), '');
  await assert.rejects(validateTools(root, {}, ['gomod'], inspect(['go.mod', 'go.sum'], { go: 'go version go1.25.0 linux/amd64' })), /committed go.sum/);
});
