import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, mkdir, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { inputs, validateEvent, readPolicy, github, preflight, configuration, verifyArtifacts, verifyCaller } from '../.github/actions/dependency-updates/policy.mjs';
import { run, childEnvironment } from '../.github/actions/dependency-updates/run.mjs';

const env = {
  GITHUB_REPOSITORY: 'example/service', UPDATE_BOT: 'updater[bot]', UPDATE_DRY_RUN: 'true',
  UPDATE_WRITER_TOKEN: 'synthetic-caller-token', UPDATE_PR_LIMIT: '3',
  GITHUB_REF: 'refs/heads/main', GITHUB_EVENT_NAME: 'workflow_dispatch',
};
const event = { repository: { full_name: env.GITHUB_REPOSITORY, default_branch: 'main' } };
const own = (number, extra = {}) => ({ number, title: 'Update dependency', body: '', labels: [], base: { sha: 'a'.repeat(40) }, user: { login: 'updater[bot]' }, head: { repo: { full_name: 'example/service' }, ref: `dependency-updates/dep-${number}`, sha: String(number).repeat(40).slice(0, 40) }, ...extra });
const config = () => inputs(env);
const pages = (values = {}) => {
  const read = async path => values[path] ?? (/^pulls\/\d+\/commits$/.test(path) ? [{ commit: { author: { email: 'example-service@dependency-updates.invalid' }, committer: { email: 'example-service@dependency-updates.invalid' } } }] : []);
  read.manifest = async () => '{}';
  return read;
};
const now = Date.parse('2026-11-05T00:00:00Z');

async function fixture(t) {
  await mkdir('.tmp', { recursive: true });
  const root = await mkdtemp(resolve('.tmp', 'updater-test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  return root;
}

test('caller, write mode and source credentials are explicit', () => {
  assert.equal(config().dryRun, true);
  for (const patch of [{ GITHUB_REPOSITORY: '../other' }, { UPDATE_BOT: 'human' }, { UPDATE_DRY_RUN: 'yes' }, { UPDATE_PR_LIMIT: '0' }, { UPDATE_PR_LIMIT: '11' }, { UPDATE_SOURCE_TOKEN: 'synthetic-caller-token', UPDATE_SOURCE_REPOSITORIES: '["example/private"]' }, { UPDATE_SOURCE_TOKEN: 'reader' }, { UPDATE_SOURCE_TOKEN: 'reader', UPDATE_SOURCE_REPOSITORIES: '["example/service"]' }, { UPDATE_SOURCE_TOKEN: 'reader', UPDATE_SOURCE_REPOSITORIES: '["example/*"]' }]) assert.throws(() => inputs({ ...env, ...patch }));
  validateEvent(config(), event, env);
  for (const patch of [{ GITHUB_EVENT_NAME: 'pull_request' }, { GITHUB_EVENT_NAME: 'pull_request_target' }, { GITHUB_REF: 'refs/heads/feature' }]) assert.throws(() => validateEvent(config(), event, { ...env, ...patch }));
  assert.throws(() => validateEvent(config(), { repository: { ...event.repository, full_name: 'fork/service' } }, env));
  assert.throws(() => validateEvent(config(), { repository: { ...event.repository, fork: true } }, env));
  assert.throws(() => inputs({ ...env, GITHUB_API_URL: 'https://enterprise.example/api' }));
  const writing = inputs({ ...env, UPDATE_DRY_RUN: 'false' });
  assert.throws(() => validateEvent(writing, event, env));
  validateEvent(writing, event, { ...env, UPDATE_WRITE_ENABLED: 'true' });
});

test('registry reader is separately scoped to an HTTPS origin/path', () => {
  const valid = { ...env, UPDATE_PACKAGE_TOKEN: 'package-reader', UPDATE_PACKAGE_SCOPE: '@private', UPDATE_REGISTRY_URL: 'https://packages.example/team/' };
  assert.equal(inputs(valid).registry, 'https://packages.example/team/');
  for (const url of ['http://packages.example/', 'https://secret@packages.example/', 'https://packages.example/?token=secret', 'https://packages.example/#fragment', 'https://packages.example/no-slash', 'https://packages.example/\n']) assert.throws(() => inputs({ ...valid, UPDATE_REGISTRY_URL: url }));
  assert.throws(() => inputs({ ...valid, UPDATE_PACKAGE_TOKEN: valid.UPDATE_WRITER_TOKEN }));
});

test('policy accepts presentation/exclusions and refuses executable or escaping configuration', async t => {
  const root = await fixture(t);
  await writeFile(join(root, 'policy.json'), JSON.stringify({ commitMessagePrefix: 'deps:', ignoreDeps: ['example'] }));
  assert.equal((await readPolicy(root, 'policy.json')).commitMessagePrefix, 'deps:');
  await writeFile(join(root, 'unsafe.json'), JSON.stringify({ postUpgradeTasks: { commands: ['echo unsafe'] } }));
  await assert.rejects(readPolicy(root, 'unsafe.json'), /Unsupported/);
  await symlink('/etc/passwd', join(root, 'escape.json'));
  await assert.rejects(readPolicy(root, 'escape.json'), /outside/);
  await assert.rejects(readPolicy(root, '/etc/passwd'), /relative/);
});

test('capacity keeps managers active in maintenance; foreign renamed manifests pause only their ecosystem', async () => {
  const full = await preflight(config(), pages({ 'pulls?state=open': [own(1), own(2), own(3)] }), now);
  assert.deepEqual(full.managers, ['npm', 'gomod']);
  assert.equal(full.maintenance, true);
  const one = await preflight(config(), pages({ 'pulls?state=open': [{ number: 8, user: { login: 'human' } }], 'pulls/8/files': [{ filename: 'archive/old.txt', previous_filename: 'web/pnpm-lock.yaml' }] }), now);
  assert.deepEqual(one.managers, ['gomod']);
  await assert.rejects(preflight(config(), pages({ 'pulls?state=open': [{ number: 8 }], 'pulls/8/files': [{ filename: 'go.mod' }, { filename: 'package.json' }] }), now), /All dependency/);
  await assert.rejects(preflight(config(), pages({ 'pulls?state=open': [{ number: 8 }], 'pulls/8/files': Array.from({ length: 3000 }, () => ({ filename: 'README.md' })) }), now), /ceiling/);
});

test('closed autoclosed branches cannot evade capacity through native reopen behavior', async () => {
  const closed = own(1, { title: 'dependency - autoclosed', merged_at: null, closed_at: '2026-11-04T00:00:00Z', updated_at: '2026-11-04T00:00:00Z' });
  await assert.rejects(preflight(config(), pages({ 'pulls?state=closed&sort=updated&direction=desc': [closed] }), now), /autoclosed/);
  await preflight(config(), pages({ 'pulls?state=closed&sort=updated&direction=desc': [{ ...closed, merged_at: closed.closed_at }] }), now);
  await assert.rejects(preflight(config(), pages({ 'pulls?state=closed&sort=updated&direction=desc': [{ ...closed, updated_at: 'bad' }] }), now), /history/);
});

test('API errors and incomplete pagination fail with bounded diagnostics', async () => {
  let calls = 0;
  const request = async (url, options) => {
    calls++;
    assert.equal(new URL(url).hostname, 'api.github.com');
    assert.equal(options.headers.Authorization, 'Bearer synthetic-caller-token');
    return { ok: true, json: async () => Array(100).fill({}) };
  };
  await assert.rejects(github(config(), request)('pulls?state=open'), /pagination/);
  assert.equal(calls, 31);
  await assert.rejects(github(config(), async () => ({ ok: false, status: 403 }))('pulls'), /HTTP 403/);
  await assert.rejects(github(config(), async () => { throw new Error('synthetic-secret'); })('pulls'), error => !error.message.includes('synthetic-secret'));
});

test('configuration forces safety controls and capacity modes over presentation policy', () => {
  const result = configuration(config(), { commitMessagePrefix: 'deps:' }, { managers: ['npm'], count: 3, maintenance: true });
  assert.equal(result.mode, 'silent');
  assert.equal(result.force.prCreation, 'approval');
  assert.equal(result.force.draftPR, true);
  assert.equal(result.allowScripts, false);
  assert.equal(result.allowPlugins, false);
  assert.deepEqual(result.allowedCommands, []);
  assert.equal(result.force.automerge, false);
  assert.equal(result.force.platformAutomerge, false);
  assert.equal(result.force.recreateWhen, 'never');
  assert.equal(result.force.vulnerabilityAlerts.enabled, false);
  assert.deepEqual(result.force.gitIgnoredAuthors, []);
  assert.deepEqual(result.force.postUpgradeTasks.commands, []);
  assert.equal(result.force.prHourlyLimit, 1);
  assert.equal(configuration(config(), {}, { managers: ['gomod'], count: 0, maintenance: false }).force.prCreation, 'immediate');
});

test('artifact statuses are checked on the exact current update head and read failures stop', async () => {
  const pr = own(3);
  const requested = [];
  const failing = async path => {
    requested.push(path);
    return path === 'pulls?state=open' ? [pr] : path.endsWith('/files') ? [{ filename: 'package.json' }] : [{ context: 'renovate/artifacts', state: 'failure' }];
  };
  failing.manifest = async () => '{}';
  await assert.rejects(verifyArtifacts(config(), failing), /artifact generation failed/);
  assert.deepEqual(requested, ['pulls?state=open', 'pulls/3/files', `commits/${pr.head.sha}/statuses`]);
  await verifyArtifacts(config(), pages({ 'pulls?state=open': [pr], 'pulls/3/files': [{ filename: 'package.json' }], [`commits/${pr.head.sha}/statuses`]: [{ context: 'renovate/artifacts', state: 'success', creator: { login: 'updater[bot]' } }] }));
});

test('worker receives only explicit credentials and no inherited executable configuration', () => {
  const result = childEnvironment({ ...env, RENOVATE_AUTOMERGE: 'true', NODE_OPTIONS: '--require=bad', OPERATOR_SECRET: 'not-forwarded', PATH: '/usr/bin' }, config(), {}, { managers: ['npm'], count: 0 }, '/workspace/temp');
  assert.equal(result.NODE_OPTIONS, undefined);
  assert.equal(result.OPERATOR_SECRET, undefined);
  assert.equal(result.RENOVATE_AUTOMERGE, undefined);
  assert.equal(result.GIT_CONFIG_GLOBAL, '/dev/null');
  assert.equal(result.HOME, '/workspace/temp/home');
});

for (const failure of [false, true]) test(`transient state is removed after engine ${failure ? 'failure' : 'success'}`, async t => {
  const root = await fixture(t);
  await writeFile(join(root, 'event.json'), JSON.stringify(event));
  await writeFile(join(root, 'policy.json'), '{}');
  const runtime = { ...env, GITHUB_WORKSPACE: root, GITHUB_EVENT_PATH: join(root, 'event.json'), UPDATE_POLICY_PATH: 'policy.json', RUNNER_TEMP: root, PATH: process.env.PATH };
  let directory;
  const operation = run(runtime, {
    request: async url => ({ ok: true, json: async () => url.includes('/installation/') ? { total_count: 1, repositories: [{ full_name: env.GITHUB_REPOSITORY }] } : url.endsWith('/graphql') ? { data: { viewer: { login: env.UPDATE_BOT } } } : [] }),
    tools: async () => {},
    execute: async child => {
      directory = child.TMPDIR;
      assert.ok(directory.startsWith(root));
      assert.deepEqual(JSON.parse(child.UPDATE_PREFLIGHT).managers, ['npm', 'gomod']);
      await writeFile(join(directory, 'transient'), 'fixture state');
      if (failure) throw new Error('Controlled engine failure');
    },
  });
  if (failure) await assert.rejects(operation, /Controlled/); else await operation;
  assert.ok(directory);
  assert.ok(!(await readdir(root)).some(name => name.startsWith('dependency-updates-')));
});

test('rejected events never start a worker or inspect pull requests', async t => {
  const root = await fixture(t);
  await writeFile(join(root, 'event.json'), JSON.stringify(event));
  await assert.rejects(run({ ...env, GITHUB_EVENT_PATH: join(root, 'event.json'), GITHUB_EVENT_NAME: 'pull_request' }, { request: () => assert.fail('API not allowed'), execute: () => assert.fail('engine not allowed') }), /default-branch/);
});


test('human fixes pause their ecosystem and manual rebase cannot override preservation', async () => {
  const pr = own(4);
  const result = await preflight(config(), pages({
    'pulls?state=open': [pr],
    'pulls/4/commits': [{ commit: { author: { email: 'human@example.invalid' }, committer: { email: 'human@example.invalid' } } }],
    'pulls/4/files': [{ filename: 'web/package.json' }],
  }), now);
  assert.deepEqual(result.managers, ['gomod']);
  assert.equal(result.count, 1);
  await assert.rejects(preflight(config(), pages({ 'pulls?state=open': [own(4, { title: 'rebase! Update dependency' })] }), now), /Manual rebase/);
  await assert.rejects(preflight(config(), pages({ 'pulls?state=open': [own(4, { body: '- [x] <!-- rebase-check --> request rebase' })] }), now), /Manual rebase/);
});


test('published update files and Go compiler directives stay within the contract', async () => {
  const pr = own(5, { base: { sha: 'a'.repeat(40) } });
  await assert.rejects(verifyArtifacts(config(), pages({ 'pulls?state=open': [pr], 'pulls/5/files': [{ filename: '.github/workflows/release.yml' }] })), /outside/);
  const api = pages({ 'pulls?state=open': [pr], 'pulls/5/files': [{ filename: 'go.mod' }], [`commits/${pr.head.sha}/statuses`]: [{ context: 'renovate/artifacts', state: 'success', creator: { login: 'updater[bot]' } }] });
  api.manifest = async (path, sha) => sha === pr.base.sha ? 'go 1.25.0' : 'go 1.26.0';
  await assert.rejects(verifyArtifacts(config(), api), /toolchain directives/);
  api.manifest = async () => 'go 1.25.0';
  await verifyArtifacts(config(), api);
});


test('a missing or unrelated artifact publication is not success', async () => {
  const pr = own(6);
  for (const statuses of [[], [{ context: 'renovate/artifacts', state: 'success', creator: { login: 'other[bot]' } }]]) {
    await assert.rejects(verifyArtifacts(config(), pages({ 'pulls?state=open': [pr], 'pulls/6/files': [{ filename: 'package.json' }], [`commits/${pr.head.sha}/statuses`]: statuses })), /artifact generation failed/);
  }
});

test('the commits endpoint ceiling stops inspection before native update selection', async () => {
  const commit = { commit: { author: { email: 'example-service@dependency-updates.invalid' }, committer: { email: 'example-service@dependency-updates.invalid' } } };
  await assert.rejects(preflight(config(), pages({ 'pulls?state=open': [own(7)], 'pulls/7/commits': Array(250).fill(commit) }), now), /complete update branch authors/);
});

test('package manager and runtime declarations cannot change in published PRs', async () => {
  const pr = own(8);
  const api = pages({ 'pulls?state=open': [pr], 'pulls/8/files': [{ filename: 'package.json' }], [`commits/${pr.head.sha}/statuses`]: [{ context: 'renovate/artifacts', state: 'success', creator: { login: 'updater[bot]' } }] });
  api.manifest = async (path, sha) => JSON.stringify({ packageManager: sha === pr.base.sha ? 'pnpm@10.28.0' : 'pnpm@11.0.0' });
  await assert.rejects(verifyArtifacts(config(), api), /runtime declarations/);
});


test('unchanged paused human heads are retained without claiming new artifact evidence', async () => {
  const pr = own(9);
  const paused = [{ number: pr.number, sha: pr.head.sha }];
  await verifyArtifacts(config(), pages({ 'pulls?state=open': [pr] }), paused);
  const changed = { ...pr, head: { ...pr.head, sha: 'b'.repeat(40) } };
  await assert.rejects(verifyArtifacts(config(), pages({ 'pulls?state=open': [changed] }), paused), /complete update artifacts/);
});

test('foreign ecosystem work pauses matching existing bot heads while Go stays eligible', async () => {
  const pr = own(1);
  const result = await preflight(config(), pages({ 'pulls?state=open': [pr, { number: 2 }], 'pulls/2/files': [{ filename: 'web/package.json' }], 'pulls/1/files': [{ filename: 'web/pnpm-lock.yaml' }] }), now);
  assert.deepEqual(result.managers, ['gomod']);
  assert.deepEqual(result.pausedHeads, [{ number: pr.number, sha: pr.head.sha }]);
});


test('actual caller identity and one-repository installation scope must match before work', async () => {
  const request = (repos, login) => async url => ({ ok: true, json: async () => url.includes('/installation/') ? { total_count: repos.length, repositories: repos.map(full_name => ({ full_name })) } : { data: { viewer: { login } } } });
  await verifyCaller(config(), request(['example/service'], 'updater[bot]'));
  await assert.rejects(verifyCaller(config(), request(['example/service', 'example/other'], 'updater[bot]')), /limited/);
  await assert.rejects(verifyCaller(config(), request(['example/service'], 'different[bot]')), /configured bot/);
  await assert.rejects(verifyCaller(config(), async () => ({ ok: false })), /Cannot verify/);
});
