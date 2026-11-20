import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { collect, exitCode, pnpmVersions, goVersions, vulnerable, audienceFor } from './report.mjs';
import { apiJSON, publish } from './cli.mjs';

const sha = 'a'.repeat(40);
const ctx = { repository: 'example/app', repositoryID: '123', ownerID: '45', runID: '900', attempt: '1', sha, ref: 'refs/heads/main', event: 'push', workflowRef: 'example/app/.github/workflows/security.yml@refs/heads/main', scannerRevision: 'b'.repeat(40) };
const event = { repository: { default_branch: 'main' } };
function alert({ name = 'fixture-child', manifest = 'web/package.json', ecosystem = 'npm', patch = '1.0.1', range = '< 1.0.1', number = 1 } = {}) {
  return { number, dependency: { package: { name, ecosystem }, manifest_path: manifest }, security_advisory: { ghsa_id: 'GHSA-aaaa-bbbb-cccc', severity: 'high', description: 'DO_NOT_RETAIN_PRIVATE_CONTENT' }, security_vulnerability: { vulnerable_version_range: range, first_patched_version: patch ? { identifier: patch } : null } };
}
function fixture({ alerts = [alert()], lock = "lockfileVersion: '9.0'\nimporters: {web: {}}\nsnapshots: {fixture-child@1.0.0: {}}\npackages:\n  fixture-child@1.0.0: {resolution: {integrity: sha512-Zml4dHVyZQ==}}\n", tree = [{ path: 'web/pnpm-lock.yaml', type: 'blob' }], currentPR = sha, fail = '' } = {}) {
  const calls = [];
  return { calls, async json(route) {
    calls.push(route);
    if (fail && route.includes(fail)) throw new Error('DO_NOT_RETAIN_PRIVATE_CONTENT');
    if (route === '/repos/example/app') return { id: 123, owner: { id: 45 }, full_name: 'example/app', default_branch: 'main' };
    if (route.includes('/dependabot/alerts')) return alerts;
    if (route.includes('/git/trees/')) return { tree, truncated: false };
    if (route.includes('/contents/')) return { type: 'file', encoding: 'base64', size: Buffer.byteLength(lock), content: Buffer.from(lock).toString('base64') };
    if (route.includes('/pulls/')) return { state: 'open', head: { sha: currentPR } };
    throw new Error('unexpected fixture request');
  } };
}
test('a residual transitive package fails even with a patched parent manifest', async () => {
  const api = fixture(); const r = await collect(api, ctx, event);
  assert.equal(r.outcome, 'findings'); assert.equal(r.finding_count, 1); assert.equal(exitCode(r), 1);
  assert.deepEqual(r.checks[0].versions, ['1.0.0']); assert.equal(r.coverage.lockfiles, true);
  assert.ok(api.calls.some(p => p.includes(`ref=${sha}`))); assert.ok(!JSON.stringify(r).includes('DO_NOT_RETAIN'));
});
test('a regenerated patched lock is scoped clean, without claiming inventory or deployed safety', async () => {
  const r = await collect(fixture({ lock: "lockfileVersion: '9.0'\nimporters: {web: {}}\nsnapshots: {fixture-child@1.0.1: {}}\npackages:\n  fixture-child@1.0.1: {resolution: {integrity: sha512-Zml4dHVyZQ==}}\n" }), ctx, event);
  assert.equal(r.outcome, 'clean'); assert.equal(exitCode(r), 0); assert.equal(r.checks[0].outcome, 'fixed');
  assert.equal(r.scope, 'dependabot-open-alerts'); assert.equal(r.coverage.inventory, false); assert.equal(r.coverage.reachability, false); assert.equal(r.coverage.deployed, false);
});
test('an affected advisory without a patch remains a finding', async () => {
  const r = await collect(fixture({ alerts: [alert({ patch: null })] }), ctx, event);
  assert.equal(r.checks[0].reason, 'no_upstream_fix'); assert.equal(r.finding_count, 1); assert.equal(exitCode(r), 1);
});
test('empty open-alert scope is clean without a source checkout', async () => {
  const api = fixture({ alerts: [] }); const r = await collect(api, ctx, event);
  assert.equal(exitCode(r), 0); assert.equal(r.alert_count, 0); assert.equal(api.calls.length, 3);
});
for (const scenario of [
  { name: 'API unavailable', options: { fail: '/dependabot/alerts' } },
  { name: 'unsupported lock', options: { lock: 'lockfileVersion: 5.4\npackages: {}\n' } },
  { name: 'missing expected package', options: { lock: 'lockfileVersion: 9\npackages: {}\n' } },
  { name: 'duplicate mapping keys', options: { lock: 'lockfileVersion: 9\npackages: {}\npackages: {}\n' } },
  { name: 'missing lock', options: { tree: [] } },
  { name: 'unsupported range', options: { alerts: [alert({ range: 'not a version range' })] } },
  { name: 'unsupported ecosystem', options: { alerts: [alert({ ecosystem: 'pip' })] } },
  { name: 'credential-shaped metadata', options: { alerts: [alert({ name: 'ghp_fixturevalue' })] } },
]) test(scenario.name + ' remains error rather than clean', async () => {
  const r = await collect(fixture(scenario.options), ctx, event);
  assert.equal(r.outcome, 'error'); assert.equal(exitCode(r), 2); assert.ok(r.errors.length); assert.ok(!JSON.stringify(r).includes('DO_NOT_RETAIN'));
});
test('known findings plus unverified dependencies retain findings and incomplete failure', async () => {
  const r = await collect(fixture({ alerts: [alert(), alert({ number: 2, ecosystem: 'pip' })] }), ctx, event);
  assert.equal(r.outcome, 'error'); assert.equal(r.finding_count, 1); assert.equal(r.coverage.lockfiles, false); assert.equal(exitCode(r), 2);
});
test('PR head movement invalidates the old result and preserves execution/source distinction', async () => {
  const head = 'c'.repeat(40);
  const c = { ...ctx, event: 'pull_request', ref: 'refs/pull/12/merge' };
  const e = { ...event, pull_request: { number: 12, head: { sha: head } } };
  const r = await collect(fixture({ currentPR: 'd'.repeat(40) }), c, e);
  assert.equal(r.source.sha, head); assert.equal(r.execution.sha, sha); assert.equal(exitCode(r), 2); assert.ok(r.errors.includes('stale_pr_head'));
});
test('repository ID mismatch prevents inspection', async () => {
  const r = await collect(fixture(), { ...ctx, repositoryID: '999' }, event);
  assert.equal(exitCode(r), 2); assert.equal(r.coverage.alerts, false);
});
test('duplicate pagination entries and truncated trees cannot establish completeness', async () => {
  const api = fixture(); const original = api.json.bind(api);
  api.json = p => p.includes('/dependabot/alerts') ? Array.from({ length: 100 }, () => alert()) : original(p);
  assert.equal(exitCode(await collect(api, ctx, event)), 2);
  const treeAPI = fixture(); const originalTree = treeAPI.json.bind(treeAPI);
  treeAPI.json = p => p.includes('/git/trees/') ? { tree: [], truncated: true } : originalTree(p);
  assert.equal(exitCode(await collect(treeAPI, ctx, event)), 2);
});
test('pnpm scoped packages and peer-qualified keys use real semver boundaries', () => {
  const s = "lockfileVersion: '6.0'\nimporters: {web: {}}\npackages:\n  /@scope/child@1.0.0(peer@2.0.0): {resolution: {integrity: sha512-Zml4dHVyZQ==}}\n  /@scope/child@1.0.1: {resolution: {integrity: sha512-Zml4dHVyZQ==}}\n";
  assert.deepEqual(pnpmVersions(s, '@scope/child'), ['1.0.0', '1.0.1']);
  assert.equal(vulnerable('1.0.0', '>= 1.0.0, < 1.0.1'), true); assert.equal(vulnerable('1.0.1', '>= 1.0.0, < 1.0.1'), false);
  assert.equal(vulnerable('1.0.1', 'invalid'), undefined);
});
test('Go module inspection excludes replacements and minimum-version inference', async () => {
  const text = 'module example/app\ngo 1.25\nrequire (\n github.com/fixture/child v1.0.0 // indirect\n)\n';
  assert.deepEqual(goVersions(text, 'github.com/fixture/child'), ['v1.0.0']);
  assert.throws(() => goVersions(text, 'stdlib'));
  assert.throws(() => goVersions(text + 'replace github.com/fixture/child => ../child\n', 'github.com/fixture/child'));
  const r = await collect(fixture({ alerts: [alert({ name: 'github.com/fixture/child', manifest: 'go.mod', ecosystem: 'Go' })], lock: text }), ctx, event);
  assert.equal(r.outcome, 'error'); assert.equal(exitCode(r), 2); assert.equal(r.checks[0].reason, 'unverified_go_resolution'); assert.deepEqual(r.checks[0].versions, ['v1.0.0']);
});
test('GitHub API credentials stay on its fixed origin and redirects are rejected', async () => {
  await apiJSON('/repos/example/app', 'synthetic-reader', async (url, options) => {
    assert.equal(url, 'https://api.github.com/repos/example/app'); assert.equal(options.redirect, 'error');
    assert.equal(options.headers.Authorization, 'Bearer synthetic-reader'); return new Response('{}');
  });
  await assert.rejects(apiJSON('https://other.invalid', 'synthetic-reader', () => { throw new Error('must not fetch'); }));
});
test('delivery binds exactly the bytes sent and separates OIDC and receiver credentials', async () => {
  const bytes = Buffer.from('{"schema":1}\n'); const endpoint = 'https://security.example.com/api/security-reports'; const calls = [];
  await publish(endpoint, bytes, 'https://vstoken.actions.githubusercontent.com/id?job=1', 'synthetic-request', async (url, options) => {
    calls.push(url); assert.equal(options.redirect, 'error');
    if (calls.length === 1) {
      assert.equal(new URL(url).searchParams.get('audience'), endpoint + '#sha256=' + createHash('sha256').update(bytes).digest('hex'));
      assert.equal(options.headers.Authorization, 'Bearer synthetic-request'); return Response.json({ value: 'eyJfixture.payload.signature' });
    }
    assert.equal(url, endpoint); assert.equal(options.headers.Authorization, 'Bearer eyJfixture.payload.signature');
    assert.deepEqual(options.body, bytes); return Response.json({ status: 'stored' }, { status: 201 });
  });
  assert.equal(calls.length, 2);
  assert.notEqual(audienceFor(endpoint, bytes), audienceFor(endpoint, Buffer.from('{"schema":1}')));
});
for (const endpoint of ['http://security.example.com/x', 'https://user:password@security.example.com/x', 'https://security.example.com/x?key=value', 'https://security.example.com/x#fragment']) test('unsafe receiver rejected before requesting credentials: ' + new URL(endpoint).protocol, async () => {
  await assert.rejects(publish(endpoint, Buffer.from('{}'), 'https://vstoken.actions.githubusercontent.com/id', 'fixture', () => { throw new Error('must not fetch'); }));
});
test('OIDC request credentials cannot be sent to another host', async () => {
  await assert.rejects(publish('https://security.example.com/x', Buffer.from('{}'), 'https://actions.githubusercontent.com.attacker.invalid/id', 'fixture', () => { throw new Error('must not fetch'); }));
});
test('the actual CLI writes bounded metadata and enforces a finding result without running repository code', async () => {
  await fs.mkdir('.tmp', { recursive: true });
  const dir = await fs.mkdtemp(path.resolve('.tmp/cli-'));
  try {
    const lock = "lockfileVersion: '9.0'\nimporters: {web: {}}\nsnapshots: {fixture-child@1.0.0: {}}\npackages:\n  fixture-child@1.0.0: {resolution: {integrity: sha512-Zml4dHVyZQ==}}\n";
    const bootstrap = `globalThis.fetch = async (url) => {
      const p = new URL(url).pathname;
      const result = p.endsWith('/dependabot/alerts') ? ${JSON.stringify([alert()])}
        : p.includes('/git/trees/') ? {tree:[{path:'web/pnpm-lock.yaml',type:'blob'}],truncated:false}
        : p.includes('/contents/') ? ${JSON.stringify({ type: 'file', encoding: 'base64', size: Buffer.byteLength(lock), content: Buffer.from(lock).toString('base64') })}
        : {id:123,owner:{id:45},full_name:'example/app',default_branch:'main'};
      return Response.json(result);
    };`;
    await fs.writeFile(path.join(dir, 'bootstrap.mjs'), bootstrap);
    await fs.writeFile(path.join(dir, 'event.json'), JSON.stringify({ ...event, private_content: 'DO_NOT_RETAIN_PRIVATE_CONTENT' }));
    const env = { PATH: process.env.PATH, RUNNER_TEMP: dir, GITHUB_EVENT_PATH: path.join(dir, 'event.json'), GITHUB_OUTPUT: path.join(dir, 'output'), GITHUB_STEP_SUMMARY: path.join(dir, 'summary'),
      GITHUB_REPOSITORY: ctx.repository, GITHUB_REPOSITORY_ID: ctx.repositoryID, GITHUB_REPOSITORY_OWNER_ID: ctx.ownerID, GITHUB_RUN_ID: ctx.runID, GITHUB_RUN_ATTEMPT: ctx.attempt,
      GITHUB_SHA: sha, GITHUB_REF: ctx.ref, GITHUB_EVENT_NAME: ctx.event, GITHUB_WORKFLOW_REF: ctx.workflowRef, SCANNER_REVISION: ctx.scannerRevision, ALERTS_READ_TOKEN: 'synthetic-reader' };
    const run = spawnSync(process.execPath, ['--import', path.join(dir, 'bootstrap.mjs'), 'cli.mjs', 'collect'], { env, encoding: 'utf8' });
    assert.equal(run.status, 0, run.stderr);
    const raw = await fs.readFile(path.join(dir, 'dependency-security/report.json'), 'utf8');
    assert.equal(JSON.parse(raw).finding_count, 1); assert.ok(!raw.includes('DO_NOT_RETAIN')); assert.ok(!raw.includes('synthetic-reader'));
    assert.equal((await fs.stat(path.join(dir, 'dependency-security/report.json'))).mode & 0o777, 0o600);
    const finish = spawnSync(process.execPath, ['cli.mjs', 'finish'], { env, encoding: 'utf8' });
    assert.equal(finish.status, 1);
  } finally { await fs.rm(dir, { recursive: true, force: true }); }
});

test('safe Go requirements cannot establish clean with workspace or MVS overrides uninspected', async () => {
  const r = await collect(fixture({ alerts: [alert({ name: 'github.com/fixture/child', manifest: 'go.mod', ecosystem: 'Go' })], lock: 'module example/app\nrequire github.com/fixture/child v1.0.1\n', tree: [{path: 'go.work', type: 'blob'}] }), ctx, event);
  assert.equal(r.outcome, 'error'); assert.equal(r.coverage.lockfiles, false); assert.equal(r.checks[0].outcome, 'unknown');
});
test('an alert closing between pages cannot hide the shifted affected alert', async () => {
  const api = fixture(); const original = api.json.bind(api); let pageCalls = 0;
  const page = Array.from({length:100}, (_, i) => alert({number:i+1}));
  api.json = route => {
    if (!route.includes('/dependabot/alerts')) return original(route);
    pageCalls++;
    return pageCalls === 1 ? page : pageCalls === 2 ? [] : pageCalls === 3 ? [...page.slice(1), alert({number:101})] : [];
  };
  const r = await collect(api, ctx, event);
  assert.equal(exitCode(r), 2); assert.equal(r.coverage.alerts, false);
});

test('malformed lock entries and missing resolution data cannot establish clean', async () => {
  for (const entry of ['broken', '{}', '{resolution: {tarball: https://example.invalid/package}}']) {
    const lock = `lockfileVersion: '9.0'\nimporters: {web: {}}\nsnapshots: {fixture-child@1.0.1: {}}\npackages:\n  fixture-child@1.0.1: ${entry}\n`;
    assert.equal(exitCode(await collect(fixture({lock}), ctx, event)), 2);
  }
});
