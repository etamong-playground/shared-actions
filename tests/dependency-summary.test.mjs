import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { inputs } from '../.github/actions/dependency-updates/policy.mjs';
import { summarize, publish } from '../.github/actions/dependency-updates/summary.mjs';

const env = { GITHUB_REPOSITORY: 'example/service', UPDATE_BOT: 'updater[bot]', UPDATE_DRY_RUN: 'true', UPDATE_WRITER_TOKEN: 'synthetic-caller', UPDATE_PR_LIMIT: '3' };
const config = inputs(env);
const work = { managers: ['npm', 'gomod'], pausedHeads: [] };
async function fixture(t) {
  await mkdir('.tmp', { recursive: true });
  const root = await mkdtemp(resolve('.tmp', 'updater-summary-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  return root;
}
const report = branches => ({ repositories: { [config.repository]: { status: 'onboarded', packageFiles: { npm: [{ packageFile: 'package.json' }] }, branches } } });

test('preview distinguishes an empty scan from proposed dependency changes', async t => {
  const root = await fixture(t);
  const file = join(root, 'report.json');
  await writeFile(file, JSON.stringify(report([])));
  const empty = await summarize(file, config, work, {});
  assert.equal(empty.candidateUpdates, 0);
  await writeFile(file, JSON.stringify(report([{ upgrades: [{ depName: 'fixture-dep', packageFile: 'web/package.json', currentVersion: '1.0.0', newVersion: '1.1.0' }] }])));
  const proposed = await summarize(file, config, work, {});
  assert.equal(proposed.candidateUpdates, 1);
  assert.deepEqual(proposed.updates, [{ manifest: 'web/package.json', dependency: 'fixture-dep', from: '1.0.0', to: '1.1.0' }]);
  const output = join(root, 'output');
  const markdown = join(root, 'summary');
  await publish(proposed, { GITHUB_OUTPUT: output, GITHUB_STEP_SUMMARY: markdown });
  assert.deepEqual(JSON.parse((await readFile(output, 'utf8')).trim().slice('summary='.length)), proposed);
  assert.ok((await readFile(markdown, 'utf8')).includes('fixture-dep'));
});

test('preview omits raw diagnostics, credential encodings and unsafe metadata', async t => {
  const root = await fixture(t);
  const file = join(root, 'report.json');
  const upgrade = { depName: config.token, packageFile: '../outside/package.json', currentVersion: 'https://user:secret@example.test/', newVersion: Buffer.from(config.token).toString('base64') };
  const raw = report(Array.from({ length: 55 }, () => ({ upgrades: [upgrade] })));
  raw.repositories[config.repository].problems = [{ level: 30, message: 'raw-secret-diagnostic' }];
  await writeFile(file, JSON.stringify(raw));
  const summary = await summarize(file, config, work, {});
  assert.equal(summary.updates.length, 50);
  assert.equal(summary.omittedUpdates, 5);
  assert.ok(Object.values(summary.updates[0]).every(value => value === '[omitted]'));
  assert.ok(!JSON.stringify(summary).includes(config.token));
  assert.ok(!JSON.stringify(summary).includes('raw-secret-diagnostic'));
});

test('a missing or incomplete worker report cannot appear as no candidates', async t => {
  const root = await fixture(t);
  const file = join(root, 'report.json');
  await assert.rejects(summarize(file, config, work, {}), /unavailable/);
  await writeFile(file, JSON.stringify({ repositories: {} }));
  await assert.rejects(summarize(file, config, work, {}), /completed scan/);
  await writeFile(file, 'x'.repeat(5 * 1024 * 1024 + 1));
  await assert.rejects(summarize(file, config, work, {}), /exceeded/);
});

test('the pinned native structured reporter feeds the same bounded preview', async t => {
  const root = await fixture(t);
  const native = path => import(pathToFileURL(resolve('.github/actions/dependency-updates/runtime/node_modules/renovate/dist', path)));
  const reporting = await native('instrumentation/reporting.js');
  const { addSecretForSanitizing } = await native('util/sanitize.js');
  addSecretForSanitizing(config.token, 'global');
  const options = { repository: config.repository, reportType: 'file', reportPath: join(root, 'report.json') };
  reporting.addRepositoryStatus(options, 'onboarded');
  reporting.addExtractionStats(options, { packageFiles: { npm: [{ packageFile: 'package.json' }] } });
  for (const branches of [[{ upgrades: [{ depName: 'fixture-dep', packageFile: 'package.json', currentVersion: '1.0.0', newVersion: '1.1.0' }] }], []]) {
    reporting.addBranchStats(options, branches);
    await reporting.exportStats(options);
    const result = await summarize(options.reportPath, config, work, {});
    assert.equal(result.candidateUpdates, branches.length);
  }
});
