import assert from 'node:assert/strict';
import { test } from 'node:test';
import { spawnSync } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { configuration, inputs } from '../.github/actions/dependency-updates/policy.mjs';

const runtime = resolve('.github/actions/dependency-updates/runtime/node_modules/renovate/dist');
const native = path => import(pathToFileURL(join(runtime, path)));
const git = (cwd, ...args) => {
  const result = spawnSync('git', args, { cwd, encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
};

test('pinned worker maintains an existing PR at capacity, refuses new branches and preserves human commits', async t => {
  await mkdir('.tmp', { recursive: true });
  const root = await mkdtemp(resolve('.tmp', 'updater-maintenance-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const remote = join(root, 'remote.git');
  const publisher = join(root, 'publisher');
  const clone = join(root, 'worker');
  await mkdir(publisher);
  await mkdir(clone);
  git(root, 'init', '--bare', '--initial-branch=main', remote);
  git(publisher, 'init', '--initial-branch=main');
  const contract = inputs({ GITHUB_REPOSITORY: 'example/service', UPDATE_BOT: 'updater[bot]', UPDATE_DRY_RUN: 'false', UPDATE_WRITER_TOKEN: 'synthetic-caller', UPDATE_PR_LIMIT: '3' });
  const settings = configuration(contract, {}, { managers: ['npm'], count: 3, maintenance: true });
  git(publisher, 'config', 'user.name', 'Dependency updater');
  git(publisher, 'config', 'user.email', 'example-service@dependency-updates.invalid');
  const manifest = version => JSON.stringify({ name: 'fixture', private: true, dependencies: { 'fixture-dep': version } }, null, 2) + '\n';
  await writeFile(join(publisher, 'package.json'), manifest('1.0.0'));
  git(publisher, 'add', 'package.json');
  git(publisher, 'commit', '-m', 'fixture: initialize');
  git(publisher, 'remote', 'add', 'origin', remote);
  git(publisher, 'push', 'origin', 'main');
  const branch = 'dependency-updates/fixture';
  git(publisher, 'switch', '-c', branch);
  await writeFile(join(publisher, 'package.json'), manifest('1.1.0'));
  git(publisher, 'commit', '-am', 'deps: update fixture');
  git(publisher, 'push', 'origin', branch);
  git(publisher, 'switch', 'main');
  await writeFile(join(publisher, 'latest.txt'), 'new base change\n');
  git(publisher, 'add', 'latest.txt');
  git(publisher, 'commit', '-m', 'fixture: advance base');
  git(publisher, 'push', 'origin', 'main');

  const { GlobalConfig } = await native('config/global.js');
  const { getConfig } = await native('config/defaults.js');
  const nativeGit = await native('util/git/index.js');
  const { resetCache } = await native('util/cache/repository/index.js');
  const { DefaultGitScm } = await native('modules/platform/default-scm.js');
  const { platformScmImpls } = await native('modules/platform/scm.js');
  const { default: platforms } = await native('modules/platform/api.js');
  const { setPlatformApi } = await native('modules/platform/index.js');
  const { init, getProblems } = await native('logger/index.js');
  await init();
  const { setCount } = await native('workers/global/limits.js');
  setCount('ConcurrentPRs', 3); setCount('Branches', 3); setCount('HourlyPRs', 1);
  const { processBranch } = await native('workers/repository/update/branch/index.js');
  const pr = { number: 1, title: 'deps: update fixture', body: 'Update fixture dependency.', state: 'open', sourceBranch: branch, targetBranch: 'main', labels: [], canRebase: true, isDraft: true, bodyStruct: {} };
  let updates = 0;
  const fake = new Proxy({
    labelCharLimit: () => 50,
    getBranchPr: async name => name === branch ? pr : null,
    findPr: async () => null,
    getPrList: async () => [pr],
    getPr: async () => pr,
    refreshPr: async () => pr,
    getBranchStatus: async () => 'success',
    getBranchStatusCheck: async () => null,
    getIssueComments: async () => [],
    ensureComment: async () => false,
    ensureCommentRemoval: async () => false,
    getPrFiles: async () => ['package.json'],
    updatePr: async () => { updates++; return pr; },
    createPr: async () => assert.fail('No new PR may be created at capacity'),
    setBranchStatus: async () => {},
    getVulnerabilityAlerts: async () => [],
    massageMarkdown: value => value,
    supportsPlatformAutomerge: false,
  }, { get(target, key) { if (!(key in target)) throw new Error(`Unconfigured platform method ${String(key)}`); return target[key]; } });
  platforms.set('fixture', fake);
  platformScmImpls.set('fixture', DefaultGitScm);
  setPlatformApi('fixture');
  GlobalConfig.set({ platform: 'fixture', localDir: clone, cacheDir: join(root, 'cache'), binarySource: 'global', allowScripts: false, allowPlugins: false, dryRun: null });
  resetCache();
  await nativeGit.initRepo({ url: pathToFileURL(remote).href, repository: 'example/service' });
  nativeGit.setGitAuthor(settings.gitAuthor);
  await nativeGit.checkoutBranch('main');
  assert.equal(await nativeGit.isBranchModified(branch, 'main'), false);
  const upgrade = { prConcurrentLimit: 3, branchConcurrentLimit: 3, prHourlyLimit: 1, manager: 'npm', packageFile: 'package.json', depType: 'dependencies', depName: 'fixture-dep', currentValue: '1.0.0', currentVersion: '1.0.0', newValue: '1.2.0', newVersion: '1.2.0', updateType: 'minor', versioning: 'npm' };
  const config = { ...getConfig(), ...settings.force, repository: 'example/service', baseBranch: 'main', defaultBranch: 'main', branchName: branch, branchPrefixOld: 'dependency-updates/', prTitle: 'deps: update fixture', prBodyTemplate: 'Update fixture dependency.', commitMessage: 'deps: update fixture', rebaseWhen: 'behind-base-branch', upgrades: [upgrade], packageFiles: { npm: [{ packageFile: 'package.json', deps: [upgrade] }] }, fetchChangeLogs: 'off', errors: [], warnings: [] };
  const result = await processBranch(config);
  assert.notEqual(result.result, 'error', JSON.stringify({ result, problems: getProblems() }));
  assert.equal(JSON.parse(git(remote, 'show', `${branch}:package.json`)).dependencies['fixture-dep'], '1.2.0');
  assert.equal(git(remote, 'show', `${branch}:latest.txt`), 'new base change');
  const head = git(remote, 'rev-parse', branch);
  await processBranch(config);
  assert.equal(git(remote, 'rev-parse', branch), head, 'Repeated maintenance does not add another commit');
  const denied = await processBranch({ ...config, branchName: 'dependency-updates/new-fixture' });
  assert.equal(denied.result, 'needs-approval');
  assert.equal(git(remote, 'for-each-ref', '--format=%(refname)', 'refs/heads/dependency-updates/new-fixture'), '');

  git(publisher, 'fetch', 'origin');
  git(publisher, 'switch', branch);
  git(publisher, 'reset', '--hard', `origin/${branch}`);
  git(publisher, 'config', 'user.email', 'human@example.invalid');
  await writeFile(join(publisher, 'human.txt'), 'keep this fix\n');
  git(publisher, 'add', 'human.txt');
  git(publisher, 'commit', '-m', 'fixture: retain human edit');
  git(publisher, 'push', 'origin', branch);
  await nativeGit.initRepo({ url: pathToFileURL(remote).href, repository: 'example/service' });
  nativeGit.setGitAuthor(settings.gitAuthor);
  await nativeGit.checkoutBranch('main');
  assert.equal(await nativeGit.isBranchModified(branch, 'main'), true);
  const editedHead = git(remote, 'rev-parse', branch);
  const edited = await processBranch({ ...config, upgrades: [{ ...upgrade, newValue: '1.3.0', newVersion: '1.3.0' }] });
  assert.equal(git(remote, 'rev-parse', branch), editedHead, JSON.stringify(edited));
  assert.equal(git(remote, 'show', `${branch}:human.txt`), 'keep this fix');
  assert.deepEqual(getProblems().filter(problem => problem.level >= 50), []);
});
