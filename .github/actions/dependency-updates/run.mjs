import { chmod, mkdir, mkdtemp, readFile, rm } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { validateTools } from './tools.mjs';
import { runCommand } from './process.mjs';
import { github, inputs, preflight, readPolicy, validateEvent, verifyArtifacts, verifyCaller } from './policy.mjs';

const action = dirname(fileURLToPath(import.meta.url));
const inputNames = ['UPDATE_BOT', 'UPDATE_DRY_RUN', 'UPDATE_PR_LIMIT', 'UPDATE_WRITER_TOKEN', 'UPDATE_SOURCE_TOKEN', 'UPDATE_SOURCE_REPOSITORIES', 'UPDATE_PACKAGE_TOKEN', 'UPDATE_REGISTRY_URL', 'UPDATE_PACKAGE_SCOPE', 'GITHUB_REPOSITORY'];

export function childEnvironment(env, config, policy, work, directory) {
  const child = Object.fromEntries(inputNames.filter(key => env[key] !== undefined).map(key => [key, env[key]]));
  Object.assign(child, {
    PATH: env.PATH, LANG: 'C.UTF-8', CI: 'true', HOME: join(directory, 'home'),
    TMPDIR: directory, XDG_CACHE_HOME: join(directory, 'cache'),
    GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_TERMINAL_PROMPT: '0',
    GOTOOLCHAIN: 'local', GOPRIVATE: config.sources.map(repo => `github.com/${repo}`).join(','),
    UPDATE_POLICY: JSON.stringify(policy), UPDATE_PREFLIGHT: JSON.stringify(work),
    RENOVATE_CONFIG_FILE: join(action, 'config.cjs'),
    RENOVATE_BASE_DIR: join(directory, 'work'), RENOVATE_CACHE_DIR: join(directory, 'cache'),
    RENOVATE_DRY_RUN: config.dryRun ? 'full' : '', LOG_LEVEL: 'warn',
  });
  const settings = [{ key: 'credential.helper', value: '' }, { key: 'core.hooksPath', value: '/dev/null' }];
  for (const repo of config.sources) {
    const value = `Authorization: Basic ${Buffer.from(`x-access-token:${config.sourceToken}`).toString('base64')}`;
    for (const suffix of ['', '.git']) settings.push({ key: `http.https://github.com/${repo}${suffix}.extraHeader`, value });
  }
  child.GIT_CONFIG_COUNT = String(settings.length);
  settings.forEach(({ key, value }, index) => {
    child[`GIT_CONFIG_KEY_${index}`] = key;
    child[`GIT_CONFIG_VALUE_${index}`] = value;
  });
  return child;
}

export async function executeEngine(env, signal) {
  await runCommand(process.execPath, [join(action, 'runtime/node_modules/renovate/dist/renovate.js')], { env, signal });
}

export async function run(env, { request = fetch, execute = executeEngine, signal = new AbortController().signal, tools = validateTools } = {}) {
  const config = inputs(env);
  let event;
  try { event = JSON.parse(await readFile(env.GITHUB_EVENT_PATH, 'utf8')); } catch { throw new Error('Cannot read caller event'); }
  validateEvent(config, event, env);
  await verifyCaller(config, request, signal);
  const policy = await readPolicy(env.GITHUB_WORKSPACE, env.UPDATE_POLICY_PATH);
  const pages = github(config, request, signal);
  const work = await preflight(config, pages);
  await tools(env.GITHUB_WORKSPACE, policy, work.managers);
  const directory = await mkdtemp(join(env.RUNNER_TEMP, 'dependency-updates-'));
  await chmod(directory, 0o700);
  try {
    await mkdir(join(directory, 'home'));
    if (signal.aborted) throw new Error('Dependency update interrupted');
    await execute(childEnvironment(env, config, policy, work, directory), signal);
    if (!config.dryRun) await verifyArtifacts(config, pages, work.pausedHeads);
    console.info(`Dependency updates completed (${config.dryRun ? 'dry-run' : 'draft PRs'}; ${work.maintenance ? 'maintenance' : 'normal'} mode)`);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const controller = new AbortController();
  for (const name of ['SIGINT', 'SIGTERM']) process.on(name, () => controller.abort());
  run(process.env, { signal: controller.signal }).catch(error => {
    console.error(`Dependency updater stopped: ${error.message}`);
    process.exitCode = 1;
  });
}
