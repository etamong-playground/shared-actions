import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runCommand } from './process.mjs';

const action = dirname(fileURLToPath(import.meta.url));
const controller = new AbortController();
for (const name of ['SIGTERM', 'SIGINT']) process.on(name, () => controller.abort());
let directory;
try {
  directory = await mkdtemp(join(process.env.RUNNER_TEMP, 'dependency-engine-'));
  await writeFile(join(directory, 'user.npmrc'), '', { mode: 0o600 });
  await writeFile(join(directory, 'global.npmrc'), '', { mode: 0o600 });
  const env = {
    PATH: process.env.PATH, HOME: directory, TMPDIR: directory,
    npm_config_userconfig: join(directory, 'user.npmrc'), npm_config_globalconfig: join(directory, 'global.npmrc'),
    npm_config_registry: 'https://registry.npmjs.org/', npm_config_cache: join(directory, 'cache'),
    CI: 'true',
  };
  await runCommand('npm', ['ci', '--engine-strict', '--ignore-scripts', '--no-audit', '--no-fund'], {
    cwd: join(action, 'runtime'), env, signal: controller.signal,
  });
  await runCommand(process.execPath, [
    join(action, 'runtime/node_modules/node-gyp/bin/node-gyp.js'), 'rebuild', '--jobs=2',
    `--devdir=${join(directory, 'headers')}`,
  ], { cwd: join(action, 'runtime/node_modules/re2'), env, signal: controller.signal });
  await runCommand(process.execPath, ['-e', "require('./node_modules/re2')"], {
    cwd: join(action, 'runtime'), env, signal: controller.signal,
  });
  console.info('Pinned update engine prepared without package install hooks');
} catch (error) {
  console.error(`Engine preparation stopped: ${error.message}`);
  process.exitCode = 1;
} finally {
  if (directory) await rm(directory, { recursive: true, force: true });
}
