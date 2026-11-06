import { open, appendFile } from 'node:fs/promises';

export async function summarize(path, config, work, policy) {
  let report;
  let file;
  try { file = await open(path, 'r'); } catch { throw new Error('Worker report is unavailable'); }
  try {
    const limit = 5 * 1024 * 1024;
    const buffer = Buffer.alloc(limit + 1);
    let bytesRead = 0;
    while (bytesRead < buffer.length) {
      const read = await file.read(buffer, bytesRead, buffer.length - bytesRead, bytesRead);
      if (!read.bytesRead) break;
      bytesRead += read.bytesRead;
    }
    if (bytesRead > limit) throw new Error('Worker report exceeded its limit');
    try { report = JSON.parse(buffer.subarray(0, bytesRead).toString('utf8')); } catch { throw new Error('Cannot inspect worker report'); }
  } finally { await file.close(); }
  const repository = report.repositories?.[config.repository];
  if (!repository || !['onboarded', 'activated'].includes(repository.status) || !Array.isArray(repository.branches) || !repository.packageFiles || typeof repository.packageFiles !== 'object' || Array.isArray(repository.packageFiles)) throw new Error('Worker report did not establish a completed scan');
  if (!Array.isArray(report.problems ?? []) || !Array.isArray(repository.problems ?? [])) throw new Error('Invalid worker diagnostic report');
  if ([...(report.problems ?? []), ...(repository.problems ?? [])].some(problem => problem.level >= 50)) throw new Error('Worker reported update errors');
  if (repository.branches.length > 10000) throw new Error('Worker candidate report exceeded its limit');
  const secrets = [config.token, config.sourceToken, config.packageToken].filter(Boolean).flatMap(value => [value, encodeURIComponent(value), Buffer.from(value).toString('base64'), Buffer.from(`x-access-token:${value}`).toString('base64')]);
  const safe = (value, kind) => {
    if (typeof value !== 'string' || value.length > 200 || secrets.some(secret => value.includes(secret))) return '[omitted]';
    if (kind === 'path' && (value.startsWith('/') || value.split('/').some(part => part === '..' || part === '.'))) return '[omitted]';
    return /^[A-Za-z0-9@._/+^~*=<>| -]+$/.test(value) ? value : '[omitted]';
  };
  const updates = [];
  let totalUpdates = 0;
  for (const branch of repository.branches) {
    if (!Array.isArray(branch.upgrades) || branch.upgrades.length > 10000) throw new Error('Invalid worker candidate report');
    for (const upgrade of branch.upgrades) {
      totalUpdates++;
      if (updates.length < 50) updates.push({
        manifest: safe(upgrade.packageFile, 'path'), dependency: safe(upgrade.depName, 'name'),
        from: safe(upgrade.currentVersion ?? upgrade.currentValue ?? upgrade.currentDigest, 'version'),
        to: safe(upgrade.newVersion ?? upgrade.newValue ?? upgrade.newDigest, 'version'),
      });
    }
  }
  const manifests = {};
  for (const manager of ['npm', 'gomod']) {
    const files = repository.packageFiles[manager] ?? [];
    if (!Array.isArray(files)) throw new Error('Invalid worker extraction report');
    manifests[manager] = files.length;
  }
  return { mode: config.dryRun ? 'dry-run' : 'write', managers: work.managers, manifests,
    candidateBranches: repository.branches.length, candidateUpdates: totalUpdates,
    omittedUpdates: totalUpdates - updates.length, configuredExclusions: (policy.ignoreDeps?.length ?? 0) + (policy.ignorePaths?.length ?? 0),
    retainedHeads: work.pausedHeads.length, updates };
}

export async function publish(summary, env) {
  const json = JSON.stringify(summary);
  if (Buffer.byteLength(json) > 64 * 1024) throw new Error('Safe update summary exceeded its limit');
  if (env.GITHUB_OUTPUT) await appendFile(env.GITHUB_OUTPUT, `summary=${json}\n`);
  if (env.GITHUB_STEP_SUMMARY) await appendFile(env.GITHUB_STEP_SUMMARY, `\n## Dependency update preview\n\n\`\`\`json\n${json}\n\`\`\`\n`);
  console.info(`Dependency update preview: ${json}`);
}
