import { readFile, realpath } from 'node:fs/promises';
import { resolve, sep } from 'node:path';

const repositoryPattern = /^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/(?!\.{1,2}$)[A-Za-z0-9_.-]{1,100}$/;
const manifest = {
  npm: /(^|\/)(package\.json|pnpm-workspace\.yaml|\.npmrc|\.yarnrc\.yml|pnpm-lock\.yaml|package-lock\.json|npm-shrinkwrap\.json|yarn\.lock)$/,
  gomod: /(^|\/)(go\.mod|go\.sum|go\.work|go\.work\.sum)$/,
};
const policyKeys = new Set(['commitMessagePrefix', 'commitMessageAction', 'prBodyTemplate', 'ignoreDeps', 'ignorePaths']);

export function inputs(env) {
  if ((env.GITHUB_API_URL && env.GITHUB_API_URL !== 'https://api.github.com') || (env.GITHUB_SERVER_URL && env.GITHUB_SERVER_URL !== 'https://github.com')) throw new Error('Only github.com callers are supported');
  const repository = env.GITHUB_REPOSITORY;
  const bot = env.UPDATE_BOT;
  if (!repositoryPattern.test(repository ?? '') || !/^[a-z0-9-]+\[bot\]$/.test(bot ?? '')) throw new Error('Invalid caller or bot identity');
  if (!['true', 'false'].includes(env.UPDATE_DRY_RUN)) throw new Error('dry-run must be true or false');
  const limit = Number(env.UPDATE_PR_LIMIT);
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 10) throw new Error('PR limit must be between 1 and 10');
  const token = env.UPDATE_WRITER_TOKEN;
  if (!token || /\s/.test(token)) throw new Error('Missing or invalid caller token');
  const sourceToken = env.UPDATE_SOURCE_TOKEN || '';
  const packageToken = env.UPDATE_PACKAGE_TOKEN || '';
  if ([sourceToken, packageToken].some(value => value && (value === token || /\s/.test(value)))) throw new Error('Dependency readers must be separate from the caller token');
  let sources;
  try { sources = JSON.parse(env.UPDATE_SOURCE_REPOSITORIES || '[]'); } catch { throw new Error('Invalid source repository list'); }
  if (!Array.isArray(sources) || sources.length > 20 || sources.some(value => typeof value !== 'string' || !repositoryPattern.test(value)) || new Set(sources.map(value => value.toLowerCase())).size !== sources.length || sources.some(value => value.toLowerCase() === repository.toLowerCase())) throw new Error('Invalid source repository list');
  if (Boolean(sourceToken) !== Boolean(sources.length)) throw new Error('Source credentials require an explicit repository list');
  const registry = env.UPDATE_REGISTRY_URL || '';
  const scope = env.UPDATE_PACKAGE_SCOPE || '';
  if (registry || scope || packageToken) {
    let url;
    try { url = new URL(registry); } catch { throw new Error('Invalid package registry'); }
    if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || /[\s\\]/.test(registry) || !registry.endsWith('/') || !/^@[a-z0-9][a-z0-9._-]*$/.test(scope) || !packageToken) throw new Error('Package reader requires an HTTPS registry and explicit scope');
  }
  return { repository, bot, limit, token, sourceToken, packageToken, sources, registry, scope, dryRun: env.UPDATE_DRY_RUN === 'true' };
}

export function validateEvent(config, event, env) {
  const name = env.GITHUB_EVENT_NAME;
  if (!['workflow_dispatch', 'schedule'].includes(name)) throw new Error('Only default-branch manual or scheduled runs are allowed');
  if (event.repository?.fork || event.repository?.full_name !== config.repository || !event.repository?.default_branch || env.GITHUB_REF !== `refs/heads/${event.repository.default_branch}`) throw new Error('Updater must run on the caller default branch');
  if (!config.dryRun && env.UPDATE_WRITE_ENABLED !== 'true') throw new Error('Caller has not enabled update writes');
}

export async function readPolicy(workspace, filename) {
  if (!filename || filename.startsWith('/') || filename.includes('\\')) throw new Error('Policy must be a caller-relative file');
  let root, path;
  try { root = await realpath(workspace); path = await realpath(resolve(root, filename)); } catch { throw new Error('Cannot locate caller policy'); }
  if (!path.startsWith(root + sep)) throw new Error('Policy is outside the caller checkout');
  let policy;
  try { policy = JSON.parse(await readFile(path, 'utf8')); } catch { throw new Error('Cannot read a valid update policy'); }
  if (!policy || Array.isArray(policy) || typeof policy !== 'object' || Object.keys(policy).some(key => !policyKeys.has(key))) throw new Error('Unsupported update policy option');
  for (const [key, value] of Object.entries(policy)) {
    if (['ignoreDeps', 'ignorePaths'].includes(key)) {
      if (!Array.isArray(value) || value.length > 100 || value.some(item => typeof item !== 'string' || !item.trim() || item.length > 500)) throw new Error('Invalid policy exclusion');
    } else if (typeof value !== 'string' || !value.trim() || value.length > 10000) throw new Error('Invalid PR presentation text');
  }
  return policy;
}

export function github(config, request = fetch, signal) {
  const pages = async function(path) {
    const items = [];
    for (let page = 1; page <= 31; page++) {
      let response;
      try { response = await request(`https://api.github.com/repos/${config.repository}/${path}${path.includes('?') ? '&' : '?'}per_page=100&page=${page}`, {
        headers: { Authorization: `Bearer ${config.token}`, Accept: 'application/vnd.github+json' },
        signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(30000)]) : AbortSignal.timeout(30000),
      }); } catch { throw new Error('GitHub inspection interrupted or unavailable'); }
      if (!response.ok) throw new Error(`GitHub inspection failed (HTTP ${response.status})`);
      let values;
      try { values = await response.json(); } catch { throw new Error('Invalid GitHub inspection response'); }
      if (!Array.isArray(values)) throw new Error('Invalid GitHub inspection response');
      items.push(...values);
      if (values.length < 100) return items;
    }
    throw new Error('GitHub inspection exceeded its pagination limit');
  };
  pages.goDirectives = async (filename, sha) => {
    if (!/^[a-f0-9]{40}$/.test(sha ?? '') || filename.split('/').some(part => !part || part === '.' || part === '..' || part.includes('\\'))) throw new Error('Invalid Go manifest identity');
    let result;
    try {
      const path = filename.split('/').map(encodeURIComponent).join('/');
      const response = await request(`https://api.github.com/repos/${config.repository}/contents/${path}?ref=${sha}`, {
        headers: { Authorization: `Bearer ${config.token}`, Accept: 'application/vnd.github+json' },
        signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(30000)]) : AbortSignal.timeout(30000),
      });
      if (!response.ok) throw new Error();
      result = await response.json();
    } catch { throw new Error('Cannot inspect complete Go directives'); }
    if (result.type !== 'file' || result.encoding !== 'base64' || !Number.isSafeInteger(result.size) || result.size > 1024 * 1024 || typeof result.content !== 'string') throw new Error('Cannot inspect complete Go directives');
    return Buffer.from(result.content, 'base64').toString('utf8').split('\n').map(line => line.trim()).filter(line => /^(?:go|toolchain)\s/.test(line)).join('\n');
  };
  return pages;
}

export function owned(pr, config) {
  return pr.user?.login === config.bot && pr.head?.ref?.startsWith('dependency-updates/');
}

export async function preflight(config, pages, now = Date.now()) {
  if (!Number.isFinite(now)) throw new Error('Invalid inspection clock');
  let previous = Infinity;
  for (const pr of await pages('pulls?state=closed&sort=updated&direction=desc')) {
    const updated = Date.parse(pr.updated_at);
    const closed = Date.parse(pr.closed_at);
    if (!Number.isFinite(updated) || !Number.isFinite(closed) || closed > updated || updated > previous || (pr.merged_at !== null && !Number.isFinite(Date.parse(pr.merged_at)))) throw new Error('Invalid closed PR history');
    previous = updated;
    if (owned(pr, config) && !pr.merged_at && typeof pr.title !== 'string') throw new Error('Invalid closed PR history');
    if (owned(pr, config) && !pr.merged_at && pr.title.endsWith(' - autoclosed') && closed >= now - 7 * 86400000) throw new Error('Recent autoclosed update can bypass PR limits');
  }
  const paused = new Set();
  let count = 0;
  const open = await pages('pulls?state=open');
  for (const pr of open) {
    if (!Number.isSafeInteger(pr.number) || pr.number < 1) throw new Error('Invalid PR identity');
    if (owned(pr, config)) {
      count++;
      if (typeof pr.title !== 'string' || (pr.labels !== undefined && !Array.isArray(pr.labels)) || (pr.body !== null && pr.body !== undefined && typeof pr.body !== 'string')) throw new Error('Invalid update PR metadata');
      if (pr.title.startsWith('rebase!') || pr.labels?.some(label => label.name === 'rebase') || /- \[[xX]\] <!-- rebase-check -->/.test(pr.body ?? '')) throw new Error('Manual rebase controls require explicit branch disposition');
      const commits = await pages(`pulls/${pr.number}/commits`);
      if (!commits.length) throw new Error('Cannot inspect update branch authors');
      const email = `${config.repository.replace('/', '-')}@dependency-updates.invalid`;
      let edited = false;
      for (const commit of commits) {
        if (typeof commit.commit?.author?.email !== 'string' || typeof commit.commit?.committer?.email !== 'string') throw new Error('Cannot inspect update branch authors');
        edited ||= commit.commit.author.email !== email || commit.commit.committer.email !== email;
      }
      if (!edited) continue;
    }
    if (!Number.isSafeInteger(pr.number) || pr.number < 1) throw new Error('Invalid PR identity');
    const files = await pages(`pulls/${pr.number}/files`);
    if (owned(pr, config) && !files.some(file => Object.values(manifest).some(pattern => pattern.test(file.filename ?? '') || pattern.test(file.previous_filename ?? '')))) throw new Error('Edited update branch has no identifiable ecosystem');
    if (files.length >= 3000) throw new Error('PR file inspection reached the API ceiling');
    for (const file of files) {
      if (typeof file.filename !== 'string' || (file.previous_filename !== undefined && typeof file.previous_filename !== 'string')) throw new Error('Invalid PR file');
      for (const name of [file.filename, file.previous_filename].filter(Boolean)) {
        for (const [manager, pattern] of Object.entries(manifest)) if (pattern.test(name)) paused.add(manager);
      }
    }
  }
  const managers = Object.keys(manifest).filter(manager => !paused.has(manager));
  if (!managers.length) throw new Error('All dependency ecosystems have other open work');
  return { managers, count, maintenance: count >= config.limit };
}

export function configuration(config, policy, work, runtime = {}) {
  const mode = work.maintenance ? 'silent' : 'full';
  const hostRules = [];
  if (config.packageToken) hostRules.push({ hostType: 'npm', matchHost: config.registry, token: config.packageToken, abortOnError: true });
  for (const repository of config.sources) {
    for (const hostType of ['github-tags', 'github-releases']) hostRules.push({ hostType, matchHost: `https://api.github.com/repos/${repository}/`, token: config.sourceToken, abortOnError: true });
  }
  return {
    customEnvVariables: Object.fromEntries(Object.entries(runtime).filter(([key]) => /^GIT_CONFIG_(?:COUNT|KEY_\d+|VALUE_\d+|GLOBAL|NOSYSTEM)$/.test(key) || ['GOTOOLCHAIN', 'GOPRIVATE', 'GIT_TERMINAL_PROMPT'].includes(key))),
    binarySource: 'global',
    platform: 'github', endpoint: 'https://api.github.com/', token: config.token,
    username: config.bot, repositories: [config.repository], autodiscover: false,
    onboarding: false, requireConfig: 'ignored', mode,
    gitAuthor: `Dependency updater <${config.repository.replace('/', '-')}@dependency-updates.invalid>`,
    platformCommit: 'disabled', allowScripts: false, allowPlugins: false, allowedCommands: [],
    exposeAllEnv: false, persistRepoData: false, repositoryCache: 'disabled',
    configValidationError: true, exitCodeForErrors: true, hostRules,
    force: {
      ...policy, enabledManagers: work.managers, mode, branchPrefix: 'dependency-updates/',
      ignorePaths: ['**/node_modules/**', '**/bower_components/**', ...(policy.ignorePaths ?? [])],
      draftPR: true, automerge: false, platformAutomerge: false, autoApprove: false,
      dependencyDashboard: false, dependencyDashboardApproval: false,
      suppressNotifications: ['configErrorIssue'], configMigration: false,
      recreateWhen: 'never', pruneStaleBranches: false, vulnerabilityAlerts: { enabled: false },
      prConcurrentLimit: config.limit, branchConcurrentLimit: config.limit,
      prHourlyLimit: Math.max(1, config.limit - work.count),
      prCreation: work.maintenance ? 'approval' : 'immediate',
      ignoreScripts: true, gitIgnoredAuthors: [], postUpgradeTasks: { commands: [] },
      ...(config.registry ? { npmrc: `${config.scope}:registry=${config.registry}` } : {}),
      packageRules: [
        { matchManagers: ['npm'], matchUpdateTypes: ['minor', 'patch'], groupName: 'npm non-major dependencies' },
        { matchManagers: ['gomod'], matchUpdateTypes: ['minor', 'patch'], groupName: 'Go non-major dependencies' },
        ...(config.scope || config.sources.length ? [{ matchPackageNames: [...(config.scope ? [`${config.scope}/**`] : []), ...config.sources.map(repo => `github.com/${repo}{,/**}`)], groupName: null }] : []),
        { matchManagers: ['gomod'], matchDepTypes: ['golang', 'toolchain'], enabled: false },
      ],
    },
  };
}

export async function verifyArtifacts(config, pages) {
  for (const pr of await pages('pulls?state=open')) {
    if (!owned(pr, config)) continue;
    if (!Number.isSafeInteger(pr.number) || pr.number < 1) throw new Error('Invalid update identity');
    const sha = pr.head?.sha;
    if (!/^[a-f0-9]{40}$/.test(sha ?? '')) throw new Error('Invalid update head');
    const files = await pages(`pulls/${pr.number}/files`);
    if (!files.length || files.length >= 3000) throw new Error('Cannot inspect complete update artifacts');
    for (const file of files) {
      if (typeof file.filename !== 'string' || !/(^|\/)(package\.json|pnpm-workspace\.yaml|pnpm-lock\.yaml|package-lock\.json|npm-shrinkwrap\.json|go\.mod|go\.sum|go\.work|go\.work\.sum)$/.test(file.filename) || file.previous_filename) throw new Error('Update PR changes files outside the dependency contract');
      if (/(^|\/)(go\.mod|go\.work)$/.test(file.filename)) {
        if (!pages.goDirectives || await pages.goDirectives(file.filename, pr.base?.sha) !== await pages.goDirectives(file.filename, sha)) throw new Error('Update PR changes Go or toolchain directives');
      }
    }
    const statuses = await pages(`commits/${sha}/statuses`);
    const status = statuses.find(value => value.context === 'renovate/artifacts');
    if (status && status.state !== 'success') throw new Error(`Update artifact generation failed on PR #${pr.number}`);
  }
}
