import { parseDocument } from 'yaml';
import semver from 'semver';
import { createHash } from 'node:crypto';

export const MAX_REPORT_BYTES = 1024 * 1024;
const SHA = /^[a-f0-9]{40}$/;
const ID = /^[1-9][0-9]{0,17}$/;
const unsafe = /github_pat_|gh[pousr]_|AKIA[A-Z0-9]{16}|eyJ[A-Za-z0-9_-]{10,}\./;
export function safeText(value, max = 255) {
  return typeof value === 'string' && value.length > 0 && value.length <= max && !/[\x00-\x1f\x7f]/.test(value) && !unsafe.test(value);
}
export function validPath(value) {
  return safeText(value, 512) && !value.startsWith('/') && !value.includes('\\') && value.split('/').every(x => x !== '.' && x !== '..' && x !== '');
}
export function audienceFor(endpoint, bytes) {
  const u = new URL(endpoint);
  if (u.protocol !== 'https:' || u.username || u.password || u.search || u.hash || u.href !== endpoint) throw new Error('invalid_receiver');
  return endpoint + '#sha256=' + createHash('sha256').update(bytes).digest('hex');
}
export function vulnerable(version, range) {
  if (!safeText(version, 128) || !safeText(range, 512)) return undefined;
  const v = semver.valid(version);
  const r = semver.validRange(range.replaceAll(',', ' '));
  if (!v || !r) return undefined;
  return semver.satisfies(v, r, { includePrerelease: true });
}
export function pnpmVersions(text, name) {
  const doc = parseDocument(text, { uniqueKeys: true, strict: true });
  if (doc.errors.length) throw new Error('invalid_lockfile');
  const data = doc.toJS({ mapAsMap: true, maxAliasCount: 0 });
  if (!(data instanceof Map) || !['6.0', '6', '9.0', '9'].includes(String(data.get('lockfileVersion')))) throw new Error('unsupported_lockfile');
  const importers = data.get('importers');
  const snapshots = data.get('snapshots');
  const v9 = ['9', '9.0'].includes(String(data.get('lockfileVersion')));
  if (!(importers instanceof Map) || (v9 && !(snapshots instanceof Map))) throw new Error('unsupported_lockfile');
  for (const entry of importers.values()) if (!(entry instanceof Map)) throw new Error('invalid_lockfile');
  if (v9) for (const entry of snapshots.values()) if (!(entry instanceof Map)) throw new Error('invalid_lockfile');
  const packages = data.get('packages');
  if (!(packages instanceof Map)) throw new Error('invalid_lockfile');
  const versions = new Set();
  for (const [key, entry] of packages) {
    if (!(entry instanceof Map)) throw new Error('invalid_lockfile');
    if (typeof key !== 'string') throw new Error('invalid_lockfile');
    const k = key.replace(/^\//, '');
    if (!k.startsWith(name + '@')) continue;
    const resolution = entry.get('resolution');
    if (!(resolution instanceof Map) || !/^sha(1|256|384|512)-[A-Za-z0-9+/]+={0,2}$/.test(resolution.get('integrity') ?? '')) throw new Error('unsupported_resolution');
    if (v9 && ![...snapshots.keys()].some(x => typeof x === 'string' && x.split('(')[0] === k.split('(')[0])) throw new Error('invalid_lockfile');
    const v = k.slice(name.length + 1).split('(')[0];
    if (!semver.valid(v) || !safeText(v, 128)) throw new Error('unsupported_version');
    versions.add(v);
    if (versions.size > 1000) throw new Error('version_limit');
  }
  return [...versions].sort();
}
export function goVersions(text, name) {
  if (/^\s*(replace|exclude)\b/m.test(text) || name === 'stdlib' || name === 'toolchain') throw new Error('unsupported_go_resolution');
  let block = false;
  const versions = new Set();
  for (let line of text.split('\n')) {
    line = line.replace(/\/\/.*$/, '').trim();
    if (/^require\s*\($/.test(line)) { block = true; continue; }
    if (line === ')') { block = false; continue; }
    if (!block && !line.startsWith('require ')) continue;
    line = line.replace(/^require\s+/, '');
    const parts = line.split(/\s+/);
    if (parts[0] !== name) continue;
    if (parts.length !== 2 || !semver.valid(parts[1]) || !safeText(parts[1], 128)) throw new Error('unsupported_version');
    versions.add(parts[1]);
    if (versions.size > 1000) throw new Error('version_limit');
  }
  return [...versions];
}
function identity(context, event) {
  const [owner, repo] = (context.repository ?? '').split('/');
  if (!/^[A-Za-z0-9_.-]+$/.test(owner ?? '') || !/^[A-Za-z0-9_.-]+$/.test(repo ?? '') || !ID.test(context.repositoryID) || !ID.test(context.ownerID) || !ID.test(context.runID) || !ID.test(context.attempt) || !SHA.test(context.sha) || !SHA.test(context.scannerRevision)) throw new Error('invalid_source_identity');
  if (!['push', 'schedule', 'workflow_dispatch', 'pull_request'].includes(context.event)) throw new Error('unsupported_event');
  const pr = context.event === 'pull_request' ? event.pull_request : null;
  if (pr && (!Number.isSafeInteger(pr.number) || !SHA.test(pr.head?.sha ?? ''))) throw new Error('invalid_pr_identity');
  const defaultBranch = event.repository?.default_branch;
  if (!safeText(defaultBranch, 255) || !safeText(context.ref, 512) || !safeText(context.workflowRef, 1024)) throw new Error('invalid_source_identity');
  return {
    schema: 1, kind: 'dependency-advisories', scope: 'dependabot-open-alerts',
    repository: { id: context.repositoryID, owner_id: context.ownerID, name: context.repository, default_branch: defaultBranch },
    source: { sha: pr ? pr.head.sha : context.sha, ref: context.ref, event: context.event, pr_number: pr ? pr.number : null },
    execution: { run_id: context.runID, attempt: context.attempt, sha: context.sha, workflow_ref: context.workflowRef },
    scanner_revision: context.scannerRevision, observed_at: new Date().toISOString(),
    outcome: 'error', coverage: { alerts: false, lockfiles: false, inventory: false, reachability: false, deployed: false },
    alert_count: 0, finding_count: 0, checks: [], errors: [],
  };
}
function advisory(alert) {
  const a = alert.security_advisory;
  const v = alert.security_vulnerability;
  const p = alert.dependency?.package;
  const manifest = alert.dependency?.manifest_path;
  if (!/^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$/.test(a?.ghsa_id ?? '') || !safeText(p?.name) || !validPath(manifest) || !safeText(v?.vulnerable_version_range, 512) || !['low', 'moderate', 'high', 'critical'].includes(a?.severity)) throw new Error('invalid_alert_metadata');
  if (!['npm', 'go'].includes(String(p.ecosystem).toLowerCase())) throw new Error('unsupported_ecosystem');
  if (p.ecosystem.toLowerCase() === 'npm' && !/^(@[A-Za-z0-9._-]+\/)?[A-Za-z0-9][A-Za-z0-9._-]*$/.test(p.name)) throw new Error('invalid_alert_metadata');
  if (p.ecosystem.toLowerCase() === 'go' && !/^[A-Za-z0-9.-]+(?:\/[A-Za-z0-9._~+-]+)+$/.test(p.name) && !['stdlib', 'toolchain'].includes(p.name)) throw new Error('invalid_alert_metadata');
  const patched = v.first_patched_version?.identifier ?? '';
  if (patched && (!safeText(patched, 128) || !semver.valid(patched))) throw new Error('invalid_alert_metadata');
  return { ghsa: a.ghsa_id, ecosystem: p.ecosystem.toLowerCase(), package: p.name, manifest, severity: a.severity, patched_version: patched, range: v.vulnerable_version_range, versions: [], outcome: 'unknown', reason: '' };
}
export async function collect(api, context, event) {
  const report = identity(context, event);
  const root = `/repos/${context.repository}`;
  const fail = code => { if (!report.errors.includes(code) && report.errors.length < 32) report.errors.push(code); };
  try {
    const repo = await api.json(root);
    if (String(repo.id) !== report.repository.id || String(repo.owner?.id) !== report.repository.owner_id || repo.full_name !== context.repository || repo.default_branch !== report.repository.default_branch) throw new Error('repository_identity_mismatch');
    async function readAlerts() {
      const seen = new Set(); const result = [];
      for (let page = 1; ; page++) {
        if (page > 10) throw new Error('incomplete_pagination');
        const batch = await api.json(`${root}/dependabot/alerts?state=open&per_page=100&page=${page}`);
        if (!Array.isArray(batch) || batch.length > 100) throw new Error('invalid_alert_response');
        for (const a of batch) {
          if (!Number.isSafeInteger(a.number) || seen.has(a.number)) throw new Error('inconsistent_pagination');
          seen.add(a.number); result.push(a);
        }
        if (batch.length < 100) return result;
      }
    }
    const alerts = await readAlerts();
    const confirmed = await readAlerts();
    const signature = list => JSON.stringify(list.map(a => [a.number, a.dependency, a.security_advisory?.ghsa_id, a.security_advisory?.severity, a.security_vulnerability]).sort((a, b) => a[0] - b[0]));
    if (signature(alerts) !== signature(confirmed)) throw new Error('inconsistent_pagination');
    report.coverage.alerts = true;
    report.alert_count = alerts.length;
    let paths = [];
    if (alerts.some(a => String(a.dependency?.package?.ecosystem).toLowerCase() === 'npm')) {
      const tree = await api.json(`${root}/git/trees/${report.source.sha}?recursive=1`);
      if (tree.truncated || !Array.isArray(tree.tree) || tree.tree.length > 100000) throw new Error('incomplete_tree');
      paths = tree.tree.filter(x => x.type === 'blob' && /(^|\/)pnpm-lock\.yaml$/.test(x.path)).map(x => x.path);
    }
    let bytes = 0;
    const files = new Map();
    async function read(path) {
      if (files.has(path)) return files.get(path);
      if (files.size >= 64 || !validPath(path)) throw new Error('source_limit');
      const file = await api.json(`${root}/contents/${path.split('/').map(encodeURIComponent).join('/')}?ref=${report.source.sha}`);
      if (file.type !== 'file' || file.encoding !== 'base64' || !Number.isSafeInteger(file.size) || file.size > 1024 * 1024 || typeof file.content !== 'string') throw new Error('invalid_source_file');
      const b = Buffer.from(file.content, 'base64');
      bytes += b.length;
      if (b.length !== file.size || bytes > 8 * 1024 * 1024) throw new Error('source_limit');
      const text = new TextDecoder('utf-8', { fatal: true }).decode(b);
      files.set(path, text); return text;
    }
    for (const alert of alerts) {
      let check;
      try {
        check = advisory(alert);
        let path;
        if (check.ecosystem === 'npm') {
          if (!/(^|\/)package\.json$/.test(check.manifest)) throw new Error('unsupported_manifest');
          const ancestors = check.manifest.split('/').slice(0, -1);
          for (let depth = ancestors.length; depth >= 0; depth--) {
            const candidate = [...ancestors.slice(0, depth), 'pnpm-lock.yaml'].join('/');
            if (paths.includes(candidate)) { path = candidate; break; }
          }
          if (!path) throw new Error('missing_lockfile');
          check.versions = pnpmVersions(await read(path), check.package);
        } else {
          if (!/(^|\/)go\.mod$/.test(check.manifest)) throw new Error('unsupported_manifest');
          check.versions = goVersions(await read(check.manifest), check.package);
          check.reason = 'unverified_go_resolution';
          throw new Error('unsupported_go_resolution');
        }
        if (!check.versions.length) throw new Error('missing_package');
        const matches = check.versions.map(v => vulnerable(v, check.range));
        if (matches.some(x => x === undefined)) throw new Error('unsupported_range');
        check.outcome = matches.some(Boolean) ? 'vulnerable' : 'fixed';
        check.reason = check.outcome === 'vulnerable' && !check.patched_version ? 'no_upstream_fix' : '';
      } catch { fail('unverified_dependency'); }
      if (check) report.checks.push(check);
    }
    report.coverage.lockfiles = report.checks.length === alerts.length && report.checks.every(x => x.outcome !== 'unknown');
    if (report.source.pr_number !== null) {
      const pr = await api.json(`${root}/pulls/${report.source.pr_number}`);
      if (pr.head?.sha !== report.source.sha || pr.state !== 'open') { report.coverage.lockfiles = false; fail('stale_pr_head'); }
    }
  } catch { fail('inspection_failed'); }
  report.finding_count = report.checks.filter(x => x.outcome === 'vulnerable').length;
  report.outcome = !report.coverage.alerts || !report.coverage.lockfiles || report.errors.length ? 'error' : report.finding_count ? 'findings' : 'clean';
  if (Buffer.byteLength(JSON.stringify(report)) > MAX_REPORT_BYTES) {
    report.checks = []; report.finding_count = 0; report.outcome = 'error'; report.coverage.lockfiles = false; report.errors = ['report_limit'];
  }
  return report;
}
export function exitCode(report) {
  if (!report.coverage.alerts || !report.coverage.lockfiles || report.errors.length) return 2;
  return report.outcome === 'clean' ? 0 : 1;
}
