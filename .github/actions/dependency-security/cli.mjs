import fs from 'node:fs/promises';
import { constants } from 'node:fs';
import path from 'node:path';
import { collect, exitCode, audienceFor, MAX_REPORT_BYTES } from './report.mjs';

async function responseBytes(response, limit) {
  if (!response.ok) throw new Error('request_failed');
  const chunks = []; let size = 0;
  for await (const chunk of response.body) {
    size += chunk.length;
    if (size > limit) { await response.body.cancel().catch(() => {}); throw new Error('response_limit'); }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}
export async function apiJSON(route, token, fetcher = fetch) {
  if (!route.startsWith('/repos/') || !token || /[\r\n]/.test(token)) throw new Error('invalid_request');
  const response = await fetcher('https://api.github.com' + route, {
    headers: { Authorization: 'Bearer ' + token, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' },
    redirect: 'error', signal: AbortSignal.timeout(15000),
  });
  return JSON.parse((await responseBytes(response, 8 * 1024 * 1024)).toString('utf8'));
}
export async function publish(endpoint, bytes, requestURL, requestToken, fetcher = fetch) {
  const audience = audienceFor(endpoint, bytes);
  const u = new URL(requestURL);
  if (u.protocol !== 'https:' || !u.hostname.endsWith('.actions.githubusercontent.com') || u.username || u.password || u.hash || !requestToken || /[\r\n]/.test(requestToken)) throw new Error('invalid_oidc_request');
  u.searchParams.set('audience', audience);
  const tokenResponse = await fetcher(u.href, { headers: { Authorization: 'Bearer ' + requestToken }, redirect: 'error', signal: AbortSignal.timeout(15000) });
  const data = JSON.parse((await responseBytes(tokenResponse, 65536)).toString('utf8'));
  if (typeof data.value !== 'string' || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(data.value)) throw new Error('invalid_oidc_response');
  const response = await fetcher(endpoint, {
    method: 'POST', headers: { Authorization: 'Bearer ' + data.value, 'Content-Type': 'application/json' }, body: bytes,
    redirect: 'error', signal: AbortSignal.timeout(15000),
  });
  const receipt = JSON.parse((await responseBytes(response, 4096)).toString('utf8'));
  if (![200, 201].includes(response.status) || !['stored', 'already_stored'].includes(receipt.status)) throw new Error('invalid_receipt');
}
function context(env) {
  return { repository: env.GITHUB_REPOSITORY, repositoryID: env.GITHUB_REPOSITORY_ID, ownerID: env.GITHUB_REPOSITORY_OWNER_ID,
    runID: env.GITHUB_RUN_ID, attempt: env.GITHUB_RUN_ATTEMPT, sha: env.GITHUB_SHA, ref: env.GITHUB_REF,
    event: env.GITHUB_EVENT_NAME, workflowRef: env.GITHUB_WORKFLOW_REF, scannerRevision: env.SCANNER_REVISION };
}
async function readReport(file) {
  const h = await fs.open(file, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const stat = await h.stat();
    if (!stat.isFile() || stat.size > MAX_REPORT_BYTES) throw new Error('invalid_report_file');
    const bytes = await h.readFile();
    return { report: JSON.parse(bytes.toString('utf8')), bytes };
  } finally { await h.close(); }
}
async function main(command, env) {
  if (!env.RUNNER_TEMP || /[\r\n]/.test(env.RUNNER_TEMP)) throw new Error('missing_runner_temp');
  const dir = path.join(env.RUNNER_TEMP, 'dependency-security');
  const file = path.join(dir, 'report.json');
  if (command === 'collect') {
    const eventBytes = await fs.readFile(env.GITHUB_EVENT_PATH);
    if (eventBytes.length > 16 * 1024 * 1024) throw new Error('event_limit');
    const event = JSON.parse(eventBytes.toString('utf8'));
    const report = await collect({ json: p => apiJSON(p, env.ALERTS_READ_TOKEN) }, context(env), event);
    await fs.mkdir(dir, { mode: 0o700 });
    await fs.writeFile(file, JSON.stringify(report) + '\n', { mode: 0o600, flag: 'wx' });
    if (env.GITHUB_OUTPUT) await fs.appendFile(env.GITHUB_OUTPUT, `report-path=${file}\nexit-code=${exitCode(report)}\n`);
    if (env.GITHUB_STEP_SUMMARY) await fs.appendFile(env.GITHUB_STEP_SUMMARY,
      `## Dependency security evidence\n\nOutcome: **${report.outcome}**. Affected checks: ${report.finding_count}. Open alerts inspected: ${report.alert_count}.\n\nAlert coverage: ${report.coverage.alerts ? 'complete' : 'incomplete'}; lockfile coverage: ${report.coverage.lockfiles ? 'complete' : 'incomplete'}.\n\nScope is open Dependabot alerts, not a complete inventory, reachability analysis or deployment verification.\n`);
    return 0;
  }
  const { report, bytes } = await readReport(file);
  if (command === 'finish') return exitCode(report);
  if (command !== 'publish') throw new Error('invalid_command');
  if (!env.REPORT_ENDPOINT) return 0;
  if (report.source.pr_number !== null || !['push', 'schedule', 'workflow_dispatch'].includes(report.source.event) || report.source.ref !== 'refs/heads/' + report.repository.default_branch) return 0;
  await publish(env.REPORT_ENDPOINT, bytes, env.ACTIONS_ID_TOKEN_REQUEST_URL, env.ACTIONS_ID_TOKEN_REQUEST_TOKEN);
  return 0;
}
if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname)) {
  main(process.argv[2], process.env).then(code => { process.exitCode = code; }).catch(() => {
    process.stderr.write('Dependency evidence could not be completed; raw diagnostics suppressed.\n'); process.exitCode = 2;
  });
}
