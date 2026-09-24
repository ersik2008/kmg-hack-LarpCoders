#!/usr/bin/env node
/**
 * KMG AI Security Agent — git guard.
 *
 * Runs inside git's pre-push / pre-commit hooks, i.e. BEFORE git transfers
 * anything to the remote. It reads the exact blobs git is about to send,
 * submits them to the KMG backend (which runs the real Semgrep/Gitleaks/Trivy
 * pipeline), and prints what was found. Local hooks are deliberately advisory:
 * they always let the commit or push continue. The same script runs in CI,
 * where a BLOCK or incomplete scan exits non-zero and enforces the policy.
 *
 * Usage:
 *   node kmg-guard.mjs pre-push  <remote-name> <remote-url>   (refs on stdin)
 *   node kmg-guard.mjs pre-commit
 *
 * Configuration (env vars, or a .kmg.json file in the repository root):
 *   KMG_API_URL        default http://localhost:3000/api
 *   KMG_TOKEN          KMG session token (required)
 *   KMG_BLOCK_ON       CRITICAL | HIGH | ANY     (default: server policy verdict)
 *   KMG_FAIL_OPEN      1 = allow a failed CI scan (default: 0; CI is fail-closed)
 *   KMG_MAX_FILES      default 5000 (в режиме ci усечение = проверка неполная, exit 2)
 *   KMG_SCAN_SCOPE     all (по умолчанию, ТЗ п. 4.4.1) | changed
 *   KMG_MAX_FILE_KB    default 512
 */

import { execFileSync } from 'node:child_process';
import { readFileSync, existsSync, writeFileSync, appendFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { buildJsonReport, buildMarkdownReport, violatedRequirementsLines } from './kmg-report.mjs';

const ZERO_SHA = '0000000000000000000000000000000000000000';
const NEWLINE = String.fromCharCode(10);

const colors = process.stdout.isTTY
  ? {
      reset: '\x1b[0m', bold: '\x1b[1m', dim: '\x1b[2m',
      red: '\x1b[31m', yellow: '\x1b[33m', green: '\x1b[32m',
      cyan: '\x1b[36m', magenta: '\x1b[35m',
    }
  : new Proxy({}, { get: () => '' });

const SEVERITY_ORDER = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };
const SEVERITY_COLOR = {
  CRITICAL: colors.red, HIGH: colors.red, MEDIUM: colors.yellow,
  LOW: colors.cyan, INFO: colors.dim,
};

function git(args, opts = {}) {
  return execFileSync('git', args, {
    encoding: opts.encoding === 'buffer' ? 'buffer' : 'utf8',
    maxBuffer: 64 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

function gitQuiet(args, opts = {}) {
  try {
    return git(args, opts);
  } catch {
    return null;
  }
}

function repoRoot() {
  return (gitQuiet(['rev-parse', '--show-toplevel']) || '').trim();
}

function loadConfig(root) {
  let fileConfig = {};
  const configPath = join(root, '.kmg.json');
  if (existsSync(configPath)) {
    try {
      fileConfig = JSON.parse(readFileSync(configPath, 'utf8'));
    } catch (err) {
      console.error(`${colors.yellow}[KMG] .kmg.json is not valid JSON, ignoring it: ${err.message}${colors.reset}`);
    }
  }

  // git config keys (kmg.token, kmg.apiurl, ...) keep the token out of the
  // shell environment and out of the repository.
  const fromGitConfig = key => {
    const value = gitQuiet(['config', '--get', `kmg.${key}`]);
    const trimmed = value ? value.trim() : '';
    return trimmed || undefined;
  };

  const pick = (envKey, fileKey, fallback) =>
    process.env[envKey] ?? fromGitConfig(fileKey.toLowerCase()) ?? fileConfig[fileKey] ?? fallback;

  return {
    apiUrl: String(pick('KMG_API_URL', 'apiUrl', 'http://localhost:3000/api')).replace(/\/+$/, ''),
    token: pick('KMG_TOKEN', 'token', ''),
    blockOn: String(pick('KMG_BLOCK_ON', 'blockOn', '')).toUpperCase(),
    failOpen: String(pick('KMG_FAIL_OPEN', 'failOpen', '0')) === '1',
    maxFiles: Number(pick('KMG_MAX_FILES', 'maxFiles', 5000)),
    maxFileKb: Number(pick('KMG_MAX_FILE_KB', 'maxFileKb', 512)),
    // Явный KMG_TIMEOUT_MS ограничивает один запрос; без него в режиме ci запрос
    // ограничен только общим бюджетом времени (см. timeBudgetMs).
    timeoutMs: Number(pick('KMG_TIMEOUT_MS', 'timeoutMs', 0)),
    // ТЗ п. 4.7: шаг проверки укладывается в 30 минут. Бюджет заведомо меньше, чтобы
    // агент успел сформировать отчёт и вернуть код завершения сам (п. 4.7.2), а не
    // был убит по timeout-minutes без отчёта.
    timeBudgetMs: Number(pick('KMG_TIME_BUDGET_MS', 'timeBudgetMs', 25 * 60 * 1000)),
    // Explicit "owner/name" override for remotes that are not github.com URLs.
    repository: pick('KMG_REPOSITORY', 'repository', ''),
  };
}

function parseRepoFullName(remoteUrl) {
  if (!remoteUrl) return null;
  const match = String(remoteUrl)
    .trim()
    .match(/github\.com[:/]+([^/\s]+)\/([^/\s]+?)(?:\.git)?$/i);
  return match ? `${match[1]}/${match[2]}` : null;
}

/** Files that git is about to push, per ref update read from stdin. */
function collectPrePushTargets(stdinText) {
  const targets = [];

  for (const line of stdinText.split('\n')) {
    const parts = line.trim().split(/\s+/);
    if (parts.length < 4) continue;

    const [localRef, localSha, remoteRef, remoteSha] = parts;
    if (localSha === ZERO_SHA) continue; // branch deletion — nothing to scan

    let paths = [];

    if (remoteSha === ZERO_SHA) {
      // New branch on the remote: scan everything that is new compared to
      // whatever the remote already knows, falling back to the full tree.
      const newCommits = (gitQuiet(['rev-list', localSha, '--not', '--remotes']) || '')
        .trim().split('\n').filter(Boolean);

      if (newCommits.length > 0) {
        const oldest = newCommits[newCommits.length - 1];
        const base = (gitQuiet(['rev-parse', `${oldest}^`]) || '').trim();
        if (base) {
          paths = diffNames(base, localSha);
        }
      }

      if (paths.length === 0) {
        paths = (gitQuiet(['ls-tree', '-r', '--name-only', localSha]) || '')
          .trim().split('\n').filter(Boolean);
      }
    } else {
      paths = diffNames(remoteSha, localSha);
    }

    targets.push({ ref: localRef || remoteRef, sha: localSha, paths });
  }

  return targets;
}

function diffNames(from, to) {
  const out = gitQuiet(['diff', '--name-only', '--diff-filter=ACMR', from, to]);
  return (out || '').trim().split('\n').filter(Boolean);
}

function collectPreCommitTargets() {
  const paths = (gitQuiet(['diff', '--cached', '--name-only', '--diff-filter=ACMR']) || '')
    .trim().split('\n').filter(Boolean);
  return [{ ref: 'INDEX', sha: null, paths }];
}

/**
 * Files to check in a CI run.
 *
 * Same code path as the git hooks, so what CI enforces and what the developer
 * saw locally are produced by exactly the same logic.
 */
function collectCiTargets() {
  const head = (process.env.KMG_HEAD_REF || '').trim() || (gitQuiet(['rev-parse', 'HEAD']) || '').trim();
  const base = (process.env.KMG_BASE_REF || '').trim();
  // ТЗ п. 4.4.1: по умолчанию — весь проект, а не дифф коммита.
  const scope = (process.env.KMG_SCAN_SCOPE || 'all').toLowerCase();

  if (scope === 'all' || !base || /^0+$/.test(base)) {
    const paths = (gitQuiet(['ls-tree', '-r', '--name-only', head || 'HEAD']) || '')
      .trim().split(NEWLINE).filter(Boolean);
    return [{ ref: 'CI', sha: head || null, paths }];
  }

  let paths = diffNames(base, head);
  if (paths.length === 0) {
    // Base commit unreachable in a shallow clone: fall back to the full tree
    // rather than silently checking nothing.
    paths = (gitQuiet(['ls-tree', '-r', '--name-only', head || 'HEAD']) || '')
      .trim().split(NEWLINE).filter(Boolean);
  }
  return [{ ref: 'CI', sha: head || null, paths }];
}

function looksBinary(buffer) {
  const slice = buffer.subarray(0, Math.min(buffer.length, 8000));
  return slice.includes(0);
}

/** Reads a blob exactly as it exists in the commit/index being checked. */
function readBlob(sha, path) {
  const spec = sha ? `${sha}:${path}` : `:${path}`;
  return gitQuiet(['show', spec], { encoding: 'buffer' });
}

/**
 * Lock-файлы зависимостей. Trivy находит уязвимые зависимости именно по ним, а
 * у реального проекта package-lock.json легко весит мегабайты. Общий лимит
 * размера файла (512 КБ) молча убрал бы их из проверки, и раздел «зависимости»
 * превратился бы в «нечего проверять». Предел для них — ограничение самого API
 * (4 млн символов base64 ≈ 2,9 МБ).
 */
const LOCKFILE = /(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|Pipfile\.lock|go\.sum|Cargo\.lock|composer\.lock|Gemfile\.lock)$/;
const LOCKFILE_MAX_BYTES = 2_800_000;

function buildPayloadFiles(targets, config) {
  const seen = new Map();
  const skipped = { binary: 0, tooLarge: 0, unreadable: 0, truncated: 0, tooLargeNames: [] };

  for (const target of targets) {
    for (const path of target.paths) {
      if (seen.has(path)) continue;
      if (seen.size >= config.maxFiles) {
        skipped.truncated++;
        continue;
      }

      const buffer = readBlob(target.sha, path);
      if (!buffer) {
        skipped.unreadable++;
        continue;
      }
      const limit = LOCKFILE.test(path) ? LOCKFILE_MAX_BYTES : config.maxFileKb * 1024;
      if (buffer.length > limit) {
        skipped.tooLarge++;
        if (skipped.tooLargeNames.length < 8) skipped.tooLargeNames.push(path);
        continue;
      }
      if (looksBinary(buffer)) {
        skipped.binary++;
        continue;
      }

      seen.set(path, { path, contentBase64: buffer.toString('base64') });
    }
  }

  return { files: [...seen.values()], skipped };
}

async function requestCheck(config, payload, timeoutMs = config.timeoutMs || 300000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(`${config.apiUrl}/prepush/check`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${config.token}`,
      },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });

    const text = await res.text();

    if (!res.ok) {
      let detail = text.slice(0, 400);
      try {
        const parsed = JSON.parse(text);
        detail = parsed.message || parsed.error || detail;
      } catch { /* keep raw text */ }
      throw new Error(`KMG API responded ${res.status}: ${detail}`);
    }

    return JSON.parse(text);
  } catch (err) {
    // Превышение времени — отдельная причина: оператору важно отличить «backend
    // не ответил» от «мы сами прервали проверку по бюджету».
    if (err?.name === 'AbortError') {
      const timeout = new Error(`Превышено время ожидания ответа KMG (${Math.round(timeoutMs / 1000)} с)`);
      timeout.timedOut = true;
      throw timeout;
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Результат «проверка не выполнена» для отчёта.
 *
 * ТЗ п. 4.3.4: отчёт сохраняется как артефакт и доступен вне зависимости от
 * результата пайплайна. Поэтому и при сбое проверки формируется отчёт — с
 * результатом ERROR, кодом 2 и причиной, а не пустота на месте артефакта.
 */
export function buildErrorResult({ reason, timedOut = false, filesChecked = null, commitSha = null, startedAt = null }) {
  return {
    verdict: null,
    statusText: timedOut ? 'TIME_LIMIT' : 'SCAN_ERROR',
    blocked: true,
    incomplete: true,
    riskScore: null,
    reasons: [reason],
    counts: {},
    findings: [],
    scanners: {},
    requirements: [],
    requirementsEvaluated: false,
    violatedRequirements: [],
    insufficientRequirements: [],
    decisionBasis: 'incomplete',
    filesChecked,
    commitSha,
    startedAt,
    finishedAt: new Date().toISOString(),
    error: true,
  };
}

function printFindings(result) {
  const findings = [...(result.findings || [])].sort(
    (a, b) => (SEVERITY_ORDER[b.severity] || 0) - (SEVERITY_ORDER[a.severity] || 0),
  );

  if (findings.length === 0) {
    console.error(`${colors.green}  Уязвимостей в изменённых файлах не найдено.${colors.reset}`);
    return;
  }

  for (const f of findings) {
    const color = SEVERITY_COLOR[f.severity] || '';
    const location = f.filePath
      ? `${f.filePath}${f.startLine ? `:${f.startLine}` : ''}`
      : '(файл не указан)';

    console.error('');
    console.error(`  ${color}${colors.bold}[${f.severity}]${colors.reset} ${f.title}`);
    console.error(`    ${colors.cyan}${location}${colors.reset}  ${colors.dim}(${f.scanner}${f.ruleId ? ` · ${f.ruleId}` : ''})${colors.reset}`);

    if (f.description) {
      const text = String(f.description).replace(/\s+/g, ' ').trim();
      console.error(`    ${text.length > 400 ? `${text.slice(0, 400)}…` : text}`);
    }

    if (f.codeSnippet && f.codeSnippet !== '***REDACTED***') {
      const snippet = String(f.codeSnippet).split('\n').slice(0, 4);
      for (const line of snippet) {
        console.error(`    ${colors.dim}│ ${line.trim()}${colors.reset}`);
      }
    }
  }
}

/** Статус по каждому требованию ИБ, включая не нарушенные (ТЗ п. 4.6.3). */
function printRequirementMatrix(result) {
  const list = result.requirements || [];
  if (list.length === 0) {
    if (result.requirementsEvaluated === false) {
      console.error(`  ${colors.dim}Требования ИБ-01…ИБ-08: не оценивались (анализ по изменённым файлам).${colors.reset}`);
    }
    return;
  }
  console.error(`  ${colors.bold}Требования ИБ:${colors.reset}`);
  for (const r of list) {
    const color = r.status === 'VIOLATION' ? colors.red
      : r.status === 'PASS' ? colors.green
      : r.status === 'INSUFFICIENT_EVIDENCE' ? colors.yellow : colors.dim;
    console.error(`    ${color}${r.requirementId.padEnd(6)} ${r.status}${colors.reset}  ${colors.dim}${r.title}${colors.reset}`);
  }
  console.error('');
}

function printScannerStatus(result) {
  const entries = Object.entries(result.scanners || {});
  const broken = entries.filter(([, rec]) => rec.status !== 'COMPLETED');

  const summary = entries
    .map(([name, rec]) => `${name}=${rec.status}`)
    .join(' ');
  console.error(`  ${colors.dim}Сканеры: ${summary}${colors.reset}`);

  for (const [name, rec] of broken) {
    if (rec.error) {
      console.error(`  ${colors.yellow}! ${name}: ${String(rec.error).slice(0, 220)}${colors.reset}`);
    }
  }
}

function shouldBlock(result, config) {
  // An explicit threshold can make CI stricter than the server-side policy.
  if (config.blockOn && SEVERITY_ORDER[config.blockOn]) {
    const threshold = SEVERITY_ORDER[config.blockOn];
    const worst = (result.findings || []).reduce(
      (max, f) => Math.max(max, SEVERITY_ORDER[f.severity] || 0), 0,
    );
    if (worst >= threshold) return true;
  }
  if (config.blockOn === 'ANY' && (result.findings || []).length > 0) return true;

  return Boolean(result.blocked || result.verdict === 'BLOCK');
}

/** Local hooks report security verdicts; CI is the only enforcing mode. */
export function enforcementMode(mode) {
  return mode === 'ci' ? 'enforce' : 'advisory';
}

function hasFailedScanner(result) {
  return Object.values(result.scanners || {}).some(scanner =>
    scanner?.status && scanner.status !== 'COMPLETED' && scanner.status !== 'SKIPPED',
  );
}

/**
 * Коды завершения по ТЗ п. 4.3.3.
 *
 *   0 — нарушений Требований ИБ не выявлено, пайплайн продолжается;
 *   1 — выявлено одно или более нарушений, пайплайн прерывается;
 *   2 — проверка НЕ ВЫПОЛНЕНА из-за внутренней ошибки (недоступность модели
 *       или backend, превышение лимитов, ошибка разбора проекта).
 *
 * Разделение 1 и 2 принципиально: «код нарушает требования» и «мы не смогли
 * проверить» — разные факты. Раньше оба давали 1, и оператор CI не мог отличить
 * дефект безопасности от сбоя инфраструктуры. Ни один из них не равен 0:
 * невыполненная проверка никогда не трактуется как успешная.
 */
export const EXIT_PASS = 0;
export const EXIT_VIOLATION = 1;
export const EXIT_ERROR = 2;

/**
 * Итоговый код завершения по результату проверки.
 *
 * Локальные хуки всегда возвращают 0: вердикт остаётся настоящим, меняется
 * только точка его применения.
 */
export function resolveExitCode(result, config, mode) {
  if (enforcementMode(mode) !== 'enforce') return EXIT_PASS;

  // Подтверждённое нарушение обязательного требования ИБ решает дело само по
  // себе: проверка требований от сканеров не зависит, поэтому нарушение
  // остаётся нарушением (код 1) и при незавершённом сканере, а не прячется под
  // кодом 2. Это единственный случай, когда «не выполнено» уступает «нарушено».
  if (Array.isArray(result?.violatedRequirements) && result.violatedRequirements.length > 0) {
    return EXIT_VIOLATION;
  }

  // Сначала «проверка не выполнена»: незавершённый сканер или оборванный скан
  // не позволяют вынести вердикт вообще, поэтому это не нарушение, а ошибка.
  if (result?.incomplete || hasFailedScanner(result) || result?.truncated) return EXIT_ERROR;

  return shouldBlock(result, config) ? EXIT_VIOLATION : EXIT_PASS;
}

/**
 * Keep the security decision separate from where it is enforced. A BLOCK is
 * still a BLOCK locally; it just never turns into a non-zero hook exit code.
 */
export function shouldFailProcess(result, config, mode) {
  return resolveExitCode(result, config, mode) !== EXIT_PASS;
}

/** KMG_FAIL_OPEN applies only to an unavailable CI scan, never to a verdict. */
export function shouldFailOnScanError(config, mode) {
  return enforcementMode(mode) === 'enforce' && !config.failOpen;
}


/**
 * Минимальный SARIF 2.1.0 по результату pre-push проверки.
 *
 * Тот же формат, что отдаёт backend, но собирается локально: в CI не нужно
 * ходить за отчётом вторым запросом, а GitHub-экшену достаточно файла.
 */
const SARIF_LEVEL = {
  CRITICAL: { level: 'error', score: '9.5' },
  HIGH: { level: 'error', score: '7.5' },
  MEDIUM: { level: 'warning', score: '5.0' },
  LOW: { level: 'note', score: '3.0' },
  INFO: { level: 'note', score: '1.0' },
};

function toSarif(result) {
  const rules = [];
  const ruleIndex = new Map();
  const results = [];

  for (const f of result.findings || []) {
    const sev = SARIF_LEVEL[f.severity] || SARIF_LEVEL.MEDIUM;
    const ruleId = `${f.scanner}/${String(f.ruleId || 'unknown-rule').replace(/\s+/g, '-')}`;

    if (!ruleIndex.has(ruleId)) {
      ruleIndex.set(ruleId, rules.length);
      rules.push({
        id: ruleId,
        shortDescription: { text: String(f.title || ruleId).slice(0, 200) },
        fullDescription: { text: String(f.description || f.title || '').slice(0, 1000) },
        defaultConfiguration: { level: sev.level },
        properties: {
          tags: ['security', f.scanner],
          'security-severity': sev.score,
        },
      });
    }

    results.push({
      ruleId,
      ruleIndex: ruleIndex.get(ruleId),
      level: sev.level,
      message: { text: String(f.title || ruleId).slice(0, 1000) },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: String(f.filePath || 'unknown').replace(/^\.?\//, '') },
          region: { startLine: f.startLine && f.startLine > 0 ? f.startLine : 1 },
        },
      }],
    });
  }

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: { driver: { name: 'KMG AI Security Agent', version: '1.0.0', rules } },
      automationDetails: { id: 'kmg-ai/security-scan' },
      results,
    }],
  };
}

/**
 * CI surface: a job summary a reviewer can read without opening logs, plus
 * step outputs so a workflow can branch on the verdict.
 */
function emitCiArtifacts(result, exitCode, context = {}) {
  const c = result.counts || {};
  const scanIncomplete = result.incomplete || hasFailedScanner(result) || Boolean(result.truncated);
  const verdict = scanIncomplete ? 'INCOMPLETE' : result.verdict || result.statusText || 'UNKNOWN';
  const failed = exitCode !== EXIT_PASS;

  // Отчёт Агента (ТЗ п. 4.6): JSON и Markdown строятся из одного результата и
  // одного кода завершения, поэтому не расходятся между собой и с решением
  // пайплайна (п. 4.6.5).
  try {
    writeFileSync('kmg-scan-report.json', JSON.stringify(buildJsonReport(result, exitCode, context), null, 2));
  } catch { /* report file is a convenience, not a requirement */ }
  try {
    writeFileSync('kmg-report.md', buildMarkdownReport(result, exitCode, context));
  } catch { /* the Markdown view is a convenience, not a requirement */ }
  try {
    // Сырой ответ backend — для отладки; в отчёт для комиссии не входит.
    writeFileSync('kmg-scan-response.json', JSON.stringify(result, null, 2));
  } catch { /* debug copy */ }

  // SARIF для GitHub Code Scanning: находки попадают во вкладку Security и
  // аннотируются прямо на строках изменённых файлов.
  try {
    writeFileSync('kmg-results.sarif', JSON.stringify(toSarif(result), null, 2));
  } catch { /* SARIF — дополнение, его отсутствие не ломает проверку */ }

  const out = process.env.GITHUB_OUTPUT;
  if (out) {
    try {
      appendFileSync(
        out,
        `verdict=${verdict}${NEWLINE}critical=${c.CRITICAL || 0}${NEWLINE}` +
        `high=${c.HIGH || 0}${NEWLINE}blocked=${failed}${NEWLINE}` +
        `exit-code=${exitCode}${NEWLINE}` +
        `violated-requirements=${(result.violatedRequirements || []).join(',')}${NEWLINE}` +
        `report=kmg-scan-report.json${NEWLINE}report-md=kmg-report.md${NEWLINE}sarif=kmg-results.sarif${NEWLINE}`,
      );
    } catch { /* not running under GitHub Actions */ }
  }

  const summaryPath = process.env.GITHUB_STEP_SUMMARY;
  if (!summaryPath) return;

  // Job summary — тот же Markdown-отчёт, что и артефакт kmg-report.md: человек,
  // открывший запуск, видит причину прерывания без скачивания артефакта.
  try {
    appendFileSync(summaryPath, buildMarkdownReport(result, exitCode, context) + NEWLINE);
  } catch { /* summary is best-effort */ }
}


function header(stage) {
  console.error('');
  const title = stage === 'pre-commit'
    ? 'перед коммитом'
    : stage === 'ci'
      ? 'в CI (enforcing)'
      : 'перед push';
  console.error(`${colors.magenta}${colors.bold}  KMG AI Security Agent — проверка ${title}${colors.reset}`);
  console.error(`${colors.dim}  ────────────────────────────────────────────────────────────${colors.reset}`);
}

function printLocalScanFailure(stage, error) {
  console.error('');
  console.error(`${colors.yellow}${colors.bold}  ⚠ KMG Security Agent could not complete the scan.${colors.reset}`);
  console.error(`  ${colors.dim}${error.message}${colors.reset}`);
  if (stage === 'pre-commit') {
    console.error('  Commit allowed.');
    console.error('  Review findings before opening a Pull Request.');
  } else {
    console.error('  Push allowed locally.');
    console.error('  CI/GitHub security check will perform the authoritative scan.');
  }
}

function printLocalAdvisory(stage, result, policyBlocked) {
  const scanIncomplete = result.incomplete || hasFailedScanner(result);
  const decision = scanIncomplete
    ? 'INCOMPLETE'
    : result.verdict || result.statusText || (policyBlocked ? 'BLOCK' : 'UNKNOWN');

  console.error('');
  if (policyBlocked || scanIncomplete) {
    console.error(`${colors.yellow}${colors.bold}  ⚠ Security policy: ${decision}${colors.reset}`);
  } else if ((result.findings || []).length > 0) {
    console.error(`${colors.yellow}${colors.bold}  ⚠ KMG Security Agent found security issues.${colors.reset}`);
  } else {
    console.error(`${colors.green}${colors.bold}  ✔ Security policy: ${decision}.${colors.reset}`);
  }

  if (stage === 'pre-commit') {
    console.error('  Commit allowed.');
    console.error('  Review findings before opening a Pull Request.');
  } else {
    console.error('  Local push is allowed.');
    console.error('  CI/GitHub merge protection will enforce this policy.');
  }
  console.error(`  ${colors.dim}Enforcement: Local ADVISORY · CI BLOCKING.${colors.reset}`);
  console.error('');
}

/** exit 1 — проверка выполнена и выявила нарушения. */
function printCiFailure(result, policyBlocked) {
  const decision = result.verdict || result.statusText || (policyBlocked ? 'BLOCK' : 'FAILED');
  const violated = violatedRequirementsLines(result);
  console.error('');
  console.error(`${colors.red}${colors.bold}  ✖ Выявлены нарушения требований ИБ — сборка остановлена (exit 1).${colors.reset}`);
  // ТЗ п. 4.3.5: количество нарушений и перечень нарушенных требований — прямо
  // в журнале шага, без открытия артефакта.
  if (violated.length > 0) {
    console.error(`  ${colors.red}${colors.bold}Нарушено требований ИБ: ${violated.length}${colors.reset}`);
    for (const line of violated) console.error(`  ${colors.red}· ${line}${colors.reset}`);
  }
  console.error(`  ${colors.red}${colors.bold}Security policy: ${decision}.${colors.reset}`);
  console.error('  Merge cannot proceed until security checks pass.');
  console.error('');
}

/**
 * exit 2 — проверка НЕ ВЫПОЛНЕНА.
 *
 * Отдельное сообщение принципиально: «мы не смогли проверить» не равно «код
 * нарушает требования». Причина печатается явно, чтобы оператор CI сразу видел,
 * что чинить — инфраструктуру, а не код.
 */
function printCiIncomplete(result) {
  const causes = [];
  if (result.incomplete) causes.push(`вердикт не вынесен (${result.statusText || 'SCAN_INCOMPLETE'})`);
  for (const [name, rec] of Object.entries(result.scanners || {})) {
    if (rec?.status && rec.status !== 'COMPLETED' && rec.status !== 'SKIPPED') {
      causes.push(`сканер ${name}: ${rec.status}${rec.error ? ` — ${String(rec.error).slice(0, 160)}` : ''}`);
    }
  }
  if (result.truncated) causes.push(`не проверено файлов: ${result.truncated} (превышен KMG_MAX_FILES)`);

  console.error('');
  console.error(`${colors.yellow}${colors.bold}  ✖ Проверка не выполнена — вердикт не вынесен (exit 2).${colors.reset}`);
  for (const cause of causes.length ? causes : ['причина не детализирована']) {
    console.error(`  ${colors.yellow}· ${cause}${colors.reset}`);
  }
  console.error('');
  console.error(`  ${colors.bold}Отсутствие находок в этом отчёте НЕ означает, что код безопасен.${colors.reset}`);
  console.error('  Merge cannot proceed until the security check completes.');
  console.error('');
}

async function main() {
  const processStart = Date.now();
  const mode = process.argv[2];
  const isCi = mode === 'ci';
  const stage = isCi ? 'ci' : mode === 'pre-commit' ? 'pre-commit' : 'pre-push';
  const remoteName = process.argv[3] || 'origin';
  const remoteUrlArg = process.argv[4];

  const root = repoRoot();
  if (!root) {
    console.error(`${colors.yellow}[KMG] Не git-репозиторий — проверку выполнить невозможно.${colors.reset}`);
    // Не «нарушений нет» и не «есть нарушение»: разобрать проект не удалось.
    return isCi ? EXIT_ERROR : EXIT_PASS;
  }

  const config = loadConfig(root);

  let stdinText = '';
  if (!isCi && stage === 'pre-push' && !process.stdin.isTTY) {
    stdinText = readFileSync(0, 'utf8');
  }

  const targets = isCi
    ? collectCiTargets()
    : stage === 'pre-push'
      ? collectPrePushTargets(stdinText)
      : collectPreCommitTargets();

  const scanScope = (process.env.KMG_SCAN_SCOPE || 'all').toLowerCase();

  const totalPaths = targets.reduce((sum, t) => sum + t.paths.length, 0);
  if (totalPaths === 0) {
    // При scope=changed пустой дифф — нормальная ситуация (менялись только
    // удалённые или бинарные файлы). При scope=all пустое дерево означает, что
    // проверять было нечего: это ошибка разбора проекта, а не чистый результат.
    if (isCi && scanScope === 'all') {
      console.error(`${colors.red}${colors.bold}  ✖ Проверка не выполнена: в репозитории не найдено ни одного файла.${colors.reset}`);
      return EXIT_ERROR;
    }
    console.error(`${colors.dim}[KMG] Нет изменённых файлов для проверки — пропуск.${colors.reset}`);
    return EXIT_PASS;
  }

  header(stage);

  if (!config.token) {
    const error = new Error('KMG_TOKEN is not configured; the security scan cannot run.');
    if (shouldFailOnScanError(config, mode)) {
      console.error(`${colors.red}${colors.bold}  ✖ Проверка не выполнена (exit 2).${colors.reset}`);
      console.error(`  ${error.message}`);
      console.error('  Merge cannot proceed until security checks pass.');
      if (isCi) {
        emitCiArtifacts(
          buildErrorResult({ reason: `Проверка не выполнена: ${error.message}`, commitSha: (gitQuiet(['rev-parse', 'HEAD']) || '').trim() || null, startedAt: new Date(processStart).toISOString() }),
          EXIT_ERROR,
          { commitSha: (gitQuiet(['rev-parse', 'HEAD']) || '').trim() || null, scope: scanScope, startedAt: new Date(processStart).toISOString(), finishedAt: new Date().toISOString() },
        );
      }
      return EXIT_ERROR;
    }
    if (isCi) {
      console.error(`${colors.yellow}  KMG_FAIL_OPEN=1 — CI scan could not run; build allowed by explicit configuration.${colors.reset}`);
      return EXIT_PASS;
    }
    printLocalScanFailure(stage, error);
    return EXIT_PASS;
  }

  const { files, skipped } = buildPayloadFiles(targets, config);

  if (files.length === 0) {
    if (isCi) {
      console.error(`${colors.red}${colors.bold}  ✖ Проверка не выполнена: ни один файл не пригоден для анализа.${colors.reset}`);
      console.error(`  Пропущено: бинарных ${skipped.binary}, слишком больших ${skipped.tooLarge}, нечитаемых ${skipped.unreadable}.`);
      emitCiArtifacts(
        buildErrorResult({
          reason: `Проверка не выполнена: ни один файл не пригоден для анализа (бинарных ${skipped.binary}, слишком больших ${skipped.tooLarge}, нечитаемых ${skipped.unreadable}).`,
          filesChecked: 0,
          commitSha: (gitQuiet(['rev-parse', 'HEAD']) || '').trim() || null,
          startedAt: new Date(processStart).toISOString(),
        }),
        EXIT_ERROR,
        { commitSha: (gitQuiet(['rev-parse', 'HEAD']) || '').trim() || null, scope: scanScope, startedAt: new Date(processStart).toISOString(), finishedAt: new Date().toISOString() },
      );
      return EXIT_ERROR;
    }
    console.error(`${colors.dim}  Нет текстовых файлов для анализа (бинарные/слишком большие пропущены).${colors.reset}`);
    return EXIT_PASS;
  }

  const remoteUrl = remoteUrlArg || (gitQuiet(['remote', 'get-url', remoteName]) || '').trim();
  const branch = (gitQuiet(['rev-parse', '--abbrev-ref', 'HEAD']) || '').trim();

  console.error(
    `  Проверяется ${colors.bold}${files.length}${colors.reset} файл(ов) ` +
    `(${scanScope === 'all' ? 'весь репозиторий' : 'изменённые файлы'}) ` +
    `из ветки ${colors.bold}${branch || '?'}${colors.reset}...`,
  );
  if (skipped.tooLarge) {
    // Не «нечего проверять», а «не проверено»: в отчёте это должно быть видно.
    console.error(`  ${colors.dim}Пропущено как слишком большие (> ${config.maxFileKb} КБ): ${skipped.tooLarge}${skipped.tooLargeNames.length ? ` — ${skipped.tooLargeNames.slice(0, 3).join(', ')}${skipped.tooLarge > 3 ? '…' : ''}` : ''}${colors.reset}`);
  }
  if (skipped.truncated) {
    console.error(`  ${colors.yellow}! Превышен лимит KMG_MAX_FILES=${config.maxFiles}: не проверено файлов — ${skipped.truncated}.${colors.reset}`);
    console.error(`  ${colors.yellow}  Проверка неполная: поднимите max-files, иначе результат не покрывает проект целиком.${colors.reset}`);
  }

  const startedAt = new Date().toISOString();
  const payload = {
    repository: config.repository || process.env.GITHUB_REPOSITORY || parseRepoFullName(remoteUrl) || undefined,
    branch: branch || undefined,
    commitSha: targets[0]?.sha || (gitQuiet(['rev-parse', 'HEAD']) || '').trim() || undefined,
    remote: remoteName,
    stage,
    // Сервер оценивает сквозные требования ИБ только при полном объёме: по
    // диффу их установить нельзя (ТЗ п. 1.19, 4.4.2).
    scope: isCi ? (scanScope === 'all' ? 'all' : 'changed') : 'changed',
    startedAt,
    files,
  };

  // Оставшийся бюджет времени: запрос не должен пережить сам шаг проверки.
  const remainingMs = config.timeBudgetMs - (Date.now() - processStart);
  const requestTimeout = isCi
    ? Math.max(1000, Math.min(config.timeoutMs || Infinity, remainingMs))
    : (config.timeoutMs || 300000);

  let result;
  try {
    result = await requestCheck(config, payload, requestTimeout);
  } catch (err) {
    if (shouldFailOnScanError(config, mode)) {
      console.error('');
      console.error(`${colors.red}${colors.bold}  ✖ Проверка не выполнена: security validation could not complete (exit 2).${colors.reset}`);
      console.error(`  ${err.message}`);
      if (err.timedOut) {
        console.error(`  Бюджет времени шага: ${Math.round(config.timeBudgetMs / 60000)} мин (ТЗ п. 4.7.1: не более 30).`);
      }
      console.error('  Merge cannot proceed until security checks pass.');
      if (isCi) {
        // Отчёт формируется и при сбое — он нужен именно тогда (ТЗ п. 4.3.4, 4.7.2).
        emitCiArtifacts(
          buildErrorResult({
            reason: err.timedOut
              ? `Превышен бюджет времени проверки: ${err.message}`
              : `Проверка не выполнена: ${err.message}`,
            timedOut: Boolean(err.timedOut),
            filesChecked: files.length,
            commitSha: payload.commitSha ?? null,
            startedAt,
          }),
          EXIT_ERROR,
          { repository: payload.repository, branch: payload.branch, commitSha: payload.commitSha, scope: payload.scope, startedAt, finishedAt: new Date().toISOString() },
        );
      }
      return EXIT_ERROR;
    }
    if (isCi) {
      console.error(`${colors.yellow}  KMG_FAIL_OPEN=1 — CI scan could not run; build allowed by explicit configuration.${colors.reset}`);
      return EXIT_PASS;
    }
    printLocalScanFailure(stage, err);
    return EXIT_PASS;
  }

  // Усечение по KMG_MAX_FILES — тоже неполная проверка: она попадает в вердикт
  // как превышение лимита, а не молча остаётся предупреждением в логе.
  if (skipped.truncated > 0) {
    result.truncated = skipped.truncated;
    result.reasons = [
      ...(result.reasons || []),
      `Превышен лимит KMG_MAX_FILES=${config.maxFiles}: ${skipped.truncated} файл(ов) не проверено — результат не покрывает проект целиком.`,
    ];
  }

  printRequirementMatrix(result);
  printFindings(result);
  console.error('');
  printScannerStatus(result);

  const c = result.counts || {};
  console.error(
    `  ${colors.bold}Итог:${colors.reset} ` +
    `${colors.red}CRITICAL ${c.CRITICAL || 0}${colors.reset}  ` +
    `${colors.red}HIGH ${c.HIGH || 0}${colors.reset}  ` +
    `${colors.yellow}MEDIUM ${c.MEDIUM || 0}${colors.reset}  ` +
    `${colors.cyan}LOW ${c.LOW || 0}${colors.reset}  ` +
    `${colors.dim}INFO ${c.INFO || 0}${colors.reset}`,
  );
  console.error(
    `  Вердикт политики: ${colors.bold}${result.verdict || result.statusText}${colors.reset}` +
    (result.riskScore != null ? `   Риск: ${result.riskScore}/10` : ''),
  );
  for (const reason of result.reasons || []) {
    console.error(`  ${colors.dim}· ${reason}${colors.reset}`);
  }
  if (result.scanId) {
    console.error(`  ${colors.dim}Детали: ${config.apiUrl.replace(/\/api$/, '')}  scan ${result.scanId}${colors.reset}`);
  }

  const policyBlocked = shouldBlock(result, config);
  const exitCode = resolveExitCode(result, config, mode);

  if (isCi) {
    emitCiArtifacts(result, exitCode, {
      repository: payload.repository,
      branch: payload.branch,
      commitSha: payload.commitSha,
      scope: payload.scope,
      startedAt,
      finishedAt: new Date().toISOString(),
    });
  }

  if (exitCode === EXIT_ERROR) {
    printCiIncomplete(result);
    return EXIT_ERROR;
  }

  if (exitCode === EXIT_VIOLATION) {
    printCiFailure(result, policyBlocked);
    return EXIT_VIOLATION;
  }

  if (!isCi) {
    printLocalAdvisory(stage, result, policyBlocked);
  } else if ((result.findings || []).length > 0) {
    console.error(`${colors.yellow}${colors.bold}  ⚠ Проверка пройдена с замечаниями — рекомендуется исправить.${colors.reset}`);
  } else {
    console.error(`${colors.green}${colors.bold}  ✔ Проблем не найдено.${colors.reset}`);
  }
  console.error('');
  return EXIT_PASS;
}

const invokedAsScript = process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href;

if (invokedAsScript) {
  main()
    .then(code => process.exit(code))
    .catch(err => {
      const isCi = process.argv[2] === 'ci';
      console.error(`${colors.red}[KMG] Internal guard error: ${err?.stack || err}${colors.reset}`);
      // Внутренний сбой самого агента — это код 2, а не «нарушение найдено».
      process.exit(isCi && process.env.KMG_FAIL_OPEN !== '1' ? EXIT_ERROR : EXIT_PASS);
    });
}
