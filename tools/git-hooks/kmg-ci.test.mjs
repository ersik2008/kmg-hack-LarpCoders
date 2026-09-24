/**
 * Сквозные проверки CI-режима guard-а: коды завершения 0/1/2, перечень
 * нарушений в журнале и файлы отчёта (ТЗ п. 4.3.3–4.3.5, 4.6, 4.7.2).
 *
 * Каждый тест запускает настоящий процесс `node kmg-guard.mjs ci` в настоящем
 * git-репозитории против HTTP-заглушки backend. Ничего не подменяется внутри
 * самого guard-а.
 */
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { once } from 'node:events';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const hookDirectory = dirname(fileURLToPath(import.meta.url));
const guardPath = join(hookDirectory, 'kmg-guard.mjs');

const REQ_IDS = ['ИБ-01', 'ИБ-02', 'ИБ-03', 'ИБ-04', 'ИБ-05', 'ИБ-06', 'ИБ-07', 'ИБ-08'];

function git(cwd, args) {
  return execFileSync('git', args, { cwd, encoding: 'utf8' });
}

function run(command, args, { cwd, env } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd, env: { ...process.env, ...env }, stdio: ['pipe', 'pipe', 'pipe'] });
    let output = '';
    child.stdout.on('data', d => { output += d; });
    child.stderr.on('data', d => { output += d; });
    child.on('error', reject);
    child.on('close', code => resolve({ code, output }));
    child.stdin.end();
  });
}

function createRepo() {
  const root = mkdtempSync(join(tmpdir(), 'kmg-ci-test-'));
  const repo = join(root, 'repository');
  git(root, ['init', repo]);
  git(repo, ['config', 'user.email', 'security-test@example.invalid']);
  git(repo, ['config', 'user.name', 'KMG Security Test']);
  writeFileSync(join(repo, 'app.js'), 'export const safe = true;\n');
  writeFileSync(join(repo, 'README.md'), '# demo\n');
  git(repo, ['add', '.']);
  git(repo, ['commit', '-m', 'initial']);
  return { root, repo };
}

async function startKmg(handler) {
  const seen = [];
  const sockets = new Set();
  const server = createServer((req, res) => {
    let body = '';
    req.on('data', d => { body += d; });
    req.on('end', () => {
      try { seen.push(JSON.parse(body)); } catch { /* тело не JSON */ }
      handler(req, res);
    });
  });
  server.on('connection', s => { sockets.add(s); s.on('close', () => sockets.delete(s)); });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return {
    seen,
    apiUrl: `http://127.0.0.1:${server.address().port}/api`,
    close: () => new Promise(resolve => { for (const s of sockets) s.destroy(); server.close(resolve); }),
  };
}

const replyJson = payload => (_req, res) => {
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(payload));
};
const neverReply = () => { /* соединение остаётся открытым */ };

function requirementsFor(violated) {
  return REQ_IDS.map(id => ({
    requirementId: id,
    title: `Требование ${id}`,
    requirementText: `Текст требования ${id}`,
    status: violated.includes(id) ? 'VIOLATION' : 'PASS',
    confidence: 'HIGH',
    summary: `Сводка ${id}`,
    evidence: [],
    violations: violated.includes(id)
      ? [{
          filePath: 'src/auth/password.ts', lineStart: 5, lineEnd: 5, symbol: 'хеширование пароля',
          evidence: "createHash('sha256').update(password)",
          explanation: 'Пароль хешируется быстрой хеш-функцией общего назначения без адаптивного KDF.',
          severity: 'CRITICAL', confidence: 'HIGH', recommendation: 'Заменить на argon2id.',
        }]
      : [],
    insufficientReason: null,
  }));
}

function response(violated = [], overrides = {}) {
  const bad = violated.length > 0;
  return {
    verdict: bad ? 'BLOCK' : 'PASS',
    statusText: bad ? 'BLOCK' : 'PASS',
    blocked: bad,
    incomplete: false,
    decisionBasis: 'requirements',
    requirementsEvaluated: true,
    riskScore: 0,
    counts: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
    findings: [],
    scanners: {
      semgrep: { status: 'COMPLETED' }, gitleaks: { status: 'COMPLETED' }, trivy: { status: 'COMPLETED' },
    },
    requirements: requirementsFor(violated),
    violatedRequirements: violated,
    insufficientRequirements: [],
    reasons: bad ? [`Нарушены обязательные требования ИБ: ${violated.join(', ')}.`] : ['Нарушений нет.'],
    filesChecked: 2,
    scanId: 'ci-scan',
    commitSha: 'abc123',
    startedAt: '2026-09-24T09:00:00.000Z',
    finishedAt: '2026-09-24T09:01:00.000Z',
    durationSeconds: 60,
    ...overrides,
  };
}

function env(apiUrl, extra = {}) {
  return {
    KMG_TOKEN: 'test-token',
    KMG_API_URL: apiUrl,
    KMG_SCAN_SCOPE: 'all',
    KMG_TIMEOUT_MS: '5000',
    // Иначе тест внутри GitHub Actions писал бы в реальный summary job-а.
    GITHUB_STEP_SUMMARY: '',
    GITHUB_OUTPUT: '',
    ...extra,
  };
}

const readJson = repo => JSON.parse(readFileSync(join(repo, 'kmg-scan-report.json'), 'utf8'));

test('нарушение требования ИБ → exit 1, перечень требований в журнале, отчёты сформированы', async t => {
  const { root, repo } = createRepo();
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const kmg = await startKmg(replyJson(response(['ИБ-04'])));
  t.after(kmg.close);

  const ci = await run('node', [guardPath, 'ci'], { cwd: repo, env: env(kmg.apiUrl) });
  assert.equal(ci.code, 1, ci.output);

  // ТЗ п. 4.3.5: количество нарушений и перечень требований — прямо в журнале.
  assert.match(ci.output, /Нарушено требований ИБ: 1/);
  assert.match(ci.output, /ИБ-04/);
  assert.match(ci.output, /src\/auth\/password\.ts:5/);

  const json = readJson(repo);
  assert.equal(json.metadata.result, 'BLOCK');
  assert.equal(json.metadata.exit_code, 1);
  assert.equal(json.metadata.violations_count, 1);
  assert.equal(json.metadata.commit_id, 'abc123');
  assert.deepEqual(Object.keys(json.requirements), REQ_IDS);
  assert.equal(json.requirements['ИБ-04'].status, 'VIOLATION');

  const md = readFileSync(join(repo, 'kmg-report.md'), 'utf8');
  assert.match(md, /## Статус по каждому требованию ИБ/);
  assert.match(md, /Заменить на argon2id/);
});

test('нарушений нет → exit 0, в отчёте статус каждого из восьми требований', async t => {
  const { root, repo } = createRepo();
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const kmg = await startKmg(replyJson(response([])));
  t.after(kmg.close);

  const ci = await run('node', [guardPath, 'ci'], { cwd: repo, env: env(kmg.apiUrl) });
  assert.equal(ci.code, 0, ci.output);

  const json = readJson(repo);
  assert.equal(json.metadata.result, 'PASS');
  assert.equal(json.metadata.exit_code, 0);
  assert.equal(json.metadata.violations_count, 0);
  assert.equal(Object.keys(json.requirements).length, 8);
  for (const id of REQ_IDS) assert.equal(json.requirements[id].status, 'PASS');
});

test('backend не отвечает дольше бюджета времени → exit 2 и отчёт ERROR (ТЗ п. 4.7.2)', async t => {
  const { root, repo } = createRepo();
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const kmg = await startKmg(neverReply);
  t.after(kmg.close);

  const started = Date.now();
  const ci = await run('node', [guardPath, 'ci'], {
    cwd: repo,
    env: env(kmg.apiUrl, { KMG_TIMEOUT_MS: '0', KMG_TIME_BUDGET_MS: '1500' }),
  });
  const elapsed = Date.now() - started;

  assert.equal(ci.code, 2, ci.output);
  assert.ok(elapsed < 10000, `агент не завершился по бюджету: ${elapsed} мс`);
  assert.match(ci.output, /Бюджет времени шага/);

  // Отчёт формируется даже при сбое — он нужен именно тогда (п. 4.3.4).
  assert.ok(existsSync(join(repo, 'kmg-scan-report.json')), 'нет JSON-отчёта');
  assert.ok(existsSync(join(repo, 'kmg-report.md')), 'нет Markdown-отчёта');
  const json = readJson(repo);
  assert.equal(json.metadata.result, 'ERROR');
  assert.equal(json.metadata.exit_code, 2);
  assert.equal(json.violations.length, 0);
  const md = readFileSync(join(repo, 'kmg-report.md'), 'utf8');
  assert.match(md, /код безопасен/);
  // Отчёт при коде 2 не должен утверждать «нарушений нет» и не должен ссылаться на дифф.
  assert.doesNotMatch(md, /Нарушений обязательных требований ИБ не выявлено/);
  assert.doesNotMatch(md, /только изменённые/);
  assert.match(md, /Вердикт не вынесен/);
});

test('недоступный backend → exit 2 и отчёт ERROR, а не тишина', async t => {
  const { root, repo } = createRepo();
  t.after(() => rmSync(root, { recursive: true, force: true }));

  const ci = await run('node', [guardPath, 'ci'], { cwd: repo, env: env('http://127.0.0.1:65534/api') });
  assert.equal(ci.code, 2, ci.output);
  assert.equal(readJson(repo).metadata.result, 'ERROR');
});

test('без токена → exit 2 с отчётом; при fail-open → exit 0', async t => {
  const { root, repo } = createRepo();
  t.after(() => rmSync(root, { recursive: true, force: true }));

  const noToken = await run('node', [guardPath, 'ci'], {
    cwd: repo,
    env: env('http://127.0.0.1:65534/api', { KMG_TOKEN: '' }),
  });
  assert.equal(noToken.code, 2, noToken.output);
  assert.equal(readJson(repo).metadata.result, 'ERROR');

  const failOpen = await run('node', [guardPath, 'ci'], {
    cwd: repo,
    env: env('http://127.0.0.1:65534/api', { KMG_FAIL_OPEN: '1' }),
  });
  assert.equal(failOpen.code, 0, failOpen.output);
});

test('нарушение при незавершённом сканере → всё равно exit 1', async t => {
  const { root, repo } = createRepo();
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const kmg = await startKmg(replyJson(response(['ИБ-02'], {
    verdict: null,
    incomplete: true,
    statusText: 'SCAN_PARTIAL',
    scanners: { semgrep: { status: 'FAILED', error: 'crash' }, gitleaks: { status: 'COMPLETED' }, trivy: { status: 'COMPLETED' } },
  })));
  t.after(kmg.close);

  const ci = await run('node', [guardPath, 'ci'], { cwd: repo, env: env(kmg.apiUrl) });
  assert.equal(ci.code, 1, ci.output);
  assert.match(ci.output, /ИБ-02/);
});

test('незавершённая проверка без нарушений → exit 2, а не 0 и не 1', async t => {
  const { root, repo } = createRepo();
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const kmg = await startKmg(replyJson(response([], {
    verdict: null,
    incomplete: true,
    blocked: false,
    statusText: 'SCAN_PARTIAL',
    scanners: { semgrep: { status: 'FAILED', error: 'crash' }, gitleaks: { status: 'COMPLETED' }, trivy: { status: 'COMPLETED' } },
  })));
  t.after(kmg.close);

  const ci = await run('node', [guardPath, 'ci'], { cwd: repo, env: env(kmg.apiUrl) });
  assert.equal(ci.code, 2, ci.output);
  assert.equal(readJson(repo).metadata.result, 'ERROR');
});

test('без KMG_SCAN_SCOPE проверяется весь проект (ТЗ п. 4.4.1)', async t => {
  const { root, repo } = createRepo();
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const kmg = await startKmg(replyJson(response([])));
  t.after(kmg.close);

  const base = env(kmg.apiUrl);
  delete base.KMG_SCAN_SCOPE;
  const clean = { ...process.env, ...base };
  delete clean.KMG_SCAN_SCOPE;

  await new Promise((resolve, reject) => {
    const child = spawn('node', [guardPath, 'ci'], { cwd: repo, env: clean, stdio: 'ignore' });
    child.on('error', reject);
    child.on('close', resolve);
  });

  assert.equal(kmg.seen.length, 1);
  assert.equal(kmg.seen[0].stage, 'ci');
  assert.equal(kmg.seen[0].scope, 'all');
  // Весь проект — это оба файла репозитория, а не дифф.
  assert.deepEqual(kmg.seen[0].files.map(f => f.path).sort(), ['README.md', 'app.js']);
});

test('scope=changed передаётся серверу как changed: требования ИБ по диффу не оцениваются', async t => {
  const { root, repo } = createRepo();
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const kmg = await startKmg(replyJson(response([], { requirementsEvaluated: false, requirements: [], decisionBasis: 'severity' })));
  t.after(kmg.close);

  const ci = await run('node', [guardPath, 'ci'], {
    cwd: repo,
    env: env(kmg.apiUrl, { KMG_SCAN_SCOPE: 'changed', KMG_BASE_REF: '', KMG_HEAD_REF: '' }),
  });
  assert.equal(ci.code, 0, ci.output);
  assert.equal(kmg.seen[0].scope, 'changed');
  assert.match(ci.output, /не оценивались/);
});
