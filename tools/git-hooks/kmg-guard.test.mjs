import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { once } from 'node:events';
import { rmSync, mkdtempSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  EXIT_ERROR,
  EXIT_PASS,
  EXIT_VIOLATION,
  enforcementMode,
  resolveExitCode,
  shouldFailOnScanError,
  shouldFailProcess,
} from './kmg-guard.mjs';

const strictConfig = { blockOn: '', failOpen: false };
const pass = { verdict: 'PASS', blocked: false, incomplete: false, findings: [] };
const high = {
  verdict: 'REVIEW',
  blocked: false,
  incomplete: false,
  findings: [{ severity: 'HIGH' }],
};
const critical = {
  verdict: 'BLOCK',
  blocked: true,
  incomplete: false,
  findings: [{ severity: 'CRITICAL' }],
};
const incomplete = {
  verdict: null,
  statusText: 'SCAN_INCOMPLETE',
  blocked: true,
  incomplete: true,
  findings: [],
};

const hookDirectory = dirname(fileURLToPath(import.meta.url));
const guardPath = join(hookDirectory, 'kmg-guard.mjs');

function git(cwd, args) {
  return execFileSync('git', args, { cwd, encoding: 'utf8' });
}

function run(command, args, { cwd, env, input } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd,
      env: { ...process.env, ...env },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let output = '';
    child.stdout.on('data', data => { output += data; });
    child.stderr.on('data', data => { output += data; });
    child.on('error', reject);
    child.on('close', code => resolve({ code, output }));
    child.stdin.end(input);
  });
}

async function startMockKmg(result) {
  const server = createServer((req, res) => {
    req.resume();
    req.on('end', () => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(result));
    });
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address();
  let closed = false;
  return {
    apiUrl: `http://127.0.0.1:${port}/api`,
    close: () => new Promise(resolve => {
      if (closed) return resolve();
      closed = true;
      server.close(resolve);
    }),
  };
}

function createGitFixture() {
  const root = mkdtempSync(join(tmpdir(), 'kmg-guard-test-'));
  const remote = join(root, 'remote.git');
  const repo = join(root, 'repository');
  git(root, ['init', '--bare', remote]);
  git(root, ['init', repo]);
  git(repo, ['config', 'user.email', 'security-test@example.invalid']);
  git(repo, ['config', 'user.name', 'KMG Security Test']);
  git(repo, ['remote', 'add', 'origin', remote]);
  writeFileSync(join(repo, 'app.js'), 'export const safe = true;\n');
  git(repo, ['add', 'app.js']);
  git(repo, ['commit', '-m', 'initial']);
  git(repo, ['config', 'core.hooksPath', hookDirectory]);
  return { root, repo, remote };
}

const blockResponse = {
  verdict: 'BLOCK',
  blocked: true,
  incomplete: false,
  riskScore: 9.5,
  counts: { CRITICAL: 1, HIGH: 0, MEDIUM: 0, LOW: 0 },
  findings: [{ severity: 'CRITICAL', title: 'Test finding', scanner: 'semgrep', filePath: 'app.js', startLine: 1 }],
  scanners: {
    semgrep: { status: 'COMPLETED' },
    gitleaks: { status: 'COMPLETED' },
    trivy: { status: 'COMPLETED' },
  },
  reasons: ['Test policy BLOCK'],
  scanId: 'test-scan',
};

test('TEST 1: pre-push + PASS exits 0', () => {
  assert.equal(resolveExitCode(pass, strictConfig, 'pre-push'), EXIT_PASS);
});

test('TEST 2: pre-push + HIGH exits 0', () => {
  assert.equal(resolveExitCode(high, strictConfig, 'pre-push'), EXIT_PASS);
});

test('TEST 3: pre-push + CRITICAL exits 0', () => {
  assert.equal(resolveExitCode(critical, strictConfig, 'pre-push'), EXIT_PASS);
});

test('TEST 4: pre-push + BLOCK exits 0', () => {
  assert.equal(resolveExitCode(critical, strictConfig, 'pre-push'), EXIT_PASS);
});

test('TEST 5: pre-push + unavailable backend exits 0', () => {
  assert.equal(shouldFailOnScanError(strictConfig, 'pre-push'), false);
});

test('TEST 6: pre-commit + BLOCK exits 0', () => {
  assert.equal(resolveExitCode(critical, strictConfig, 'pre-commit'), EXIT_PASS);
});

test('TEST 7: CI + PASS exits 0', () => {
  assert.equal(resolveExitCode(pass, strictConfig, 'ci'), EXIT_PASS);
});

test('TEST 8: CI + BLOCK exits 1 (нарушение, ТЗ п. 4.3.3)', () => {
  assert.equal(resolveExitCode(critical, strictConfig, 'ci'), EXIT_VIOLATION);
});

test('TEST 9: CI + INCOMPLETE exits 2 (проверка не выполнена, ТЗ п. 4.3.3)', () => {
  assert.equal(resolveExitCode(incomplete, strictConfig, 'ci'), EXIT_ERROR);
});

test('TEST 10: CI + scanner failure exits 2 with fail-closed configuration', () => {
  assert.equal(
    resolveExitCode({ ...pass, scanners: { semgrep: { status: 'FAILED' } } }, strictConfig, 'ci'),
    EXIT_ERROR,
  );
  assert.equal(shouldFailOnScanError(strictConfig, 'ci'), true);
});

test('TEST 11: отключённый политикой сканер (SKIPPED) не делает проверку невыполненной', () => {
  const skipped = { ...pass, scanners: { ...pass.scanners, trivy: { status: 'SKIPPED' } } };
  assert.equal(resolveExitCode(skipped, strictConfig, 'ci'), EXIT_PASS);
});

test('TEST 12: усечение по KMG_MAX_FILES делает проверку неполной → exit 2', () => {
  // Часть проекта не проверена: это не «нарушений нет», а «проверка неполная».
  assert.equal(resolveExitCode({ ...pass, truncated: 17 }, strictConfig, 'ci'), EXIT_ERROR);
  // Локально по-прежнему только информирование.
  assert.equal(resolveExitCode({ ...pass, truncated: 17 }, strictConfig, 'pre-push'), EXIT_PASS);
});

test('TEST 13: незавершённая проверка имеет приоритет над вердиктом BLOCK', () => {
  // «Мы не смогли проверить» нельзя подменять на «мы нашли нарушение»:
  // причины разные, и чинить нужно разное.
  const blockedAndIncomplete = { ...critical, incomplete: true };
  assert.equal(resolveExitCode(blockedAndIncomplete, strictConfig, 'ci'), EXIT_ERROR);
});

test('TEST 13b: подтверждённое нарушение требования ИБ остаётся кодом 1 даже при незавершённом сканере', () => {
  // Проверка требований от сканеров не зависит: нарушение — это нарушение.
  const violatedAndIncomplete = { ...incomplete, violatedRequirements: ['ИБ-04'] };
  assert.equal(resolveExitCode(violatedAndIncomplete, strictConfig, 'ci'), EXIT_VIOLATION);
  // Без подтверждённых нарушений незавершённость по-прежнему код 2.
  assert.equal(resolveExitCode({ ...incomplete, violatedRequirements: [] }, strictConfig, 'ci'), EXIT_ERROR);
  // Локально — только информирование.
  assert.equal(resolveExitCode(violatedAndIncomplete, strictConfig, 'pre-push'), EXIT_PASS);
});

test('TEST 14: ни один исход не совпадает с PASS, кроме реального PASS', () => {
  assert.notEqual(resolveExitCode(critical, strictConfig, 'ci'), EXIT_PASS);
  assert.notEqual(resolveExitCode(incomplete, strictConfig, 'ci'), EXIT_PASS);
  assert.notEqual(EXIT_VIOLATION, EXIT_ERROR);
});

test('KMG_FAIL_OPEN only allows an unavailable CI scan, not a BLOCK verdict', () => {
  const failOpenConfig = { ...strictConfig, failOpen: true };
  assert.equal(shouldFailOnScanError(failOpenConfig, 'ci'), false);
  assert.equal(resolveExitCode(critical, failOpenConfig, 'ci'), EXIT_VIOLATION);
  assert.equal(resolveExitCode(incomplete, failOpenConfig, 'ci'), EXIT_ERROR);
  assert.equal(enforcementMode('pre-push'), 'advisory');
  assert.equal(enforcementMode('ci'), 'enforce');
});

test('shouldFailProcess остаётся согласован с resolveExitCode', () => {
  for (const [result, mode] of [[pass, 'ci'], [critical, 'ci'], [incomplete, 'ci'], [critical, 'pre-push']]) {
    assert.equal(
      shouldFailProcess(result, strictConfig, mode),
      resolveExitCode(result, strictConfig, mode) !== EXIT_PASS,
    );
  }
});

test('real Git hooks allow local BLOCK and unavailable backend while CI rejects BLOCK', async t => {
  const fixture = createGitFixture();
  t.after(() => rmSync(fixture.root, { recursive: true, force: true }));

  const mock = await startMockKmg(blockResponse);
  t.after(mock.close);
  const scanEnv = {
    KMG_GUARD_PATH: guardPath,
    KMG_TOKEN: 'test-token',
    KMG_API_URL: mock.apiUrl,
    KMG_TIMEOUT_MS: '1000',
  };

  writeFileSync(join(fixture.repo, 'app.js'), 'export const criticalFinding = true;\n');
  git(fixture.repo, ['add', 'app.js']);
  const commit = await run('git', ['commit', '-m', 'critical local change'], {
    cwd: fixture.repo,
    env: scanEnv,
  });
  assert.equal(commit.code, 0, commit.output);
  assert.match(commit.output, /Security policy: BLOCK/);
  assert.match(commit.output, /Commit allowed/);

  const push = await run('git', ['push', 'origin', 'HEAD:refs/heads/main'], {
    cwd: fixture.repo,
    env: scanEnv,
  });
  assert.equal(push.code, 0, push.output);
  assert.match(push.output, /Security policy: BLOCK/);
  assert.match(push.output, /Local push is allowed/);
  assert.equal(git(fixture.root, ['--git-dir', fixture.remote, 'rev-parse', 'refs/heads/main']).trim().length, 40);

  const ci = await run('node', [guardPath, 'ci'], { cwd: fixture.repo, env: scanEnv });
  assert.equal(ci.code, 1, ci.output);
  assert.match(ci.output, /Выявлены нарушения/);
  assert.match(ci.output, /Security policy: BLOCK/);

  // Тот же репозиторий, но backend отвечает «сканер не завершился»: в CI это
  // уже не exit 1, а exit 2 — проверка не выполнена.
  const incompleteMock = await startMockKmg({
    ...blockResponse,
    verdict: null,
    blocked: true,
    incomplete: true,
    statusText: 'SCAN_PARTIAL',
    findings: [],
    scanners: { semgrep: { status: 'FAILED', error: 'semgrep crashed' } },
  });
  t.after(incompleteMock.close);
  const ciIncomplete = await run('node', [guardPath, 'ci'], {
    cwd: fixture.repo,
    env: { ...scanEnv, KMG_API_URL: incompleteMock.apiUrl },
  });
  assert.equal(ciIncomplete.code, 2, ciIncomplete.output);
  assert.match(ciIncomplete.output, /Проверка не выполнена/);
  assert.match(ciIncomplete.output, /НЕ означает, что код безопасен/);
  await incompleteMock.close();

  // Недоступный backend в CI при fail-closed — тоже exit 2, а не exit 1.
  const ciUnavailable = await run('node', [guardPath, 'ci'], {
    cwd: fixture.repo,
    env: { ...scanEnv, KMG_API_URL: 'http://127.0.0.1:65534/api' },
  });
  assert.equal(ciUnavailable.code, 2, ciUnavailable.output);

  await mock.close();
  writeFileSync(join(fixture.repo, 'app.js'), 'export const backendUnavailable = true;\n');
  git(fixture.repo, ['add', 'app.js']);
  const advisoryCommit = await run('git', ['commit', '-m', 'backend unavailable'], {
    cwd: fixture.repo,
    env: { ...scanEnv, KMG_API_URL: 'http://127.0.0.1:65534/api' },
  });
  assert.equal(advisoryCommit.code, 0, advisoryCommit.output);
  const unavailablePush = await run('git', ['push', 'origin', 'HEAD:refs/heads/main'], {
    cwd: fixture.repo,
    env: { ...scanEnv, KMG_API_URL: 'http://127.0.0.1:65534/api' },
  });
  assert.equal(unavailablePush.code, 0, unavailablePush.output);
  assert.match(unavailablePush.output, /Push allowed locally/);
});
