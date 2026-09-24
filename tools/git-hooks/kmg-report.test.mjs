import assert from 'node:assert/strict';
import test from 'node:test';

import {
  buildJsonReport,
  buildMarkdownReport,
  collectAdditionalFindings,
  collectViolations,
  redact,
  violatedRequirementsLines,
} from './kmg-report.mjs';

const REQ_TEXT = 'Пароли должны храниться в виде значений функций формирования ключа bcrypt, argon2 или scrypt.';

function requirement(id, status, extra = {}) {
  return {
    requirementId: id,
    title: `Требование ${id}`,
    requirementText: REQ_TEXT,
    status,
    confidence: 'HIGH',
    summary: `Сводка ${id}`,
    evidence: [],
    violations: [],
    insufficientReason: null,
    ...extra,
  };
}

const IDS = ['ИБ-01', 'ИБ-02', 'ИБ-03', 'ИБ-04', 'ИБ-05', 'ИБ-06', 'ИБ-07', 'ИБ-08'];

function fullResult(overrides = {}) {
  return {
    verdict: 'BLOCK',
    blocked: true,
    incomplete: false,
    decisionBasis: 'requirements',
    commitSha: '4f2c1ab9e7d05836c1b4a92e7f30d8c5a1b6e402',
    startedAt: '2026-09-24T09:00:00.000Z',
    finishedAt: '2026-09-24T09:02:30.000Z',
    durationSeconds: 150,
    filesChecked: 128,
    requirements: IDS.map(id =>
      id === 'ИБ-04'
        ? requirement('ИБ-04', 'VIOLATION', {
            violations: [{
              filePath: 'src/auth/auth.service.ts',
              lineStart: 58,
              lineEnd: 60,
              symbol: 'хеширование пароля',
              evidence: "crypto.createHash('sha256').update(password).digest('hex')",
              explanation: 'Пароль хешируется быстрой хеш-функцией общего назначения.',
              severity: 'CRITICAL',
              confidence: 'HIGH',
              recommendation: 'Заменить на argon2id.',
            }],
          })
        : requirement(id, 'PASS'),
    ),
    violatedRequirements: ['ИБ-04'],
    insufficientRequirements: [],
    findings: [
      { scanner: 'trivy', ruleId: 'CVE-2021-23337', severity: 'HIGH', confidence: 'HIGH',
        title: 'lodash@4.17.15: CVE-2021-23337', filePath: 'package.json', startLine: 21 },
    ],
    scanners: {
      semgrep: { status: 'COMPLETED' }, gitleaks: { status: 'COMPLETED' }, trivy: { status: 'COMPLETED' },
    },
    reasons: ['Нарушены обязательные требования ИБ: ИБ-04.'],
    ...overrides,
  };
}

test('JSON: сводная часть по ТЗ п. 4.6.3', () => {
  const r = buildJsonReport(fullResult(), 1, { repository: 'owner/repo', branch: 'main', scope: 'all' });
  const m = r.metadata;
  assert.equal(m.commit_id, '4f2c1ab9e7d05836c1b4a92e7f30d8c5a1b6e402');
  assert.equal(m.started_at, '2026-09-24T09:00:00.000Z');
  assert.equal(m.finished_at, '2026-09-24T09:02:30.000Z');
  assert.equal(m.duration_seconds, 150);
  assert.equal(m.result, 'BLOCK');
  assert.equal(m.exit_code, 1);
  assert.equal(m.violations_count, 1);
  assert.deepEqual(m.violated_requirements, ['ИБ-04']);
});

test('JSON: статус по КАЖДОМУ из восьми требований, включая не нарушенные', () => {
  const r = buildJsonReport(fullResult(), 1);
  assert.deepEqual(Object.keys(r.requirements), IDS);
  assert.equal(r.requirements['ИБ-04'].status, 'VIOLATION');
  assert.equal(r.requirements['ИБ-01'].status, 'PASS');
});

test('JSON: нарушение содержит все поля п. 4.6.2', () => {
  const [v] = buildJsonReport(fullResult(), 1).violations;
  for (const field of [
    'requirement_id', 'requirement_text', 'file_path', 'line_start', 'line_end',
    'symbol', 'evidence', 'explanation', 'severity', 'recommendation',
  ]) {
    assert.ok(v[field] !== undefined && v[field] !== null && v[field] !== '', `нет поля ${field}`);
  }
  assert.equal(v.requirement_id, 'ИБ-04');
  assert.equal(v.file_path, 'src/auth/auth.service.ts');
  assert.equal(v.line_start, 58);
});

test('п. 4.6.5: результат отчёта согласован с кодом завершения', () => {
  assert.equal(buildJsonReport(fullResult(), 0).metadata.result, 'PASS');
  assert.equal(buildJsonReport(fullResult(), 1).metadata.result, 'BLOCK');
  assert.equal(buildJsonReport(fullResult(), 2).metadata.result, 'ERROR');
  for (const code of [0, 1, 2]) {
    assert.match(buildMarkdownReport(fullResult(), code), new RegExp('`' + code + '`'));
  }
});

test('п. 4.8.1: прочие находки — отдельным разделом и не блокируют при решении по требованиям', () => {
  const r = buildJsonReport(fullResult({
    findings: [{ scanner: 'trivy', severity: 'CRITICAL', title: 'CVE', filePath: 'a', startLine: 1 }],
  }), 1);
  assert.equal(r.violations.length, 1);
  assert.equal(r.additional_findings.length, 1);
  assert.equal(r.additional_findings[0].blocks_pipeline, false);
});

test('дубликаты: detected_by перечисляет все обнаружившие инструменты', () => {
  const [f] = collectAdditionalFindings({
    decisionBasis: 'requirements',
    findings: [{ scanner: 'semgrep', detectedBy: ['semgrep', 'trivy'], severity: 'HIGH', title: 'x' }],
  });
  assert.deepEqual(f.detected_by, ['semgrep', 'trivy']);
});

test('Markdown: обязательные разделы и место нарушения', () => {
  const md = buildMarkdownReport(fullResult(), 1, { scope: 'all' });
  for (const heading of [
    '# Отчёт KMG AI Security Agent', '## Сводка', '## Статус по каждому требованию ИБ',
    '## Нарушения', '## Дополнительные находки', '## Сканеры',
  ]) {
    assert.ok(md.includes(heading), `нет раздела ${heading}`);
  }
  assert.match(md, /src\/auth\/auth\.service\.ts:58-60/);
  assert.match(md, /ИБ-04/);
  assert.match(md, /Заменить на argon2id/);
});

test('Markdown: при коде 2 отчёт прямо говорит, что отсутствие находок не означает безопасность', () => {
  const md = buildMarkdownReport(fullResult({ violatedRequirements: [], requirements: [] }), 2);
  assert.match(md, /Проверка не выполнена/);
  assert.match(md, /не означает/);
});

test('Markdown: без оценки требований (дифф) это сказано явно, а не выдаётся за PASS', () => {
  const md = buildMarkdownReport(fullResult({ requirements: [], violatedRequirements: [] }), 0);
  assert.match(md, /не оценивались/);
});

test('INSUFFICIENT_EVIDENCE выводится отдельно и не выглядит как PASS', () => {
  const md = buildMarkdownReport(fullResult({
    violatedRequirements: [],
    insufficientRequirements: ['ИБ-05'],
    requirements: IDS.map(id => id === 'ИБ-05'
      ? requirement(id, 'INSUFFICIENT_EVIDENCE', { insufficientReason: 'Нужна ручная проверка' })
      : requirement(id, 'PASS')),
  }), 0);
  assert.match(md, /Недостаточно данных для вывода/);
  assert.match(md, /Нужна ручная проверка/);
});

// Значения секретов собираются на лету: литерал в исходнике сам стал бы находкой
// Gitleaks при проверке этого репозитория.
const fakeGithubToken = () => 'ghp_' + 'abcdefghij'.repeat(3) + 'abcdef';
const fakeAwsKey = () => 'AKIA' + 'ABCDEFGHIJKLMNOP';
const fakeDbUri = () => ['postgres', '://admin:', 'hunter22', '@db:5432/app'].join('');

test('секреты не попадают в отчёт', () => {
  const leaky = fullResult();
  leaky.requirements[3].violations[0].evidence = `const token = '${fakeGithubToken()}'; ${fakeDbUri()}`;
  const json = JSON.stringify(buildJsonReport(leaky, 1));
  const md = buildMarkdownReport(leaky, 1);
  for (const text of [json, md]) {
    assert.ok(!text.includes(fakeGithubToken()));
    assert.ok(!text.includes('hunter22'));
  }
});

test('redact: значения секретов заменяются', () => {
  assert.ok(!redact(fakeAwsKey()).includes('ABCDEFGHIJKLMNOP'));
  assert.ok(!redact('api_key = "s3cr3t-value-123456"').includes('s3cr3t-value-123456'));
  assert.equal(redact(null), null);
});

test('перечень нарушенных требований для журнала (ТЗ п. 4.3.5)', () => {
  const lines = violatedRequirementsLines(fullResult());
  assert.equal(lines.length, 1);
  assert.match(lines[0], /^ИБ-04 /);
  assert.match(lines[0], /src\/auth\/auth\.service\.ts:58/);
});

test('collectViolations: сквозная нумерация в порядке требований', () => {
  const r = fullResult();
  r.requirements[0] = requirement('ИБ-01', 'VIOLATION', {
    violations: [{ filePath: 'a.ts', lineStart: 1, lineEnd: 1, symbol: 's', evidence: 'e',
      explanation: 'x', severity: 'HIGH', confidence: 'HIGH', recommendation: 'r' }],
  });
  const ids = collectViolations(r).map(v => `${v.id}:${v.requirement_id}`);
  assert.deepEqual(ids, ['v-001:ИБ-01', 'v-002:ИБ-04']);
});
