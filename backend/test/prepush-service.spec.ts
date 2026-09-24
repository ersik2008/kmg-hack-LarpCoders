import { describe, it, expect, vi } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { of, throwError } from 'rxjs';
import { plainToInstance } from 'class-transformer';
import { validate } from 'class-validator';

import { PrepushService } from '../src/prepush/prepush.service.js';
import { PrePushCheckDto } from '../src/prepush/dto/prepush-check.dto.js';
import { PolicyService } from '../src/policy/policy.service.js';
import { RequirementsService } from '../src/requirements/requirements.service.js';

/**
 * Сквозная проверка серверной части CI-пути: DTO → материализация файлов →
 * сканеры (заглушка движка) → требования ИБ → политика → код завершения.
 *
 * Именно этот путь используют composite action и guard в режиме ci. Ошибка в
 * DTO (`stage: 'ci'` не проходил валидацию) делала весь путь нерабочим и не
 * ловилась ни одним тестом.
 */

const FIXTURES = path.resolve(__dirname, '../../security-test-repository/requirements');

function readTree(dir: string, base = dir): Array<{ path: string; contentBase64: string }> {
  const out: Array<{ path: string; contentBase64: string }> = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...readTree(full, base));
    else out.push({
      path: path.relative(base, full).replace(/\\/g, '/'),
      contentBase64: fs.readFileSync(full).toString('base64'),
    });
  }
  return out;
}

const okEngine = {
  status: 'success',
  scanners: {
    semgrep: { status: 'COMPLETED', findingsCount: 0, error: null },
    gitleaks: { status: 'COMPLETED', findingsCount: 0, error: null },
    trivy: { status: 'COMPLETED', findingsCount: 0, error: null },
  },
  findings: [] as any[],
};

function makeService(engine: () => any) {
  const prisma: any = {
    policy: { findFirst: vi.fn().mockResolvedValue(null) },
    repository: { findFirst: vi.fn().mockResolvedValue(null) },
  };
  const post = vi.fn(engine);
  const config: any = { get: (_k: string, d?: string) => d };
  const service = new PrepushService(
    prisma,
    config,
    { post } as any,
    new PolicyService(prisma),
    { scanWorkspace: vi.fn().mockResolvedValue([]) } as any,
    { emit: vi.fn() } as any,
    new RequirementsService(prisma),
  );
  return { service, post };
}

const dto = (name: 'violating' | 'compliant', extra: Record<string, unknown> = {}) => ({
  stage: 'ci',
  scope: 'all',
  commitSha: 'abc123',
  branch: 'main',
  files: readTree(path.join(FIXTURES, name)),
  ...extra,
}) as any;

describe('DTO: запрос из CI проходит валидацию', () => {
  const errorsFor = async (body: object) => validate(plainToInstance(PrePushCheckDto, body), {
    whitelist: true, forbidNonWhitelisted: true,
  });

  it("stage='ci' допустим (раньше отклонялся — путь composite action не работал)", async () => {
    expect(await errorsFor({ stage: 'ci', scope: 'all', files: [{ path: 'a', contentBase64: 'eA==' }] })).toEqual([]);
  });

  it('scope и startedAt допустимы', async () => {
    expect(await errorsFor({ stage: 'ci', scope: 'changed', startedAt: '2026-09-24T09:00:00.000Z',
      files: [{ path: 'a', contentBase64: 'eA==' }] })).toEqual([]);
  });

  it('неизвестный stage и scope отклоняются', async () => {
    expect((await errorsFor({ stage: 'deploy', files: [] })).length).toBeGreaterThan(0);
    expect((await errorsFor({ scope: 'everything', files: [] })).length).toBeGreaterThan(0);
  });

  it('неизвестные поля отклоняются (forbidNonWhitelisted)', async () => {
    expect((await errorsFor({ files: [], surprise: true })).length).toBeGreaterThan(0);
  });

  it('до 10 000 файлов в запросе (полный проект)', async () => {
    const files = Array.from({ length: 6000 }, (_, i) => ({ path: `f${i}`, contentBase64: 'eA==' }));
    expect(await errorsFor({ stage: 'ci', scope: 'all', files })).toEqual([]);
  });
});

describe('PrepushService.check: полный проект → требования ИБ → код завершения', () => {
  it('нарушающий проект: BLOCK, код 1, перечень требований, статусы всех восьми', async () => {
    const { service } = makeService(() => of({ data: okEngine }));
    const r = await service.check('user-1', dto('violating'));

    expect(r.requirementsEvaluated).toBe(true);
    expect(r.requirements).toHaveLength(8);
    expect(r.violatedRequirements.length).toBeGreaterThan(0);
    expect(r.verdict).toBe('BLOCK');
    expect(r.blocked).toBe(true);
    expect(r.exitCode).toBe(1);
    expect(r.decisionBasis).toBe('requirements');
    // Отчётные поля п. 4.6.3
    expect(r.commitSha).toBe('abc123');
    expect(Date.parse(r.startedAt)).not.toBeNaN();
    expect(Date.parse(r.finishedAt)).not.toBeNaN();
    expect(r.durationSeconds).toBeGreaterThanOrEqual(0);
  });

  it('соответствующий проект: PASS, код 0, все требования PASS', async () => {
    const { service } = makeService(() => of({ data: okEngine }));
    const r = await service.check('user-1', dto('compliant'));

    expect(r.requirements.map(x => x.status)).toEqual(Array(8).fill('PASS'));
    expect(r.violatedRequirements).toEqual([]);
    expect(r.verdict).toBe('PASS');
    expect(r.exitCode).toBe(0);
  });

  it('п. 4.8.1: CRITICAL вне перечня ИБ на соответствующем проекте не блокирует', async () => {
    const engine = {
      ...okEngine,
      findings: [{
        scanner: 'semgrep', ruleId: 'some.rule', severity: 'CRITICAL', confidence: 'HIGH',
        title: 'Some critical issue', filePath: 'src/main.ts', startLine: 1,
      }],
    };
    const { service } = makeService(() => of({ data: engine }));
    const r = await service.check('user-1', dto('compliant'));

    expect(r.counts.CRITICAL).toBe(1);
    expect(r.violatedRequirements).toEqual([]);
    expect(r.verdict).toBe('REVIEW');
    expect(r.exitCode).toBe(0);
  });

  it('scope=changed: требования не оцениваются, решение по severity', async () => {
    const engine = {
      ...okEngine,
      findings: [{ scanner: 'semgrep', ruleId: 'r', severity: 'CRITICAL', confidence: 'HIGH', title: 't', filePath: 'a', startLine: 1 }],
    };
    const { service } = makeService(() => of({ data: engine }));
    const r = await service.check('user-1', dto('violating', { scope: 'changed' }));

    expect(r.requirementsEvaluated).toBe(false);
    expect(r.requirements).toEqual([]);
    expect(r.decisionBasis).toBe('severity');
    expect(r.exitCode).toBe(1);
  });

  it('хук (stage=pre-push) требования не оценивает и не блокирует по ним', async () => {
    const { service } = makeService(() => of({ data: okEngine }));
    const r = await service.check('user-1', dto('violating', { stage: 'pre-push', scope: undefined }));
    expect(r.requirementsEvaluated).toBe(false);
  });

  it('сканер не завершился, нарушений требований нет → код 2, не PASS', async () => {
    const engine = {
      ...okEngine,
      scanners: { ...okEngine.scanners, semgrep: { status: 'FAILED', findingsCount: 0, error: 'crash' } },
    };
    const { service } = makeService(() => of({ data: engine }));
    const r = await service.check('user-1', dto('compliant'));

    expect(r.incomplete).toBe(true);
    expect(r.verdict).toBeNull();
    expect(r.exitCode).toBe(2);
  });

  it('сканер не завершился, но требование нарушено → код 1 и вердикт BLOCK', async () => {
    const engine = {
      ...okEngine,
      scanners: { ...okEngine.scanners, trivy: { status: 'FAILED', findingsCount: 0, error: 'db' } },
    };
    const { service } = makeService(() => of({ data: engine }));
    const r = await service.check('user-1', dto('violating'));

    expect(r.incomplete).toBe(true);
    expect(r.violatedRequirements.length).toBeGreaterThan(0);
    expect(r.verdict).toBe('BLOCK');
    expect(r.exitCode).toBe(1);
  });

  it('движок недоступен → все сканеры FAILED, резерв не спасает от кода 2', async () => {
    const { service } = makeService(() => throwError(() => new Error('connect ECONNREFUSED')));
    const r = await service.check('user-1', dto('compliant'));

    expect(r.engineUsed).toBe('builtin-fallback');
    expect(r.incomplete).toBe(true);
    expect(r.exitCode).toBe(2);
  });

  it('одна проблема от нескольких сканеров — одна находка с detectedBy', async () => {
    const same = { severity: 'CRITICAL', confidence: 'HIGH', filePath: 'src/a.ts', startLine: 4, codeSnippet: '***REDACTED***' };
    const engine = {
      ...okEngine,
      findings: [
        { ...same, scanner: 'gitleaks', ruleId: 'aws-access-token', title: 'Exposed secret: aws-access-token' },
        { ...same, scanner: 'trivy', ruleId: 'aws-access-key-id', title: 'Exposed secret: AWS Access Key ID' },
      ],
    };
    const { service } = makeService(() => of({ data: engine }));
    const r = await service.check('user-1', dto('compliant'));

    expect(r.findings).toHaveLength(1);
    expect(r.findings[0].detectedBy.sort()).toEqual(['gitleaks', 'trivy']);
    expect(r.counts.CRITICAL).toBe(1);
  });

  it('нет файлов → 400, а не пустой PASS', async () => {
    const { service } = makeService(() => of({ data: okEngine }));
    await expect(service.check('u', { stage: 'ci', scope: 'all', files: [] } as any)).rejects.toThrow(/No files/);
  });

  it('пути вне рабочей области пропускаются, остальные проверяются', async () => {
    const { service } = makeService(() => of({ data: okEngine }));
    const files = [
      ...readTree(path.join(FIXTURES, 'compliant')),
      { path: '../../etc/passwd', contentBase64: Buffer.from('x').toString('base64') },
    ];
    const r = await service.check('u', { stage: 'ci', scope: 'all', files } as any);
    expect(r.filesChecked).toBe(files.length - 1);
  });

  it('рабочая область удаляется после проверки', async () => {
    const { service, post } = makeService(() => of({ data: okEngine }));
    await service.check('u', dto('compliant'));
    const workspace = post.mock.calls[0][1].repository_path as string;
    expect(fs.existsSync(workspace)).toBe(false);
  });

  it('токен движка передаётся заголовком, если настроен', async () => {
    const prisma: any = { policy: { findFirst: vi.fn().mockResolvedValue(null) }, repository: { findFirst: vi.fn() } };
    const post = vi.fn(() => of({ data: okEngine }));
    const config: any = { get: (k: string, d?: string) => (k === 'ENGINE_TOKEN' ? 'secret-token' : d) };
    const service = new PrepushService(
      prisma, config, { post } as any, new PolicyService(prisma),
      { scanWorkspace: vi.fn().mockResolvedValue([]) } as any, { emit: vi.fn() } as any, new RequirementsService(prisma),
    );
    await service.check('u', dto('compliant'));
    expect((post.mock.calls[0] as any[])[2].headers).toEqual({ 'X-Engine-Token': 'secret-token' });
  });

  it('в режиме ci таймаут движка — как у полного скана (не 5 минут «быстрого» хука)', async () => {
    const { service, post } = makeService(() => of({ data: okEngine }));
    await service.check('u', dto('compliant'));
    expect((post.mock.calls[0] as any[])[2].timeout).toBe(600000);

    const hook = makeService(() => of({ data: okEngine }));
    await hook.service.check('u', dto('compliant', { stage: 'pre-push', scope: undefined }));
    expect((hook.post.mock.calls[0] as any[])[2].timeout).toBe(300000);
  });
});
