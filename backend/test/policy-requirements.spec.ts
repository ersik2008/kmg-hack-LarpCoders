import { describe, it, expect, vi } from 'vitest';
import {
  DEFAULT_POLICY,
  PolicyService,
  ScannerStatusRecord,
  exitCodeFor,
} from '../src/policy/policy.service.js';
import { Finding } from '../src/generated/prisma/client.js';

/**
 * Решение по обязательным Требованиям ИБ (ТЗ п. 4.3.3 и 4.8.1).
 *
 * До этого набора политика работала только по severity: SQL-инъекция вне
 * перечня ИБ блокировала пайплайн, а подтверждённое нарушение ИБ-04 — нет.
 */

const prismaStub: any = { policy: { findFirst: vi.fn(), create: vi.fn(), update: vi.fn() } };
const policy = new PolicyService(prismaStub);

const completed = (): Record<string, ScannerStatusRecord> => ({
  semgrep: { status: 'COMPLETED', findingsCount: 0, error: null },
  gitleaks: { status: 'COMPLETED', findingsCount: 0, error: null },
  trivy: { status: 'COMPLETED', findingsCount: 0, error: null },
});

const finding = (severity: Finding['severity']): Finding => ({
  id: `f-${severity}`,
  scanId: 's',
  scanner: 'semgrep',
  ruleId: 'r',
  severity,
  confidence: 'HIGH',
  title: 't',
  description: null,
  filePath: 'a.ts',
  startLine: 1,
  endLine: 1,
  codeSnippet: null,
  category: null,
  metadata: null,
  createdAt: new Date(),
});

const allPass = () =>
  ['ИБ-01', 'ИБ-02', 'ИБ-03', 'ИБ-04', 'ИБ-05', 'ИБ-06', 'ИБ-07', 'ИБ-08'].map(requirementId => ({
    requirementId,
    status: 'PASS' as const,
  }));

const withStatus = (id: string, status: 'PASS' | 'VIOLATION' | 'INSUFFICIENT_EVIDENCE' | 'NOT_APPLICABLE') =>
  allPass().map(r => (r.requirementId === id ? { ...r, status } : r));

const base = { scanners: completed(), repositoryStatus: 'READY' as const };

describe('Политика: решение по требованиям ИБ', () => {
  it('нет нарушений и нет находок → PASS, код 0', () => {
    const r = policy.evaluate({ ...base, findings: [], requirements: allPass() });
    expect(r.result).toBe('PASS');
    expect(r.basis).toBe('requirements');
    expect(exitCodeFor(r)).toBe(0);
  });

  it('одно нарушение требования → BLOCK, код 1, требование названо', () => {
    const r = policy.evaluate({ ...base, findings: [], requirements: withStatus('ИБ-04', 'VIOLATION') });
    expect(r.result).toBe('BLOCK');
    expect(r.violatedRequirements).toEqual(['ИБ-04']);
    expect(r.reasons.join(' ')).toContain('ИБ-04');
    expect(exitCodeFor(r)).toBe(1);
  });

  it('несколько нарушений перечисляются все', () => {
    const reqs = allPass().map(r => (['ИБ-01', 'ИБ-07'].includes(r.requirementId) ? { ...r, status: 'VIOLATION' as const } : r));
    const r = policy.evaluate({ ...base, findings: [], requirements: reqs });
    expect(r.violatedRequirements).toEqual(['ИБ-01', 'ИБ-07']);
  });

  it('п. 4.8.1: находка CRITICAL вне перечня ИБ НЕ блокирует пайплайн', () => {
    const r = policy.evaluate({ ...base, findings: [finding('CRITICAL')], requirements: allPass() });
    expect(r.result).toBe('REVIEW');
    expect(r.isBlocked).toBe(false);
    expect(exitCodeFor(r)).toBe(0);
    expect(r.reasons.join(' ')).toMatch(/4\.8\.1/);
  });

  it('прежняя строгость включается явно: blockOnAdditionalFindings', () => {
    const r = policy.evaluate({
      ...base,
      findings: [finding('CRITICAL')],
      requirements: allPass(),
      thresholds: { ...DEFAULT_POLICY, blockOnAdditionalFindings: true },
    });
    expect(r.result).toBe('BLOCK');
    expect(exitCodeFor(r)).toBe(1);
  });

  it('без оценки требований (дифф) действует прежняя оценка по severity', () => {
    const r = policy.evaluate({ ...base, findings: [finding('CRITICAL')] });
    expect(r.result).toBe('BLOCK');
    expect(r.basis).toBe('severity');
  });

  it('пустой список требований — это «не оценивались», а не «все в порядке»', () => {
    const r = policy.evaluate({ ...base, findings: [finding('CRITICAL')], requirements: [] });
    expect(r.basis).toBe('severity');
    expect(r.result).toBe('BLOCK');
  });
});

describe('INSUFFICIENT_EVIDENCE никогда не равен PASS', () => {
  it('по умолчанию → REVIEW: пайплайн не прерывается, но вердикт не PASS', () => {
    const r = policy.evaluate({ ...base, findings: [], requirements: withStatus('ИБ-05', 'INSUFFICIENT_EVIDENCE') });
    expect(r.result).toBe('REVIEW');
    expect(r.isPass).toBe(false);
    expect(r.insufficientRequirements).toEqual(['ИБ-05']);
    expect(exitCodeFor(r)).toBe(0);
  });

  it('политика может считать недостаточность данных блокирующей', () => {
    const r = policy.evaluate({
      ...base,
      findings: [],
      requirements: withStatus('ИБ-05', 'INSUFFICIENT_EVIDENCE'),
      thresholds: { ...DEFAULT_POLICY, insufficientEvidenceBlocks: true },
    });
    expect(r.result).toBe('BLOCK');
    expect(exitCodeFor(r)).toBe(1);
  });

  it('NOT_APPLICABLE не мешает PASS', () => {
    const r = policy.evaluate({ ...base, findings: [], requirements: withStatus('ИБ-08', 'NOT_APPLICABLE') });
    expect(r.result).toBe('PASS');
  });

  it('нарушение старше недостаточности данных', () => {
    const reqs = allPass().map(r =>
      r.requirementId === 'ИБ-04' ? { ...r, status: 'VIOLATION' as const }
        : r.requirementId === 'ИБ-05' ? { ...r, status: 'INSUFFICIENT_EVIDENCE' as const } : r);
    expect(policy.evaluate({ ...base, findings: [], requirements: reqs }).result).toBe('BLOCK');
  });
});

describe('Приоритеты: ERROR ≠ PASS, нарушение остаётся нарушением', () => {
  it('сканер не завершился, нарушений нет → вердикта нет, код 2', () => {
    const scanners = completed();
    scanners.semgrep = { status: 'FAILED', findingsCount: 0, error: 'crash' };
    const r = policy.evaluate({ ...base, scanners, findings: [], requirements: allPass() });
    expect(r.result).toBeNull();
    expect(r.isIncomplete).toBe(true);
    expect(r.isPass).toBe(false);
    expect(exitCodeFor(r)).toBe(2);
  });

  it('сканер не завершился, НО нарушение требования подтверждено → код 1, а не 2', () => {
    const scanners = completed();
    scanners.trivy = { status: 'FAILED', findingsCount: 0, error: 'db' };
    const r = policy.evaluate({ ...base, scanners, findings: [], requirements: withStatus('ИБ-02', 'VIOLATION') });
    expect(r.violatedRequirements).toEqual(['ИБ-02']);
    expect(r.reasons.join(' ')).toContain('ИБ-02');
    expect(exitCodeFor(r)).toBe(1);
  });

  it('рабочая область не готова → код 2, требования не подменяют PASS', () => {
    const r = policy.evaluate({ ...base, repositoryStatus: 'FAILED', findings: [], requirements: allPass() });
    expect(r.result).toBeNull();
    expect(exitCodeFor(r)).toBe(2);
  });

  it('все три кода различны и PASS достижим только при реальном PASS', () => {
    const pass = exitCodeFor(policy.evaluate({ ...base, findings: [], requirements: allPass() }));
    const viol = exitCodeFor(policy.evaluate({ ...base, findings: [], requirements: withStatus('ИБ-01', 'VIOLATION') }));
    const sc = completed();
    sc.gitleaks = { status: 'FAILED', findingsCount: 0, error: 'x' };
    const err = exitCodeFor(policy.evaluate({ ...base, scanners: sc, findings: [], requirements: allPass() }));
    expect([pass, viol, err]).toEqual([0, 1, 2]);
  });

  it('SKIPPED-сканер не делает проверку неполной', () => {
    const scanners = completed();
    scanners.trivy = { status: 'SKIPPED', findingsCount: 0, error: 'disabled' };
    const r = policy.evaluate({
      ...base, scanners, findings: [], requirements: allPass(), requiredScanners: ['semgrep', 'gitleaks'],
    });
    expect(r.result).toBe('PASS');
  });
});

describe('Настройки политики', () => {
  it('новые параметры нормализуются и по умолчанию соответствуют ТЗ', () => {
    const settings = (policy as any).normalize({});
    expect(settings.blockOnAdditionalFindings).toBe(false);
    expect(settings.insufficientEvidenceBlocks).toBe(false);
  });

  it('нечисловой/нелогический ввод не включает блокировку', () => {
    const settings = (policy as any).normalize({ blockOnAdditionalFindings: 'yes', insufficientEvidenceBlocks: 1 });
    expect(settings.blockOnAdditionalFindings).toBe(false);
    expect(settings.insufficientEvidenceBlocks).toBe(false);
  });
});
