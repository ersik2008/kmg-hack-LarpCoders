import { Injectable, Logger } from '@nestjs/common';
import { Finding, PolicyResult } from '../generated/prisma/client.js';
import { PrismaService } from '../prisma/index.js';
import type { RequirementStatus } from '../requirements/requirement-definitions.js';

export type ScannerStatus = 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'SKIPPED' | 'INVALID';

export interface ScannerStatusRecord {
  status: ScannerStatus;
  startedAt?: string;
  finishedAt?: string;
  findingsCount: number;
  error?: string | null;
  rawOutputAvailable?: boolean;
}

export interface PolicyEvaluationInput {
  findings: Finding[];
  /**
   * Результаты проверки обязательных Требований ИБ-01…ИБ-08 (ТЗ п. 4.5).
   *
   * Когда переданы, именно они определяют блокировку пайплайна: ТЗ п. 4.3.3
   * прерывает пайплайн при нарушении Требований ИБ, а п. 4.8.1 прямо говорит,
   * что прочие дефекты безопасности основанием для прерывания не являются.
   * Когда не переданы (проверка по диффу: сквозные требования по нему не
   * установить), действует прежняя оценка по severity.
   */
  requirements?: Array<{ requirementId: string; status: RequirementStatus }>;
  scanners: Record<string, ScannerStatusRecord>;
  repositoryStatus: 'READY' | 'FAILED' | 'INCOMPLETE';
  hasConfirmedAttackPaths?: boolean;
  requiredScanners?: string[];
  thresholds?: PolicyThresholds;
}

/** Operator-configurable gate thresholds, persisted in the `policies` table. */
export interface PolicyThresholds {
  /**
   * Статус INSUFFICIENT_EVIDENCE не равен PASS, но решение по нему ТЗ оставляет
   * политике (п. 4.3.3, 4.4.5). По умолчанию — REVIEW: пайплайн не прерывается,
   * в отчёте остаётся явная пометка. true — считать недостаточность данных блокирующей.
   */
  insufficientEvidenceBlocks: boolean;
  /**
   * По ТЗ п. 4.8.1 прочие находки (SQL-инъекции, зависимости, секреты вне
   * перечня ИБ) пайплайн не прерывают. true возвращает прежнюю строгость:
   * находки CRITICAL и порог оценки риска блокируют и в режиме требований.
   */
  blockOnAdditionalFindings: boolean;
  blockOnCritical: boolean;
  blockRiskScore: number;
  reviewRiskScore: number;
  reviewHighCount: number;
}

export interface PolicySettings extends PolicyThresholds {
  scanners: { semgrep: boolean; gitleaks: boolean; trivy: boolean };
  aiAnalysis: boolean;
}

export const DEFAULT_POLICY: PolicySettings = {
  insufficientEvidenceBlocks: false,
  blockOnAdditionalFindings: false,
  blockOnCritical: true,
  blockRiskScore: 7.0,
  reviewRiskScore: 3.5,
  reviewHighCount: 1,
  scanners: { semgrep: true, gitleaks: true, trivy: true },
  aiAnalysis: true,
};

const POLICY_NAME = 'default';

export interface PolicyEvaluationResult {
  riskScore: number | null;
  result: PolicyResult | null;
  isBlocked: boolean;
  isReview: boolean;
  isPass: boolean;
  isIncomplete: boolean;
  statusText: string;
  reasons: string[];
  /** По чему принято решение: статусы требований ИБ либо severity находок. */
  basis: 'requirements' | 'severity' | 'incomplete';
  /** Идентификаторы нарушенных требований ИБ — для журнала CI (ТЗ п. 4.3.5). */
  violatedRequirements: string[];
  /** Требования, по которым данных недостаточно. */
  insufficientRequirements: string[];
}

/**
 * Код завершения шага проверки ИБ (ТЗ п. 4.3.3).
 *
 *   0 — нарушений Требований ИБ не выявлено;
 *   1 — выявлено одно или более нарушений;
 *   2 — проверка не выполнена (сканер не завершился, рабочая область не готова).
 *
 * Подтверждённое нарушение обязательного требования решает дело само по себе:
 * проверка требований от сканеров не зависит, поэтому нарушение остаётся
 * нарушением и при незавершённом сканере, а не прячется под кодом 2.
 * Незавершённая проверка без подтверждённых нарушений никогда не равна 0.
 */
export type ExitCode = 0 | 1 | 2;

export function exitCodeFor(result: {
  isIncomplete: boolean;
  isBlocked: boolean;
  violatedRequirements: string[];
}): ExitCode {
  if (result.violatedRequirements.length > 0) return 1;
  if (result.isIncomplete) return 2;
  return result.isBlocked ? 1 : 0;
}

@Injectable()
export class PolicyService {
  private readonly logger = new Logger(PolicyService.name);

  constructor(private readonly prisma: PrismaService) {}

  /**
   * Returns the stored gate configuration, creating the default row on first
   * use. Values come from the database — nothing here is hardcoded UI state.
   */
  async getSettings(): Promise<PolicySettings> {
    const row = await this.prisma.policy.findFirst({
      where: { name: POLICY_NAME, isActive: true },
      orderBy: { updatedAt: 'desc' },
    });

    if (!row) return { ...DEFAULT_POLICY };
    return this.normalize(row.rules);
  }

  async updateSettings(input: unknown): Promise<PolicySettings> {
    const settings = this.normalize(input);

    const existing = await this.prisma.policy.findFirst({ where: { name: POLICY_NAME } });
    if (existing) {
      await this.prisma.policy.update({
        where: { id: existing.id },
        data: { rules: settings as any, isActive: true },
      });
    } else {
      await this.prisma.policy.create({
        data: { name: POLICY_NAME, rules: settings as any, isActive: true },
      });
    }

    this.logger.log(`Policy settings updated: ${JSON.stringify(settings)}`);
    return settings;
  }

  /** Clamps arbitrary input onto the supported shape and ranges. */
  private normalize(input: unknown): PolicySettings {
    const raw = (input && typeof input === 'object' ? input : {}) as Record<string, any>;
    const rawScanners = (raw.scanners && typeof raw.scanners === 'object' ? raw.scanners : {}) as Record<string, any>;

    const num = (value: unknown, fallback: number) => {
      const n = Number(value);
      if (!Number.isFinite(n)) return fallback;
      return Math.min(Math.max(n, 0), 10);
    };

    const bool = (value: unknown, fallback: boolean) =>
      typeof value === 'boolean' ? value : fallback;

    return {
      insufficientEvidenceBlocks: bool(raw.insufficientEvidenceBlocks, DEFAULT_POLICY.insufficientEvidenceBlocks),
      blockOnAdditionalFindings: bool(raw.blockOnAdditionalFindings, DEFAULT_POLICY.blockOnAdditionalFindings),
      blockOnCritical: bool(raw.blockOnCritical, DEFAULT_POLICY.blockOnCritical),
      blockRiskScore: num(raw.blockRiskScore, DEFAULT_POLICY.blockRiskScore),
      reviewRiskScore: num(raw.reviewRiskScore, DEFAULT_POLICY.reviewRiskScore),
      reviewHighCount: Math.max(0, Math.round(num(raw.reviewHighCount, DEFAULT_POLICY.reviewHighCount))),
      scanners: {
        semgrep: bool(rawScanners.semgrep, DEFAULT_POLICY.scanners.semgrep),
        gitleaks: bool(rawScanners.gitleaks, DEFAULT_POLICY.scanners.gitleaks),
        trivy: bool(rawScanners.trivy, DEFAULT_POLICY.scanners.trivy),
      },
      aiAnalysis: bool(raw.aiAnalysis, DEFAULT_POLICY.aiAnalysis),
    };
  }

  evaluate(input: PolicyEvaluationInput): PolicyEvaluationResult {
    const {
      findings,
      scanners,
      repositoryStatus,
      hasConfirmedAttackPaths = false,
      requirements,
      requiredScanners = ['semgrep', 'gitleaks', 'trivy'],
      thresholds = DEFAULT_POLICY,
    } = input;

    const reasons: string[] = [];

    // Статусы требований ИБ вычисляются независимо от сканеров: это
    // детерминированные проверки по индексу рабочей области.
    const evaluatedRequirements = requirements && requirements.length > 0 ? requirements : null;
    const violatedRequirements = (evaluatedRequirements ?? [])
      .filter(r => r.status === 'VIOLATION')
      .map(r => r.requirementId);
    const insufficientRequirements = (evaluatedRequirements ?? [])
      .filter(r => r.status === 'INSUFFICIENT_EVIDENCE')
      .map(r => r.requirementId);

    // 1. REPOSITORY VALIDATION
    if (repositoryStatus !== 'READY') {
      reasons.push(`Repository preparation status is '${repositoryStatus}'. Security verdict cannot be determined.`);
      this.logger.warn(`Policy evaluation: Repository not ready (${repositoryStatus}). CANNOT PASS.`);
      return {
        riskScore: null,
        result: null,
        isBlocked: true,
        isReview: false,
        isPass: false,
        isIncomplete: true,
        statusText: 'SCAN_INCOMPLETE',
        reasons,
        basis: 'incomplete',
        violatedRequirements: [],
        insufficientRequirements: [],
      };
    }

    // 2. REQUIRED SCANNERS COMPLETION CHECK
    if (requiredScanners.length === 0) {
      reasons.push('No scanners are enabled in the active policy. Security verdict cannot be determined.');
      return {
        riskScore: null,
        result: null,
        isBlocked: true,
        isReview: false,
        isPass: false,
        isIncomplete: true,
        statusText: 'SCAN_INCOMPLETE',
        reasons,
        basis: 'incomplete',
        violatedRequirements: [],
        insufficientRequirements: [],
      };
    }

    const failedScanners: string[] = [];
    const missingScanners: string[] = [];

    for (const req of requiredScanners) {
      const rec = scanners[req];
      if (!rec) {
        missingScanners.push(req);
      } else if (rec.status !== 'COMPLETED') {
        failedScanners.push(`${req} (${rec.status}${rec.error ? ': ' + rec.error : ''})`);
      }
    }

    if (failedScanners.length > 0 || missingScanners.length > 0) {
      if (failedScanners.length > 0) {
        reasons.push(`Required scanners failed: ${failedScanners.join('; ')}`);
      }
      if (missingScanners.length > 0) {
        reasons.push(`Required scanners missing or unexecuted: ${missingScanners.join(', ')}`);
      }

      this.logger.warn(`Policy evaluation: Required scanners not completed. CANNOT PASS. Reasons: ${reasons.join(' | ')}`);

      // Calculate partial risk score for any findings that were discovered
      const partialRisk = this.calculateRiskScore(findings, hasConfirmedAttackPaths);

      return {
        riskScore: partialRisk,
        result: null, // Verdict is suppressed because scan is incomplete/partial
        isBlocked: false,
        isReview: false,
        isPass: false,
        isIncomplete: true,
        statusText: 'SCAN_PARTIAL',
        reasons: violatedRequirements.length > 0
          ? [`Нарушены обязательные требования ИБ: ${violatedRequirements.join(', ')}.`, ...reasons]
          : reasons,
        basis: 'incomplete',
        // Подтверждённое нарушение обязательного требования остаётся нарушением,
        // даже если сканеры не завершились: проверка требований от них не зависит.
        violatedRequirements,
        insufficientRequirements,
      };
    }

    // 3. DETERMINISTIC RISK CALCULATION
    const riskScore = this.calculateRiskScore(findings, hasConfirmedAttackPaths);

    const criticalCount = findings.filter(f => f.severity === 'CRITICAL').length;
    const highCount = findings.filter(f => f.severity === 'HIGH').length;

    let result: PolicyResult = 'PASS';
    let basis: 'requirements' | 'severity' = 'severity';

    if (evaluatedRequirements) {
      // ТЗ п. 4.3.3 и 4.8.1: решение принимается по обязательным Требованиям ИБ.
      // Прочие находки в отчёте остаются, но пайплайн сами по себе не прерывают.
      basis = 'requirements';

      const strictAdditional =
        thresholds.blockOnAdditionalFindings &&
        ((thresholds.blockOnCritical && criticalCount > 0) || riskScore >= thresholds.blockRiskScore);

      if (violatedRequirements.length > 0) {
        result = 'BLOCK';
        reasons.push(`Нарушены обязательные требования ИБ: ${violatedRequirements.join(', ')}.`);
      } else if (strictAdditional) {
        result = 'BLOCK';
        reasons.push(
          `Требования ИБ не нарушены, но включена блокировка по прочим находкам: критических ${criticalCount}, ` +
            `оценка риска ${riskScore.toFixed(1)}/${thresholds.blockRiskScore}.`,
        );
      } else if (insufficientRequirements.length > 0) {
        // INSUFFICIENT_EVIDENCE никогда не равен PASS.
        result = thresholds.insufficientEvidenceBlocks ? 'BLOCK' : 'REVIEW';
        reasons.push(
          `Данных для вывода недостаточно по требованиям: ${insufficientRequirements.join(', ')}. ` +
            (thresholds.insufficientEvidenceBlocks
              ? 'Политика считает недостаточность данных блокирующей.'
              : 'Пайплайн не прерывается, вывод требует ручной проверки.'),
        );
      } else if (findings.length > 0) {
        result = 'REVIEW';
        reasons.push(
          `Нарушений обязательных требований ИБ нет. Дополнительных находок: ${findings.length} ` +
            `(критических ${criticalCount}, high ${highCount}) — приведены отдельно и пайплайн не прерывают (ТЗ п. 4.8.1).`,
        );
      } else {
        result = 'PASS';
        reasons.push('Нарушений обязательных требований ИБ нет, дополнительных находок нет.');
      }
    } else if ((thresholds.blockOnCritical && criticalCount > 0) || riskScore >= thresholds.blockRiskScore) {
      result = 'BLOCK';
      reasons.push(`Critical vulnerabilities detected (${criticalCount}) or risk score threshold exceeded (${riskScore.toFixed(1)}/${thresholds.blockRiskScore}).`);
    } else if (highCount > thresholds.reviewHighCount || riskScore >= thresholds.reviewRiskScore) {
      result = 'REVIEW';
      reasons.push(`High severity issues detected (${highCount}) or elevated risk score (${riskScore.toFixed(1)}/${thresholds.reviewRiskScore}). Manual security review required.`);
    } else if (findings.length > 0) {
      result = 'REVIEW';
      reasons.push(`${findings.length} low/medium findings detected. Review recommended.`);
    } else {
      result = 'PASS';
      reasons.push('No supported vulnerabilities detected across all completed scanners.');
    }

    this.logger.log(`Policy evaluated: Score=${riskScore.toFixed(1)}, Verdict=${result}, basis=${basis}`);

    return {
      riskScore,
      result,
      isBlocked: result === 'BLOCK',
      isReview: result === 'REVIEW',
      isPass: result === 'PASS',
      isIncomplete: false,
      statusText: result,
      reasons,
      basis,
      violatedRequirements,
      insufficientRequirements,
    };
  }

  private calculateRiskScore(findings: Finding[], hasConfirmedAttackPaths: boolean): number {
    if (findings.length === 0) {
      return 0.0;
    }

    let score = 0;
    for (const f of findings) {
      let weight = 0;
      switch (f.severity) {
        case 'CRITICAL':
          weight = 10.0;
          break;
        case 'HIGH':
          weight = 6.0;
          break;
        case 'MEDIUM':
          weight = 3.0;
          break;
        case 'LOW':
          weight = 1.0;
          break;
        case 'INFO':
          weight = 0.2;
          break;
      }

      // Confidence factor
      const confFactor = f.confidence === 'HIGH' ? 1.0 : f.confidence === 'MEDIUM' ? 0.8 : 0.6;
      score += weight * confFactor;
    }

    // Multiplier for confirmed attack paths
    if (hasConfirmedAttackPaths) {
      score *= 1.25;
    }

    // Cap strictly at 10.0
    return Math.min(Math.round(score * 10) / 10, 10.0);
  }
}
