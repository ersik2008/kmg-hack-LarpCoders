import { Injectable, Logger } from '@nestjs/common';

import { PrismaService } from '../prisma/index.js';
import {
  REQUIREMENT_DEFINITIONS,
  REQUIREMENT_IDS,
  RequirementId,
  RequirementResult,
} from './requirement-definitions.js';
import { WorkspaceIndex } from './workspace-index.js';
import { checkIb01 } from './checkers/ib01-admin-authorization.js';
import { checkIb02 } from './checkers/ib02-session-validation.js';
import { checkIb03 } from './checkers/ib03-transport-security.js';
import { checkIb04 } from './checkers/ib04-data-at-rest.js';
import { checkIb05 } from './checkers/ib05-local-logs.js';
import { checkIb06 } from './checkers/ib06-regulatory-references.js';
import { checkIb07 } from './checkers/ib07-audit-logging.js';
import { checkIb08 } from './checkers/ib08-data-export.js';

export type RequirementChecker = (
  index: WorkspaceIndex,
  context: CheckerContext,
) => Promise<RequirementResult>;

export interface CheckerContext {
  hasWebSurface: boolean;
}

export interface RequirementsOutcome {
  results: RequirementResult[];
  /** Требования со статусом VIOLATION — основание для прерывания пайплайна (ТЗ п. 4.3.3). */
  violations: RequirementResult[];
  summary: {
    total: number;
    pass: number;
    violation: number;
    insufficient: number;
    notApplicable: number;
  };
  errors: string[];
}

const CHECKERS: Record<RequirementId, RequirementChecker> = {
  'ИБ-01': checkIb01,
  'ИБ-02': checkIb02,
  'ИБ-03': checkIb03,
  'ИБ-04': checkIb04,
  'ИБ-05': checkIb05,
  'ИБ-06': checkIb06,
  'ИБ-07': checkIb07,
  'ИБ-08': checkIb08,
};

/**
 * Проверка соответствия проекта обязательным Требованиям ИБ (ТЗ п. 4.5).
 *
 * Отвечает на главный вопрос ТЗ: «соответствует ли проект Требованию ИБ-XX».
 * Это не то же самое, что находки сканеров («где в коде уязвимость») и не то
 * же, что оценка контролей («реализован ли механизм защиты вообще»).
 *
 * Все восемь проверок детерминированы: они опираются на индекс рабочей области
 * и на регулярные выражения с привязкой к `file:line`. Языковая модель на
 * статус требования не влияет — по ТЗ п. 4.1.3 вывод должен быть
 * воспроизводимым, а вердикт CI (п. 4.3.3) — детерминированным.
 */
@Injectable()
export class RequirementsService {
  private readonly logger = new Logger(RequirementsService.name);

  constructor(private readonly prisma: PrismaService) {}

  /**
   * Чистая оценка: без обращения к БД. Сохранение — отдельным вызовом `save`,
   * потому что в pre-push запись скана появляется уже после анализа.
   */
  async evaluate(workspacePath: string, label = 'scan'): Promise<RequirementsOutcome> {
    const outcome: RequirementsOutcome = {
      results: [],
      violations: [],
      summary: { total: 0, pass: 0, violation: 0, insufficient: 0, notApplicable: 0 },
      errors: [],
    };

    const index = await WorkspaceIndex.build(workspacePath);
    if (index.fileCount === 0) {
      outcome.errors.push('Рабочая область пуста — проверка требований не выполнялась');
      return outcome;
    }

    const hasWebSurface = await index.hasWebSurface();
    const context: CheckerContext = { hasWebSurface };

    this.logger.log(
      `${label}: проверка требований ИБ по ${index.fileCount} файлам, ` +
        `веб-поверхность: ${hasWebSurface ? 'есть' : 'нет'}`,
    );

    for (const id of REQUIREMENT_IDS) {
      const definition = REQUIREMENT_DEFINITIONS[id];

      // Требование, завязанное на HTTP-поверхность, неприменимо к библиотеке
      // или набору скриптов. Это NOT_APPLICABLE с обоснованием, а не PASS:
      // «нечего проверять» и «проверено, нарушений нет» — разные факты.
      if (definition.requiresWebSurface && !hasWebSurface) {
        outcome.results.push({
          requirementId: id,
          title: definition.title,
          requirementText: definition.text,
          status: 'NOT_APPLICABLE',
          confidence: 'MEDIUM',
          summary:
            'В проекте не обнаружено HTTP-поверхности (веб-фреймворка в манифесте или ' +
            'обработчиков запросов в коде), к которой применимо это требование.',
          evidence: [],
          violations: [],
          insufficientReason: null,
        });
        continue;
      }

      try {
        outcome.results.push(await CHECKERS[id](index, context));
      } catch (err: any) {
        const message = `${id}: ${err.message}`;
        this.logger.warn(`Проверка требования не выполнена — ${message}`);
        outcome.errors.push(message);

        // Сбой проверки не превращается в PASS: статус явно говорит, что
        // вывод не получен.
        outcome.results.push({
          requirementId: id,
          title: definition.title,
          requirementText: definition.text,
          status: 'INSUFFICIENT_EVIDENCE',
          confidence: 'LOW',
          summary: 'Проверку выполнить не удалось из-за внутренней ошибки.',
          evidence: [],
          violations: [],
          insufficientReason: err.message,
        });
      }
    }

    outcome.violations = outcome.results.filter(r => r.status === 'VIOLATION');
    outcome.summary = {
      total: outcome.results.length,
      pass: outcome.results.filter(r => r.status === 'PASS').length,
      violation: outcome.violations.length,
      insufficient: outcome.results.filter(r => r.status === 'INSUFFICIENT_EVIDENCE').length,
      notApplicable: outcome.results.filter(r => r.status === 'NOT_APPLICABLE').length,
    };

    this.logger.log(
      `${label}: требования ИБ — PASS=${outcome.summary.pass} ` +
        `VIOLATION=${outcome.summary.violation} ` +
        `INSUFFICIENT=${outcome.summary.insufficient} ` +
        `N/A=${outcome.summary.notApplicable}` +
        (outcome.violations.length
          ? ` | нарушены: ${outcome.violations.map(v => v.requirementId).join(', ')}`
          : ''),
    );

    return outcome;
  }

  /** Сохраняет результаты проверки за сканом. Сбой записи вывод не отменяет. */
  async save(scanId: string, results: RequirementResult[]): Promise<void> {
    for (const result of results) {
      try {
        await this.prisma.requirementResult.upsert({
          where: { scanId_requirementId: { scanId, requirementId: result.requirementId } },
          create: {
            scanId,
            requirementId: result.requirementId,
            title: result.title,
            requirementText: result.requirementText,
            status: result.status as any,
            confidence: result.confidence as any,
            summary: result.summary,
            insufficientReason: result.insufficientReason,
            evidence: result.evidence as any,
            violations: result.violations as any,
          },
          update: {
            title: result.title,
            requirementText: result.requirementText,
            status: result.status as any,
            confidence: result.confidence as any,
            summary: result.summary,
            insufficientReason: result.insufficientReason,
            evidence: result.evidence as any,
            violations: result.violations as any,
          },
        });
      } catch (err: any) {
        // Проблема с сохранением не должна отменять уже полученный вывод.
        this.logger.warn(`Не удалось сохранить результат ${result.requirementId}: ${err.message}`);
      }
    }
  }

  /** Матрица требований для отчёта и интерфейса. */
  async getForScan(scanId: string) {
    const rows = await this.prisma.requirementResult.findMany({
      where: { scanId },
      orderBy: { requirementId: 'asc' },
    });

    const count = (status: string) => rows.filter(r => r.status === status).length;

    return {
      requirements: rows,
      summary: {
        total: rows.length,
        pass: count('PASS'),
        violation: count('VIOLATION'),
        insufficient: count('INSUFFICIENT_EVIDENCE'),
        notApplicable: count('NOT_APPLICABLE'),
        violatedIds: rows.filter(r => r.status === 'VIOLATION').map(r => r.requirementId),
      },
    };
  }
}
