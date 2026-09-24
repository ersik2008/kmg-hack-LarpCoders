import {
  REQUIREMENT_DEFINITIONS,
  RequirementEvidence,
  RequirementResult,
  RequirementViolation,
} from '../requirement-definitions.js';
import { Hit, WorkspaceIndex } from '../workspace-index.js';
import {
  ADMIN_ROLE_CHECK,
  AUDIT_WRITE,
  buildResult,
  findGlobalMechanism,
  toEvidence,
} from './shared.js';

/**
 * ИБ-08 — контроль выгрузки персональных данных (ТЗ п. 4.5.8).
 *
 * Для каждого обнаруженного потока выгрузки проверяются ДВА условия
 * одновременно:
 *   1) серверная проверка роли «администратор»;
 *   2) запись в журнал аудита при каждом факте выгрузки.
 *
 * Отсутствие любого из них — нарушение, и в отчёте указывается, какого именно.
 */

const DEFINITION = REQUIREMENT_DEFINITIONS['ИБ-08'];

/** Признаки потока выгрузки данных. */
const EXPORT_SIGNALS: Array<{ label: string; pattern: RegExp }> = [
  {
    label: 'Маршрут выгрузки',
    // Приёмник — любой идентификатор (`exportRouter`, `usersRouter`), кроме
    // HTTP-клиентов: иначе `axios.get('/export')` считался бы серверным маршрутом.
    pattern: /(?<![\w$.])(?!(?:axios|http|https|request|got|client|fetch|superagent)\.)[A-Za-z_$][\w$]*\.(?:get|post)\s*\(\s*['"`][^'"`]*\/(?:export|download|dump|backup|report)s?\b|@(?:Get|Post)\s*\(\s*['"`][^'"`]*(?:export|download|dump|backup|report)/i,
  },
  {
    label: 'Отдача файла вложением',
    pattern: /\bres\.(?:download|attachment)\s*\(|Content-Disposition['"`]?\s*[,:]\s*['"`]attachment|send_file\s*\(|FileResponse\s*\(|StreamingHttpResponse\s*\(/i,
  },
  {
    label: 'Формирование CSV/Excel',
    pattern: /\b(?:createObjectCsvWriter|json2csv|parseAsync|new\s+Parser\s*\(|ExcelJS|XLSX\.utils|writeFile\s*\(\s*workbook|to_csv\s*\(|csv\.writer\s*\(|openpyxl|Workbook\s*\(\s*\))/,
  },
  {
    label: 'MIME-тип выгрузки',
    pattern: /['"`](?:text\/csv|application\/vnd\.ms-excel|application\/vnd\.openxmlformats-officedocument\.spreadsheetml\.sheet)['"`]/i,
  },
];

/** Признаки того, что выгружаются именно персональные данные. */
const PERSONAL_DATA = /\b(?:users?|customers?|clients?|employees?|persons?|profiles?|accounts?|citizens?|contacts?|пользовател|клиент|сотрудник)\b/i;

/** Технические выгрузки, к персональным данным не относящиеся. */
const TECHNICAL_EXPORT = /\b(?:metrics?|logs?|traces?|sarif|coverage|build|bundle|sitemap|openapi|swagger|schema|changelog)\b/i;

const SEARCH_RADIUS = 40;

export async function checkIb08(index: WorkspaceIndex): Promise<RequirementResult> {
  const evidence: RequirementEvidence[] = [];
  const violations: RequirementViolation[] = [];

  // 1. Поиск потоков выгрузки. Клиентский код исключён: формирование CSV в
  // браузере из уже полученных данных потоком серверной выгрузки не является.
  const exportHits: Array<Hit & { label: string }> = [];
  for (const signal of EXPORT_SIGNALS) {
    const hits = await index.grep(signal.pattern, {
      kinds: ['source'],
      excludeTests: true,
      limit: 20,
      perFile: 2,
    });
    for (const hit of hits) {
      const file = index.files.find(f => f.relPath === hit.filePath);
      if (file?.clientSide) continue;
      if (TECHNICAL_EXPORT.test(hit.text) && !PERSONAL_DATA.test(hit.text)) continue;
      exportHits.push({ ...hit, label: signal.label });
    }
  }

  if (exportHits.length === 0) {
    return buildResult(DEFINITION, {
      status: 'NOT_APPLICABLE',
      confidence: 'MEDIUM',
      summary:
        'В проекте не обнаружено серверных потоков выгрузки данных (маршрутов экспорта, ' +
        'отдачи файлов вложением, формирования CSV/Excel). Требование неприменимо.',
      evidence: [],
      violations: [],
      insufficientReason: null,
    });
  }

  // 2. Глобальный механизм аудита: если он есть, отсутствие явного вызова в
  // конкретном обработчике нарушением не является.
  const globalAudit = await findGlobalMechanism(index, AUDIT_WRITE);
  const hasGlobalAudit = globalAudit.length > 0;
  if (hasGlobalAudit) {
    evidence.push(toEvidence(globalAudit[0], 'Централизованный механизм аудита', 'CONTEXT'));
  }

  // 3. По каждому файлу выгрузки — проверка роли и аудита в окрестности.
  const byFile = new Map<string, Array<Hit & { label: string }>>();
  for (const hit of exportHits) {
    const list = byFile.get(hit.filePath) ?? [];
    list.push(hit);
    byFile.set(hit.filePath, list);
  }

  let protectedFlows = 0;

  for (const [filePath, hits] of byFile) {
    const lines = await index.readCode(filePath);
    if (!lines) continue;

    const anchor = hits[0];
    const from = Math.max(0, anchor.line - 1 - SEARCH_RADIUS);
    const to = Math.min(lines.length, anchor.line + SEARCH_RADIUS);
    const region = lines.slice(from, to);
    const regionText = region.join('\n');
    // Декоратор или guard может стоять на уровне класса, выше окрестности.
    const fileHead = lines.slice(0, Math.min(lines.length, 60)).join('\n');

    const hasAdminCheck = ADMIN_ROLE_CHECK.test(regionText) || ADMIN_ROLE_CHECK.test(fileHead);
    const hasAudit = AUDIT_WRITE.test(regionText) || hasGlobalAudit;

    const locate = (pattern: RegExp): number => {
      const idx = region.findIndex(l => pattern.test(l));
      return idx === -1 ? anchor.line : from + idx + 1;
    };

    if (hasAdminCheck) {
      evidence.push({
        filePath,
        line: locate(ADMIN_ROLE_CHECK),
        snippet: (region.find(l => ADMIN_ROLE_CHECK.test(l)) ?? anchor.text).trim().slice(0, 240),
        note: 'Серверная проверка роли администратора на потоке выгрузки',
        kind: 'SUPPORTS',
      });
    }
    if (hasAudit && !hasGlobalAudit) {
      evidence.push({
        filePath,
        line: locate(AUDIT_WRITE),
        snippet: (region.find(l => AUDIT_WRITE.test(l)) ?? anchor.text).trim().slice(0, 240),
        note: 'Запись в журнал аудита при выгрузке',
        kind: 'SUPPORTS',
      });
    }

    if (hasAdminCheck && hasAudit) {
      protectedFlows++;
      continue;
    }

    const missing: string[] = [];
    if (!hasAdminCheck) missing.push('серверная проверка роли «администратор»');
    if (!hasAudit) missing.push('запись в журнал аудита');

    violations.push({
      filePath,
      lineStart: anchor.line,
      lineEnd: anchor.line,
      symbol: anchor.label,
      evidence: anchor.text,
      explanation:
        `Обнаружен поток выгрузки данных (${anchor.label.toLowerCase()}), для которого ` +
        `отсутствует: ${missing.join(' и ')}. Требование ИБ-08 обязывает предоставлять ` +
        'выгрузку данных с персональными сведениями исключительно пользователям с ролью ' +
        '«администратор» и фиксировать каждый факт выгрузки записью в журнале аудита. ' +
        `Проверена окрестность ±${SEARCH_RADIUS} строк и объявления в начале файла.`,
      severity: DEFINITION.severity,
      confidence: hasGlobalAudit || hasAdminCheck ? 'MEDIUM' : 'HIGH',
      recommendation: !hasAdminCheck && !hasAudit
        ? 'Применить к обработчику серверный guard роли «администратор» и добавить вызов ' +
          'сервиса аудита до отдачи файла. Запись должна содержать идентификатор субъекта, ' +
          'тип и объём выгруженных данных, время.'
        : !hasAdminCheck
          ? 'Применить к обработчику серверный guard роли «администратор». Сокрытие кнопки ' +
            'экспорта в интерфейсе выполнением требования не является.'
          : 'Добавить запись в журнал аудита до отдачи файла: кто выгрузил, что именно, ' +
            'когда и в каком объёме.',
    });

    evidence.push(toEvidence(anchor, `${anchor.label} без полной защиты`, 'VIOLATES'));
  }

  const total = byFile.size;

  if (violations.length === 0) {
    return buildResult(DEFINITION, {
      status: 'PASS',
      confidence: hasGlobalAudit ? 'MEDIUM' : 'HIGH',
      summary:
        `Обнаружено потоков выгрузки: ${total}. Для каждого найдена серверная проверка роли ` +
        `администратора и запись в журнал аудита${hasGlobalAudit ? ' (аудит централизован)' : ''}.`,
      evidence: evidence.slice(0, 12),
      violations: [],
      insufficientReason: null,
    });
  }

  return buildResult(DEFINITION, {
    status: 'VIOLATION',
    confidence: 'HIGH',
    summary:
      `Обнаружено потоков выгрузки: ${total}, из них защищены полностью: ${protectedFlows}. ` +
      `Нарушений: ${violations.length}.`,
    evidence: evidence.slice(0, 12),
    violations,
    insufficientReason: null,
  });
}
