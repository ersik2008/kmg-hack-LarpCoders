import {
  REGULATORY_ACTS,
  RequirementEvidence,
  RequirementResult,
  RequirementViolation,
  REQUIREMENT_DEFINITIONS,
} from '../requirement-definitions.js';
import { WorkspaceIndex } from '../workspace-index.js';

/**
 * ИБ-06 — ссылки на нормативную базу в документации проекта (ТЗ п. 4.5.6).
 *
 * Проверка полностью детерминированная: требуется установить наличие ссылок на
 * шесть актов перечня п. 3.1 ТЗ. Языковая модель здесь не нужна и не
 * используется — поиск шести строк не тот случай, где уместна интерпретация.
 *
 * Требование считается выполненным при наличии ссылок. Фактическая
 * сертификация не проверяется и не требуется (п. 3.3 ТЗ).
 */

const DEFINITION = REQUIREMENT_DEFINITIONS['ИБ-06'];

/**
 * Документация проекта в смысле требования: README, каталог docs и технические
 * спецификации. Лицензии, changelog и шаблоны issue документацией проекта в
 * этом смысле не являются, и требовать от них нормативных ссылок некорректно.
 */
const PROJECT_DOC = /(^|\/)(readme|readme\.[a-z-]+)\.(md|markdown|rst|adoc|txt)$/i;
const DOC_DIR = /(^|\/)(docs?|documentation|doc)\//i;
const SPEC_DOC = /(техническ|specification|spec|тз|требован)/i;
const EXCLUDED_DOC = /(^|\/)(license|licence|changelog|code_of_conduct|contributing|security\.md|\.github\/)/i;

export async function checkIb06(index: WorkspaceIndex): Promise<RequirementResult> {
  const docs = index
    .byKind('docs')
    .filter(f => !EXCLUDED_DOC.test(f.relPath))
    .filter(f => PROJECT_DOC.test(f.relPath) || DOC_DIR.test(f.relPath) || SPEC_DOC.test(f.relPath));

  const base = {
    requirementId: DEFINITION.id,
    title: DEFINITION.title,
    requirementText: DEFINITION.text,
  };

  // Документации нет вовсе. По п. 4.4.5 ТЗ отсутствие реализации требования —
  // такое же нарушение, как некорректная реализация, поэтому это VIOLATION, а
  // не «недостаточно данных».
  if (docs.length === 0) {
    return {
      ...base,
      status: 'VIOLATION',
      confidence: 'HIGH',
      summary:
        'В проекте не обнаружено документации (README, каталог docs, техническая ' +
        'спецификация), в которой могли бы содержаться ссылки на нормативную базу.',
      evidence: [],
      violations: [{
        filePath: null,
        lineStart: null,
        lineEnd: null,
        symbol: null,
        evidence: '(документация в репозитории отсутствует)',
        explanation:
          'Требование ИБ-06 обязывает документацию проекта содержать ссылки на акты и ' +
          'стандарты перечня п. 3.1 ТЗ. Документация отсутствует, следовательно ссылки ' +
          'отсутствуют тоже.',
        severity: DEFINITION.severity,
        confidence: 'HIGH',
        recommendation:
          'Создать README.md в корне репозитория с разделом «Нормативная база», ' +
          'перечислив все шесть актов пункта 3.1 ТЗ с указанием номеров, дат и названий.',
      }],
      insufficientReason: null,
    };
  }

  const evidence: RequirementEvidence[] = [];
  const found = new Set<string>();

  for (const act of REGULATORY_ACTS) {
    for (const doc of docs) {
      if (found.has(act.key)) break;

      const lines = await index.read(doc.relPath);
      if (!lines) continue;

      for (let i = 0; i < lines.length; i++) {
        if (!act.patterns.some(p => p.test(lines[i]))) continue;

        found.add(act.key);
        evidence.push({
          filePath: doc.relPath,
          line: i + 1,
          snippet: lines[i].trim().slice(0, 240),
          note: `Ссылка на акт ${act.clause}: ${act.title}`,
          kind: 'SUPPORTS',
        });
        break;
      }
    }
  }

  const missing = REGULATORY_ACTS.filter(a => a.required && !found.has(a.key));
  const docList = docs.slice(0, 5).map(d => d.relPath).join(', ');

  if (missing.length === 0) {
    return {
      ...base,
      status: 'PASS',
      confidence: 'HIGH',
      summary:
        `Документация проекта содержит ссылки на все ${REGULATORY_ACTS.length} актов ` +
        `перечня п. 3.1 ТЗ. Проверено документов: ${docs.length}.`,
      evidence,
      violations: [],
      insufficientReason: null,
    };
  }

  const missingList = missing.map(a => `${a.clause} — ${a.title}`).join('; ');
  const primaryDoc = docs.find(d => PROJECT_DOC.test(d.relPath)) ?? docs[0];

  return {
    ...base,
    status: 'VIOLATION',
    confidence: 'HIGH',
    summary:
      `В документации проекта отсутствуют ссылки на ${missing.length} из ` +
      `${REGULATORY_ACTS.length} актов перечня п. 3.1 ТЗ. ` +
      `Найдено ссылок: ${found.size}. Проверенные документы: ${docList}.`,
    evidence,
    violations: [{
      filePath: primaryDoc.relPath,
      lineStart: null,
      lineEnd: null,
      symbol: 'Нормативная база',
      evidence: `(в документе ${primaryDoc.relPath} отсутствуют ссылки на: ${missingList})`,
      explanation:
        'Требование ИБ-06 обязывает документацию проекта содержать ссылки на акты и ' +
        `стандарты перечня п. 3.1 ТЗ. Не найдено ссылок на следующие акты: ${missingList}. ` +
        'Проверка выполнена по документации проекта; фактическая сертификация не требуется ' +
        'и не проверялась.',
      severity: DEFINITION.severity,
      confidence: 'HIGH',
      recommendation:
        `Добавить в ${primaryDoc.relPath} (или в отдельный документ, на который есть ссылка ` +
        'из README) раздел «Нормативная база» с указанием: ' +
        missing.map(a => a.title).join('; ') + '.',
    }],
    insufficientReason: null,
  };
}
