import {
  REQUIREMENT_DEFINITIONS,
  RequirementEvidence,
  RequirementResult,
  RequirementViolation,
} from '../requirement-definitions.js';
import { Hit, WorkspaceIndex } from '../workspace-index.js';
import {
  AUDIT_WRITE,
  ROUTE_DECLARATION,
  buildResult,
  filesOf,
  findGlobalMechanism,
  percent,
  toEvidence,
} from './shared.js';

/**
 * ИБ-07 — журналирование действий пользователей и событий СУБД (ТЗ п. 4.5.7).
 *
 * Сквозное требование: журналирование должно охватывать проект в целом, а не
 * отдельную функцию или модуль. Реализация в части функций доступа к данным при
 * отсутствии в остальных — нарушение.
 *
 * Поэтому проверка отвечает не на вопрос «есть ли логгер» (прежний контроль
 * AUDIT_LOGGING останавливался на 8 совпадениях и другого ответа дать не
 * мог), а на два других:
 *   1) существует ли ЕДИНЫЙ механизм, применённый глобально;
 *   2) если единого механизма нет — какая доля обработчиков данных
 *      журналируется по отдельности.
 * Плюс отдельно — журнал событий СУБД.
 */

const DEFINITION = REQUIREMENT_DEFINITIONS['ИБ-07'];

/** Единый механизм журналирования действий пользователей. */
const UNIFIED_MECHANISMS: Array<{ label: string; pattern: RegExp }> = [
  { label: 'Глобальный интерцептор журналирования (NestJS)', pattern: /useGlobalInterceptors\s*\(|provide\s*:\s*APP_INTERCEPTOR/ },
  { label: 'Глобальный middleware журналирования', pattern: /app\.use\s*\(\s*(?:morgan|audit\w*|requestLogger|accessLog\w*|logRequests?|auditMiddleware)\b|app\.use\s*\(\s*(?:\w+\.)?(?:audit|activity)\w*\(|add_middleware\s*\(\s*\w*(?:Audit|Logging|Activity)\w*/i },
  { label: 'Сервис аудита', pattern: /\b(?:class|export\s+class)\s+\w*Audit\w*(?:Service|Logger|Interceptor|Middleware)\b|def\s+\w*audit\w*\s*\(/i },
  { label: 'Аудит на уровне ORM', pattern: /\bprisma\.\$use\s*\(|\$extends\s*\(\s*\{[^}]*query|@EventSubscriber\s*\(|@EntityListener|sequelize\.addHook|Model\.addHook|event\.listen\s*\(|post_save\.connect|pre_save\.connect|@receiver\s*\(\s*(?:post|pre)_(?:save|delete)/ },
  { label: 'Декоратор аудита', pattern: /@Audit(?:ed|Log)?\s*\(|@Auditable\b|@LogAction\b|@audit_log\b/ },
];

/** Журналирование событий СУБД. */
const DB_EVENT_LOGGING: Array<{ label: string; pattern: RegExp }> = [
  { label: 'Prisma: журнал запросов', pattern: /\blog\s*:\s*\[[^\]]*['"`](?:query|info|warn|error)['"`]|\$on\s*\(\s*['"`]query['"`]/ },
  { label: 'TypeORM/Sequelize: журнал SQL', pattern: /\blogging\s*:\s*(?:true|\[|['"`](?:all|query))|\blogger\s*:\s*['"`]advanced-console/ },
  { label: 'SQLAlchemy: журнал SQL', pattern: /echo\s*=\s*True|logging\.getLogger\s*\(\s*['"`]sqlalchemy/ },
  { label: 'Django: журнал SQL', pattern: /['"`]django\.db\.backends['"`]/ },
  { label: 'СУБД: log_statement / pgaudit', pattern: /\blog_statement\b|\bpgaudit\b|log_connections|log_disconnections|general_log|audit_log_plugin|server_audit/i },
  { label: 'Триггер аудита в БД', pattern: /CREATE\s+(?:OR\s+REPLACE\s+)?TRIGGER\s+\w*(?:audit|log|history)\w*|CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?["`]?\w*(?:audit|_log|_history)\w*["`]?/i },
  { label: 'Hibernate Envers / JPA аудит', pattern: /@Audited\b|@EntityListeners\s*\(\s*AuditingEntityListener/ },
];

/** Обработчик, работающий с данными: тот же детектор маршрутов, что в ИБ-01/02/08. */
const DATA_HANDLER = ROUTE_DECLARATION;

/** Вызов журналирования пользовательского действия рядом с обработчиком. */
const ACTION_LOG =
  /\b(?:audit\w*|activity\w*|logAction|log_action|auditLog|recordEvent)\s*[.(]|\blogger\.(?:info|log|warn)\s*\([^)]*(?:user|actor|userId|user_id|created|updated|deleted|read|access|export|login)/i;

/** Запись в журнал внутри тела механизма. */
const LOG_CALL = /\b(?:logger|log|audit\w*|console)\s*\.\s*\w+\s*\(|\bauditLog\b|\.record\s*\(|\.emit\s*\(\s*['"`]audit/i;

/** Механизм фиксирует СУБЪЕКТА действия: без него это журнал запросов, а не журнал действий пользователей. */
// `user-agent` — заголовок клиента, а не субъект действия: без исключения access-лог
// с userAgent принимался за журнал действий пользователей.
const SUBJECT_REF = /\buser(?![-_]?agent)\b|\b(?:actor|userId|user_id|principal|username|identity|sub)\b|req\.user|request\.user|currentUser/i;

/**
 * Механизмы, для которых наличие в проекте ничего не доказывает: важно, что
 * именно они пишут. `useGlobalInterceptors(new LoggingInterceptor())` может
 * фиксировать метод и время ответа, не зная, кто обратился.
 */
const NEEDS_CONTENT_CHECK = /Глобальный/;

/**
 * Проверяет, что глобальный механизм пишет журнал и фиксирует субъекта.
 * Возвращает null, если реализацию найти не удалось (внешняя библиотека).
 */
async function mechanismRecordsSubject(
  index: WorkspaceIndex,
  hit: Hit,
): Promise<{ logs: boolean; subject: boolean } | null> {
  const lines = await index.readCode(hit.filePath);
  const around = (lines ?? []).slice(Math.max(0, hit.line - 2), hit.line + 3).join(' ');
  const name =
    /new\s+([A-Z]\w+)\s*\(/.exec(around)?.[1] ??
    /useClass\s*:\s*(\w+)/.exec(around)?.[1] ??
    /\.use\s*\(\s*(\w+)\s*[,)]/.exec(around)?.[1];
  if (!name) return null;

  const definition = new RegExp('\\b(?:class|function|const|let|var|def)\\s+' + name + '\\b');
  for (const file of index.byKind('source')) {
    const src = await index.readCode(file.relPath);
    if (!src) continue;
    const text = src.join(String.fromCharCode(10));
    if (!definition.test(text)) continue;
    return { logs: LOG_CALL.test(text), subject: SUBJECT_REF.test(text) };
  }
  return null;
}

/** Порог доли покрытия для вывода «журналирование охватывает проект». */
const COVERAGE_PASS = 80;
const COVERAGE_VIOLATION = 50;

export async function checkIb07(index: WorkspaceIndex): Promise<RequirementResult> {
  const evidence: RequirementEvidence[] = [];
  const violations: RequirementViolation[] = [];

  const source = { kinds: ['source' as const, 'config' as const], excludeTests: true };

  // ---- 1. Единый механизм ------------------------------------------------
  const unified: Array<Hit & { label: string }> = [];
  for (const mechanism of UNIFIED_MECHANISMS) {
    const hits = await index.grep(mechanism.pattern, { ...source, limit: 4, perFile: 2 });
    for (const hit of hits) unified.push({ ...hit, label: mechanism.label });
  }

  // Глобальная регистрация ещё не журнал действий: проверяем содержимое
  // механизма. Access-лог без субъекта («GET /x 200 12ms») требованию ИБ-07 не
  // соответствует — в журнале не видно, КТО обратился к данным.
  const accessLogOnly: Array<Hit & { label: string }> = [];
  const confirmedUnified: Array<Hit & { label: string }> = [];
  for (const hit of unified) {
    if (!NEEDS_CONTENT_CHECK.test(hit.label)) {
      confirmedUnified.push(hit);
      continue;
    }
    const content = await mechanismRecordsSubject(index, hit);
    if (content === null || (content.logs && content.subject)) confirmedUnified.push(hit);
    else accessLogOnly.push(hit);
  }

  const globalRegistration = confirmedUnified.filter(u =>
    /Глобальный|ORM|Сервис аудита|Декоратор/.test(u.label),
  );
  const hasUnified = globalRegistration.length > 0;

  for (const hit of confirmedUnified.slice(0, 5)) {
    evidence.push(toEvidence(hit, hit.label, 'SUPPORTS'));
  }
  for (const hit of accessLogOnly.slice(0, 2)) {
    evidence.push(toEvidence(
      hit,
      `${hit.label}: механизм не фиксирует субъекта действия — это журнал запросов, а не журнал действий пользователей`,
      'CONTEXT',
    ));
  }

  // ---- 2. Журнал событий СУБД --------------------------------------------
  const dbLogging: Array<Hit & { label: string }> = [];
  for (const rule of DB_EVENT_LOGGING) {
    const hits = await index.grep(rule.pattern, {
      kinds: ['source', 'config', 'migration'],
      excludeTests: true,
      limit: 3,
      perFile: 1,
    });
    for (const hit of hits) dbLogging.push({ ...hit, label: rule.label });
  }
  const hasDbLogging = dbLogging.length > 0;
  for (const hit of dbLogging.slice(0, 3)) {
    evidence.push(toEvidence(hit, hit.label, 'SUPPORTS'));
  }

  // ---- 3. Обработчики данных и их покрытие -------------------------------
  const handlerHits = await index.grep(DATA_HANDLER, {
    kinds: ['source'],
    excludeTests: true,
    serverOnly: false,
    limit: 400,
    perFile: 50,
  });
  // Файл считается файлом обработчиков, если в нём сработал шаблон объявления
  // маршрута. Клиентский код исключается: fetch/axios в браузере — не обработчик.
  const handlerFiles = [...filesOf(handlerHits)].filter(f => {
    const file = index.files.find(x => x.relPath === f);
    return Boolean(file) && !file!.clientSide;
  });

  let coveredFiles = 0;
  const uncovered: string[] = [];

  for (const filePath of handlerFiles) {
    const lines = await index.readCode(filePath);
    if (!lines) continue;
    const text = lines.join('\n');

    if (ACTION_LOG.test(text) || AUDIT_WRITE.test(text) || /@Audit/.test(text)) {
      coveredFiles++;
    } else {
      uncovered.push(filePath);
    }
  }

  const totalHandlerFiles = handlerFiles.length;
  const coverage = hasUnified ? 100 : percent(coveredFiles, totalHandlerFiles);

  // ---- 4. Нет обработчиков и нет журналирования ---------------------------
  const anyLogging = unified.length > 0 || accessLogOnly.length > 0 || dbLogging.length > 0 || coveredFiles > 0;

  if (totalHandlerFiles === 0 && !anyLogging) {
    // Проект не обрабатывает пользовательские запросы и не пишет журнал:
    // требование к нему в этой форме неприменимо, но это надо подтвердить.
    return buildResult(DEFINITION, {
      status: 'INSUFFICIENT_EVIDENCE',
      confidence: 'LOW',
      summary:
        'Не обнаружено ни обработчиков данных, ни механизмов журналирования. Невозможно ' +
        'установить, работает ли проект с пользовательскими данными.',
      evidence: [],
      violations: [],
      insufficientReason:
        'В проекте не найдены серверные обработчики и признаки журналирования; журналирование ' +
        'может быть вынесено в инфраструктурный слой, конфигурация которого вне репозитория.',
    });
  }

  // ---- 5. Формирование нарушений ------------------------------------------
  if (!hasUnified && totalHandlerFiles > 0) {
    if (coverage < COVERAGE_PASS) {
      const sample = uncovered.slice(0, 5);
      const anchor = sample[0] ?? handlerFiles[0];
      violations.push({
        filePath: anchor,
        lineStart: null,
        lineEnd: null,
        symbol: 'покрытие журналированием',
        evidence:
          `Единый механизм журналирования не обнаружен. Журналирование действий присутствует ` +
          `в ${coveredFiles} из ${totalHandlerFiles} файлов с обработчиками данных (${coverage}%). ` +
          `Без журналирования: ${sample.join(', ')}${uncovered.length > sample.length ? ` и ещё ${uncovered.length - sample.length}` : ''}.`,
        explanation:
          'Требование ИБ-07 обязывает реализовать единый журнал действий пользователей, ' +
          'охватывающий проект в целом. Единого механизма (глобального интерцептора, ' +
          'middleware, аудита на уровне ORM) не найдено, а журналирование выполняется в части ' +
          'обработчиков. Пункт 4.5.7 ТЗ прямо относит к нарушениям реализацию журналирования ' +
          'в части функций доступа к данным при отсутствии его в остальных.',
        severity: coverage < COVERAGE_VIOLATION ? 'HIGH' : 'MEDIUM',
        confidence: 'MEDIUM',
        recommendation:
          'Зарегистрировать глобальный механизм (интерцептор, middleware либо middleware ORM), ' +
          'фиксирующий субъекта, действие, объект и результат для всех обработчиков данных, ' +
          'вместо точечных вызовов логгера.',
      });
    }
  }

  if (!hasDbLogging) {
    violations.push({
      filePath: null,
      lineStart: null,
      lineEnd: null,
      symbol: 'журнал событий СУБД',
      evidence: '(признаков журналирования событий СУБД в проекте не найдено)',
      explanation:
        'Требование ИБ-07 обязывает вести, помимо журнала действий пользователей, журнал ' +
        'событий системы управления базами данных. В проекте не обнаружено ни журналирования ' +
        'запросов на уровне ORM/драйвера, ни настроек журналирования СУБД (log_statement, ' +
        'pgaudit), ни триггеров аудита в миграциях. Конфигурация СУБД, лежащая вне ' +
        'репозитория, статически не видна.',
      severity: 'MEDIUM',
      confidence: 'MEDIUM',
      recommendation:
        'Включить журналирование запросов на уровне ORM (например, log: ["query"] в Prisma) ' +
        'и/или настроить журнал на стороне СУБД (log_statement, pgaudit); для критичных ' +
        'таблиц — триггеры аудита.',
    });
  }

  // ---- 6. Итог ----------------------------------------------------------
  const coverageNote =
    totalHandlerFiles > 0
      ? `Обработчики данных: ${totalHandlerFiles} файлов, журналируются: ${hasUnified ? 'все (единый механизм)' : `${coveredFiles} (${coverage}%)`}.`
      : 'Отдельные обработчики данных не выделены.';

  if (violations.length === 0) {
    return buildResult(DEFINITION, {
      status: 'PASS',
      confidence: hasUnified ? 'MEDIUM' : 'LOW',
      summary:
        `Единый механизм журналирования ${hasUnified ? 'обнаружен' : 'не обнаружен, но покрытие обработчиков высокое'}; ` +
        `журнал событий СУБД обнаружен. ${coverageNote}`,
      evidence: evidence.slice(0, 10),
      violations: [],
      insufficientReason: null,
    });
  }

  return buildResult(DEFINITION, {
    status: 'VIOLATION',
    confidence: 'MEDIUM',
    summary:
      `Журналирование не охватывает проект в целом: ${violations.length} нарушений. ${coverageNote} ` +
      (hasDbLogging ? '' : 'Журнал событий СУБД не обнаружен.'),
    evidence: evidence.slice(0, 10),
    violations,
    insufficientReason: null,
  });
}
