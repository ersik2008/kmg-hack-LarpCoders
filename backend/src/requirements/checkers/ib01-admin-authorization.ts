import {
  REQUIREMENT_DEFINITIONS,
  RequirementEvidence,
  RequirementResult,
  RequirementViolation,
} from '../requirement-definitions.js';
import { Hit, WorkspaceIndex } from '../workspace-index.js';
import {
  ADMIN_PATH,
  ADMIN_ROLE_CHECK,
  GLOBAL_REGISTRATION,
  ROLE_GUARD,
  ROUTE_DECLARATION,
  buildResult,
  findGlobalMechanism,
  toEvidence,
} from './shared.js';

/**
 * ИБ-01 — разграничение доступа к административному функционалу (ТЗ п. 4.5.1).
 *
 * Строится перечень серверных административных маршрутов, и для КАЖДОГО
 * проверяется, покрыт ли он серверной проверкой роли: guard на классе или
 * модуле, декоратор на методе, явная проверка в теле, глобальный guard.
 *
 * Отдельно фиксируется «UI hiding != authorization»: если проверка роли
 * присутствует только в клиентском коде, а на сервере её нет, это нарушение,
 * а не выполнение требования.
 */

const DEFINITION = REQUIREMENT_DEFINITIONS['ИБ-01'];

/** Операция, изменяющая чужие данные по идентификатору из запроса (IDOR). */
const IDOR_OPERATION =
  /\b(?:delete|remove|update|destroy|findByIdAndUpdate|findByIdAndDelete)\w*\s*\([^)]*(?:req\.(?:params|body|query)\.(?:id|userId|user_id)|params\.(?:id|userId)|@Param\s*\(\s*['"`](?:id|userId))/i;

/** Проверка владельца ресурса. */
const OWNERSHIP_CHECK =
  /\b(?:ownerId|userId|user_id|createdBy|authorId)\s*(?:===|!==|==|!=)\s*(?:req\.user|currentUser|user\.id|session\.user|request\.user)|(?:req\.user|currentUser|request\.user)[.\w]*\s*(?:===|!==)\s*\w*\.(?:ownerId|userId|user_id)/i;

/** Проверка роли на стороне клиента. */
const CLIENT_ROLE_CHECK =
  /\b(?:isAdmin|role\s*===?\s*['"`]admin|user\.role|hasRole|canAccess|permissions?\.includes)\b/i;

interface Route {
  filePath: string;
  line: number;
  text: string;
  path: string;
  isAdmin: boolean;
}

export async function checkIb01(index: WorkspaceIndex): Promise<RequirementResult> {
  const evidence: RequirementEvidence[] = [];
  const violations: RequirementViolation[] = [];

  // ---- 1. Перечень серверных маршрутов ---------------------------------------
  const routeHits = await index.grep(ROUTE_DECLARATION, {
    kinds: ['source'],
    excludeTests: true,
    limit: 600,
    perFile: 80,
  });

  const routes: Route[] = [];
  for (const hit of routeHits) {
    const file = index.files.find(f => f.relPath === hit.filePath);
    if (!file || file.clientSide) continue;

    const match = ROUTE_DECLARATION.exec(hit.text);
    const routePath = match?.slice(1).find(Boolean) ?? '';
    routes.push({
      filePath: hit.filePath,
      line: hit.line,
      text: hit.text,
      path: routePath,
      isAdmin: ADMIN_PATH.test(routePath) || ADMIN_PATH.test(hit.filePath),
    });
  }

  // ---- 2. Глобальный guard ролей --------------------------------------------
  const globalGuard = await findGlobalMechanism(
    index,
    /\b(?:APP_GUARD[^;]{0,200}(?:Roles|Permission|Admin)Guard|useGlobalGuards\s*\([^)]*(?:Roles|Permission|Admin)Guard)/,
  );
  const hasGlobalRoleGuard = globalGuard.length > 0;
  if (hasGlobalRoleGuard) {
    evidence.push(toEvidence(globalGuard[0], 'Глобальный guard ролей', 'SUPPORTS'));
  }

  const adminRoutes = routes.filter(r => r.isAdmin);

  // ---- 3. Клиентская проверка без серверной ---------------------------------
  const clientRoleChecks = await index.grep(CLIENT_ROLE_CHECK, {
    kinds: ['source'],
    excludeTests: true,
    pathPattern: /(frontend|client|web|ui|pages|components|views|hooks)\//i,
    limit: 5,
  });
  const serverRoleChecks = await index.grep(ROLE_GUARD, {
    kinds: ['source'],
    excludeTests: true,
    serverOnly: true,
    limit: 10,
  });

  // ---- 4. Нет ни серверных маршрутов, ни клиентского кода -----------------
  if (routes.length === 0) {
    return buildResult(DEFINITION, {
      status: 'INSUFFICIENT_EVIDENCE',
      confidence: 'LOW',
      summary:
        'HTTP-поверхность обнаружена по манифесту, но объявления маршрутов распознать не удалось ' +
        '(нестандартная маршрутизация, динамическая регистрация либо неподдерживаемый фреймворк).',
      evidence: [],
      violations: [],
      insufficientReason:
        'Перечень серверных маршрутов построить не удалось; проверка «маршрут ↔ guard» невозможна.',
    });
  }

  // ---- 5. Проверка каждого административного маршрута ---------------------
  let unprotected = 0;

  for (const route of adminRoutes) {
    const lines = await index.readCode(route.filePath);
    if (!lines) continue;

    // Окрестность: декоратор стоит выше объявления, явная проверка — ниже.
    const above = lines.slice(Math.max(0, route.line - 1 - 6), route.line - 1).join('\n');
    const below = lines.slice(route.line - 1, Math.min(lines.length, route.line + 24)).join('\n');
    // Guard на классе контроллера или на router.use выше по файлу.
    const classLevel = lines.slice(0, route.line).join('\n');

    const protectedByMethod = ROLE_GUARD.test(above) || ADMIN_ROLE_CHECK.test(below);
    const protectedByClass =
      /@UseGuards\s*\([^)]*(?:Roles|Admin|Permission)Guard|@Roles?\s*\(|router\.use\s*\([^)]*(?:admin|role|permission)/i.test(classLevel);

    if (protectedByMethod || protectedByClass || hasGlobalRoleGuard) {
      evidence.push({
        filePath: route.filePath,
        line: route.line,
        snippet: route.text,
        note: `Административный маршрут ${route.path || '(без пути)'} покрыт серверной проверкой роли (${
          protectedByMethod ? 'метод' : protectedByClass ? 'класс/роутер' : 'глобальный guard'
        })`,
        kind: 'SUPPORTS',
      });
      continue;
    }

    unprotected++;
    violations.push({
      filePath: route.filePath,
      lineStart: route.line,
      lineEnd: route.line,
      symbol: route.path || 'административный маршрут',
      evidence: route.text,
      explanation:
        `Административный маршрут ${route.path ? `«${route.path}»` : ''} не покрыт серверной ` +
        'проверкой роли «администратор»: ни guard/декоратор на методе или классе, ни явная ' +
        'проверка роли в теле обработчика, ни глобальный guard ролей не обнаружены. ' +
        'Пункт 4.5.1 ТЗ требует проверять роль на стороне сервера при каждом обращении.' +
        (clientRoleChecks.length > 0 && serverRoleChecks.length === 0
          ? ' Проверка роли обнаружена только в клиентском коде — сокрытие элементов интерфейса ' +
            'выполнением требования не является.'
          : ''),
      severity: DEFINITION.severity,
      confidence: route.path && ADMIN_PATH.test(route.path) ? 'HIGH' : 'MEDIUM',
      recommendation:
        'Применить серверный guard роли «администратор» к маршруту либо ко всей группе ' +
        'административных маршрутов (@UseGuards(RolesGuard) + @Roles("admin"), middleware ' +
        'requireAdmin). Покрыть тестами случаи «без токена», «обычный пользователь», «администратор».',
    });
  }

  // ---- 6. Чувствительные операции по id без сопоставления владельца -------
  const idorHits = await index.grep(IDOR_OPERATION, {
    kinds: ['source'],
    excludeTests: true,
    serverOnly: false,
    limit: 8,
  });
  for (const hit of idorHits) {
    const file = index.files.find(f => f.relPath === hit.filePath);
    if (file?.clientSide) continue;

    const lines = await index.readCode(hit.filePath);
    if (!lines) continue;
    const region = lines.slice(Math.max(0, hit.line - 10), Math.min(lines.length, hit.line + 8)).join('\n');

    if (OWNERSHIP_CHECK.test(region) || ROLE_GUARD.test(region) || ADMIN_ROLE_CHECK.test(region)) continue;
    if (hasGlobalRoleGuard) continue;

    violations.push({
      filePath: hit.filePath,
      lineStart: hit.line,
      lineEnd: hit.line,
      symbol: 'операция по идентификатору из запроса',
      evidence: hit.text,
      explanation:
        'Изменяющая операция выполняется по идентификатору из параметров запроса без ' +
        'сопоставления владельца ресурса и без проверки роли. Любой аутентифицированный ' +
        'пользователь может воздействовать на чужие данные (IDOR).',
      severity: 'HIGH',
      confidence: 'MEDIUM',
      recommendation:
        'Сопоставить владельца ресурса с текущим пользователем либо потребовать роль ' +
        '«администратор» на уровне сервера.',
    });
  }

  // ---- 7. Административных маршрутов нет ---------------------------------
  if (adminRoutes.length === 0) {
    if (violations.length > 0) {
      return buildResult(DEFINITION, {
        status: 'VIOLATION',
        confidence: 'MEDIUM',
        summary:
          `Административных маршрутов не выделено (всего маршрутов: ${routes.length}), но обнаружены ` +
          `изменяющие операции без проверки прав: ${violations.length}.`,
        evidence: evidence.slice(0, 10),
        violations,
        insufficientReason: null,
      });
    }

    return buildResult(DEFINITION, {
      status: serverRoleChecks.length > 0 ? 'PASS' : 'INSUFFICIENT_EVIDENCE',
      confidence: 'LOW',
      summary: serverRoleChecks.length > 0
        ? `Маршрутов: ${routes.length}. Административные по пути не выделены; серверная проверка ролей ` +
          'в проекте присутствует.'
        : `Маршрутов: ${routes.length}. Административные не выделены по пути или имени файла, ` +
          'серверных проверок ролей не обнаружено. Установить, есть ли в проекте административный ' +
          'функционал, статически не удалось.',
      evidence: serverRoleChecks.slice(0, 3).map(h => toEvidence(h, 'Серверная проверка роли', 'SUPPORTS')),
      violations: [],
      insufficientReason: serverRoleChecks.length > 0
        ? null
        : 'Не найдено ни административных маршрутов, ни серверных проверок ролей; если административный ' +
          'интерфейс существует, он мог быть распознан неверно.',
    });
  }

  // ---- 8. Итог по административным маршрутам ---------------------------
  if (violations.length === 0) {
    return buildResult(DEFINITION, {
      status: 'PASS',
      confidence: hasGlobalRoleGuard ? 'MEDIUM' : 'HIGH',
      summary:
        `Административных маршрутов: ${adminRoutes.length}, все покрыты серверной проверкой роли. ` +
        `Всего маршрутов в проекте: ${routes.length}.`,
      evidence: evidence.slice(0, 10),
      violations: [],
      insufficientReason: null,
    });
  }

  return buildResult(DEFINITION, {
    status: 'VIOLATION',
    confidence: 'HIGH',
    summary:
      `Административных маршрутов: ${adminRoutes.length}, без серверной проверки роли: ${unprotected}. ` +
      `Всего нарушений: ${violations.length}.`,
    evidence: [
      ...evidence,
      ...violations.slice(0, 3).map(v => ({
        filePath: v.filePath ?? '',
        line: v.lineStart ?? 0,
        snippet: v.evidence,
        note: 'Маршрут без серверной проверки роли',
        kind: 'VIOLATES' as const,
      })),
    ].slice(0, 12),
    violations,
    insufficientReason: null,
  });
}
