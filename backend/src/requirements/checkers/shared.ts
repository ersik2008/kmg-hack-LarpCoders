import { RequirementDefinition, RequirementResult } from '../requirement-definitions.js';
import { Hit, WorkspaceIndex } from '../workspace-index.js';

/**
 * Общие примитивы для проверок, завязанных на HTTP-маршруты: ИБ-01, ИБ-02, ИБ-08.
 *
 * Все три требования отвечают на вариации одного вопроса — «защищён ли
 * конкретный обработчик серверной проверкой», — поэтому обнаружение маршрутов и
 * guard-ов вынесено сюда, а не продублировано трижды.
 */

/** Объявление серверного HTTP-обработчика. */
export const ROUTE_DECLARATION =
  // Приёмник — любой идентификатор (`adminRouter`, `ordersRouter`, `app`), а не
  // только `app|router|api`: в реальных проектах маршрутизаторы называют по
  // предметной области. Чтобы это не ловило исходящие HTTP-вызовы, исключены
  // известные клиенты, а путь обязан начинаться с «/».
  /(?<![\w$.])(?!(?:axios|http|https|request|got|superagent|ky|client|supertest|cy|fetch|params|headers|map|cache|storage|session|env|config)\.)[A-Za-z_$][\w$]*\.(?:get|post|put|patch|delete|all)\s*\(\s*['"`](\/[^'"`]*)['"`]|@(?:Get|Post|Put|Patch|Delete|All)\s*\(\s*(?:['"`]([^'"`]*)['"`])?\s*\)|@app\.route\s*\(\s*['"`]([^'"`]*)['"`]|@(?:router|app)\.(?:get|post|put|patch|delete)\s*\(\s*['"`]([^'"`]*)['"`]/;

/** Серверная проверка аутентификации: middleware, guard, декоратор, стратегия. */
export const AUTH_GUARD =
  /\b(?:AuthGuard|JwtAuthGuard|@UseGuards|passport\.authenticate|requireAuth|isAuthenticated|ensureAuthenticated|login_required|@jwt_required|IsAuthenticated|authenticate_user|verifyToken|authMiddleware|requireLogin|HTTPBearer|APIKeyHeader|OAuth2PasswordBearer|Depends\s*\(\s*\w*(?:auth|token|verify|current_user|security|api_key)\w*)\b/i;

/** Серверная проверка роли или права доступа. */
export const ROLE_GUARD =
  /\b(?:RolesGuard|@Roles?\s*\(|hasRole|checkRole|requireRole|requireAdmin|isAdmin\b|admin_required|@admin_required|IsAdminUser|checkPermission|requirePermission|can\s*\(\s*['"`]|ability\.|authorize\s*\(|AdminGuard|PermissionGuard)\b/;

/** Явная проверка роли администратора. */
export const ADMIN_ROLE_CHECK =
  /\b(?:role\s*(?:===|==|!=|!==)\s*['"`]admin|['"`]admin['"`]\s*(?:===|==)\s*\w*role|isAdmin\b|is_admin\b|requireAdmin|AdminGuard|@Roles?\s*\(\s*['"`]?admin|ROLE_ADMIN|UserRole\.ADMIN|Role\.ADMIN|admin_required)/i;

/** Признаки того, что путь относится к административному функционалу. */
export const ADMIN_PATH = /(^|[\/._-])admin([\/._-]|$)|\badministrator\b|\bbackoffice\b|\bmanage(ment)?\b/i;

/** Запись в журнал аудита. */
export const AUDIT_WRITE =
  /\b(?:auditLog|audit_log|auditService|AuditService|writeAudit|recordAudit|logAudit|audit\.(?:log|record|write)|createAuditEntry|AuditEvent|audit_event)\b/;

/**
 * Глобальная регистрация middleware или интерцептора.
 * Нужна для сквозных требований: guard может быть применён один раз ко всему
 * приложению, и отсутствие его в конкретном файле нарушением не является.
 */
export const GLOBAL_REGISTRATION =
  /\b(?:APP_GUARD|APP_INTERCEPTOR|app\.useGlobalGuards|app\.useGlobalInterceptors|app\.use\s*\(|useGlobalFilters|add_middleware|MIDDLEWARE\s*=|middleware\.Use|router\.Use|before_request|@app\.before_request)\b/;

export function buildResult(
  definition: RequirementDefinition,
  partial: Omit<RequirementResult, 'requirementId' | 'title' | 'requirementText'>,
): RequirementResult {
  return {
    requirementId: definition.id,
    title: definition.title,
    requirementText: definition.text,
    ...partial,
  };
}

/**
 * Находит файлы, в которых зарегистрирован глобальный механизм.
 *
 * Используется, чтобы не объявлять нарушением отсутствие проверки в отдельном
 * обработчике, когда действует общий слой. Это прямая защита от ложного
 * срабатывания, описанного в SECURITY_REQUIREMENTS.md.
 */
export async function findGlobalMechanism(
  index: WorkspaceIndex,
  mechanism: RegExp,
): Promise<Hit[]> {
  const bootstrapFiles = /(^|\/)(main|app|server|index|bootstrap|application|settings|urls|middleware|module)\.(ts|js|mjs|py|go|java|rb)$/i;

  const inBootstrap = await index.grep(mechanism, {
    kinds: ['source'],
    pathPattern: bootstrapFiles,
    excludeTests: true,
    limit: 10,
  });
  if (inBootstrap.length > 0) return inBootstrap;

  // Модульная регистрация (NestJS providers, Django settings) может лежать вне
  // файлов с каноническими именами.
  return index.grep(mechanism, {
    kinds: ['source', 'config'],
    excludeTests: true,
    serverOnly: true,
    limit: 10,
  });
}

/** Доля, округлённая до целых процентов. */
export function percent(part: number, total: number): number {
  if (total <= 0) return 0;
  return Math.round((part / total) * 100);
}

/** Уникальные файлы из списка попаданий. */
export function filesOf(hits: Hit[]): Set<string> {
  return new Set(hits.map(h => h.filePath));
}

export function toEvidence(hit: Hit, note: string, kind: 'SUPPORTS' | 'VIOLATES' | 'CONTEXT') {
  return { filePath: hit.filePath, line: hit.line, snippet: hit.text, note, kind };
}
