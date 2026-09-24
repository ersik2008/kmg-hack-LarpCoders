import {
  REQUIREMENT_DEFINITIONS,
  RequirementEvidence,
  RequirementResult,
  RequirementViolation,
} from '../requirement-definitions.js';
import { WorkspaceIndex } from '../workspace-index.js';
import {
  AUTH_GUARD,
  ROUTE_DECLARATION,
  buildResult,
  findGlobalMechanism,
  toEvidence,
} from './shared.js';

/**
 * ИБ-02 — проверка сессии и токена на стороне сервера (ТЗ п. 4.5.2).
 *
 * Валидность сессии или токена должна проверяться на сервере при КАЖДОМ
 * обращении к защищённым конечным точкам, включая API. Поэтому недостаточно
 * найти в проекте `AuthGuard`: нужно установить, что он покрывает маршруты.
 *
 * Проверяются: глобальная регистрация guard-а, покрытие маршрутов, способ
 * проверки токена (подпись, а не просто декодирование), срок жизни, флаги cookie.
 */

const DEFINITION = REQUIREMENT_DEFINITIONS['ИБ-02'];

/** Публичные по замыслу маршруты — требовать от них токен некорректно. */
const PUBLIC_ROUTE =
  /(?:^|\/)(?:health|healthz|ready|readiness|liveness|ping|metrics|status|login|logout|signin|signup|register|auth|oauth|callback|webhook|public|docs|swagger|openapi|favicon|robots\.txt|static|assets|\.well-known)(?:\/|$|\?)/i;

const PUBLIC_MARKER = /@Public\s*\(|@SkipAuth|@AllowAnonymous|IS_PUBLIC_KEY|publicRoute|skipAuth|@permission_classes\s*\(\s*\[\s*AllowAny/i;

/** Токен декодируется без проверки подписи. */
const JWT_DECODE_ONLY = /\bjwt\.decode\s*\(|jwt_decode\s*\(|jwtDecode\s*\(|verify_signature['"`]?\s*:\s*False|ignoreExpiration\s*:\s*true|verify\s*=\s*False/;
const JWT_VERIFY = /\bjwt\.verify\s*\(|jwtService\.verify(?:Async)?\s*\(|verifyToken\s*\(|jwt\.decode\s*\([^)]*algorithms|passport\.authenticate|PassportStrategy|jwt\.parse\s*\(|ParseWithClaims/;

/** Алгоритм none и жёстко заданный секрет. */
const JWT_NONE = /algorithms?\s*:\s*\[[^\]]*['"`]none['"`]|alg\s*[:=]\s*['"`]none['"`]/i;
const JWT_HARDCODED_SECRET = /(?:jwt\.sign|sign)\s*\([^)]*,\s*['"`][A-Za-z0-9!@#$%^&*()_+\-=]{4,}['"`]\s*[,)]|secret(?:OrKey)?\s*:\s*['"`][A-Za-z0-9!@#$%^&*()_+\-=]{4,}['"`]|JWT_SECRET\s*=\s*['"`][^'"`]{4,}['"`]/;

/** Срок жизни токена. */
const TOKEN_EXPIRY = /\bexpiresIn\b|\bexp\s*:|maxAge\s*:|ACCESS_TOKEN_LIFETIME|JWT_EXPIRATION|TOKEN_EXPIRE|SESSION_COOKIE_AGE|ttl\s*:/i;

/** Cookie сессии. */
const COOKIE_SET = /\b(?:res\.cookie|cookie-session|express-session|session\s*\(\s*\{|set_cookie|SESSION_COOKIE|Set-Cookie)\b/;
const COOKIE_FLAGS_OK = /httpOnly\s*:\s*true|HttpOnly|SESSION_COOKIE_HTTPONLY\s*=\s*True/;
const COOKIE_SECURE = /secure\s*:\s*(?:true|process\.env|isProd|!isDev)|SESSION_COOKIE_SECURE\s*=\s*True|Secure\b/;

export async function checkIb02(index: WorkspaceIndex): Promise<RequirementResult> {
  const evidence: RequirementEvidence[] = [];
  const violations: RequirementViolation[] = [];

  const src = { kinds: ['source' as const], excludeTests: true, serverOnly: false };

  // ---- 1. Глобальный guard аутентификации -----------------------------------
  const globalAuth = await findGlobalMechanism(
    index,
    /\b(?:APP_GUARD[^;]{0,200}(?:Jwt|Auth)Guard|useGlobalGuards\s*\([^)]*(?:Jwt|Auth)Guard|app\.use\s*\(\s*(?:auth|authenticate|verifyToken|jwtMiddleware|passport\.authenticate|requireAuth)\w*|add_middleware\s*\(\s*\w*Auth|MIDDLEWARE\s*=[^\]]*Authentication|DEFAULT_AUTHENTICATION_CLASSES|before_request[^)]*auth)/i,
  );
  const hasGlobalAuth = globalAuth.length > 0;
  if (hasGlobalAuth) evidence.push(toEvidence(globalAuth[0], 'Глобально зарегистрированная проверка аутентификации', 'SUPPORTS'));

  // ---- 2. Серверные механизмы аутентификации ---------------------------------
  const authMechanisms = await index.grep(AUTH_GUARD, { ...src, serverOnly: true, limit: 12 });
  for (const hit of authMechanisms.slice(0, 3)) {
    evidence.push(toEvidence(hit, 'Серверный механизм аутентификации', 'SUPPORTS'));
  }

  // ---- 3. Маршруты и их покрытие ----------------------------------------------
  const routeHits = await index.grep(ROUTE_DECLARATION, { ...src, limit: 600, perFile: 80 });
  const serverRoutes = routeHits.filter(h => {
    const f = index.files.find(x => x.relPath === h.filePath);
    return f && !f.clientSide;
  });

  // Покрытие по файлам: guard объявлен на классе/роутере или в теле метода.
  const byFile = new Map<string, number>();
  for (const r of serverRoutes) byFile.set(r.filePath, (byFile.get(r.filePath) ?? 0) + 1);

  const unprotectedRoutes: Array<{ filePath: string; line: number; text: string; path: string }> = [];
  let protectedCount = 0;
  let publicCount = 0;

  for (const [filePath] of byFile) {
    const lines = await index.readCode(filePath);
    if (!lines) continue;
    const fileText = lines.join('\n');
    // Guard, объявленный на классе контроллера или на роутере, стоит выше
    // конкретного метода и покрывает все маршруты файла.
    const fileHasGuard = AUTH_GUARD.test(fileText);

    for (const r of serverRoutes.filter(x => x.filePath === filePath)) {
      const match = ROUTE_DECLARATION.exec(r.text);
      const routePath = match?.slice(1).find(Boolean) ?? '';

      if (PUBLIC_ROUTE.test(routePath) || PUBLIC_ROUTE.test(filePath)) {
        publicCount++;
        continue;
      }

      const above = lines.slice(Math.max(0, r.line - 1 - 6), r.line - 1).join('\n');
      const below = lines.slice(r.line - 1, Math.min(lines.length, r.line + 12)).join('\n');
      if (PUBLIC_MARKER.test(above)) {
        publicCount++;
        continue;
      }

      if (hasGlobalAuth || fileHasGuard || AUTH_GUARD.test(above) || AUTH_GUARD.test(below)) {
        protectedCount++;
      } else {
        unprotectedRoutes.push({ filePath, line: r.line, text: r.text, path: routePath });
      }
    }
  }

  // ---- 4. Способ проверки токена -----------------------------------------------
  const decodeOnly = await index.grep(JWT_DECODE_ONLY, { ...src, limit: 6 });
  const jwtVerify = await index.grep(JWT_VERIFY, { ...src, limit: 4 });
  const algNone = await index.grep(JWT_NONE, { ...src, limit: 3 });
  const hardSecret = await index.grep(JWT_HARDCODED_SECRET, { ...src, limit: 3 });

  for (const hit of jwtVerify.slice(0, 2)) {
    evidence.push(toEvidence(hit, 'Криптографическая проверка токена на сервере', 'SUPPORTS'));
  }

  // ---- 5. Срок жизни и cookie --------------------------------------------------
  const expiry = await index.grep(TOKEN_EXPIRY, { kinds: ['source', 'config'], excludeTests: true, limit: 4 });
  const signHits = await index.grep(/jwt\.sign\s*\(|jwtService\.sign(?:Async)?\s*\(|\.signAsync\s*\(/, { ...src, limit: 4 });
  const cookies = await index.grep(COOKIE_SET, { ...src, limit: 4 });

  // ---- Нарушения ------------------------------------------------------------------
  for (const hit of decodeOnly.slice(0, 3)) {
    // Декодирование допустимо, если рядом выполняется проверка подписи.
    const lines = await index.readCode(hit.filePath);
    const region = (lines ?? []).slice(Math.max(0, hit.line - 6), hit.line + 8).join('\n');
    if (JWT_VERIFY.test(region)) continue;

    violations.push({
      filePath: hit.filePath,
      lineStart: hit.line,
      lineEnd: hit.line,
      symbol: 'проверка токена',
      evidence: hit.text,
      explanation:
        'Токен декодируется без проверки подписи (jwt.decode, verify=False, ignoreExpiration). ' +
        'Такой токен может быть подделан клиентом: сервер принимает то, что прислал ' +
        'злоумышленник. Требование ИБ-02 обязывает проверять валидность токена на сервере.',
      severity: 'CRITICAL',
      confidence: 'HIGH',
      recommendation: 'Использовать jwt.verify с явным списком допустимых алгоритмов и проверкой срока действия.',
    });
  }

  for (const hit of algNone.slice(0, 1)) {
    violations.push({
      filePath: hit.filePath,
      lineStart: hit.line,
      lineEnd: hit.line,
      symbol: 'алгоритм подписи',
      evidence: hit.text,
      explanation: 'Допускается алгоритм подписи «none»: токен без подписи будет принят как валидный.',
      severity: 'CRITICAL',
      confidence: 'HIGH',
      recommendation: 'Явно перечислить допустимые алгоритмы (например, HS256/RS256), исключив «none».',
    });
  }

  for (const hit of hardSecret.slice(0, 1)) {
    violations.push({
      filePath: hit.filePath,
      lineStart: hit.line,
      lineEnd: hit.line,
      symbol: 'секрет подписи токена',
      evidence: hit.text.replace(/(['"`])[A-Za-z0-9!@#$%^&*()_+\-=]{4,}\1/g, '$1***REDACTED***$1'),
      explanation:
        'Секрет подписи токена задан в исходном коде. Тот, кто имеет доступ к репозиторию, ' +
        'может выпускать токены, которые сервер сочтёт валидными.',
      severity: 'CRITICAL',
      confidence: 'MEDIUM',
      recommendation: 'Вынести секрет в переменную окружения или секрет-хранилище.',
    });
  }

  // Токен выпускается, но срок его жизни нигде не задаётся.
  if (signHits.length > 0 && expiry.length === 0) {
    const hit = signHits[0];
    violations.push({
      filePath: hit.filePath,
      lineStart: hit.line,
      lineEnd: hit.line,
      symbol: 'срок жизни токена',
      evidence: hit.text,
      explanation:
        'Токен выпускается, но ограничение срока его действия (expiresIn, exp, maxAge) в проекте ' +
        'не найдено. Сервер не сможет отвергнуть токен по истечении срока — украденный токен ' +
        'останется валидным бессрочно.',
      severity: 'HIGH',
      confidence: 'MEDIUM',
      recommendation: 'Задать expiresIn при выпуске токена и проверять срок на сервере.',
    });
  }

  if (cookies.length > 0) {
    const cookieText = (
      await Promise.all(cookies.map(async c => ((await index.readCode(c.filePath)) ?? []).join('\n')))
    ).join('\n');
    if (!COOKIE_FLAGS_OK.test(cookieText)) {
      violations.push({
        filePath: cookies[0].filePath,
        lineStart: cookies[0].line,
        lineEnd: cookies[0].line,
        symbol: 'cookie сессии',
        evidence: cookies[0].text,
        explanation:
          'Сессия хранится в cookie, но флаг httpOnly не установлен: скрипт на странице может ' +
          'прочитать идентификатор сессии.' +
          (COOKIE_SECURE.test(cookieText) ? '' : ' Флаг secure также не обнаружен.'),
        severity: 'MEDIUM',
        confidence: 'MEDIUM',
        recommendation: 'Установить httpOnly: true, secure: true и sameSite для cookie сессии.',
      });
    }
  }

  // Защищённые маршруты без серверного guard-а. Порог: если незащищённых
  // подавляющее большинство и нет ни одного глобального или файлового guard-а.
  const totalNonPublic = protectedCount + unprotectedRoutes.length;
  if (unprotectedRoutes.length > 0 && !hasGlobalAuth) {
    const share = totalNonPublic === 0 ? 0 : Math.round((unprotectedRoutes.length / totalNonPublic) * 100);
    const anchor = unprotectedRoutes[0];

    violations.push({
      filePath: anchor.filePath,
      lineStart: anchor.line,
      lineEnd: anchor.line,
      symbol: anchor.path || 'маршрут',
      evidence:
        `${anchor.text} — и ещё ${unprotectedRoutes.length - 1} маршрутов без серверной проверки ` +
        `аутентификации (${share}% непубличных маршрутов). Примеры: ` +
        unprotectedRoutes.slice(0, 4).map(r => `${r.filePath}:${r.line}`).join(', '),
      explanation:
        'Найдены серверные маршруты, для которых не обнаружено ни guard-а/middleware ' +
        'аутентификации на классе, роутере или методе, ни глобальной регистрации. Требование ' +
        'ИБ-02 обязывает проверять сессию и токен на стороне сервера при каждом обращении к ' +
        'защищённым конечным точкам, включая API. Публичные по замыслу маршруты (health, login, ' +
        'webhook и т.п.) исключены из подсчёта.',
      severity: DEFINITION.severity,
      confidence: share >= 70 ? 'HIGH' : 'MEDIUM',
      recommendation:
        'Зарегистрировать guard аутентификации глобально (APP_GUARD, app.use, middleware) с явным ' +
        'белым списком публичных маршрутов либо применить его к каждому контроллеру.',
    });
  }

  // ---- Итог ------------------------------------------------------------------------
  const noServerAuthAtAll = authMechanisms.length === 0 && !hasGlobalAuth && jwtVerify.length === 0;

  // Найденное нарушение (jwt.decode, секрет в коде, алгоритм none) не теряется из-за того,
  // что маршруты распознать не удалось: «недостаточно данных» — только когда вывода нет вовсе.
  if (serverRoutes.length === 0 && authMechanisms.length === 0 && violations.length === 0) {
    return buildResult(DEFINITION, {
      status: 'INSUFFICIENT_EVIDENCE',
      confidence: 'LOW',
      summary: 'HTTP-поверхность обнаружена, но серверных маршрутов и механизмов аутентификации распознать не удалось.',
      evidence: [],
      violations,
      insufficientReason:
        'Объявления маршрутов и guard-ов не распознаны; аутентификация может быть делегирована ' +
        'внешнему провайдеру или реализована на неподдерживаемом фреймворке.',
    });
  }

  // Маршруты есть, серверной аутентификации нет вообще. По п. 4.4.5 ТЗ это
  // нарушение — если только все маршруты не публичные по замыслу. Отдельная
  // запись нужна лишь когда выше не сработало покрытие по маршрутам.
  if (noServerAuthAtAll && totalNonPublic > 0 && violations.length === 0) {
    const anchor = unprotectedRoutes[0] ?? serverRoutes[0];
    violations.push({
      filePath: anchor.filePath,
      lineStart: anchor.line,
      lineEnd: anchor.line,
      symbol: 'серверная аутентификация',
      evidence: '(в проекте не найдено ни guard-а, ни middleware аутентификации, ни проверки токена)',
      explanation:
        'В проекте объявлены серверные маршруты, однако механизм проверки сессии или токена ' +
        'на сервере отсутствует. Отсутствие реализации — нарушение в той же мере, что и ' +
        'некорректная реализация (п. 4.4.5 ТЗ).',
      severity: DEFINITION.severity,
      confidence: 'MEDIUM',
      recommendation:
        'Реализовать серверную проверку токена (guard/middleware) и применить её ко всем ' +
        'защищённым маршрутам.',
    });
  }

  if (violations.length === 0) {
    return buildResult(DEFINITION, {
      status: 'PASS',
      confidence: hasGlobalAuth ? 'MEDIUM' : 'HIGH',
      summary:
        `Серверных маршрутов: ${serverRoutes.length} (защищено: ${protectedCount}, публичных: ${publicCount}). ` +
        (hasGlobalAuth ? 'Проверка аутентификации зарегистрирована глобально. ' : '') +
        (jwtVerify.length ? 'Токен проверяется криптографически. ' : '') +
        'Работа guard-а во время выполнения статически не доказывается.',
      evidence: evidence.slice(0, 10),
      violations: [],
      insufficientReason: null,
    });
  }

  return buildResult(DEFINITION, {
    status: 'VIOLATION',
    confidence: 'HIGH',
    summary:
      `Серверных маршрутов: ${serverRoutes.length}, защищено: ${protectedCount}, без проверки: ${unprotectedRoutes.length}. ` +
      `Нарушений: ${violations.length}.`,
    evidence: [
      ...evidence,
      ...violations.slice(0, 3).map(v => ({
        filePath: v.filePath ?? '',
        line: v.lineStart ?? 0,
        snippet: v.evidence.slice(0, 240),
        note: v.symbol ?? 'нарушение',
        kind: 'VIOLATES' as const,
      })),
    ].slice(0, 12),
    violations,
    insufficientReason: null,
  });
}
