import {
  REQUIREMENT_DEFINITIONS,
  RequirementEvidence,
  RequirementResult,
  RequirementViolation,
} from '../requirement-definitions.js';
import { Hit, WorkspaceIndex } from '../workspace-index.js';
import { buildResult, toEvidence } from './shared.js';

/**
 * ИБ-04 — криптографическая защита персональных данных при хранении (ТЗ п. 4.5.4).
 *
 * Пароли должны храниться в виде значений функций формирования ключа bcrypt,
 * argon2 или scrypt. Нарушением является хранение в открытом виде, а РАВНО с
 * применением быстрых хеш-функций общего назначения без адаптивного алгоритма.
 *
 * Прежняя оценка контролей ловила только md5 и sha1. SHA-256, SHA-512, SHA-3 и
 * BLAKE — такие же быстрые хеши общего назначения, и п. 4.5.4 запрещает их для
 * паролей ровно так же; здесь они детектируются наравне с остальными.
 */

const DEFINITION = REQUIREMENT_DEFINITIONS['ИБ-04'];

/** Быстрые хеш-функции общего назначения. Для хранения пароля недопустимы. */
const FAST_HASH =
  /createHash\s*\(\s*['"`](?:md5|sha-?1|sha-?224|sha-?256|sha-?384|sha-?512|sha3-\d+|blake2[bs]?\d*|ripemd160)['"`]\s*\)|hashlib\.(?:md5|sha1|sha224|sha256|sha384|sha512|sha3_\d+|blake2[bs])\s*\(|MessageDigest\.getInstance\s*\(\s*['"`](?:MD5|SHA-?1|SHA-?256|SHA-?512)['"`]\)|\b(?:md5|sha1|sha256|sha512)\s*\.\s*(?:new|Sum|hexdigest|digest)\b|Digest::(?:MD5|SHA1|SHA256)/i;

/** Адаптивные KDF, допустимые по п. 4.5.4 ТЗ. */
const ADAPTIVE_KDF =
  /\b(?:bcrypt(?:js)?|argon2(?:id|i|d)?|scrypt(?:Sync)?|passlib\.hash\.(?:bcrypt|argon2|scrypt)|BCryptPasswordEncoder|Argon2PasswordEncoder|SCryptPasswordEncoder|golang\.org\/x\/crypto\/(?:bcrypt|argon2|scrypt)|password_hash\s*\(|PASSWORD_(?:BCRYPT|ARGON2ID?))\b/i;

/**
 * PBKDF2 — адаптивная функция, но в закрытом перечне ТЗ (bcrypt, argon2, scrypt)
 * её нет. Такой случай не объявляется нарушением автоматически: он выносится в
 * отчёт как основание для решения экспертной комиссии.
 */
const PBKDF2 = /\bpbkdf2(?:Sync)?\s*\(|PBKDF2(?:HMAC|PasswordEncoder)|hashlib\.pbkdf2_hmac/i;

/** Контекст, в котором хеш применяется именно к паролю. */
const PASSWORD_CONTEXT = /\b(?:password|passwd|pwd|passphrase|пароль)\w*/i;

/** Признаки того, что хеш считается для не-пароля: контрольная сумма, ETag, ключ идемпотентности. */
const NON_PASSWORD_HASH_CONTEXT =
  /\b(?:checksum|etag|fingerprint|integrity|digest\s+of\s+file|file(?:hash|sum)|cache[_-]?key|idempotenc|content[_-]?hash|gravatar|sri|subresource|signature\s+of\s+webhook)\b/i;

/** Пароль сравнивается или сохраняется как есть. */
const PLAINTEXT_PASSWORD: Array<{ label: string; pattern: RegExp }> = [
  { label: 'Пароль сравнивается строгим равенством', pattern: /\b(?:user|account|record|row|dbUser)\.password\s*(?:===|==)\s*(?:password|body\.password|req\.body\.password|input)|\bpassword\s*(?:===|==)\s*(?:user|account|record|row|dbUser)\.password/i },
  { label: 'Пароль записывается в БД без хеширования', pattern: /(?:INSERT\s+INTO\s+\w*users?\w*[^;]*|users?\.create\s*\(\s*\{[^}]*)\bpassword\s*[:,]\s*(?:req\.body\.password|body\.password|dto\.password|password)\b(?![^}]*(?:hash|bcrypt|argon|scrypt))/i },
  { label: 'Пароль хранится в открытом виде (явно)', pattern: /\bplain(?:text)?[_-]?password\b|\bpassword_plain\b|\bpasswordText\b/i },
];

/** Симметричное шифрование пароля: пароль должен быть невосстановим. */
const REVERSIBLE_PASSWORD =
  /\b(?:encrypt|cipher|aes|createCipher(?:iv)?)\w*\s*\([^)]*\bpassword\b|\bpassword\b[^;\n]{0,60}\b(?:encrypt|createCipher(?:iv)?)\s*\(|decryptPassword|decrypt_password/i;

/** Ключ шифрования, записанный в коде. */
const HARDCODED_KEY =
  /(?:encryption|encrypt|cipher|aes|secret|master)[_-]?key\s*[:=]\s*['"`][A-Za-z0-9+/=_-]{16,}['"`]|createCipheriv\s*\([^,]+,\s*['"`][^'"`]{16,}['"`]/i;

/** Режимы без контроля целостности. */
const WEAK_CIPHER_MODE = /aes-(?:128|192|256)-ecb\b|createCipher\s*\(|\bDES(?:ede)?[-_]|\brc4\b/i;

/** Поля персональных данных в схемах. */
const PII_FIELD =
  /\b(?:first[_-]?name|last[_-]?name|middle[_-]?name|full[_-]?name|surname|patronymic|email|e[_-]?mail|phone|birth[_-]?date|iin|passport|фамилия|имя|отчество)\b/i;

export async function checkIb04(index: WorkspaceIndex): Promise<RequirementResult> {
  const evidence: RequirementEvidence[] = [];
  const violations: RequirementViolation[] = [];

  const source = { kinds: ['source' as const], excludeTests: true, serverOnly: false };

  // ---- 1. Быстрые хеши, применённые к паролю ---------------------------------
  const fastHashHits = await index.grep(FAST_HASH, { ...source, limit: 60, perFile: 6 });
  const passwordFastHashes: Hit[] = [];

  for (const hit of fastHashHits) {
    const lines = await index.readCode(hit.filePath);
    if (!lines) continue;

    // Контекст вокруг вызова: пароль должен упоминаться рядом, а признаки
    // контрольной суммы — нет. Это защита от ложного срабатывания на хеш файла.
    const region = lines.slice(Math.max(0, hit.line - 8), Math.min(lines.length, hit.line + 6)).join('\n');
    const file = index.files.find(f => f.relPath === hit.filePath);
    if (file?.clientSide) continue;

    if (PASSWORD_CONTEXT.test(region) && !NON_PASSWORD_HASH_CONTEXT.test(region)) {
      // Если рядом же используется адаптивный KDF, это, скорее всего, миграция
      // или проверка легаси-хеша: фиксируем, но с пониженной уверенностью.
      passwordFastHashes.push(hit);
    }
  }

  // ---- 2. Адаптивные KDF и PBKDF2 ------------------------------------------
  const kdfHits = await index.grep(ADAPTIVE_KDF, { ...source, limit: 8 });
  const manifestKdf = await index.grep(/["']?(?:bcrypt(?:js)?|argon2|scrypt)["']?\s*[:=]?/i, {
    kinds: ['manifest'], limit: 3,
  });
  const pbkdf2Hits = await index.grep(PBKDF2, { ...source, limit: 4 });
  const hasAdaptiveKdf = kdfHits.length > 0 || manifestKdf.length > 0;

  for (const hit of kdfHits.slice(0, 3)) {
    evidence.push(toEvidence(hit, 'Адаптивная функция формирования ключа (bcrypt/argon2/scrypt)', 'SUPPORTS'));
  }

  // ---- 3. Пароль в открытом виде ------------------------------------------
  const plaintext: Array<Hit & { label: string }> = [];
  for (const rule of PLAINTEXT_PASSWORD) {
    const hits = await index.grep(rule.pattern, { ...source, limit: 6 });
    for (const hit of hits) plaintext.push({ ...hit, label: rule.label });
  }

  const reversible = await index.grep(REVERSIBLE_PASSWORD, { ...source, limit: 4 });

  // ---- 4. Ключи и режимы шифрования ---------------------------------------
  const hardcodedKeys = await index.grep(HARDCODED_KEY, { ...source, limit: 4 });
  const weakModes = await index.grep(WEAK_CIPHER_MODE, { ...source, limit: 4 });

  // ---- 5. Наличие персональных данных в схеме -----------------------------
  const piiSchema = await index.grep(PII_FIELD, {
    kinds: ['source', 'migration'],
    pathPattern: /(schema|model|entity|migration|prisma|\.sql$)/i,
    excludeTests: true,
    limit: 6,
    perFile: 2,
  });
  const storesPasswords =
    (await index.grep(/\bpassword(?:_?hash)?\b/i, {
      kinds: ['migration', 'source'],
      pathPattern: /(schema|model|entity|migration|prisma|user|account|auth|\.sql$)/i,
      excludeTests: true,
      limit: 3,
    })).length > 0;

  // ---- Формирование нарушений ---------------------------------------------
  for (const hit of passwordFastHashes.slice(0, 5)) {
    violations.push({
      filePath: hit.filePath,
      lineStart: hit.line,
      lineEnd: hit.line,
      symbol: 'хеширование пароля',
      evidence: hit.text,
      explanation:
        'Пароль хешируется быстрой хеш-функцией общего назначения без адаптивного алгоритма. ' +
        'Такая функция вычисляется за микросекунды, что позволяет подбирать пароли из ' +
        'украденной базы на порядки быстрее, чем при bcrypt, argon2 или scrypt. ' +
        'Пункт 4.5.4 ТЗ прямо относит это к нарушениям; допустимыми названы только bcrypt, ' +
        'argon2 и scrypt.' +
        (hasAdaptiveKdf
          ? ' В проекте также используется адаптивный KDF — возможно, это проверка легаси-хеша; ' +
            'старые хеши необходимо перехешировать.'
          : ''),
      severity: 'CRITICAL',
      confidence: hasAdaptiveKdf ? 'MEDIUM' : 'HIGH',
      recommendation:
        'Заменить на argon2id (либо bcrypt с cost не ниже 12, либо scrypt). Существующие хеши ' +
        'перехешировать при следующем успешном входе пользователя. Соль в bcrypt/argon2/scrypt ' +
        'встроена — отдельную статическую соль в коде не использовать.',
    });
  }

  for (const hit of plaintext.slice(0, 4)) {
    violations.push({
      filePath: hit.filePath,
      lineStart: hit.line,
      lineEnd: hit.line,
      symbol: 'хранение пароля',
      evidence: hit.text,
      explanation:
        `${hit.label}. Требование ИБ-04 допускает хранение пароля только в виде значения ` +
        'функции формирования ключа bcrypt, argon2 или scrypt; хранение в открытом виде — ' +
        'прямое нарушение.',
      severity: 'CRITICAL',
      confidence: 'MEDIUM',
      recommendation:
        'Хешировать пароль argon2id/bcrypt/scrypt при создании и сравнивать через функцию ' +
        'проверки KDF, а не оператором равенства.',
    });
  }

  for (const hit of reversible.slice(0, 2)) {
    violations.push({
      filePath: hit.filePath,
      lineStart: hit.line,
      lineEnd: hit.line,
      symbol: 'шифрование пароля',
      evidence: hit.text,
      explanation:
        'Пароль обрабатывается обратимым шифрованием. Пароль должен храниться в виде ' +
        'необратимого значения функции формирования ключа: возможность расшифровать пароль ' +
        'означает, что он восстановим при компрометации ключа.',
      severity: 'HIGH',
      confidence: 'MEDIUM',
      recommendation: 'Заменить обратимое шифрование на argon2id/bcrypt/scrypt.',
    });
  }

  for (const hit of hardcodedKeys.slice(0, 2)) {
    violations.push({
      filePath: hit.filePath,
      lineStart: hit.line,
      lineEnd: hit.line,
      symbol: 'ключ шифрования',
      evidence: hit.text.replace(/(['"`])[A-Za-z0-9+/=_-]{16,}\1/g, '$1***REDACTED***$1'),
      explanation:
        'Ключ шифрования персональных данных задан в исходном коде. Управление ключами — ' +
        'часть криптографической защиты по п. 4.5.4: ключ, лежащий в репозитории, ' +
        'скомпрометирован для каждого, кто имеет к нему доступ.',
      severity: 'HIGH',
      confidence: 'MEDIUM',
      recommendation: 'Вынести ключ в переменную окружения или секрет-хранилище; предусмотреть ротацию.',
    });
  }

  for (const hit of weakModes.slice(0, 2)) {
    violations.push({
      filePath: hit.filePath,
      lineStart: hit.line,
      lineEnd: hit.line,
      symbol: 'режим шифрования',
      evidence: hit.text,
      explanation:
        'Используется режим шифрования без контроля целостности либо устаревший алгоритм ' +
        '(ECB/CBC без MAC, createCipher без вектора инициализации, DES, RC4). Такая защита ' +
        'не соответствует уровню, требуемому СТ РК 1073-2007.',
      severity: 'MEDIUM',
      confidence: 'MEDIUM',
      recommendation: 'Использовать AES-256-GCM или ChaCha20-Poly1305 с уникальным вектором инициализации.',
    });
  }

  for (const hit of pbkdf2Hits.slice(0, 1)) {
    evidence.push(toEvidence(
      hit,
      'PBKDF2 — адаптивная функция, но в закрытом перечне п. 4.5.4 ТЗ (bcrypt, argon2, scrypt) её нет; ' +
        'допустимость определяет экспертная комиссия',
      'CONTEXT',
    ));
  }
  for (const hit of piiSchema.slice(0, 2)) {
    evidence.push(toEvidence(hit, 'Поле персональных данных в схеме', 'CONTEXT'));
  }

  // ---- Итог ---------------------------------------------------------------
  if (violations.length > 0) {
    const critical = violations.filter(v => v.severity === 'CRITICAL').length;
    return buildResult(DEFINITION, {
      status: 'VIOLATION',
      confidence: 'HIGH',
      summary:
        `Обнаружено нарушений: ${violations.length} (критических: ${critical}). ` +
        (passwordFastHashes.length
          ? `Пароль хешируется быстрой хеш-функцией общего назначения в ${passwordFastHashes.length} местах. `
          : '') +
        (hasAdaptiveKdf ? 'Адаптивный KDF в проекте присутствует, но не исключает найденных мест.' : 'Адаптивный KDF не обнаружен.'),
      evidence: [
        ...evidence,
        ...violations.slice(0, 4).map(v => ({
          filePath: v.filePath ?? '',
          line: v.lineStart ?? 0,
          snippet: v.evidence,
          note: v.symbol ?? 'нарушение',
          kind: 'VIOLATES' as const,
        })),
      ].slice(0, 12),
      violations,
      insufficientReason: null,
    });
  }

  // Нарушений не найдено. Отличаем «проверено» от «нечего проверять».
  if (!storesPasswords && !hasAdaptiveKdf && piiSchema.length === 0) {
    return buildResult(DEFINITION, {
      status: 'NOT_APPLICABLE',
      confidence: 'MEDIUM',
      summary:
        'Хранение паролей и персональных данных в проекте не обнаружено: нет полей пароля и ' +
        'персональных данных в схемах и моделях, нет вызовов функций хеширования паролей.',
      evidence: [],
      violations: [],
      insufficientReason: null,
    });
  }

  if (storesPasswords && !hasAdaptiveKdf) {
    // Пароли, судя по схеме, хранятся, но ни одного KDF в проекте не найдено.
    // По п. 4.4.5 ТЗ отсутствие реализации — такое же нарушение.
    const anchor = (await index.grep(/\bpassword(?:_?hash)?\b/i, {
      kinds: ['migration', 'source'],
      pathPattern: /(schema|model|entity|migration|prisma|user|account|auth|\.sql$)/i,
      excludeTests: true,
      limit: 1,
    }))[0];

    return buildResult(DEFINITION, {
      status: 'VIOLATION',
      confidence: 'MEDIUM',
      summary:
        'В схеме или моделях присутствует поле пароля, но ни bcrypt, ни argon2, ни scrypt в ' +
        'проекте не обнаружено. Механизм безопасного хранения паролей не реализован ' +
        '(отсутствие реализации — нарушение в той же мере, что и некорректная реализация, п. 4.4.5 ТЗ).',
      evidence: anchor ? [toEvidence(anchor, 'Поле пароля без обнаруженного KDF', 'VIOLATES')] : [],
      violations: [{
        filePath: anchor?.filePath ?? null,
        lineStart: anchor?.line ?? null,
        lineEnd: anchor?.line ?? null,
        symbol: 'хранение пароля',
        evidence: anchor?.text ?? '(поле пароля в схеме)',
        explanation:
          'Проект хранит пароли, однако функции формирования ключа bcrypt, argon2 или scrypt ' +
          'в коде и манифестах зависимостей не найдены. Аутентификация может быть делегирована ' +
          'внешнему провайдеру — тогда нарушения нет, но это статически не устанавливается.',
        severity: 'HIGH',
        confidence: 'MEDIUM',
        recommendation: 'Подключить argon2id/bcrypt/scrypt и хешировать пароль при создании и смене.',
      }],
      insufficientReason: null,
    });
  }

  return buildResult(DEFINITION, {
    status: hasAdaptiveKdf ? 'PASS' : 'INSUFFICIENT_EVIDENCE',
    confidence: 'MEDIUM',
    summary: hasAdaptiveKdf
      ? 'Пароли хешируются адаптивной функцией (bcrypt/argon2/scrypt); быстрых хеш-функций общего ' +
        'назначения рядом с паролями, обратимого шифрования и открытого хранения не обнаружено. ' +
        'Параметры трудоёмкости и шифрование прочих персональных данных статически не подтверждаются.'
      : 'Персональные данные в схеме обнаружены, но механизм их защиты установить не удалось.',
    evidence: evidence.slice(0, 10),
    violations: [],
    insufficientReason: hasAdaptiveKdf
      ? null
      : 'Найдены поля персональных данных, но признаков шифрования при хранении не обнаружено; возможно, защита реализована на уровне СУБД либо инфраструктуры.',
  });
}
