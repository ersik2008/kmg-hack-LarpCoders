import {
  REQUIREMENT_DEFINITIONS,
  RequirementEvidence,
  RequirementResult,
} from '../requirement-definitions.js';
import { Hit, WorkspaceIndex } from '../workspace-index.js';
import { buildResult, toEvidence } from './shared.js';

/**
 * ИБ-05 — защита локальных журналов приложения (ТЗ п. 4.5.5).
 *
 * Простое наличие логгера выполнением требования не является: оно касается
 * ШИФРОВАНИЯ локального журнала и ЗАЩИТЫ ОТ МОДИФИКАЦИИ до отправки на сервер.
 *
 * Применимость определяется тем, пишет ли приложение журнал на файловую
 * систему. Сервис, пишущий только в stdout контейнера, локального журнала не
 * ведёт: сбором занимается платформа, и требовать шифрования файла, которого
 * нет, было бы ложным срабатыванием.
 */

const DEFINITION = REQUIREMENT_DEFINITIONS['ИБ-05'];

/** Запись журнала в файл. */
const FILE_LOG_SINKS: Array<{ label: string; pattern: RegExp }> = [
  { label: 'winston: файловый транспорт', pattern: /transports\.File\s*\(|new\s+winston\.transports\.File|DailyRotateFile/ },
  { label: 'pino: запись в файл', pattern: /pino\.destination\s*\(|pino\/file|pino\.transport\s*\(\s*\{[^}]*file/i },
  { label: 'bunyan: файловый поток', pattern: /type\s*:\s*['"`]rotating-file['"`]|streams\s*:\s*\[[^\]]*path\s*:/ },
  // Голое `type: 'file'` не берём: так же выглядит тип узла дерева файлов и десятки
  // других объектов. Файловый аппендер log4js опознаётся по `filename` рядом.
  { label: 'log4js/log4j: файловый аппендер', pattern: /type\s*:\s*['"`]file['"`]\s*,\s*filename|\bFileAppender\b|\bRollingFileAppender\b/ },
  { label: 'Python logging: файловый обработчик', pattern: /\blogging\.FileHandler\s*\(|RotatingFileHandler\s*\(|TimedRotatingFileHandler\s*\(|logging\.basicConfig\s*\([^)]*filename\s*=/ },
  { label: 'Go/Java: запись журнала в файл', pattern: /os\.OpenFile\s*\([^)]*\.log|lumberjack\.Logger|FileHandler\s*\(\s*['"`][^'"`]*\.log/ },
  { label: 'Прямая запись в .log-файл', pattern: /(?:createWriteStream|appendFile(?:Sync)?|writeFile(?:Sync)?)\s*\([^)]*\.log\b/ },
];

/** Шифрование содержимого журнала перед записью. */
const LOG_ENCRYPTION =
  /\b(?:createCipheriv|encryptLog|encrypt_log|EncryptedTransport|EncryptingStream|Fernet|AESGCM|secretbox|crypto_secretbox|encryptedFile|EncryptedFileHandler)\b|aes-256-gcm|chacha20-poly1305/i;

/** Защита целостности: код аутентификации, подпись, цепочка хешей. */
const LOG_INTEGRITY =
  /\b(?:createHmac|hmac\.new|HMAC|signLog|sign_log|hashChain|hash_chain|prevHash|previous_hash|chainHash|createSign|tamper)\b/i;

/** Ограничение прав доступа к файлу журнала. */
const LOG_PERMISSIONS =
  /\b(?:fs\.chmod(?:Sync)?|os\.chmod|chmod\s*\(|umask)\b|mode\s*:\s*0o?[0-7]{3,4}|0o600|0o640|0600|0640/;

/** Отправка журнала на сервер. */
const LOG_SHIPPING =
  /\b(?:winston-transport-http|transports\.Http|HTTPHandler|SysLogHandler|syslog|logstash|fluent(?:d|bit)?|filebeat|loki|splunk|datadog|sentry|shipLogs|uploadLogs|sendLogs|remoteTransport|SocketHandler)\b/i;

/** Признаки клиентского приложения на устройстве пользователя. */
const CLIENT_APP = /\b(?:electron|react-native|cordova|capacitor|nw\.js|tauri|expo|flutter|xamarin|@ionic)\b/i;

export async function checkIb05(index: WorkspaceIndex): Promise<RequirementResult> {
  const sinkHits: Array<Hit & { label: string }> = [];

  for (const sink of FILE_LOG_SINKS) {
    const hits = await index.grep(sink.pattern, {
      kinds: ['source', 'config'],
      excludeTests: true,
      limit: 8,
      perFile: 2,
    });
    for (const hit of hits) sinkHits.push({ ...hit, label: sink.label });
  }

  // Локальных журналов на файловой системе нет — требование не к чему применять.
  if (sinkHits.length === 0) {
    const manifestText = (
      await Promise.all(index.byKind('manifest').slice(0, 10).map(m => index.readCode(m.relPath)))
    ).map(l => (l ?? []).join('\n')).join('\n');
    const isClientApp = CLIENT_APP.test(manifestText);

    return buildResult(DEFINITION, {
      status: isClientApp ? 'INSUFFICIENT_EVIDENCE' : 'NOT_APPLICABLE',
      confidence: 'MEDIUM',
      summary: isClientApp
        ? 'Проект похож на клиентское приложение, но записи журнала в локальный файл не ' +
          'обнаружено. Возможно, журнал ведётся средствами платформы либо в коде, не попавшем ' +
          'под шаблоны поиска.'
        : 'Запись журнала приложения в локальный файл не обнаружена: приложение не ведёт ' +
          'локальных журналов на файловой системе (вывод в stdout собирается платформой). ' +
          'Требование неприменимо.',
      evidence: [],
      violations: [],
      insufficientReason: isClientApp
        ? 'Клиентское приложение без обнаруженного файлового журнала: нужно подтвердить вручную, где хранится журнал.'
        : null,
    });
  }

  // Есть файловый журнал — проверяем три свойства защиты. Шифрование, HMAC или
  // chmod где-то в проекте журнал не защищают: учитываются только файлы,
  // относящиеся к журналированию (сам транспорт и модули с «log»/«audit» в пути).
  // Иначе шифрование токенов в модуле аутентификации засчитывалось как защита журнала.
  const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const sinkFiles = [...new Set(sinkHits.map(h => h.filePath))].map(escapeRe);
  const logScope = new RegExp('^(?:' + sinkFiles.join('|') + ')$|(?:^|/)[^/]*(?:log|audit)[^/]*(?:/|$)', 'i');
  const scoped = { kinds: ['source' as const], excludeTests: true, limit: 5, pathPattern: logScope };

  const encryption = await index.grep(LOG_ENCRYPTION, scoped);
  const integrity = await index.grep(LOG_INTEGRITY, scoped);
  const permissions = await index.grep(LOG_PERMISSIONS, scoped);
  const shipping = await index.grep(LOG_SHIPPING, { kinds: ['source', 'config', 'manifest'], excludeTests: true, limit: 5 });

  const evidence: RequirementEvidence[] = [];
  for (const hit of sinkHits.slice(0, 4)) evidence.push(toEvidence(hit, hit.label, 'CONTEXT'));
  for (const hit of encryption.slice(0, 2)) evidence.push(toEvidence(hit, 'Шифрование', 'SUPPORTS'));
  for (const hit of integrity.slice(0, 2)) evidence.push(toEvidence(hit, 'Контроль целостности', 'SUPPORTS'));
  for (const hit of permissions.slice(0, 2)) evidence.push(toEvidence(hit, 'Ограничение прав доступа', 'SUPPORTS'));
  for (const hit of shipping.slice(0, 2)) evidence.push(toEvidence(hit, 'Отправка журнала на сервер', 'SUPPORTS'));

  const gaps: string[] = [];
  if (encryption.length === 0) gaps.push('шифрование локального журнала');
  if (integrity.length === 0 && permissions.length === 0) {
    gaps.push('защита от модификации (контроль целостности либо ограничение прав доступа)');
  }

  if (gaps.length === 0) {
    return buildResult(DEFINITION, {
      status: 'PASS',
      confidence: 'MEDIUM',
      summary:
        'Приложение пишет журнал в локальный файл; обнаружены шифрование и защита от ' +
        'модификации. Работоспособность защиты во время выполнения статически не доказывается.',
      evidence,
      violations: [],
      insufficientReason: null,
    });
  }

  const anchor = sinkHits[0];
  const missingText = gaps.join('; ');

  return buildResult(DEFINITION, {
    status: 'VIOLATION',
    confidence: encryption.length === 0 && integrity.length === 0 ? 'HIGH' : 'MEDIUM',
    summary:
      `Приложение пишет журнал в локальный файл (${sinkHits.length} мест), но не обнаружено: ` +
      `${missingText}. Наличие логгера выполнением ИБ-05 не является.`,
    evidence,
    violations: [{
      filePath: anchor.filePath,
      lineStart: anchor.line,
      lineEnd: anchor.line,
      symbol: anchor.label,
      evidence: anchor.text,
      explanation:
        'Требование ИБ-05: локальные журналы приложения должны храниться в зашифрованном ' +
        'виде и быть защищены от модификации пользователем до отправки на сервер. ' +
        `Журнал пишется в локальный файл, однако в проекте не найдено: ${missingText}. ` +
        (shipping.length === 0
          ? 'Транспорт журнала на сервер также не обнаружен, поэтому локальная копия остаётся бессрочно. '
          : '') +
        'Проверка статическая: механизмы, подключаемые на этапе развёртывания, не видны.',
      severity: DEFINITION.severity,
      confidence: 'MEDIUM',
      recommendation:
        'Шифровать записи журнала перед записью на диск (например, AES-256-GCM с ключом из ' +
        'защищённого хранилища); вычислять HMAC по каждой записи и связывать записи в цепочку ' +
        'хешей; ограничить права файла (0600) и каталога; отправлять журнал на сервер и ' +
        'удалять локальную копию после подтверждения доставки.',
    }],
    insufficientReason: null,
  });
}
