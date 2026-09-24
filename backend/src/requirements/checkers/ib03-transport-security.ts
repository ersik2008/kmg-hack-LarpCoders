import {
  REQUIREMENT_DEFINITIONS,
  RequirementEvidence,
  RequirementResult,
  RequirementViolation,
} from '../requirement-definitions.js';
import { Hit, IndexedFile, WorkspaceIndex } from '../workspace-index.js';
import { buildResult, toEvidence } from './shared.js';

/**
 * ИБ-03 — защита канала передачи данных (ТЗ п. 4.5.3).
 *
 * Обмен между клиентом и сервером — исключительно по TLS не ниже 1.2 со
 * стойкими шифронаборами. Нарушением является конфигурация, допускающая
 * передачу в открытом виде, устаревшие версии протокола или слабые шифронаборы.
 *
 * Главная трудность — контекст. `http://localhost:3000` в файле для разработки
 * нарушением не является, а такой же адрес в продакшн-конфигурации — является.
 * Поэтому каждое попадание классифицируется по среде: prod / dev / test, и
 * предупреждение без контекста нарушением автоматически не объявляется.
 */

const DEFINITION = REQUIREMENT_DEFINITIONS['ИБ-03'];

type Environment = 'prod' | 'dev' | 'test' | 'unknown';

/** Определение среды по пути файла. */
function environmentOf(file: IndexedFile | undefined): Environment {
  if (!file) return 'unknown';
  const p = file.relPath.toLowerCase();
  if (file.kind === 'test') return 'test';
  if (/(^|[\/._-])(prod|production|release|live)([\/._-]|$)/.test(p)) return 'prod';
  if (/(^|[\/._-])(dev|development|local|debug|example|sample|demo)([\/._-]|$)|docker-compose\.(dev|local)|\.env\.example|\.env\.sample/.test(p)) return 'dev';
  if (/(^|[\/._-])(test|testing|staging|stage|qa|ci)([\/._-]|$)/.test(p)) return 'test';
  return 'unknown';
}

/** Устаревшие версии протокола и слабые шифронаборы. */
const WEAK_TLS: Array<{ label: string; pattern: RegExp; severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' }> = [
  { label: 'Разрешён SSLv2/SSLv3', pattern: /ssl_protocols[^;\n]*\bSSLv[23]\b|\bSSLv[23]\b\s*(?:enabled|:\s*true)|SSLv3|ssl\.PROTOCOL_SSLv[23]|minVersion\s*:\s*['"`]SSLv/i, severity: 'CRITICAL' },
  { label: 'Разрешён TLS 1.0 / 1.1', pattern: /ssl_protocols[^;\n]*\bTLSv1(?:\.0)?\b(?!\.[23])|ssl_protocols[^;\n]*\bTLSv1\.1\b|minVersion\s*:\s*['"`]TLSv1(?:\.[01])?['"`]|ssl\.PROTOCOL_TLSv1(?:_1)?\b|TLSv1(?:\.[01])?\b\s*(?:enabled|:\s*true)|MinProtocol\s*=?\s*TLSv1(?:\.[01])?\b|secureProtocol\s*:\s*['"`]TLSv1_(?:method|1_method)/i, severity: 'HIGH' },
  { label: 'Слабые шифронаборы (RC4/DES/3DES/NULL/EXPORT/MD5)', pattern: /ssl_ciphers[^;\n]*(?:RC4|DES|3DES|NULL|EXPORT|MD5|aNULL|eNULL|LOW)\b|ciphers\s*:\s*['"`][^'"`]*(?:RC4|DES|NULL|EXPORT|MD5)|SSLCipherSuite[^\n]*(?:RC4|DES|NULL|EXPORT|MD5)/i, severity: 'HIGH' },
  { label: 'Отключена проверка сертификата', pattern: /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"`]?0|verify\s*=\s*False|InsecureSkipVerify\s*:\s*true|CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0)|strictSSL\s*:\s*false|ssl_verify\s*=\s*false|--insecure\b|(?<![A-Za-z])curl\s+[^|\n]*\s-k\b/i, severity: 'HIGH' },
];

/** Открытые протоколы. */
const PLAINTEXT_URL = /['"`](?:http|ws):\/\/(?!localhost\b|127\.0\.0\.1\b|0\.0\.0\.0\b|\[::1\]|host\.docker\.internal|www\.w3\.org|schemas\.|json-schema\.org|json\.schemastore\.org|xmlns)[A-Za-z0-9._-]+/i;

/**
 * Разрешён HTTP без перенаправления: веб-сервер слушает 80 и не редиректит
 * на HTTPS. Сам по себе `listen 80` нарушением не является — важно, что с ним
 * происходит дальше.
 */
const LISTEN_80 = /\blisten\s+(?:\[::\]:)?80\b(?!\d)|<VirtualHost\s+\*:80>/i;
const HTTPS_REDIRECT = /return\s+30[1278]\s+https:|rewrite\s+\^[^;]*https:|RewriteRule[^\n]*https:|redirectScheme|redirect_to_https|force_https|forceSSL|ssl_redirect|SECURE_SSL_REDIRECT\s*=\s*True|Redirect\s+permanent\s+\/\s+https:/i;

const TLS_LISTEN = /\blisten\s+[^;\n]*443[^;\n]*ssl|ssl_certificate\b|SSLEngine\s+on|tls\s*\{|tls_certificate|:443\b/i;
const TLS_MIN_OK = /ssl_protocols[^;\n]*TLSv1\.[23]|minVersion\s*:\s*['"`]TLSv1\.[23]['"`]|MinProtocol\s*=?\s*TLSv1\.[23]|ssl\.TLSVersion\.TLSv1_[23]|tls\.VersionTLS1[23]|SSLProtocol[^\n]*TLSv1\.[23]|min_version[^\n]*1\.[23]/i;
const HSTS = /Strict-Transport-Security|\bhsts\b|helmet\s*\(\s*\{[^}]*hsts|SECURE_HSTS_SECONDS/i;

/** Признаки того, что сервер приложения сам обслуживает HTTP без TLS. */
const HTTP_SERVER_PLAIN = /\bhttp\.createServer\s*\(|app\.listen\s*\(\s*(?:\d+|process\.env\.PORT|port)|uvicorn\.run\s*\(|http\.ListenAndServe\s*\(/;
const TLS_TERMINATED_UPSTREAM = /\b(?:trust\s*proxy|X-Forwarded-Proto|x-forwarded-proto|ProxyFix|behind\s+(?:a\s+)?(?:proxy|load\s*balancer)|TRUST_PROXY)\b/i;

export async function checkIb03(index: WorkspaceIndex): Promise<RequirementResult> {
  const evidence: RequirementEvidence[] = [];
  const violations: RequirementViolation[] = [];
  const info: string[] = [];

  const fileOf = (h: Hit) => index.files.find(f => f.relPath === h.filePath);
  const scope = { kinds: ['source' as const, 'config' as const, 'webserver' as const, 'ci' as const], limit: 30 };

  // ---- 1. Слабый TLS, устаревшие протоколы, отключённая проверка ---------------
  for (const rule of WEAK_TLS) {
    const hits = await index.grep(rule.pattern, { ...scope, perFile: 3 });

    for (const hit of hits) {
      const env = environmentOf(fileOf(hit));

      // Тестовая и dev-конфигурация нарушением не считается, но фиксируется.
      if (env === 'test' || env === 'dev') {
        info.push(`${hit.filePath}:${hit.line} (${env}) — ${rule.label}`);
        evidence.push(toEvidence(hit, `${rule.label} — только в ${env}-конфигурации, нарушением не считается`, 'CONTEXT'));
        continue;
      }

      violations.push({
        filePath: hit.filePath,
        lineStart: hit.line,
        lineEnd: hit.line,
        symbol: rule.label,
        evidence: hit.text,
        explanation:
          `${rule.label}. Пункт 4.5.3 ТЗ допускает обмен только по TLS не ниже 1.2 со стойкими ` +
          'шифронаборами; конфигурации, допускающие устаревшие версии протокола, слабые ' +
          'шифронаборы или передачу без проверки подлинности сервера, являются нарушением. ' +
          (env === 'unknown'
            ? 'Среда файла не определена по пути — считается продакшн-конфигурацией.'
            : 'Файл относится к продакшн-конфигурации.'),
        severity: rule.severity,
        confidence: env === 'prod' ? 'HIGH' : 'MEDIUM',
        recommendation:
          'Задать минимальную версию TLS 1.2 (ssl_protocols TLSv1.2 TLSv1.3), ограничить перечень ' +
          'шифронаборов стойкими (AEAD, ECDHE), не отключать проверку сертификата: при ' +
          'самоподписанном сертификате добавить доверие конкретному CA.',
      });
    }
  }

  // ---- 2. Открытые http:// и ws:// ---------------------------------------------
  const plaintext = await index.grep(PLAINTEXT_URL, { ...scope, perFile: 2, limit: 40 });
  for (const hit of plaintext) {
    const file = fileOf(hit);
    const env = environmentOf(file);

    // Комментарии, документация и пространства имён — не конечные точки.
    if (/^\s*(?:\/\/|#|\*|<!--)/.test(hit.text)) continue;
    if (file?.kind === 'docs') continue;

    if (env === 'test' || env === 'dev') {
      info.push(`${hit.filePath}:${hit.line} (${env}) — открытый протокол`);
      continue;
    }

    // ws:// критичнее: обычно это канал с пользовательскими данными.
    const isWs = /\bws:\/\//i.test(hit.text);
    violations.push({
      filePath: hit.filePath,
      lineStart: hit.line,
      lineEnd: hit.line,
      symbol: isWs ? 'ws://' : 'http://',
      evidence: hit.text,
      explanation:
        `Адрес ${isWs ? 'WebSocket' : 'HTTP'}-сервиса задан по незащищённому протоколу ` +
        `(${isWs ? 'ws://' : 'http://'}) вне dev/test-конфигурации. Данные по такому каналу ` +
        'передаются в открытом виде, что запрещено п. 4.5.3 ТЗ. Адреса localhost, ' +
        '127.0.0.1 и пространства имён XML/JSON Schema из проверки исключены.',
      severity: 'HIGH',
      confidence: env === 'prod' ? 'HIGH' : 'MEDIUM',
      recommendation: `Использовать ${isWs ? 'wss://' : 'https://'}; для внутренних вызовов — либо TLS, либо явно документированная сетевая изоляция.`,
    });
  }

  // ---- 3. Конфигурация веб-сервера ---------------------------------------------
  const webserverFiles = index.byKind('webserver');
  const nginxLike: IndexedFile[] = [
    ...webserverFiles,
    ...index.files.filter(f => /(^|\/)dockerfile/i.test(f.relPath) || f.kind === 'config'),
  ];

  let tlsConfigured = false;
  let tlsMinVersionSet = false;
  let listens80 = false;
  let redirects = false;
  let hstsSet = false;
  let listen80Hit: Hit | undefined;

  for (const file of nginxLike) {
    const lines = await index.readCode(file.relPath);
    if (!lines) continue;
    const text = lines.join('\n');

    if (TLS_LISTEN.test(text)) tlsConfigured = true;
    if (TLS_MIN_OK.test(text)) tlsMinVersionSet = true;
    if (HSTS.test(text)) hstsSet = true;
    if (HTTPS_REDIRECT.test(text)) redirects = true;

    const idx = lines.findIndex(l => LISTEN_80.test(l));
    if (idx !== -1 && environmentOf(file) !== 'test') {
      listens80 = true;
      listen80Hit ??= { filePath: file.relPath, line: idx + 1, text: lines[idx].trim(), kind: file.kind };
    }
  }

  // Также ищем TLS в коде приложения.
  const appTls = await index.grep(
    /\bhttps\.createServer\s*\(|createServer\s*\(\s*\{[^}]*(?:key|cert)|httpsOptions|ssl_context\s*=|ssl\.SSLContext|ListenAndServeTLS|SECURE_SSL_REDIRECT|app\.use\s*\(\s*helmet/,
    { kinds: ['source'], excludeTests: true, limit: 4 },
  );
  if (appTls.length > 0) tlsConfigured = true;
  for (const hit of appTls.slice(0, 2)) evidence.push(toEvidence(hit, 'TLS/защитные заголовки в коде приложения', 'SUPPORTS'));

  // HTTP на 80 порту без перенаправления на HTTPS.
  if (listens80 && !redirects && listen80Hit) {
    violations.push({
      filePath: listen80Hit.filePath,
      lineStart: listen80Hit.line,
      lineEnd: listen80Hit.line,
      symbol: 'listen 80',
      evidence: listen80Hit.text,
      explanation:
        'Веб-сервер обслуживает HTTP на порту 80 и в конфигурации не обнаружено ' +
        'перенаправления на HTTPS. Клиент, обратившийся по http://, получит данные в ' +
        'открытом виде, что противоречит п. 4.5.3 ТЗ («исключительно по TLS»). ' +
        (tlsConfigured
          ? 'TLS в проекте настроен, но HTTP-вход не закрыт.'
          : 'TLS в проекте не настроен вовсе — веб-сервер отдаёт приложение только по HTTP.'),
      severity: tlsConfigured ? 'MEDIUM' : 'HIGH',
      confidence: tlsConfigured ? 'MEDIUM' : 'HIGH',
      recommendation:
        'Настроить return 301 https://$host$request_uri для порта 80 и включить TLS 1.2+ на 443, ' +
        'либо явно зафиксировать, что TLS терминируется вышестоящим балансировщиком.',
    });
  } else if (listen80Hit) {
    evidence.push(toEvidence(listen80Hit, 'HTTP-вход с перенаправлением на HTTPS', 'SUPPORTS'));
  }

  if (tlsMinVersionSet) {
    const hit = (await index.grep(TLS_MIN_OK, { kinds: ['webserver', 'config', 'source'], limit: 1 }))[0];
    if (hit) evidence.push(toEvidence(hit, 'Минимальная версия TLS не ниже 1.2', 'SUPPORTS'));
  }
  if (hstsSet) {
    const hit = (await index.grep(HSTS, { kinds: ['webserver', 'config', 'source'], excludeTests: true, limit: 1 }))[0];
    if (hit) evidence.push(toEvidence(hit, 'HSTS', 'SUPPORTS'));
  }

  // ---- 4. Итог -----------------------------------------------------------------
  const behindProxy = (await index.grep(TLS_TERMINATED_UPSTREAM, {
    kinds: ['source', 'config', 'docs'], excludeTests: true, limit: 1,
  })).length > 0;

  if (violations.length > 0) {
    const worst = violations.some(v => v.severity === 'CRITICAL') ? 'CRITICAL' : 'HIGH';
    return buildResult(DEFINITION, {
      status: 'VIOLATION',
      confidence: 'HIGH',
      summary:
        `Обнаружено нарушений: ${violations.length} (наиболее серьёзное: ${worst}). ` +
        (info.length ? `Дополнительно отмечено ${info.length} мест в dev/test-конфигурации — нарушением не считаются. ` : '') +
        (tlsMinVersionSet ? 'Минимальная версия TLS задана, но найденные места ей противоречат.' : ''),
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

  if (tlsConfigured || tlsMinVersionSet) {
    return buildResult(DEFINITION, {
      status: 'PASS',
      confidence: tlsMinVersionSet ? 'MEDIUM' : 'LOW',
      summary:
        'Слабых протоколов, шифронаборов и отключённой проверки сертификатов в продакшн-конфигурации ' +
        'не обнаружено; TLS настроен' +
        (tlsMinVersionSet ? ', минимальная версия не ниже 1.2' : '') +
        (hstsSet ? ', включён HSTS' : '') + '. ' +
        (info.length ? `Отмечено ${info.length} мест в dev/test-конфигурации — нарушением не считаются. ` : '') +
        'Фактически согласуемая версия TLS зависит от развёртывания и статически не доказывается.',
      evidence: evidence.slice(0, 10),
      violations: [],
      insufficientReason: null,
    });
  }

  // TLS в репозитории не настроен, нарушений не найдено.
  const hasHttpService = (await index.grep(HTTP_SERVER_PLAIN, {
    kinds: ['source'], excludeTests: true, limit: 1,
  })).length > 0;

  if (behindProxy || !hasHttpService) {
    return buildResult(DEFINITION, {
      status: 'INSUFFICIENT_EVIDENCE',
      confidence: 'LOW',
      summary:
        'Конфигурация TLS в репозитории не обнаружена; слабых протоколов не найдено. ' +
        (behindProxy
          ? 'Обнаружены признаки работы за прокси/балансировщиком: TLS, вероятно, терминируется вне репозитория.'
          : 'Признаков собственного HTTP-сервера не найдено.'),
      evidence: evidence.slice(0, 10),
      violations: [],
      insufficientReason:
        'TLS может терминироваться инфраструктурой (балансировщик, ingress, CDN), описание которой ' +
        'вне репозитория. Статически установить версию протокола и шифронаборы невозможно.',
    });
  }

  // Собственный HTTP-сервер без единого признака TLS и без прокси.
  const server = (await index.grep(HTTP_SERVER_PLAIN, { kinds: ['source'], excludeTests: true, limit: 1 }))[0];
  return buildResult(DEFINITION, {
    status: 'VIOLATION',
    confidence: 'MEDIUM',
    summary:
      'Приложение обслуживает HTTP самостоятельно, но настроек TLS в проекте не обнаружено ' +
      '(нет ни конфигурации веб-сервера, ни https-сервера в коде, ни признаков работы за прокси). ' +
      'Отсутствие реализации — нарушение в той же мере, что и некорректная реализация (п. 4.4.5 ТЗ).',
    evidence: server ? [toEvidence(server, 'HTTP-сервер без TLS', 'VIOLATES')] : [],
    violations: [{
      filePath: server?.filePath ?? null,
      lineStart: server?.line ?? null,
      lineEnd: server?.line ?? null,
      symbol: 'HTTP-сервер',
      evidence: server?.text ?? '(HTTP-сервер без TLS)',
      explanation:
        'Приложение слушает порт по протоколу HTTP, при этом в репозитории не найдено настроек TLS ' +
        'и не обнаружено указаний, что TLS терминируется вышестоящим компонентом. Передача ' +
        'данных в открытом виде противоречит п. 4.5.3 ТЗ. Если TLS обеспечивается инфраструктурой, ' +
        'это следует явно зафиксировать в репозитории (конфигурация прокси, документация).',
      severity: 'HIGH',
      confidence: 'MEDIUM',
      recommendation:
        'Настроить TLS 1.2+ на веб-сервере или обратном прокси; добавить конфигурацию в репозиторий; ' +
        'включить HSTS и перенаправление с HTTP.',
    }],
    insufficientReason: null,
  });
}
